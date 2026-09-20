"""日志与状态采集模块。

从 Home Assistant 配置目录与 Supervisor API 抓取：
- Core 日志（含 custom_components 的输出）
- 主机健康信息与历史数据库大小（环境检查用）
"""

import json
import os
import time
import urllib.error
import urllib.request

SUPERVISOR_URL = os.environ.get("SUPERVISOR_URL", "http://supervisor")
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")

# Core 配置目录在插件容器内的挂载点随 Supervisor 版本而不同，按候选顺序探测：
# - /homeassistant_config：新版 Supervisor（map 目标默认为 /<type-name>）
# - /homeassistant：旧版 Supervisor 的挂载点
# - /config：本地调试 / 旧式 map: config
CORE_LOG_CANDIDATES = (
    "/homeassistant_config/home-assistant.log",
    "/homeassistant/home-assistant.log",
    "/config/home-assistant.log",
)
CORE_DB_CANDIDATES = (
    "/homeassistant_config/home-assistant_v2.db",
    "/homeassistant/home-assistant_v2.db",
    "/config/home-assistant_v2.db",
)
# 日志文件过大时只读尾部，避免占用树莓派过多内存
CORE_LOG_MAX_BYTES = 20 * 1024 * 1024
# 采集类请求的超时（秒）：Supervisor 在本机环回，正常 <1s；
# 短超时保证其故障时单轮扫描快速结束，修复动作仍用默认 60s
FETCH_TIMEOUT = 10


def request(path, method="GET", body=None, timeout=60, retries=1):
    """调用 Supervisor API，返回 (HTTP 状态码, 响应文本)。

    网络层异常（连接失败/超时）自动重试 1 次；HTTP 错误码不重试。
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    attempts = retries + 1
    for i in range(attempts):
        req = urllib.request.Request(
            SUPERVISOR_URL + path,
            data=data,
            method=method,
            headers={
                "Authorization": "Bearer " + SUPERVISOR_TOKEN,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode("utf-8", errors="replace")
            except Exception:
                return exc.code, ""
        except Exception as exc:  # 连接失败 / 超时等
            if i >= attempts - 1:
                return 0, str(exc)
            time.sleep(1)  # 瞬时抖动，稍候重试


def unwrap_logs(text):
    """部分 Supervisor 版本把日志内容包在 JSON 里返回，这里做兼容处理。"""
    try:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("data"), str):
            return data["data"]
    except (ValueError, TypeError):
        pass
    return text


def first_existing(paths):
    """返回候选路径中第一个存在的文件路径；都不存在返回空串。"""
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return ""


def tail(path, lines):
    """读取文件末尾指定行数（大文件只读最后 20MB）。"""
    if not path or not os.path.isfile(path):
        return ""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size > CORE_LOG_MAX_BYTES:
            fh.seek(-CORE_LOG_MAX_BYTES, os.SEEK_END)
            fh.readline()  # 丢弃被截断的半行
        else:
            fh.seek(0)
        chunk = fh.read()
    text = chunk.decode("utf-8", errors="replace")
    return "\n".join(text.splitlines()[-lines:])


class Collector:
    """统一采集入口。"""

    def __init__(self, options):
        self.log_lines = int(options.get("log_lines", 3000))

    # ---------------- 日志 ----------------
    def core_logs(self):
        """Core 日志：优先直接读日志文件（信息最全），失败时回退 Supervisor API。"""
        path = first_existing(CORE_LOG_CANDIDATES)
        text = tail(path, self.log_lines)
        if text:
            return text, "文件 %s" % path
        code, body = request("/core/logs?lines=%d" % self.log_lines, timeout=FETCH_TIMEOUT)
        if code == 200:
            return unwrap_logs(body), "Supervisor API /core/logs"
        return "", "无（HTTP %s）" % code

    # ---------------- 状态 ----------------
    def host_info(self):
        """主机健康信息（磁盘 / 内存），供环境检查。"""
        code, body = request("/host/info", timeout=FETCH_TIMEOUT)
        if code != 200:
            return {}
        try:
            return json.loads(body).get("data", {}) or {}
        except ValueError:
            return {}

    @staticmethod
    def disk_stats():
        """磁盘占用（字节）：statvfs 直读数据盘。

        Supervisor /host/info 的磁盘数值单位在不同版本不一致（字节 / MiB /
        GiB），按字节解释会把正常容量算成几 KB，误报「磁盘空间严重不足」；
        statvfs 恒为字节，且 /data 与 HA 配置、数据库同在数据分区，
        结果即用户关心的那块盘。
        """
        for p in ("/data", "/homeassistant_config", "/homeassistant", "/config", "/"):
            try:
                st = os.statvfs(p)
            except OSError:
                continue
            total = st.f_frsize * st.f_blocks
            if total > 0:
                free = st.f_frsize * st.f_bavail
                return {"disk_total": total, "disk_used": total - free,
                        "disk_free": free}
        return {}

    @staticmethod
    def core_log_exists():
        """Core 日志文件是否存在（未开启日志落盘时 HA 不生成该文件）。"""
        return bool(first_existing(CORE_LOG_CANDIDATES))

    @staticmethod
    def db_size():
        """历史数据库（SQLite）文件大小，单位字节；不存在返回 0。"""
        path = first_existing(CORE_DB_CANDIDATES)
        try:
            return os.path.getsize(path) if path else 0
        except OSError:
            return 0

    def ha_api(self, path):
        """通过 Supervisor 代理调用 Home Assistant Core API。"""
        code, body = request("/core/api" + path, timeout=FETCH_TIMEOUT)
        if code != 200:
            return None
        try:
            return json.loads(body)
        except ValueError:
            return None

    def config_entries(self):
        return self.ha_api("/config/config_entries/entry/list") or []

    # ---------------- 修复动作 ----------------
    def call_service(self, domain, service, payload=None, timeout=60):
        """调用 HA 服务，如 recorder.purge。耗时服务可加大 timeout。"""
        return request(
            "/core/api/services/%s/%s" % (domain, service),
            method="POST",
            body=payload or {},
            timeout=timeout,
        )

    def reload_entry(self, entry_id):
        """重载指定集成配置项。"""
        return request(
            "/core/api/config/config_entries/entry/%s/reload" % entry_id,
            method="POST",
            body={},
        )
