"""日志分析引擎。

解析 Core / Supervisor 日志行，按内置规则识别已知问题，并结合
实体状态、集成配置项（Config Entry）状态、插件运行状态做综合检测。

每个问题的结构：
{
  "id":         问题类别标识
  "title":      中文标题
  "severity":   error / warning / info
  "target":     涉及对象（集成域名、插件 slug、实体域等）
  "count":      出现次数
  "samples":    样本日志行（最多 3 条）
  "advice":     处理建议
  "action":     修复动作标识（None 表示不可自动修复）
  "switch":     对应的修复开关（config.yaml options 中的字段名）
}
"""

import re

# 兼容两种日志行格式：
# Core:       2026-09-17 19:00:00.123 ERROR (MainThread) [logger.name] message
# Supervisor: 25-09-17 19:00:00 INFO (MainThread) [hassio.core] message
# 注：Supervisor 日志可能带 ANSI 颜色码（\x1b[33m 等），解析前先剥离
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# journal 转发格式标准化：`26-05-18 23:06:14 homeassistant hassio_dns[576]: [ERROR] msg`
# → 标准格式 `26-05-18 23:06:14 ERROR (MainThread) [supervisor.hassio_dns] msg`
JOURNAL_RE = re.compile(
    r"^(?P<time>\d{2,4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\S+\s+"
    r"(?P<logger>\S+)\[\d+\]:\s*\[(?P<level>CRITICAL|ERROR|WARNING)\]\s*(?P<msg>.*)$"
)
LINE_RE = re.compile(
    r"^(?P<time>\d{2,4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<level>CRITICAL|ERROR|WARNING)\s+"
    r"\((?P<thread>[^)]*)\)\s+"
    r"\[(?P<logger>[^\]]*)\]\s*"
    r"(?P<msg>.*)$"
)

TRACEBACK_HEAD = "Traceback (most recent call last):"

# 内置问题识别规则
RULES = [
    {
        "id": "mqtt_disconnect",
        "title": "MQTT 连接断开",
        "pattern": r"(?:lost connection to mqtt|connection to mqtt lost|"
                   r"can't connect to mqtt|unable to connect to the mqtt broker|"
                   r"mqtt connection lost|mqtt.*disconnected)",
        "severity": "error",
        "action": "reload_mqtt",
        "switch": "repair_mqtt",
        "advice": "HA 与 MQTT 服务器连接中断，会导致 MQTT 设备离线、自动化失效。"
                  "请检查 MQTT 服务器（如 Mosquitto 插件）是否在线、账号密码与网络是否正常。",
    },
    {
        "id": "setup_failed",
        "title": "集成初始化失败",
        "pattern": r"Setup failed for (?:custom integration )?'(?P<target>[^']+)'",
        "severity": "error",
        "action": "reload_entry",
        "switch": "reload_integrations",
        "advice": "该集成在启动或重载时初始化失败，常见原因：配置错误、依赖缺失、"
                  "认证失败或依赖的服务不可用。",
    },
    {
        "id": "invalid_config",
        "title": "配置无效",
        "pattern": r"Invalid config for \[(?P<target>[^\]]+)\]",
        "severity": "error",
        "action": None,
        "advice": "配置校验未通过，请根据 HA 「设置 → 系统 → 修复」中的提示，"
                  "或检查 configuration.yaml / 对应集成的配置后重启。",
    },
    {
        "id": "update_timeout",
        "title": "设备数据更新超时",
        "pattern": r"Timeout fetching (?P<target>.+?) data",
        "severity": "warning",
        "action": None,
        "advice": "轮询设备超时，多为设备离线、网络不稳定或响应过慢。"
                  "若频繁出现请检查设备电源与网络。",
    },
    {
        "id": "update_fails",
        "title": "设备状态更新失败",
        "pattern": r"Update for (?P<target>.+?) fails",
        "severity": "warning",
        "action": None,
        "advice": "设备状态拉取失败，通常是设备或云服务暂时不可用。",
    },
    {
        "id": "db_error",
        "title": "历史数据库（Recorder）异常",
        "pattern": r"(?:database is locked|database disk image is malformed|"
                   r"error executing query|error during schema migration|"
                   r"database file is corrupt)",
        "severity": "error",
        "action": "purge_recorder",
        "switch": "purge_recorder",
        "advice": "Recorder 数据库异常，会导致历史数据无法写入。可清理旧历史数据减负；"
                  "若持续报错，考虑在 configuration.yaml 中设置 recorder 的 db_url "
                  "指向外部数据库，或缩短 purge_keep_days。",
    },
    {
        "id": "template_error",
        "title": "模板渲染错误",
        "pattern": r"(?:TemplateError|Error rendering template|template_err)",
        "severity": "error",
        "action": None,
        "advice": "模板（template）渲染出错，请检查自动化 / 传感器 / 卡片中的 Jinja2 模板。",
    },
    {
        "id": "connection_error",
        "title": "网络连接失败",
        "pattern": r"(?:Connection refused|Connection reset by peer|Host is unreachable|"
                   r"Connection timed out|Failed to establish a new connection)",
        "severity": "warning",
        "action": None,
        "advice": "连接外部设备或服务失败，请检查对应设备 / 服务的地址、端口与网络。",
    },
    {
        "id": "module_missing",
        "title": "Python 依赖缺失",
        "pattern": r"(?P<target>No module named '[\w\.]+')",
        "severity": "error",
        "action": None,
        "advice": "custom_components 缺少 Python 依赖。请更新该集成到最新版本，"
                  "或按其文档在配置中声明 requirements。",
    },
    {
        "id": "auth_error",
        "title": "认证失败",
        "pattern": r"(?:Invalid authentication|authentication failed|login failed|"
                   r"401 Unauthorized|invalid username or password)",
        "severity": "warning",
        "action": None,
        "advice": "账号 / 密码或令牌认证失败，请检查对应集成或 API 的凭据配置。",
    },
    {
        "id": "automation_error",
        "title": "自动化执行错误",
        "pattern": r"Error while executing automation (?P<target>[\w\.]+)",
        "severity": "error",
        "action": None,
        "advice": "自动化在执行动作时报错，多为其中的服务调用失败或模板渲染出错，"
                  "请打开该自动化的追踪（Trace）查看具体失败的步骤。",
    },
    {
        "id": "esphome_disconnect",
        "title": "ESPHome 设备断连",
        "pattern": r"(?:Can't connect to ESPHome|disconnected from API|"
                   r"error connecting to esphome|esphome.*connection.*closed)",
        "severity": "warning",
        "action": "reload_entry",
        "switch": "reload_integrations",
        "advice": "ESPHome 设备与 HA 的 API 连接断开，多为设备离线、Wi-Fi 不稳或"
                  "IP 变更（建议在路由器为设备绑定静态 IP）。",
    },
    {
        "id": "zwave_disconnect",
        "title": "Z-Wave 连接断开",
        "pattern": r"(?:z-wave (?:client|server|connection).*(?:disconnect|lost|closed)|"
                   r"connection to zwave.*lost)",
        "severity": "warning",
        "action": "reload_entry",
        "switch": "reload_integrations",
        "advice": "Z-Wave JS 与 HA 的连接断开，多为 Z-Wave JS 插件重启或串口适配器异常。",
    },
    {
        "id": "recorder_backlog",
        "title": "历史记录积压",
        "pattern": r"(?:recorder backlog queue|the database queue is full|"
                   r"commit.*took longer than)",
        "severity": "warning",
        "action": "purge_recorder",
        "switch": "purge_recorder",
        "advice": "Recorder 写入速度跟不上事件产生速度，历史数据积压。"
                  "常见于 SD 卡性能不足或数据库过大，可清理旧历史数据；"
                  "持续出现建议将 recorder 数据库迁到 SSD 或调大 commit_interval。",
    },
    {
        "id": "hacs_update_failed",
        "title": "HACS 更新失败",
        "pattern": r"(?:Error fetching data from HACS|Could not update (?:plugin|integration|theme|template) -)",
        "severity": "warning",
        "action": None,
        "advice": "HACS 从 GitHub / CDN 拉取数据失败，多为网络原因（国内访问 HACS "
                  "源经常超时）。HACS 会自动重试；持续失败建议配置代理网络后"
                  "手动刷新 HACS。重载集成无法解决网络问题，故不做自动修复。",
    },
    {
        "id": "supervisor_timeout",
        "title": "Supervisor API 超时",
        "pattern": r"(?:Timeout (?:on|connecting to) Supervisor|"
                   r"Error on Supervisor API: Timeout|Timeout on /[\w/]+ request|"
                   r"Failed to to call /(?!store/)[\w/]+)",
        "severity": "warning",
        "action": None,
        "advice": "HA 与 Supervisor 通信超时，常见于系统繁忙（SD 卡 IO 高、"
                  "正在安装插件、数据库压缩中）。偶发可忽略，通常自行恢复；"
                  "频繁出现请检查 SD 卡健康与系统负载。",
    },
    {
        "id": "integration_blocked",
        "title": "自定义集成被阻止加载",
        "pattern": r"The custom integration '(?P<target>[\w_]+)' does not have a version key",
        "severity": "error",
        "action": None,
        "advice": "该自定义集成缺少 manifest 版本信息，被新版 HA 阻止加载。"
                  "请更新该集成到最新版本，或在其 manifest.json 中补充 version 字段。",
    },
    {
        "id": "startup_blocked",
        "title": "启动阶段被阻塞",
        "pattern": r"Something is blocking Home Assistant from wrapping up the start up phase",
        "severity": "warning",
        "action": None,
        "advice": "有集成在启动阶段耗时过长，多为等待网络设备连接超时。"
                  "一般不影响使用；若启动明显过慢，请结合样本中列出的集成排查。",
    },
    {
        "id": "device_disconnected",
        "title": "设备连接断开",
        "pattern": r"Device (?P<target>[\w\-]+) disconnected",
        "severity": "warning",
        "action": None,
        "advice": "云平台 / 网关报告设备断连，多为设备休眠或离线。"
                  "设备重新上电或唤醒后会自动恢复，重载集成通常无效，故不做自动修复；"
                  "若设备实际在线但 HA 中长期不可用，可尝试重载对应集成。",
    },
    {
        "id": "entity_not_found",
        "title": "引用了不存在的实体",
        "pattern": r"(?:Forced update failed\. )?Entity (?P<target>[\w\.]+) not found",
        "severity": "warning",
        "action": None,
        "advice": "自动化 / 仪表盘引用的实体不存在（可能已被删除或改名）。"
                  "请清理相关自动化、脚本中的旧实体 ID。",
    },
    {
        "id": "store_repo_error",
        "title": "插件商店仓库更新失败",
        "pattern": r"(?:Could not reload repository \w+ due to StoreGitError|"
                   r"Wasn't able to update \S+ repo: Cmd\('git'\) failed|"
                   r"Failed to to call /store/\w+ - Cmd\('git'\) failed)",
        "severity": "warning",
        "action": None,
        "advice": "Supervisor 更新插件商店仓库（git 拉取）失败，多为网络原因"
                  "（国内访问 GitHub 不稳定）。不影响已装插件的运行，"
                  "下次刷新会自动重试；持续失败建议为树莓派配置代理网络。",
    },
    {
        "id": "store_task_busy",
        "title": "商店任务排队拥堵",
        "pattern": r"There is already a task in progress",
        "severity": "info",
        "action": None,
        "advice": "Supervisor 商店任务排队堆积（多为网络缓慢导致 git 任务积压），"
                  "任务完成后自行恢复，通常无需处理。",
    },
    {
        "id": "addon_option_invalid",
        "title": "插件配置项不被支持",
        "pattern": r"Option '\w+' does not exist in the schema for (?P<target>.+?) \(",
        "severity": "warning",
        "action": None,
        "advice": "该插件升级后已不支持配置里的某个旧选项（多为新版删除了该设置）。"
                  "请打开该插件的配置页，删除提示中提到的选项后保存。",
    },
    {
        "id": "addon_legacy_format",
        "title": "插件使用了过时的格式",
        "pattern": r"App '(?P<target>[^']+)' uses legacy map type",
        "severity": "info",
        "action": None,
        "advice": "该插件使用的老式配置格式将在未来版本停止支持，"
                  "等插件作者更新即可，目前不影响使用。",
    },
    {
        "id": "blocking_call",
        "title": "集成阻塞了主线程",
        "pattern": r"Detected (?:blocking call to \w+|I/O) .*the event loop",
        "severity": "warning",
        "action": None,
        "advice": "有集成在 HA 主线程里做了耗时的操作（读写文件、加载模块等），"
                  "会造成界面卡顿。多为集成代码质量问题，请更新对应集成；"
                  "偶发一两次可忽略。",
    },
    {
        "id": "task_exception",
        "title": "后台任务异常",
        "pattern": r"Error doing job: (?:Task|Future) exception was never retrieved",
        "severity": "error",
        "action": None,
        "advice": "HA 后台任务抛出了未被处理的异常，具体原因看配套的堆栈信息。"
                  "常见于集成的 bug 或数据异常，若反复出现请更新对应集成。",
    },
    {
        "id": "update_unexpected",
        "title": "集成数据获取异常",
        "pattern": r"Unexpected error fetching (?P<target>[\w_]+) data",
        "severity": "error",
        "action": "reload_entry",
        "switch": "reload_integrations",
        "advice": "该集成拉取数据时发生意外错误（非超时），可能造成相关实体数据"
                  "不更新。若持续出现可重载该集成，或更新集成版本。",
    },
    {
        "id": "core_crashed",
        "title": "HA 核心崩溃过",
        "pattern": r"Home Assistant has crashed!",
        "severity": "error",
        "action": None,
        "advice": "Supervisor 记录到 Home Assistant 核心曾崩溃（可能因断电、"
                  "内存不足或集成严重错误）。请结合当时的 Core 日志排查原因；"
                  "频繁崩溃请检查电源与 SD 卡健康。",
    },
    {
        "id": "update_rollback",
        "title": "系统更新失败已回滚",
        "pattern": r"(?:HomeAssistant|Home Assistant) update failed",
        "severity": "error",
        "action": None,
        "advice": "HA 更新失败并自动回滚到了旧版本。多为某个集成与新版不兼容。"
                  "可先更新所有自定义集成再重试；也可在 SSH 里用 ha core update "
                  "重试并观察报错。",
    },
    {
        "id": "db_unclean_shutdown",
        "title": "数据库未正常关闭",
        "pattern": r"could not validate that the sqlite3 database",
        "severity": "warning",
        "advice": "历史数据库上次没有正常关闭，通常是树莓派意外断电或崩溃造成的。"
                  "HA 会自动恢复（SQLite 自动回滚未完成事务），无需手动修复；"
                  "反复出现会损伤数据库，建议检查电源稳定性。",
    },
    {
        "id": "platform_setup_error",
        "title": "平台初始化失败",
        "pattern": r"(?:Error while setting up (?P<t1>[\w_]+) platform|"
                   r"Error setting up platform (?P<t2>[\w_]+))",
        "severity": "error",
        "action": "reload_entry",
        "switch": "reload_integrations",
        "advice": "该集成的某个平台（如传感器、开关）初始化失败，对应实体不会"
                  "出现。多为集成版本与 HA 不兼容或配置问题，可重载集成或更新。",
    },
    {
        "id": "integration_not_found",
        "title": "找不到集成",
        "pattern": r"Unable to find integration (?P<target>[\w_]+)",
        "severity": "error",
        "action": None,
        "advice": "HA 找不到这个集成，常见原因：configuration.yaml 里集成名拼写"
                  "错误，或该集成尚未安装。请核对名称后修正配置。",
    },
    {
        "id": "dns_error",
        "title": "内置 DNS 解析超时",
        "pattern": r"PTR: context deadline exceeded",
        "severity": "warning",
        "action": None,
        "advice": "HA 内置 DNS 服务（hassio_dns）解析域名超时，多为上游路由器 "
                  "DNS 慢或 IPv6 配置问题。设备能正常联网时可忽略；频繁出现"
                  "建议在路由器上指定更快的 DNS（如 223.5.5.5）。",
    },
    {
        "id": "yaml_duplicate_key",
        "title": "配置文件有重复项",
        "pattern": r"YAML file (?P<target>\S+) contains duplicate key",
        "severity": "warning",
        "action": None,
        "advice": "YAML 文件里有重名的配置项（后写的会覆盖先写的）。"
                  "请按提示的行号删除重复的那一项。",
    },
]

# 集成配置项的异常状态
BAD_ENTRY_STATES = ("setup_error", "setup_retry", "migration_error", "failed", "not_started")


def integration_from_logger(logger):
    """从 logger 名称推断集成域名，例如 custom_components.hacs -> hacs。"""
    if not logger:
        return None
    parts = logger.split(".")
    if parts[0] == "custom_components" and len(parts) > 1:
        return parts[1]
    if parts[0] == "homeassistant" and parts[1:2] == ["components"] and len(parts) > 2:
        return parts[2]
    return None


def parse_lines(text, source):
    """把日志文本解析成结构化行，只保留 ERROR / WARNING / CRITICAL。"""
    lines = []
    for raw in (text or "").splitlines():
        raw = ANSI_RE.sub("", raw)  # 剥离 ANSI 颜色码（Supervisor 日志自带）
        m = LINE_RE.match(raw)
        if not m:
            # journal 转发格式（hassio_dns / hassio_audio 等容器的输出）
            jm = JOURNAL_RE.match(raw)
            if not jm:
                continue
            m = jm
            raw = "%s %s (MainThread) [supervisor.%s] %s" % (
                jm.group("time"), jm.group("level"),
                jm.group("logger"), jm.group("msg"))
        lines.append({
            "time": m.group("time"),
            "level": m.group("level"),
            "logger": m.group("logger"),
            "msg": m.group("msg"),
            "raw": raw,
            "source": source,
            "matched": False,  # 是否已被某条规则命中（用于未归类聚合）
        })
    return lines


def apply_rules(lines):
    """按规则匹配日志行，聚合同类问题。"""
    issues = {}
    for ln in lines:
        for rule in RULES:
            m = re.search(rule["pattern"], ln["msg"], re.IGNORECASE)
            if not m:
                continue
            # 优先取规则捕获组中的目标（target 或备选组 t1/t2），否则从 logger 推断集成
            gd = m.groupdict()
            target = (gd.get("target") or gd.get("t1")
                      or gd.get("t2") or "").strip()
            if not target:
                target = integration_from_logger(ln["logger"]) or ""
            key = (rule["id"], target)
            if key not in issues:
                issues[key] = {
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "target": target,
                    "count": 0,
                    "samples": [],
                    "advice": rule.get("advice", ""),
                    "action": rule.get("action"),
                    "switch": rule.get("switch"),
                    "source": ln["source"],
                }
            item = issues[key]
            item["count"] += 1
            if len(item["samples"]) < 3:
                item["samples"].append(ln["raw"])
            ln["matched"] = True
            break  # 一行只归入最先命中的规则
    return list(issues.values())


def detect_tracebacks(text):
    """统计 Python 异常堆栈，提取末行异常摘要作为样本。"""
    issues = []
    raw_lines = (text or "").splitlines()
    i = 0
    while i < len(raw_lines):
        if raw_lines[i].startswith(TRACEBACK_HEAD):
            block = []
            i += 1
            while i < len(raw_lines):
                line = raw_lines[i]
                # 堆栈块在遇到下一条带时间戳的日志行时结束
                if LINE_RE.match(line) or line.startswith(TRACEBACK_HEAD):
                    break
                block.append(line)
                i += 1
            summary = ""
            for line in reversed(block):
                stripped = line.strip()
                if stripped and not stripped.startswith('File "'):
                    summary = stripped
                    break
            issues.append({
                "id": "traceback",
                "title": "Python 异常堆栈",
                "severity": "error",
                "target": "",
                "count": 1,
                "samples": [summary or block[-1] if block else ""],
                "advice": "出现未捕获的 Python 异常，请结合样本定位具体组件；"
                          "频繁出现时建议更新对应集成。",
                "action": None,
                "switch": None,
                "source": "core",
            })
        else:
            i += 1
    # 聚合堆栈数量
    if issues:
        count = len(issues)
        samples = [i["samples"][0] for i in issues[:3] if i["samples"]]
        return [{
            "id": "traceback",
            "title": "Python 异常堆栈",
            "severity": "error",
            "target": "",
            "count": count,
            "samples": samples,
            "advice": issues[0]["advice"],
            "action": None,
            "switch": None,
            "source": "core",
        }]
    return []


def aggregate_uncategorized(lines, limit=15):
    """把未被规则命中的 ERROR 行按 logger 聚合，作为待排查问题展示。"""
    groups = {}
    for ln in lines:
        if ln["matched"] or ln["level"] not in ("ERROR", "CRITICAL"):
            continue
        logger = ln["logger"] or "(未知来源)"
        if logger not in groups:
            groups[logger] = {"count": 0, "samples": []}
        groups[logger]["count"] += 1
        if len(groups[logger]["samples"]) < 2:
            groups[logger]["samples"].append(ln["raw"])
    ranked = sorted(groups.items(), key=lambda kv: -kv[1]["count"])[:limit]
    return [
        {
            "id": "uncategorized",
            "title": "未归类错误：%s" % logger,
            "severity": "error",
            "target": integration_from_logger(logger) or "",
            "count": data["count"],
            "samples": data["samples"],
            "advice": "未被内置规则覆盖的错误，请根据样本日志自行排查，"
                      "或将样本提交给对应集成的维护者。",
            "action": None,
            "switch": None,
            "source": "core",
        }
        for logger, data in ranked
    ]


def check_addons(addons):
    """结合 Supervisor API 的插件状态识别崩溃 / 异常停止。"""
    issues = []
    for a in addons or []:
        slug = a.get("slug", "")
        name = a.get("name") or slug
        state = a.get("state")
        if state == "error":
            issues.append({
                "id": "addon_crash",
                "title": "插件崩溃：%s" % name,
                "severity": "error",
                "target": slug,
                "count": 1,
                "samples": ["Supervisor 报告插件 %s 状态为 error（异常退出）" % slug],
                "advice": "插件异常退出。将自动尝试重启；若反复崩溃，"
                          "请查看该插件自身日志排查原因。",
                "action": "restart_addon",
                "switch": "restart_crashed_addons",
                "source": "supervisor",
            })
        elif a.get("boot") == "auto" and state == "stopped":
            issues.append({
                "id": "addon_stopped",
                "title": "插件未运行：%s" % name,
                "severity": "warning",
                "target": slug,
                "count": 1,
                "samples": ["插件 %s 设置了开机自启但当前处于停止状态" % slug],
                "advice": "该插件设置为自动启动但当前是停止状态，"
                          "可能被手动停止或启动失败，请确认是否符合预期。",
                "action": None,
                "switch": None,
                "source": "supervisor",
            })
    return issues


def check_entities(entities):
    """统计不可用（unavailable）/ 未知（unknown）实体，按域分组。"""
    total = len(entities or [])
    unavail_domains = {}
    unavail_examples = []
    unknown_count = 0
    for ent in entities or []:
        eid = ent.get("entity_id") or ""
        if not eid:
            continue
        domain = eid.split(".", 1)[0]
        state = ent.get("state")
        if state == "unavailable":
            unavail_domains[domain] = unavail_domains.get(domain, 0) + 1
            if len(unavail_examples) < 12:
                unavail_examples.append(eid)
        elif state == "unknown":
            unknown_count += 1

    issues = []
    if unavail_domains:
        unavail_total = sum(unavail_domains.values())
        top_domains = sorted(unavail_domains.items(), key=lambda kv: -kv[1])
        issues.append({
            "id": "entity_unavailable",
            "title": "实体不可用（%d 个）" % unavail_total,
            "severity": "warning",
            "target": "、".join("%s(%d)" % d for d in top_domains[:5]),
            "count": unavail_total,
            "domains": dict(unavail_domains),
            "samples": unavail_examples,
            "advice": "实体显示不可用通常表示设备离线、网关断连或集成异常。"
                      "电池设备休眠时也属正常现象。可尝试重载对应集成恢复。",
            "action": "reload_unavailable_entries",
            "switch": "reload_integrations",
            "source": "core_api",
        })
    if unknown_count:
        issues.append({
            "id": "entity_unknown",
            "title": "实体状态未知（%d 个）" % unknown_count,
            "severity": "info",
            "target": "",
            "count": unknown_count,
            "samples": [],
            "advice": "unknown 多为设备自上次重启后尚未上报过数据，"
                      "低功耗传感器尤其常见，一般无需处理。",
            "action": None,
            "switch": None,
            "source": "core_api",
        })
    return issues, total, unknown_count


def check_entries(entries):
    """识别处于异常状态的集成配置项（初始化失败 / 迁移失败等）。"""
    issues = []
    for e in entries or []:
        if e.get("state") in BAD_ENTRY_STATES:
            domain = e.get("domain", "")
            issues.append({
                "id": "entry_setup_error",
                "title": "集成未能加载：%s" % (e.get("title") or domain),
                "severity": "error",
                "target": domain,
                "count": 1,
                "samples": ["配置项状态：%s（domain=%s, source=%s）"
                            % (e.get("state"), domain, e.get("source", ""))],
                "advice": "该集成配置项未能成功加载（状态 %s），"
                          "请检查其账号、网络与配置后重试。" % e.get("state"),
                "action": "reload_entry",
                "switch": "reload_integrations",
                "source": "core_api",
            })
    return issues


def check_environment(host, db_size, core_log_exists):
    """环境健康检查：磁盘 / 内存 / 历史数据库大小 / Core 日志是否落盘。

    返回 (问题列表, 环境统计 dict)。
    """
    issues = []
    env = {"disk_free_bytes": None, "disk_total_bytes": None,
           "mem_used_pct": None, "db_size_bytes": db_size}

    GB = 1024 ** 3
    # ---- 磁盘（树莓派 SD 卡空间不足是数据库损坏的头号原因）----
    disk_total = host.get("disk_total") or 0
    disk_used = host.get("disk_used") or 0
    disk_free = host.get("disk_free") or (disk_total - disk_used if disk_total else 0)
    if disk_total and disk_free >= 0:
        env["disk_free_bytes"] = disk_free
        env["disk_total_bytes"] = disk_total
        free_gb = disk_free / GB
        if disk_free < 500 * 1024 ** 2:
            issues.append({
                "id": "disk_critical",
                "title": "磁盘空间严重不足（剩 %.1f GB）" % free_gb,
                "severity": "error",
                "target": "host",
                "count": 1,
                "samples": ["总容量 %.1f GB，已用 %.1f GB"
                            % (disk_total / GB, disk_used / GB)],
                "advice": "磁盘即将占满，会导致数据库损坏、日志与备份无法写入。"
                          "建议：删除旧备份（设置→系统→备份）；卸载不用的插件；"
                          "缩短 recorder 的保留天数。",
                "action": None,
                "switch": None,
                "source": "supervisor",
            })
        elif disk_free < 2 * GB:
            issues.append({
                "id": "disk_low",
                "title": "磁盘空间偏低（剩 %.1f GB）" % free_gb,
                "severity": "warning",
                "target": "host",
                "count": 1,
                "samples": ["总容量 %.1f GB，已用 %.1f GB"
                            % (disk_total / GB, disk_used / GB)],
                "advice": "磁盘剩余空间偏低，建议清理旧备份与不用的插件镜像，"
                          "避免进一步紧张。",
                "action": None,
                "switch": None,
                "source": "supervisor",
            })

    # ---- 内存 ----
    mem_total = host.get("memory_total") or host.get("mem_total") or 0
    mem_used = host.get("memory_used") or host.get("mem_used") or 0
    if mem_total:
        pct = round(mem_used * 100.0 / mem_total, 1)
        env["mem_used_pct"] = pct
        if pct >= 90:
            issues.append({
                "id": "mem_high",
                "title": "内存使用过高（%d%%）" % pct,
                "severity": "warning",
                "target": "host",
                "count": 1,
                "samples": ["总内存 %.1f GB，已用 %.1f GB"
                            % (mem_total / GB, mem_used / GB)],
                "advice": "内存接近耗尽可能触发 OOM 导致服务被杀。"
                          "建议排查占用大的插件，或减少重型集成（如过多摄像头流）。",
                "action": None,
                "switch": None,
                "source": "supervisor",
            })

    # ---- 历史数据库大小 ----
    if db_size > 2 * GB:
        issues.append({
            "id": "db_too_large",
            "title": "历史数据库过大（%.1f GB）" % (db_size / GB),
            "severity": "warning",
            "target": "recorder",
            "count": 1,
            "samples": ["/homeassistant/home-assistant_v2.db"],
            "advice": "数据库过大会拖慢历史查询与重启速度（SD 卡上尤其明显）。"
                      "将自动执行 repack 压缩清理；建议同时缩短 recorder "
                      "purge_keep_days、排除高频传感器记录。",
            "action": "repack_database",
            "switch": "purge_recorder",
            "source": "core",
        })

    # ---- Core 日志文件未落盘 ----
    if not core_log_exists:
        issues.append({
            "id": "log_file_missing",
            "title": "Core 日志未落盘",
            "severity": "info",
            "target": "logger",
            "count": 1,
            "samples": ["/homeassistant/home-assistant.log 不存在"],
            "advice": "HA 默认不生成日志文件（仅输出到系统日志）。在 "
                      "configuration.yaml 中添加「logger:\\n  default: info」并重启后，"
                      "本插件可分析到更完整的历史日志。",
            "action": None,
            "switch": None,
            "source": "core",
        })
    return issues, env


def analyze(core_text, supervisor_text,
            host=None, db_size=0, core_log_exists=True):
    """综合分析入口，返回问题列表与统计信息（纯日志 + 环境数据）。"""
    core_lines = parse_lines(core_text, "core")
    sup_lines = parse_lines(supervisor_text, "supervisor")
    lines = core_lines + sup_lines

    issues = apply_rules(lines)
    issues.extend(detect_tracebacks(core_text))
    issues.extend(aggregate_uncategorized(lines))

    env_issues, env = check_environment(host or {}, db_size, core_log_exists)
    issues.extend(env_issues)

    # 按严重程度排序：error > warning > info
    order = {"error": 0, "warning": 1, "info": 2}
    issues.sort(key=lambda i: (order.get(i["severity"], 3), -i.get("count", 1)))

    stats = {
        "core_lines": len(core_lines),
        "supervisor_lines": len(sup_lines),
        "error_lines": sum(1 for l in lines if l["level"] in ("ERROR", "CRITICAL")),
        "warning_lines": sum(1 for l in lines if l["level"] == "WARNING"),
        "tracebacks": sum(1 for i in issues if i["id"] == "traceback"),
    }
    stats.update(env)
    return {"issues": issues, "stats": stats}
