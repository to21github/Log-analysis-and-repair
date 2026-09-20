"""主入口：加载配置、启动 Web 界面（Ingress）与定时扫描主循环。

流程：采集（Core 日志 / 环境信息）→ 分析 → 修复 → 生成报告。
"""

import json
import logging
import threading
import time
from datetime import datetime

import analyzer
import collector
import repairer
import reporter
import webui

_log = logging.getLogger("log_analyzer.main")

OPTIONS_PATH = "/data/options.json"
WEB_PORT = 8124  # 与 config.yaml 的 ingress_port 保持一致
VERSION = "1.0.0"  # 与 config.yaml 的 version 保持一致

DEFAULTS = {
    "scan_interval": 300,       # 自动扫描间隔（秒）：问题近实时呈现
    "log_lines": 3000,          # 每次抓取日志行数
    "auto_repair": False,       # 自动修复总开关（默认关闭：网页面板手动修复）
    "repair_cooldown": 3600,    # 同一问题修复冷却（秒）
    # restart_crashed_addons 仅为兼容旧配置保留（schema 中已标记废弃），
    # 重启插件动作随实体/插件状态分析一并移除，不再读取
    "reload_integrations": True,
    "repair_mqtt": True,
    "purge_recorder": True,
    "keep_reports": 10,         # 历史报告保留份数
}


def load_options():
    try:
        with open(OPTIONS_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        _log.warning("读取配置失败，使用默认值：%s", exc)
        raw = {}
    cfg = dict(DEFAULTS)
    cfg.update(raw)
    return cfg


class App:
    def __init__(self):
        self.cfg = load_options()
        self.col = collector.Collector(self.cfg)
        self.rep = repairer.Repairer(self.cfg, self.col)
        self.rpt = reporter.Reporter(self.cfg)
        self.lock = threading.Lock()  # 防止定时扫描与手动扫描并发
        self.state = {
            "scanning": False,
            "last_scan": None,
            "next_scan": None,
            "last_report": None,
            "report_time": None,  # 报告版本时间戳，网页端据此判断是否重新拉取
        }
        self.ui = webui.WebUI(
            WEB_PORT,
            self.state,
            trigger_scan=lambda: self.run_scan(),
            repair_one=self.repair_one,
            read_report=reporter.read_latest,
        )

    # ---------------- 手动单项修复（网页面板按钮触发） ----------------
    def repair_one(self, payload):
        """按 id + target 在最新报告中定位问题并手动修复，返回结果 dict。"""
        try:
            rid = (payload or {}).get("id", "")
            target = (payload or {}).get("target", "")
            report = self.state.get("last_report") or reporter.read_latest()
            if not report:
                return {"status": "fail", "detail": "暂无报告，请先扫描"}

            issue = None
            for it in report.get("issues", []):
                if it.get("id") == rid and (it.get("target") or "") == target \
                        and it.get("action"):
                    issue = it
                    break
            if issue is None:
                return {"status": "fail", "detail": "未在最新报告中找到该问题，请重新扫描"}

            # 锁定报告更新，避免与并发扫描冲突；扫描进行中直接返回，避免请求挂起
            if not self.lock.acquire(blocking=False):
                return {"status": "fail", "detail": "扫描正在进行中，请稍后再试"}
            try:
                results = self.rep.repair_issues([issue], manual=True)
            finally:
                self.lock.release()
            res = results[0] if results else {"status": "fail", "detail": "该问题不可自动修复"}
            issue["repair_result"] = res
            self.rpt.save(report)
            self.state["last_report"] = report
            self.state["report_time"] = time.time()  # 通知网页端重新拉取报告
            return res
        except Exception as exc:
            _log.error("手动修复失败：%s", exc)
            return {"status": "fail", "detail": "执行异常：%s" % exc}

    # ---------------- 扫描主流程 ----------------
    def run_scan(self):
        if not self.lock.acquire(blocking=False):
            _log.info("已有扫描正在进行，跳过本次触发")
            return
        self.state["scanning"] = True
        try:
            started = time.time()
            _log.info("开始扫描…")

            # 1. 采集（纯 Core 日志分析：只抓取 Core 日志与环境信息）
            core_text, core_src = self.col.core_logs()
            host = self.col.host_info()
            # 磁盘占用改用 statvfs 直读：Supervisor API 的磁盘单位随版本不一致
            # （字节 / MiB / GiB），按字节解释会误报「磁盘空间严重不足」
            for k in ("disk_total", "disk_used", "disk_free"):
                host.pop(k, None)
            host.update(self.col.disk_stats())
            db_size = self.col.db_size()
            log_exists = self.col.core_log_exists()
            _log.info("采集完成：Core %s 行（来源：%s）",
                      len(core_text.splitlines()), core_src)

            # 2. 分析（存活窗口 = 扫描间隔 + 60s 缓冲：
            #    窗口内还在出现的问题显示，停止出现的下一次扫描即消失）
            window = int(self.cfg.get("scan_interval", 300)) + 60
            result = analyzer.analyze(core_text,
                                      host=host, db_size=db_size,
                                      core_log_exists=log_exists,
                                      window=window)
            issues = result["issues"]
            repairable = sum(1 for i in issues if i.get("action"))
            _log.info("发现 %d 类问题（可修复 %d 项）", len(issues), repairable)

            # 3. 修复
            repairs = self.rep.repair_issues(issues) if self.cfg.get("auto_repair") else []

            # 4. 报告
            report = self.rpt.build(result, repairs, core_src,
                                    time.time() - started)
            self.rpt.save(report)
            self.state["last_report"] = report
            self.state["report_time"] = time.time()
            self.state["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for issue in issues[:8]:
                rep_res = issue.get("repair_result", {}).get("status", "")
                _log.info("  - %s（%s）%s",
                          issue["title"],
                          issue["severity"],
                          "→ " + rep_res if rep_res else "")
        except Exception:
            _log.exception("扫描失败")
        finally:
            self.state["scanning"] = False
            self.lock.release()

    # ---------------- 主循环 ----------------
    def serve_forever(self):
        self.ui.start()
        # 启动后先扫一次（记录本轮扫描开始时刻，用于周期补偿）
        cycle_started = time.time()
        self.run_scan()
        while True:
            # 支持运行中修改配置：每次循环重新读取 options
            self.cfg = load_options()
            self.col.log_lines = int(self.cfg.get("log_lines", 3000))
            interval = int(self.cfg.get("scan_interval", 300))
            # 从本轮扫描开始时刻起算间隔并扣除扫描耗时，保证实际周期 = scan_interval
            wait = interval - (time.time() - cycle_started)
            if wait < 0:
                wait = 0
            self.state["next_scan"] = datetime.fromtimestamp(
                time.time() + wait).strftime("%Y-%m-%d %H:%M:%S")
            time.sleep(wait)
            cycle_started = time.time()
            self.run_scan()


if __name__ == "__main__":
    # 日志统一走 logging，format 提供统一前缀
    logging.basicConfig(level=logging.INFO,
                        format="[日志分析] %(levelname)s %(message)s")
    app = App()
    _log.info("插件启动，版本 %s（%s）",
              VERSION,
              "自动修复已开启" if app.cfg.get("auto_repair") else "手动修复模式")
    app.serve_forever()
