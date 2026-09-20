"""问题修复模块。

对可修复问题执行动作：
- reload_mqtt    重载 MQTT 集成，恢复与代理的连接
- reload_entry   重载指定集成配置项
- purge_recorder 清理历史数据库旧数据
- repack_database 清理并压缩历史数据库

带修复冷却机制：同一问题在冷却时间内不重复执行，避免反复重载造成抖动。
修复历史仅保存在内存中：插件重启后重新统计（项目既定决策）。
"""

import logging
import time
from datetime import datetime

_log = logging.getLogger("log_analyzer.repairer")

MAX_EVENTS = 200  # 内存中保留的最近修复事件数


# 修复动作的中文名称（用于报告与网页展示）
ACTION_NAMES = {
    "reload_mqtt": "重载 MQTT 集成",
    "reload_entry": "重载集成",
    "purge_recorder": "清理历史数据库",
    "repack_database": "压缩历史数据库",
}


class Repairer:
    def __init__(self, options, collector):
        self.cfg = options
        self.col = collector
        self.cooldowns = {}  # "action:target" -> 上次修复时间戳
        self.events = []     # 最近的修复事件（新的在前）
        # 重启后重新统计：冷却与已修复状态仅在本次运行期间有效，不加载历史

    # ---------------- 执行入口 ----------------
    def repair_issues(self, issues, manual=False):
        """对问题列表逐项尝试修复，返回修复结果列表。

        manual=True 为网页面板手动修复：用户明确点击，跳过总开关、
        子开关与冷却检查，直接执行。
        """
        results = []
        if not manual and not self.cfg.get("auto_repair"):
            return results
        now = time.time()
        cooldown = int(self.cfg.get("repair_cooldown", 3600))
        for issue in issues:
            action = issue.get("action")
            if not action:
                continue
            # 检查该类修复对应的独立开关（手动模式跳过）
            switch = issue.get("switch")
            if not manual and switch and not self.cfg.get(switch):
                continue

            target = issue.get("target") or ""
            key = "%s:%s" % (action, target)
            last = self.cooldowns.get(key, 0)
            if not manual and now - last < cooldown:
                results.append(self._result(issue, "cooldown",
                                            "冷却中（%d 秒内已修复过）" % cooldown))
                continue

            ok, detail = self._execute(action, issue)
            self.cooldowns[key] = now
            event = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": ACTION_NAMES.get(action, action),
                "target": target,
                "title": issue.get("title", ""),
                "ok": ok,
                "detail": detail,
            }
            self.events.insert(0, event)
            self.events = self.events[:MAX_EVENTS]
            if ok:
                _log.info("修复 %s → %s（成功）",
                          ACTION_NAMES.get(action, action),
                          target or issue.get("title", ""))
            else:
                _log.error("修复 %s → %s（失败）",
                           ACTION_NAMES.get(action, action),
                           target or issue.get("title", ""))
            results.append(self._result(issue, "ok" if ok else "fail", detail))
        return results

    @staticmethod
    def _result(issue, status, detail):
        return {"id": issue.get("id", ""), "title": issue.get("title", ""),
                "target": issue.get("target", ""),
                "action": issue.get("action"), "status": status, "detail": detail}

    # ---------------- 修复动作 ----------------
    def _execute(self, action, issue):
        try:
            if action == "reload_mqtt":
                return self._reload_domain("mqtt")
            if action == "reload_entry":
                return self._reload_domain(issue.get("target", ""))
            if action == "purge_recorder":
                # 清理旧数据可能较慢（树莓派+大库），给足超时
                code, body = self.col.call_service(
                    "recorder", "purge", {}, timeout=600)
                return code == 200, "recorder.purge HTTP %s %s" % (code, body[:200])
            if action == "repack_database":
                # purge + repack：清旧数据并 VACUUM 压缩文件（耗时操作，冷却机制防重复）
                code, body = self.col.call_service(
                    "recorder", "purge",
                    {"repack": True, "apply_filter": True}, timeout=1800)
                return code == 200, "recorder.purge(repack) HTTP %s %s" % (code, body[:200])
            return False, "未知修复动作：%s" % action
        except Exception as exc:  # 修复失败不应中断整体流程
            return False, "执行异常：%s" % exc

    def _reload_domain(self, domain):
        """重载指定域名的所有集成配置项。"""
        if not domain:
            return False, "目标为空"
        entries = self.col.config_entries()
        matched = [e for e in entries if e.get("domain") == domain]
        if not matched:
            return False, "未找到集成 %s 的配置项（可能为内置组件）" % domain
        details = []
        all_ok = True
        for e in matched:
            code, body = self.col.reload_entry(e["entry_id"])
            ok = code == 200
            all_ok = all_ok and ok
            details.append("%s(%s) HTTP %s" % (e.get("title", domain), e["entry_id"][:8], code))
        return all_ok, "；".join(details)
