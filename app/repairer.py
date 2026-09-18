"""问题修复模块。

对可修复问题执行动作：
- reload_mqtt                重载 MQTT 集成，恢复与代理的连接
- reload_entry               重载指定集成配置项
- reload_unavailable_entries 重载不可用实体集中的集成
- restart_addon              重启崩溃插件（本插件自身除外）
- purge_recorder             清理历史数据库旧数据

带修复冷却机制：同一问题在冷却时间内不重复执行，避免反复重启造成抖动。
修复历史持久化在 /addon_config/repair_history.json。
"""

import json
import os
import time
from datetime import datetime

SELF_SLUG = "log_analyzer"  # 与 config.yaml 的 slug 一致，避免自我重启
MAX_EVENTS = 200


def pick_base_dir():
    """选择持久化根目录。

    HA 容器内 /addon_config 由插件系统自动挂载，存在即直接使用；
    其余环境（如本地调试）回退到 /tmp 下的独立目录。
    """
    for d in ("/addon_config", "/data"):
        if os.path.isdir(d):
            return d
    fallback = "/tmp/log_analyzer"
    try:
        os.makedirs(fallback, exist_ok=True)
    except OSError:
        pass
    return fallback


# 修复动作的中文名称（用于报告与网页展示）
ACTION_NAMES = {
    "reload_mqtt": "重载 MQTT 集成",
    "reload_entry": "重载集成",
    "reload_unavailable_entries": "重载不可用实体的集成",
    "restart_addon": "重启插件",
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
            print("[日志分析] 修复 %s → %s（%s）"
                  % (ACTION_NAMES.get(action, action), target or issue.get("title", ""),
                     "成功" if ok else "失败"))
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
            if action == "reload_unavailable_entries":
                return self._reload_unavailable(issue)
            if action == "restart_addon":
                return self._restart_addon(issue.get("target", ""))
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

    def _reload_unavailable(self, issue):
        """对不可用实体集中的域（>=3 个）重载对应集成。"""
        domains = issue.get("domains") or {}
        entries = self.col.config_entries()
        details = []
        all_ok = True
        acted = False
        for domain, cnt in sorted(domains.items(), key=lambda kv: -kv[1]):
            if cnt < 3:
                continue  # 个别不可定多为设备休眠，不打扰
            matched = [e for e in entries if e.get("domain") == domain][:2]
            for e in matched:
                acted = True
                code, _ = self.col.reload_entry(e["entry_id"])
                ok = code == 200
                all_ok = all_ok and ok
                details.append("%s×%d HTTP %s" % (domain, cnt, code))
        if not acted:
            return False, "无集中的可重载集成（多为电池设备休眠）"
        return all_ok, "；".join(details)

    def _restart_addon(self, slug):
        """重启插件，跳过自身。"""
        if not slug:
            return False, "目标为空"
        if slug == SELF_SLUG:
            return False, "跳过自身，避免循环重启"
        code, body = self.col.restart_addon(slug)
        return code in (200, 202), "HTTP %s %s" % (code, body[:200])
