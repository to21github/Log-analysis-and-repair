"""报告生成模块。

把扫描结果整理为结构化 JSON（供网页展示）与 Markdown（人类可读），
保存最新报告并按时间归档，超出保留份数后自动清理最旧的。
"""

import glob
import json
import os
from datetime import datetime

from repairer import HISTORY_PATH, pick_base_dir

BASE_DIR = pick_base_dir()
REPORT_DIR = os.path.join(BASE_DIR, "reports")
LATEST_JSON = os.path.join(BASE_DIR, "report.json")
LATEST_MD = os.path.join(BASE_DIR, "report.md")

SEVERITY_NAMES = {"error": "错误", "warning": "警告", "info": "提示"}
STATUS_NAMES = {
    "ok": "已修复",
    "fail": "修复失败",
    "cooldown": "冷却中",
    "skipped": "未执行",
    "disabled": "自动修复未开启",
}


class Reporter:
    def __init__(self, options):
        self.cfg_options = options
        self.keep = int(options.get("keep_reports", 10))
        os.makedirs(REPORT_DIR, exist_ok=True)

    # ---------------- 构建 ----------------
    def build(self, result, repairs, core_source, supervisor_source, duration):
        """组装完整报告 dict，并把修复结果回填到对应问题上。"""
        issues = result["issues"]
        # 用 (id, target) 匹配修复结果（title 含动态数字，不适合做键）
        repair_map = {}
        for rep in repairs or []:
            repair_map[(rep.get("id", ""), rep.get("target", ""))] = rep
        for issue in issues:
            if not issue.get("action"):
                continue
            rep = repair_map.get((issue.get("id", ""), issue.get("target", "")))
            if rep:
                issue["repair_result"] = {"status": rep["status"], "detail": rep["detail"]}
            else:
                # 有修复动作但本次未执行：总开关或对应开关未开启
                switch = issue.get("switch")
                issue["repair_result"] = {"status": "disabled", "detail": ""}

        repaired = sum(1 for r in (repairs or []) if r["status"] == "ok")
        failed = sum(1 for r in (repairs or []) if r["status"] == "fail")
        repairable = sum(1 for i in issues if i.get("action"))
        return {
            "version": "1.0.0",
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "duration_sec": round(duration, 2),
            "sources": {"core": core_source, "supervisor": supervisor_source},
            "stats": result["stats"],
            "summary": {
                "issue_count": len(issues),
                "repairable": repairable,
                "repaired": repaired,
                "repair_failed": failed,
            },
            "issues": issues,
            "repair_events": [
                e for e in (repairs or [])
            ][:50],
        }

    # ---------------- 保存 ----------------
    @staticmethod
    def _atomic_write(path, content):
        """原子写：先写临时文件再替换，避免网页并发读取到半截内容。"""
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)

    def save(self, report):
        try:
            # 最新报告（JSON 供网页，MD 供阅读）
            self._atomic_write(LATEST_JSON,
                               json.dumps(report, ensure_ascii=False, indent=2))
            self._atomic_write(LATEST_MD, self.to_markdown(report))
        except OSError as exc:
            # 磁盘满等写入失败不应中断扫描循环
            print("[日志分析] 写入报告失败：%s" % exc)
            return
        # 按时间归档
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            with open(os.path.join(REPORT_DIR, stamp + ".json"), "w", encoding="utf-8") as fh:
                json.dump(report, fh, ensure_ascii=False, indent=2)
            # 清理旧归档
            archives = sorted(glob.glob(os.path.join(REPORT_DIR, "*.json")))
            for old in (archives[:-self.keep] if len(archives) > self.keep else []):
                try:
                    os.remove(old)
                except OSError:
                    pass
        except OSError as exc:
            print("[日志分析] 归档报告失败：%s" % exc)
        print("[日志分析] 报告已生成：%s（归档保留 %d 份）" % (LATEST_MD, self.keep))

    # ---------------- Markdown ----------------
    def to_markdown(self, report):
        stats = report["stats"]
        summary = report["summary"]
        lines = []
        lines.append("# Home Assistant 日志分析报告\n")
        lines.append("- 生成时间：%s" % report["generated_at"])
        lines.append("- 分析耗时：%.1f 秒" % report["duration_sec"])
        lines.append("- 日志来源：Core（%s）/ Supervisor（%s）"
                     % (report["sources"]["core"], report["sources"]["supervisor"]))
        lines.append("- 扫描行数：Core %s 行 / Supervisor %s 行\n"
                     % (stats["core_lines"], stats["supervisor_lines"]))

        lines.append("## 摘要\n")
        lines.append("| 指标 | 数值 |")
        lines.append("| --- | --- |")
        lines.append("| 发现问题 | %d 类（可修复 %d 项）|" % (summary["issue_count"], summary["repairable"]))
        lines.append("| 本次已修复 | %d 项（失败 %d 项）|" % (summary["repaired"], summary["repair_failed"]))
        lines.append("| 错误 / 警告行 | %d / %d |" % (stats["error_lines"], stats["warning_lines"]))
        lines.append("| Python 异常堆栈 | %d 处 |" % stats["tracebacks"])
        lines.append("| 实体总数 | %d（unknown %d）|" % (stats["entities_total"], stats["entities_unknown"]))
        lines.append("| 插件总数 | %d（异常 %d）|" % (stats["addons_total"], stats["addons_error"]))
        lines.append("| 集成加载失败 | %d 项 |" % stats["entries_error"])
        GB = 1024 ** 3
        if stats.get("disk_free_bytes") is not None:
            lines.append("| 磁盘剩余 | %.1f / %.1f GB |"
                         % (stats["disk_free_bytes"] / GB, stats["disk_total_bytes"] / GB))
        if stats.get("mem_used_pct") is not None:
            lines.append("| 内存使用 | %s%% |" % stats["mem_used_pct"])
        if stats.get("db_size_bytes"):
            lines.append("| 历史数据库 | %.1f GB |" % (stats["db_size_bytes"] / GB))
        lines.append("")

        if not report["issues"]:
            lines.append("## 结论\n")
            lines.append("未发现明显异常，系统运行正常。\n")
            return "\n".join(lines)

        lines.append("## 问题详情\n")
        for idx, issue in enumerate(report["issues"], 1):
            lines.append("### %d.【%s】%s%s\n"
                         % (idx, SEVERITY_NAMES.get(issue["severity"], issue["severity"]),
                            issue["title"],
                            "（出现 %d 次）" % issue["count"] if issue.get("count", 1) > 1 else ""))
            if issue.get("target"):
                lines.append("- 涉及对象：`%s`" % issue["target"])
            if issue.get("advice"):
                lines.append("- 建议：%s" % issue["advice"])
            rep = issue.get("repair_result")
            if rep:
                lines.append("- 修复：%s %s" % (STATUS_NAMES.get(rep["status"], rep["status"]),
                                               rep.get("detail", "")))
            elif issue.get("action"):
                lines.append("- 修复：未执行（自动修复关闭或冷却中）")
            if issue.get("samples"):
                lines.append("- 样本：")
                lines.append("")
                lines.append("```")
                lines.extend(issue["samples"][:3])
                lines.append("```")
            lines.append("")

        return "\n".join(lines)


def read_latest():
    """读取最新报告（网页启动时使用，避免依赖内存状态）。"""
    try:
        with open(LATEST_JSON, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def read_history():
    """读取修复历史事件。"""
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("events", [])
    except (OSError, ValueError):
        return []
