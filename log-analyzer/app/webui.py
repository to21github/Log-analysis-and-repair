"""内置 Web 界面（Ingress）。

提供中文深色报告页面：标题区、摘要卡片、问题列表，
支持右上角圆形按钮手动触发「立即扫描」与逐项「修复」。
监听端口需与 config.yaml 的 ingress_port 一致。
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>日志分析与修复</title>
<style>
:root { --blue:#00a8e8; --red:#ff1744; --orange:#ff6d00; --green:#00c853;
        --gray:#8b8d95; --bg:#111114; --card:#1b1b20; --text:#e9e9ec;
        --line:#2a2a32; --deep:#131317; }
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:"PingFang SC","Microsoft YaHei",system-ui,sans-serif;
       background:var(--bg); color:var(--text); padding:18px; max-width:960px; margin:0 auto; }
header { display:flex; align-items:flex-start; justify-content:space-between;
         gap:12px; flex-wrap:wrap; margin-bottom:16px; }
h1 { font-size:22px; font-weight:600; color:#fff; letter-spacing:.5px; }
.subtitle { color:var(--gray); font-size:13px; margin-top:4px; }
.iconbtn { width:46px; height:46px; border-radius:12px; background:var(--card);
           border:1px solid var(--line); cursor:pointer; display:flex;
           align-items:center; justify-content:center; flex-shrink:0; }
.iconbtn:hover { background:#232329; }
.iconbtn:disabled { cursor:not-allowed; opacity:.55; }
.iconbtn svg { width:22px; height:22px; stroke:var(--text); transform:scaleX(-1); }
.iconbtn.scanning svg { animation:r 1s linear infinite; }
@keyframes r { from { transform:scaleX(-1) rotate(0deg); }
               to { transform:scaleX(-1) rotate(360deg); } }
.panel { background:var(--card); border:1px solid var(--line); border-radius:14px;
         display:grid; grid-template-columns:repeat(5,1fr); margin-bottom:20px;
         overflow:hidden; }
.panel .cell { padding:16px 10px; display:flex; flex-direction:column;
               align-items:center; justify-content:center; text-align:center; }
.panel .cell + .cell { border-left:1px solid var(--line); }
.panel .num { font-size:34px; font-weight:600; color:#fff; margin-top:4px; }
.panel .lab { font-size:12px; color:var(--gray); }
.panel .num.red { color:var(--red); } .panel .num.orange { color:var(--orange); }
.panel .num.green { color:var(--green); } .panel .num.blue { color:var(--blue); }
@media (max-width:560px) {
  .panel { grid-template-columns:repeat(2,1fr); }
  .panel .cell { border-top:1px solid var(--line); }
  .panel .cell:nth-child(-n+2) { border-top:none; }
  .panel .cell:nth-child(odd) { border-left:none; }
}
h2 { font-size:15px; margin:18px 0 10px; color:#fff; }
.issue { background:var(--card); border:1px solid var(--line); border-radius:12px;
         padding:14px; margin-bottom:10px; }
.issue .head { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.issue .head .t { font-weight:600; font-size:15px; color:#fff; }
.badge { font-size:11px; padding:2px 8px; border-radius:10px; color:#fff; }
.badge.error { background:var(--red); } .badge.warning { background:var(--orange); }
.badge.info { background:var(--blue); }
.badge.ok { background:var(--green); } .badge.fail { background:var(--red); }
.badge.cooldown { background:var(--gray); } .badge.disabled { background:var(--gray); }
.fixbtn { margin-left:auto; padding:4px 14px; border:none; border-radius:6px;
  background:var(--green); color:#111; font-size:12px; font-weight:600;
  cursor:pointer; white-space:nowrap; }
.fixbtn:hover { opacity:.85; }
.count { color:var(--gray); font-size:12px; }
.target { font-family:monospace; background:#26262e; border-radius:4px;
          padding:1px 6px; font-size:12px; color:#c9c9ce; }
.advice { font-size:13px; color:#a0a2aa; margin-top:8px; line-height:1.6; }
summary { font-size:12px; color:var(--blue); cursor:pointer; }
pre { background:var(--deep); border:1px solid var(--line); border-radius:8px;
      padding:8px 10px; font-size:12px; overflow:auto; margin-top:6px;
      white-space:pre-wrap; word-break:break-all; color:#c9c9ce; }
.empty { text-align:center; color:var(--gray); padding:36px 0; }
footer { margin-top:18px; color:var(--gray); font-size:11px; text-align:center; }
</style>
</head>
<body>
<header>
  <div>
    <h1>日志分析与修复</h1>
    <div class="subtitle">Home Assistant 系统日志分析与修复问题</div>
  </div>
  <button id="scanBtn" class="iconbtn" onclick="doScan()" title="立即扫描">
    <svg viewBox="0 0 24 24" fill="none" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round">
      <polyline points="1 4 1 10 7 10"/>
      <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
    </svg>
  </button>
</header>

<div class="panel" id="cards"></div>
<h2>问题列表</h2>
<div id="issues"></div>
<footer>数据来源：Core / Supervisor 日志 · 实体状态 · 插件状态 · 集成配置项</footer>

<script>
const SEV = {error:'错误', warning:'警告', info:'提示'};
const STATUS = {ok:'已修复', fail:'修复失败', cooldown:'冷却中', disabled:'自动修复未开启'};

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g,
    c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function refresh() {
  try {
    const st = await (await fetch('api/status')).json();
    const btn = document.getElementById('scanBtn');
    btn.disabled = !!st.scanning;
    btn.classList.toggle('scanning', !!st.scanning);
    btn.title = st.scanning ? '扫描中…' : '立即扫描';

    const rep = await (await fetch('api/report')).json();
    render(rep);
  } catch (e) { /* 忽略瞬时网络错误，下轮轮询重试 */ }
}

function cell(num, label, cls) {
  return '<div class="cell"><div class="lab">' + label +
         '</div><div class="num ' + cls + '">' + num + '</div></div>';
}

function render(rep) {
  const cardsEl = document.getElementById('cards');
  const issues = document.getElementById('issues');
  if (!rep || !rep.generated_at) {
    cardsEl.innerHTML = '';
    issues.innerHTML = '<div class="empty">暂无报告，请点击右上角按钮扫描生成。</div>';
    return;
  }
  const s = rep.stats || {}, m = rep.summary || {};
  const cells = [
    cell(m.issue_count ?? 0, '发现问题', ''),
    cell(m.repairable ?? 0, '可修复', 'blue'),
    cell(m.repaired ?? 0, '已修复', 'green'),
    cell(s.addons_error ?? 0, '异常', 'orange'),
    cell(s.error_lines ?? 0, '错误', 'red'),
  ];
  cardsEl.innerHTML = cells.join('');

  if (!rep.issues || !rep.issues.length) {
    issues.innerHTML = '<div class="empty">未发现明显异常，系统运行正常。</div>';
    return;
  }
  issues.innerHTML = rep.issues.map(i => {
    const rr = i.repair_result;
    let badge = '';
    if (rr) badge = '<span class="badge ' + rr.status + '">' +
      (STATUS[rr.status] || rr.status) + '</span>';
    const cnt = i.count > 1 ? '<span class="count">出现 ' + i.count + ' 次</span>' : '';
    const tgt = i.target ? '<span class="target">' + esc(i.target) + '</span>' : '';
    // 可修复且尚未修复成功的问题显示「修复」按钮（手动模式核心交互）
    const btn = (i.action && !(rr && rr.status === 'ok'))
      ? '<button class="fixbtn" data-id="' + esc(i.id || '') + '" data-target="' +
        esc(i.target || '') + '" onclick="doRepair(this.dataset.id,this.dataset.target)">修复</button>'
      : '';
    const samples = (i.samples && i.samples.length)
      ? '<details><summary>查看日志样本</summary><pre>' +
        esc(i.samples.join('\\n')) + '</pre></details>' : '';
    const advice = i.advice ? '<div class="advice">' + esc(i.advice) + '</div>' : '';
    const detail = (rr && rr.detail) ? '<div class="advice">修复详情：' +
      esc(rr.detail) + '</div>' : '';
    return '<div class="issue"><div class="head">' +
      '<span class="badge ' + i.severity + '">' + (SEV[i.severity] || i.severity) + '</span>' +
      '<span class="t">' + esc(i.title) + '</span>' + tgt + cnt + badge + btn +
      '</div>' + advice + detail + samples + '</div>';
  }).join('');
}

async function doScan() {
  try { await fetch('api/scan', {method: 'POST'}); } catch (e) {}
  setTimeout(refresh, 800);
}

async function doRepair(id, target) {
  try {
    const r = await fetch('api/repair', {method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: id, target: target})});
    const res = await r.json();
    if (res.status !== 'ok' && res.detail) alert('修复失败：' + res.detail);
    refresh();
  } catch (e) { alert('请求失败，请重试'); }
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


class WebUI:
    """报告网页服务。

    参数：
      port          监听端口（与 config.yaml 的 ingress_port 一致）
      state         共享状态 dict（scanning / last_scan / next_scan / last_report）
      trigger_scan  触发一次扫描的回调
      read_report   读取最新报告的回调（启动时磁盘回读）
      read_history  读取修复历史事件的回调（保留接口，页面已不展示）
    """

    def __init__(self, port, state, trigger_scan, read_report, read_history,
                 repair_one=None):
        self.port = port
        self.state = state
        self.trigger_scan = trigger_scan
        self.read_report = read_report
        self.read_history = read_history
        self.repair_one = repair_one
        ui = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, content, ctype):
                payload = content.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                if self.path in ("/", "/index.html"):
                    self._send(200, PAGE, "text/html; charset=utf-8")
                elif self.path == "/api/status":
                    body = json.dumps({
                        "scanning": ui.state.get("scanning", False),
                        "last_scan": ui.state.get("last_scan"),
                        "next_scan": ui.state.get("next_scan"),
                    }, ensure_ascii=False)
                    self._send(200, body, "application/json; charset=utf-8")
                elif self.path == "/api/report":
                    report = ui.state.get("last_report") or ui.read_report()
                    body = json.dumps(report, ensure_ascii=False) if report else "{}"
                    self._send(200, body, "application/json; charset=utf-8")
                elif self.path == "/api/history":
                    body = json.dumps(ui.read_history() or [], ensure_ascii=False)
                    self._send(200, body, "application/json; charset=utf-8")
                else:
                    self._send(404, '{"error":"not found"}', "application/json; charset=utf-8")

            def do_POST(self):
                if self.path == "/api/scan":
                    threading.Thread(target=ui.trigger_scan, daemon=True).start()
                    self._send(200, '{"started":true}', "application/json; charset=utf-8")
                elif self.path == "/api/repair":
                    if not ui.repair_one:
                        self._send(501, '{"status":"fail","detail":"未启用"}',
                                   "application/json; charset=utf-8")
                        return
                    try:
                        length = int(self.headers.get("Content-Length") or 0)
                        payload = json.loads(self.rfile.read(length) or b"{}")
                    except ValueError:
                        payload = {}
                    res = ui.repair_one(payload)
                    self._send(200, json.dumps(res, ensure_ascii=False),
                               "application/json; charset=utf-8")
                else:
                    self._send(404, '{"error":"not found"}', "application/json; charset=utf-8")

            def log_message(self, *args):
                pass  # 静默访问日志，避免刷屏

        self.httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        self.httpd.daemon_threads = True

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        print("[日志分析] Web 界面已启动，监听端口 %d（Ingress）" % self.port)
