"""
Module 5 – Dashboard (Reporting & Monitoring)
Full-featured Flask web dashboard. Each investigation opens a dedicated
HTML page showing the AI summary, full scraped content, and all found links.
"""
import json
import logging
from pathlib import Path
from flask import Flask, render_template_string, jsonify, abort, send_file, redirect, url_for

from storage import (
    list_sessions, get_session, get_results, get_results_with_content,
    get_artifacts, get_audit_log, get_stats,
    export_session_json, export_session_csv, export_all_sessions_csv,
)
from reporter import get_system_health, REPORTS_DIR
from flask import Response

logging.basicConfig(level=logging.WARNING)
app = Flask(__name__)

# ── Shared CSS / base shell ──────────────────────────────────────────────────

_CSS = """
:root {
  --bg:       #0d1117;
  --bg2:      #161b22;
  --bg3:      #21262d;
  --border:   #30363d;
  --text:     #c9d1d9;
  --muted:    #8b949e;
  --blue:     #58a6ff;
  --blue2:    #1f6feb;
  --green:    #3fb950;
  --yellow:   #d29922;
  --red:      #f85149;
  --purple:   #bc8cff;
  --radius:   8px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: -apple-system, 'Segoe UI', system-ui, sans-serif;
  background: var(--bg); color: var(--text);
  font-size: 14px; line-height: 1.6;
}
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }
code, .mono { font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; font-size: .82em; }

/* NAV */
nav {
  position: sticky; top: 0; z-index: 100;
  background: var(--bg2); border-bottom: 1px solid var(--border);
  padding: .65rem 1.8rem; display: flex; align-items: center; gap: 1.6rem;
}
.nav-logo { color: var(--blue); font-weight: 700; font-size: 1rem; letter-spacing: -.3px; }
.nav-logo span { color: var(--muted); font-weight: 400; }
nav a.nav-link { color: var(--muted); font-size: .85rem; transition: color .15s; }
nav a.nav-link:hover, nav a.nav-link.active { color: var(--text); text-decoration: none; }
.nav-spacer { flex: 1; }
.nav-badge {
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 20px; padding: .15rem .65rem; font-size: .75rem; color: var(--muted);
}

/* PAGE */
.page { max-width: 1120px; margin: 0 auto; padding: 2rem 1.6rem 4rem; }
.page-sm { max-width: 840px; }

/* HEADINGS */
h1 { font-size: 1.35rem; color: #f0f6fc; font-weight: 600; }
h2 { font-size: 1rem; font-weight: 600; color: var(--blue); margin: 2rem 0 .7rem;
     display: flex; align-items: center; gap: .4rem; }
h2::after { content:''; flex:1; height:1px; background: var(--border); margin-left:.4rem; }
h3 { font-size: .9rem; font-weight: 600; color: var(--text); margin-bottom: .4rem; }

/* CARDS GRID */
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .9rem; margin: 1.2rem 0 2rem; }
.stat-card {
  background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 1.1rem 1rem; text-align: center;
}
.stat-val { font-size: 2rem; font-weight: 700; color: var(--blue); line-height: 1.1; }
.stat-lbl { font-size: .72rem; color: var(--muted); margin-top: .25rem; text-transform: uppercase; letter-spacing: .04em; }

/* BADGES */
.badge {
  display: inline-flex; align-items: center;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 20px; padding: .1rem .55rem; font-size: .72rem; color: var(--muted);
  white-space: nowrap;
}
.badge-blue   { background: #1f6feb22; border-color: #1f6feb66; color: var(--blue); }
.badge-green  { background: #238636aa; border-color: #2ea04366; color: var(--green); }
.badge-yellow { background: #b7950b22; border-color: #d2992266; color: var(--yellow); }
.badge-red    { background: #da363622; border-color: #f8514966; color: var(--red); }
.badge-purple { background: #8957e522; border-color: #bc8cff66; color: var(--purple); }

/* TABLE */
.tbl-wrap { overflow-x: auto; border-radius: var(--radius); border: 1px solid var(--border); }
table { width: 100%; border-collapse: collapse; font-size: .84rem; }
th {
  background: var(--bg3); padding: .5rem .9rem; text-align: left;
  color: var(--muted); font-weight: 600; font-size: .75rem; text-transform: uppercase; letter-spacing: .04em;
  white-space: nowrap; border-bottom: 1px solid var(--border);
}
td { padding: .45rem .9rem; border-bottom: 1px solid var(--bg3); vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg2); }

/* SESSION CARDS (list page) */
.session-row { display: flex; align-items: flex-start; gap: 1rem; padding: .9rem 1rem;
  border-bottom: 1px solid var(--border); transition: background .12s; }
.session-row:hover { background: var(--bg2); }
.session-row:last-child { border-bottom: none; }
.session-num { color: var(--muted); font-size: .78rem; min-width: 28px; padding-top: .1rem; }
.session-body { flex: 1; min-width: 0; }
.session-query { font-weight: 600; color: #f0f6fc; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.session-meta { font-size: .75rem; color: var(--muted); margin-top: .15rem; display: flex; flex-wrap: wrap; gap: .5rem; }
.session-actions { display: flex; gap: .5rem; align-items: center; flex-shrink: 0; }
.btn {
  display: inline-flex; align-items: center; gap: .3rem;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 6px; padding: .28rem .7rem; font-size: .78rem; color: var(--text);
  cursor: pointer; transition: background .12s, border-color .12s; white-space: nowrap;
}
.btn:hover { background: var(--bg2); border-color: var(--blue); color: var(--blue); text-decoration: none; }
.btn-primary { background: var(--blue2); border-color: var(--blue); color: #fff; }
.btn-primary:hover { background: var(--blue); color: #fff; }

/* INVESTIGATION PAGE */
.inv-header {
  background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 1.4rem 1.6rem; margin-bottom: 1.8rem;
}
.inv-title { font-size: 1.2rem; font-weight: 700; color: #f0f6fc; margin-bottom: .6rem; line-height: 1.3; }
.inv-meta-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: .4rem .8rem; font-size: .82rem;
}
.inv-meta-item { display: flex; gap: .4rem; }
.inv-meta-key { color: var(--muted); min-width: 80px; flex-shrink: 0; }
.inv-meta-val { color: var(--text); word-break: break-all; }
.inv-actions { display: flex; gap: .6rem; margin-top: 1rem; flex-wrap: wrap; }

/* SUMMARY BOX */
.summary-box {
  background: var(--bg2); border: 1px solid var(--border);
  border-left: 3px solid var(--blue); border-radius: 0 var(--radius) var(--radius) 0;
  padding: 1.2rem 1.4rem; font-size: .88rem; line-height: 1.75;
  white-space: pre-wrap; word-break: break-word;
}

/* CONTENT CARDS */
.content-card {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); margin-bottom: 1rem; overflow: hidden;
}
.content-card-head {
  background: var(--bg3); padding: .65rem 1rem;
  display: flex; align-items: center; gap: .6rem; flex-wrap: wrap;
}
.content-card-num {
  background: var(--blue2); color: #fff; border-radius: 50%;
  width: 22px; height: 22px; display: flex; align-items: center; justify-content: center;
  font-size: .7rem; font-weight: 700; flex-shrink: 0;
}
.content-card-url {
  flex: 1; min-width: 0; font-family: monospace; font-size: .78rem;
  color: var(--blue); word-break: break-all;
}
.content-card-url a:hover { text-decoration: underline; }
.content-card-body {
  padding: .9rem 1rem; font-size: .83rem; line-height: 1.7;
  color: var(--text); white-space: pre-wrap; word-break: break-word;
  max-height: 380px; overflow-y: auto;
}
.content-card-body::-webkit-scrollbar { width: 5px; }
.content-card-body::-webkit-scrollbar-track { background: var(--bg2); }
.content-card-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
.content-expand { display: none; }
.content-card-body.collapsed { max-height: 200px; mask-image: linear-gradient(#000 60%, transparent); -webkit-mask-image: linear-gradient(#000 60%, transparent); }
.content-toggle {
  display: block; text-align: center; padding: .4rem 1rem;
  background: var(--bg3); border-top: 1px solid var(--border);
  color: var(--muted); font-size: .75rem; cursor: pointer; transition: color .12s;
}
.content-toggle:hover { color: var(--text); }
.no-content { color: var(--muted); font-style: italic; font-size: .82rem; padding: .8rem 1rem; }

/* LINKS TABLE */
.link-num { color: var(--muted); font-size: .78rem; text-align: right; width: 36px; }
.link-title { font-weight: 500; }
.link-url { font-family: monospace; font-size: .76rem; word-break: break-all; color: var(--muted); }

/* HEALTH */
.health-row { display: flex; align-items: center; gap: 1rem; padding: .7rem 1rem; border-bottom: 1px solid var(--border); }
.health-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.health-dot.up { background: var(--green); box-shadow: 0 0 6px var(--green); }
.health-dot.down { background: var(--red); box-shadow: 0 0 6px var(--red); }
.health-name { font-weight: 600; min-width: 100px; }
.health-detail { color: var(--muted); font-size: .82rem; font-family: monospace; }

/* AUDIT */
.audit-row { font-size: .8rem; display: flex; gap: .8rem; padding: .4rem .9rem; border-bottom: 1px solid var(--bg3); align-items: flex-start; }
.audit-time { color: var(--muted); white-space: nowrap; flex-shrink: 0; }
.audit-detail { color: var(--text); word-break: break-all; flex: 1; }

/* EMPTY STATE */
.empty { text-align: center; padding: 4rem 2rem; color: var(--muted); }
.empty-icon { font-size: 3rem; margin-bottom: .8rem; }
.empty p { font-size: .9rem; }

/* TABS */
.tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
.tab {
  padding: .5rem 1.1rem; font-size: .84rem; color: var(--muted); cursor: pointer;
  border-bottom: 2px solid transparent; transition: color .15s, border-color .15s; margin-bottom: -1px;
}
.tab.active { color: var(--text); border-color: var(--blue); }

/* SEARCH */
.search-bar {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
  padding: .4rem .8rem; color: var(--text); font-size: .85rem; width: 100%;
  outline: none; transition: border-color .15s;
}
.search-bar:focus { border-color: var(--blue); }
.search-bar::placeholder { color: var(--muted); }

/* TOC */
.toc { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem 1.2rem; margin-bottom: 1.8rem; }
.toc-title { font-size: .78rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: .5rem; }
.toc a { display: block; font-size: .82rem; padding: .15rem 0; color: var(--muted); }
.toc a:hover { color: var(--blue); }

/* RESPONSIVE */
@media (max-width: 640px) {
  .page { padding: 1rem .8rem 3rem; }
  .inv-meta-grid { grid-template-columns: 1fr; }
  .session-actions { flex-direction: column; }
}
"""

_BASE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} — Dcrawler</title>
  <style>{{ css }}</style>
</head>
<body>
<nav>
  <span class="nav-logo">&#128373; Dcrawler<span> OSINT</span></span>
  <a href="/" class="nav-link {{ 'active' if active=='home' }}">Dashboard</a>
  <a href="/sessions" class="nav-link {{ 'active' if active=='sessions' }}">Investigations</a>
  <a href="/health" class="nav-link {{ 'active' if active=='health' }}">Health</a>
  <a href="/audit" class="nav-link {{ 'active' if active=='audit' }}">Audit Log</a>
  <span class="nav-spacer"></span>
  <span class="nav-badge">&#9679; Live</span>
</nav>
{% block body %}{% endblock %}
</body>
<script>
// Content card expand/collapse
document.querySelectorAll('.content-toggle').forEach(function(btn){
  btn.addEventListener('click', function(){
    var body = this.previousElementSibling;
    var collapsed = body.classList.toggle('collapsed');
    this.textContent = collapsed ? '▼ Show more' : '▲ Show less';
  });
});
// Session search
var searchInput = document.getElementById('session-search');
if(searchInput){
  searchInput.addEventListener('input', function(){
    var q = this.value.toLowerCase();
    document.querySelectorAll('.session-row').forEach(function(row){
      row.style.display = row.dataset.query.includes(q) ? '' : 'none';
    });
  });
}
</script>
</html>"""


def _render(template: str, **ctx):
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    base = env.from_string(_BASE)
    inner = env.from_string(template)
    ctx.setdefault("title", "Dcrawler")
    ctx.setdefault("active", "")
    ctx["css"] = _CSS
    block_content = inner.render(**ctx)
    # inject rendered block into base
    full = _BASE.replace("{% block body %}{% endblock %}", block_content)
    full = full.replace("{{ css }}", _CSS)
    full = full.replace("{{ title }}", ctx.get("title","Dcrawler") + " — Dcrawler")
    for k, v in [("home","home"),("sessions","sessions"),("health","health"),("audit","audit")]:
        full = full.replace(f"'active' if active=='{k}'", "'active'" if ctx.get("active")==k else "''")
    return full


def esc(s):
    return (str(s or "")
            .replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;"))


def _mode_badge(preset: str) -> str:
    if preset == "raw":
        return '<span class="badge badge-yellow">&#128269; Raw</span>'
    colors = {
        "threat_intel":      "badge-blue",
        "ransomware_malware":"badge-red",
        "personal_identity": "badge-purple",
        "corporate_espionage":"badge-yellow",
    }
    cls = colors.get(preset, "badge-blue")
    return f'<span class="badge {cls}">&#129302; {esc(preset.replace("_"," ").title())}</span>'


def _threat_badge(score: int) -> str:
    score = int(score or 0)
    if score >= 75:
        cls, label = "badge-red", "CRITICAL"
    elif score >= 50:
        cls, label = "badge-yellow", "HIGH"
    elif score >= 25:
        cls, label = "badge-blue", "MEDIUM"
    else:
        cls, label = "", "LOW"
    return f'<span class="badge {cls}" title="Threat Score {score}/100">&#9888; {label} {score}</span>'


def _status_badge(s: dict) -> str:
    if s.get("finished_at"):
        return '<span class="badge badge-green">&#10003; Complete</span>'
    return '<span class="badge badge-yellow">&#9679; Running</span>'


# ── INDEX ─────────────────────────────────────────────────────────────────────

_INDEX = """
<div class="page">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;flex-wrap:wrap;gap:.8rem">
    <div>
      <h1>&#128200; Dashboard</h1>
      <p style="color:var(--muted);font-size:.85rem;margin-top:.2rem">AI-Powered Dark Web OSINT platform</p>
    </div>
    <div style="display:flex;gap:.6rem">
      <a href="/sessions" class="btn">&#128196; All Investigations</a>
      <a href="/health" class="btn">&#10084; Health</a>
    </div>
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-val">{{ stats.total_sessions }}</div><div class="stat-lbl">Investigations</div></div>
    <div class="stat-card"><div class="stat-val">{{ stats.total_results }}</div><div class="stat-lbl">Links Found</div></div>
    <div class="stat-card"><div class="stat-val">{{ stats.total_scraped }}</div><div class="stat-lbl">Pages Scraped</div></div>
    <div class="stat-card"><div class="stat-val">{{ stats.total_artifacts }}</div><div class="stat-lbl">Artifacts</div></div>
  </div>

  <h2>&#128336; Recent Investigations</h2>
  {% if stats.recent_queries %}
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
    {% for r in stats.recent_queries %}
    <a href="/session/{{ r.session_id }}" style="text-decoration:none">
      <div class="session-row">
        <div class="session-num">{{ loop.revindex }}</div>
        <div class="session-body">
          <div class="session-query">{{ r.query }}</div>
          <div class="session-meta">
            <span>{{ r.created_at[:19].replace('T',' ') }}</span>
            {{ mode_badge(r.preset) }}
            {% if r.threat_score %}{{ threat_badge(r.threat_score) }}{% endif %}
            {% if r.tags %}{% for tag in r.tags.split(',') if tag.strip() %}<span class="badge badge-blue">&#127991; {{ tag.strip() }}</span>{% endfor %}{% endif %}
          </div>
        </div>
        <div style="color:var(--muted);font-size:.85rem">&#8250;</div>
      </div>
    </a>
    {% endfor %}
  </div>
  {% else %}
  <div class="empty"><div class="empty-icon">&#128373;</div><p>No investigations yet.<br>Run <code>dcrawler.py "your query"</code> to get started.</p></div>
  {% endif %}

  <h2>&#128295; System Status</h2>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
    {% for name, info in health.components.items() %}
    <div class="health-row">
      <div class="health-dot {{ info.status }}"></div>
      <div class="health-name">{{ name.title() }}</div>
      <div class="health-detail">
        {% for k,v in info.items() %}{% if k!='status' %}{{ k }}: {{ v }}&nbsp;&nbsp;{% endif %}{% endfor %}
      </div>
    </div>
    {% endfor %}
  </div>
</div>
"""


@app.route("/")
def index():
    stats  = get_stats()
    health = get_system_health()
    # attach session_id and preset to recent_queries
    from storage import get_conn
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT session_id, query, preset, created_at, threat_score, tags "
            "FROM sessions ORDER BY id DESC LIMIT 8"
        ).fetchall()
    stats["recent_queries"] = [dict(r) for r in rows]
    html = _INDEX.replace("{{ mode_badge(r.preset) }}", "")  # handle via jinja below
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    env.globals["mode_badge"]   = _mode_badge
    env.globals["threat_badge"] = _threat_badge
    tmpl = env.from_string(_INDEX)
    body = tmpl.render(stats=stats, health=health)
    full = _BASE.replace("{% block body %}{% endblock %}", body).replace("{{ css }}", _CSS)
    full = full.replace("{{ title }}", "Dashboard — Dcrawler")
    for k in ("home","sessions","health","audit"):
        full = full.replace(f"'active' if active=='{k}'", "'active'" if k=="home" else "''")
    return full


# ── SESSIONS LIST ────────────────────────────────────────────────────────────

@app.route("/sessions")
def sessions_view():
    tag_filter = __import__("flask").request.args.get("tag", "")
    sessions = list_sessions(200, tag=tag_filter if tag_filter else None)
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    env.globals["mode_badge"]    = _mode_badge
    env.globals["status_badge"]  = _status_badge
    env.globals["threat_badge"]  = _threat_badge
    env.globals["esc"] = esc
    _TMPL = """
<div class="page">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.2rem;flex-wrap:wrap;gap:.8rem">
    <h1>&#128196; All Investigations</h1>
    <div style="display:flex;gap:.6rem;align-items:center">
      <span class="badge">{{ sessions|length }} total</span>
      <a href="/api/export/all?format=csv" class="btn">&#11015; Export CSV</a>
      <a href="/api/export/all?format=json" class="btn">&#11015; Export JSON</a>
    </div>
  </div>
  <input id="session-search" class="search-bar" placeholder="&#128269;  Filter by query or tag…" style="margin-bottom:1.2rem">
  {% if sessions %}
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
    {% for s in sessions %}
    <div class="session-row" data-query="{{ s.query|lower }} {{ (s.tags or '')|lower }}">
      <div class="session-num">{{ loop.index }}</div>
      <div class="session-body" style="min-width:0">
        <div class="session-query">{{ s.query }}</div>
        <div class="session-meta">
          <span>{{ s.created_at[:19].replace('T',' ') }}</span>
          <span>{{ status_badge(s) }}</span>
          {{ mode_badge(s.preset) }}
          {% if s.threat_score %} {{ threat_badge(s.threat_score) }}{% endif %}
          <span class="badge">&#128279; {{ s.result_count }} links</span>
          <span class="badge">&#128196; {{ s.scrape_count }} scraped</span>
          {% if s.model and s.model != 'none' %}<span class="badge badge-purple">{{ s.model }}</span>{% endif %}
          {% if s.tags %}{% for tag in s.tags.split(',') %}<a href="/sessions?tag={{ tag.strip() }}" class="badge badge-blue" style="text-decoration:none">&#127991; {{ tag.strip() }}</a>{% endfor %}{% endif %}
        </div>
      </div>
      <div class="session-actions">
        <a href="/session/{{ s.session_id }}" class="btn btn-primary">&#128065; View</a>
      </div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="empty"><div class="empty-icon">&#128373;</div><p>No investigations yet.</p></div>
  {% endif %}
</div>
"""
    body = env.from_string(_TMPL).render(sessions=sessions)
    full = _BASE.replace("{% block body %}{% endblock %}", body).replace("{{ css }}", _CSS)
    full = full.replace("{{ title }}", "Investigations — Dcrawler")
    for k in ("home","sessions","health","audit"):
        full = full.replace(f"'active' if active=='{k}'", "'active'" if k=="sessions" else "''")
    return full


# ── SESSION DETAIL (the main page) ───────────────────────────────────────────

@app.route("/session/<sid>")
def session_view(sid: str):
    s = get_session(sid)
    if not s:
        abort(404)

    results_with_content = get_results_with_content(sid)
    scraped  = [r for r in results_with_content if r["scraped"]]
    all_links = results_with_content   # all rows (scraped + not scraped)
    artifacts = get_artifacts(sid)
    is_raw = (s.get("preset") == "raw")
    is_llm = not is_raw

    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    env.globals["mode_badge"]    = _mode_badge
    env.globals["status_badge"]  = _status_badge
    env.globals["threat_badge"]  = _threat_badge
    env.globals["esc"] = esc

    _TMPL = r"""
<div class="page">

  <!-- HEADER -->
  <div class="inv-header">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;flex-wrap:wrap">
      <div style="flex:1;min-width:0">
        <div style="font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.35rem">
          Investigation &nbsp;/&nbsp; <code style="font-size:.85em;background:var(--bg3);padding:.1rem .4rem;border-radius:4px">{{ s.session_id }}</code>
        </div>
        <div class="inv-title">{{ s.query }}</div>
        <div style="display:flex;flex-wrap:wrap;gap:.45rem;margin-top:.6rem">
          {{ status_badge(s) }}
          {{ mode_badge(s.preset) }}
          {% if s.threat_score %}{{ threat_badge(s.threat_score) }}{% endif %}
          {% if s.model and s.model != 'none' %}
          <span class="badge badge-purple">{{ s.model }}</span>
          {% endif %}
          <span class="badge">&#128279; {{ s.result_count }} links found</span>
          <span class="badge">&#128196; {{ s.scrape_count }} pages scraped</span>
          {% if artifacts %}<span class="badge badge-yellow">&#128270; {{ artifacts|length }} IOC artifacts</span>{% endif %}
          {% if s.tags %}{% for tag in s.tags.split(',') %}<a href="/sessions?tag={{ tag.strip() }}" class="badge badge-blue" style="text-decoration:none">&#127991; {{ tag.strip() }}</a>{% endfor %}{% endif %}
        </div>
        {% if s.notes %}
        <div style="margin-top:.8rem;padding:.6rem .9rem;background:var(--bg3);border-radius:6px;font-size:.82rem;color:var(--muted)">
          &#128221; <em>{{ s.notes }}</em>
        </div>
        {% endif %}
      </div>
    </div>

    <div class="inv-meta-grid" style="margin-top:1rem">
      {% if s.refined_q and s.refined_q != s.query %}
      <div class="inv-meta-item"><span class="inv-meta-key">Refined</span><span class="inv-meta-val">{{ s.refined_q }}</span></div>
      {% endif %}
      <div class="inv-meta-item"><span class="inv-meta-key">Started</span><span class="inv-meta-val">{{ s.created_at[:19].replace('T',' ') }} UTC</span></div>
      {% if s.finished_at %}<div class="inv-meta-item"><span class="inv-meta-key">Finished</span><span class="inv-meta-val">{{ s.finished_at[:19].replace('T',' ') }} UTC</span></div>{% endif %}
    </div>

    <div class="inv-actions">
      <a href="/session/{{ s.session_id }}/report/html" class="btn">&#128196; HTML Report</a>
      <a href="/session/{{ s.session_id }}/report/txt"  class="btn">&#128196; Text Report</a>
      <a href="/api/export/{{ s.session_id }}?format=json" class="btn">&#11015; JSON</a>
      <a href="/api/export/{{ s.session_id }}?format=csv"  class="btn">&#11015; CSV</a>
      <a href="/sessions" class="btn">&#8592; All Investigations</a>
    </div>
  </div>

  <!-- TABLE OF CONTENTS -->
  <div class="toc">
    <div class="toc-title">Contents</div>
    {% if s.summary %}<a href="#summary">&#127755; Intelligence Summary</a>{% endif %}
    {% if scraped %}<a href="#content">&#128196; Scraped Content ({{ scraped|length }} pages)</a>{% endif %}
    {% if artifacts %}<a href="#artifacts">&#128270; Investigation Artifacts</a>{% endif %}
    <a href="#links">&#128279; All Found Links ({{ all_links|length }})</a>
  </div>

  <!-- INTELLIGENCE SUMMARY (LLM mode) -->
  {% if s.summary %}
  <h2 id="summary">&#127755; Intelligence Summary</h2>
  <div class="summary-box">{{ s.summary }}</div>
  {% endif %}

  <!-- SCRAPED CONTENT -->
  {% if scraped %}
  <h2 id="content">&#128196; Scraped Content <span style="font-weight:400;color:var(--muted);font-size:.85rem">({{ scraped|length }} pages)</span></h2>
  {% for r in scraped %}
  <div class="content-card">
    <div class="content-card-head">
      <div class="content-card-num">{{ loop.index }}</div>
      <div class="content-card-url">
        <a href="{{ r.url }}" target="_blank" rel="noopener">{{ r.url }}</a>
      </div>
      {% if r.title and r.title != r.url %}
      <span class="badge" style="flex-shrink:0">{{ r.title[:60] }}</span>
      {% endif %}
    </div>
    {% if r.content and r.content.strip() %}
    <div class="content-card-body collapsed">{{ r.content.strip() }}</div>
    <div class="content-toggle">&#9660; Show more</div>
    {% else %}
    <div class="no-content">No content scraped for this page.</div>
    {% endif %}
  </div>
  {% endfor %}
  {% elif s.scrape_count == 0 %}
  <div class="empty" style="padding:2rem"><p>No pages were scraped in this session.</p></div>
  {% endif %}

  <!-- ARTIFACTS -->
  {% if artifacts %}
  <h2 id="artifacts">&#128270; Investigation Artifacts</h2>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>#</th><th>Type</th><th>Value</th><th>Context</th></tr></thead>
      <tbody>
      {% for a in artifacts %}
      <tr>
        <td class="link-num">{{ loop.index }}</td>
        <td><span class="badge badge-yellow">{{ a.kind }}</span></td>
        <td class="mono">{{ a.value }}</td>
        <td style="color:var(--muted);font-size:.8rem">{{ a.context or '' }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- ALL LINKS -->
  <h2 id="links">&#128279; All Found Links <span style="font-weight:400;color:var(--muted);font-size:.85rem">({{ all_links|length }})</span></h2>
  {% if all_links %}
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>#</th><th>Title</th><th>URL</th><th>Status</th></tr></thead>
      <tbody>
      {% for r in all_links %}
      <tr>
        <td class="link-num">{{ loop.index }}</td>
        <td class="link-title">{{ r.title or '—' }}</td>
        <td><a href="{{ r.url }}" target="_blank" rel="noopener" class="link-url mono">{{ r.url }}</a></td>
        <td>
          {% if r.scraped %}
          <span class="badge badge-green">&#10003; Scraped</span>
          {% else %}
          <span class="badge">&#8212; Found</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="empty" style="padding:2rem"><p>No links recorded for this session.</p></div>
  {% endif %}

</div>

<script>
// Re-run expand/collapse on this page
document.querySelectorAll('.content-toggle').forEach(function(btn){
  btn.addEventListener('click', function(){
    var body = this.previousElementSibling;
    var collapsed = body.classList.toggle('collapsed');
    this.textContent = collapsed ? '▼ Show more' : '▲ Show less';
  });
});
</script>
"""
    body = env.from_string(_TMPL).render(s=s, scraped=scraped, all_links=all_links, artifacts=artifacts)
    query_short = (s.get("query","") or "")[:40]
    full = _BASE.replace("{% block body %}{% endblock %}", body).replace("{{ css }}", _CSS)
    full = full.replace("{{ title }}", esc(query_short) + " — Dcrawler")
    for k in ("home","sessions","health","audit"):
        full = full.replace(f"'active' if active=='{k}'", "'active'" if k=="sessions" else "''")
    return full


# ── REPORT DOWNLOADS ─────────────────────────────────────────────────────────

@app.route("/session/<sid>/report/html")
def session_html_report(sid: str):
    s = get_session(sid)
    if not s:
        abort(404)
    from reporter import generate_html_report, save_html_report
    results   = get_results_with_content(sid)
    scraped_r = [r for r in results if r["scraped"]]
    artifacts = get_artifacts(sid)
    html = generate_html_report(s, s.get("summary",""), artifacts, scraped_r)
    path = save_html_report(sid, html)
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route("/session/<sid>/report/txt")
def session_txt_report(sid: str):
    s = get_session(sid)
    if not s:
        abort(404)
    from reporter import generate_text_report, save_text_report
    results   = get_results_with_content(sid)
    scraped_r = [r for r in results if r["scraped"]]
    artifacts = get_artifacts(sid)
    txt = generate_text_report(s, s.get("summary",""), artifacts, scraped_r)
    path = save_text_report(sid, txt)
    return send_file(path, as_attachment=True, download_name=path.name)


# ── HEALTH ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health_view():
    h = get_system_health()
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    _TMPL = """
<div class="page page-sm">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;flex-wrap:wrap;gap:.8rem">
    <h1>&#10084; System Health</h1>
    <span class="badge {{ 'badge-green' if h.overall == 'healthy' else 'badge-yellow' }}">
      {{ h.overall.upper() }}
    </span>
  </div>
  <p style="color:var(--muted);font-size:.82rem;margin-bottom:1.5rem">Last checked: {{ h.timestamp }}</p>

  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
    {% for name, info in h.components.items() %}
    <div class="health-row">
      <div class="health-dot {{ info.status }}"></div>
      <div class="health-name">{{ name.title() }}</div>
      <div class="health-detail">
        {% for k,v in info.items() %}{% if k not in ('status','note') %}{{ k }}: <strong>{{ v }}</strong>&nbsp;&nbsp;{% endif %}{% endfor %}
        {% if info.note %}<span style="color:var(--muted)">{{ info.note }}</span>{% endif %}
      </div>
    </div>
    {% endfor %}
  </div>

  <div style="margin-top:2rem;display:flex;gap:.6rem">
    <a href="/health" class="btn">&#8635; Refresh</a>
    <a href="/" class="btn">&#8592; Dashboard</a>
  </div>
</div>
"""
    body = env.from_string(_TMPL).render(h=h)
    full = _BASE.replace("{% block body %}{% endblock %}", body).replace("{{ css }}", _CSS)
    full = full.replace("{{ title }}", "Health — Dcrawler")
    for k in ("home","sessions","health","audit"):
        full = full.replace(f"'active' if active=='{k}'", "'active'" if k=="health" else "''")
    return full


# ── AUDIT LOG ────────────────────────────────────────────────────────────────

@app.route("/audit")
def audit_view():
    logs = get_audit_log(300)
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    _TMPL = """
<div class="page">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;flex-wrap:wrap;gap:.8rem">
    <h1>&#128220; Audit Log</h1>
    <span class="badge">{{ logs|length }} entries</span>
  </div>
  {% if logs %}
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;max-height:80vh;overflow-y:auto">
    {% for e in logs %}
    <div class="audit-row">
      <div class="audit-time">{{ e.created_at[:19].replace('T',' ') }}</div>
      <span class="badge {{ 'badge-green' if 'COMPLETE' in e.event_type else 'badge-red' if 'ERROR' in e.event_type else '' }}">
        {{ e.event_type }}
      </span>
      {% if e.session_id %}
      <a href="/session/{{ e.session_id }}" style="font-size:.75rem;color:var(--muted)" class="mono">{{ e.session_id[:14] }}…</a>
      {% endif %}
      <div class="audit-detail mono">{{ e.details }}</div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="empty"><div class="empty-icon">&#128220;</div><p>No audit entries yet.</p></div>
  {% endif %}
</div>
"""
    body = env.from_string(_TMPL).render(logs=logs)
    full = _BASE.replace("{% block body %}{% endblock %}", body).replace("{{ css }}", _CSS)
    full = full.replace("{{ title }}", "Audit Log — Dcrawler")
    for k in ("home","sessions","health","audit"):
        full = full.replace(f"'active' if active=='{k}'", "'active'" if k=="audit" else "''")
    return full


# ── JSON APIs ────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():   return jsonify(get_stats())

@app.route("/api/health")
def api_health():  return jsonify(get_system_health())

@app.route("/api/sessions")
def api_sessions():return jsonify(list_sessions(200))

@app.route("/api/session/<sid>")
def api_session(sid: str):
    s = get_session(sid)
    if not s: abort(404)
    s["results"] = get_results_with_content(sid)
    s["artifacts"] = get_artifacts(sid)
    return jsonify(s)


@app.route("/api/export/<sid>")
def api_export(sid: str):
    fmt = __import__("flask").request.args.get("format", "json")
    if sid == "all":
        if fmt == "csv":
            data = export_all_sessions_csv()
            return Response(data, mimetype="text/csv",
                            headers={"Content-Disposition": "attachment; filename=dcrawler_sessions.csv"})
        sessions = list_sessions(1000)
        return Response(__import__("json").dumps(sessions, indent=2, default=str),
                        mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=dcrawler_sessions.json"})
    if fmt == "csv":
        data = export_session_csv(sid)
        return Response(data, mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=export_{sid}.csv"})
    data = export_session_json(sid)
    return Response(data, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=export_{sid}.json"})


@app.errorhandler(404)
def not_found(e):
    return f"""<html><body style="background:#0d1117;color:#c9d1d9;font-family:system-ui;padding:3rem;text-align:center">
    <h2 style="color:#f85149">404 — Not Found</h2><p><a href="/" style="color:#58a6ff">&#8592; Dashboard</a></p></body></html>""", 404


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Dcrawler Web Dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()
    print(f"[*] Dcrawler Dashboard  →  http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
