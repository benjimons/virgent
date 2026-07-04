"""HTTP API and console over the engine (stdlib only).

Exposes the read model — posture, findings, incidents, pending decisions,
control status — and the one consequential write a human needs remotely:
resolving a decision. Bearer-token authenticated; binds localhost by default.
Every request routes through :meth:`Api.handle`, which is a pure function of
(method, path, headers, body), so it is unit-testable without opening a socket.

This is deliberately minimal — a read-only console plus the decision queue, not
a full product UI — but it's the surface that lets the agent be a system a team
operates, not just a CLI.
"""
from __future__ import annotations

import json
import os

_CONSOLE_HTML = """<!doctype html><meta charset=utf-8>
<title>Virgent Console</title>
<style>body{font:14px system-ui;margin:2rem;max-width:60rem}h1{font-size:1.2rem}
input,button{font:inherit;padding:.3rem}pre{background:#f4f4f4;padding:1rem;overflow:auto}
.sev-critical{color:#b00}.sev-high{color:#d60}</style>
<h1>Virgent Console</h1>
<p>API token: <input id=t size=40> <button onclick=load()>Load</button></p>
<div id=out><em>Enter the API token and press Load.</em></div>
<script>
async function get(p){const r=await fetch('/api'+p,{headers:{Authorization:'Bearer '+document.getElementById('t').value}});return r.json()}
async function load(){
 const [p,f,i,d]=await Promise.all([get('/posture'),get('/findings?limit=20'),get('/incidents'),get('/decisions')]);
 document.getElementById('out').innerHTML=
  '<h2>Posture</h2><pre>'+JSON.stringify(p,null,2)+'</pre>'+
  '<h2>Top findings</h2><pre>'+JSON.stringify(f,null,2)+'</pre>'+
  '<h2>Incidents</h2><pre>'+JSON.stringify(i,null,2)+'</pre>'+
  '<h2>Pending decisions</h2><pre>'+JSON.stringify(d,null,2)+'</pre>';
}
</script>"""


class Api:
    def __init__(self, agent, token: str | None = None):
        self.agent = agent
        self.token = token or os.environ.get("VIRGENT_API_TOKEN") or \
            ((agent.policy.policy.get("api") or {}).get("token"))

    # -- auth ---------------------------------------------------------------

    def _authorized(self, headers: dict) -> bool:
        if not self.token:      # no token configured -> API disabled (safe default)
            return False
        auth = headers.get("authorization") or headers.get("Authorization") or ""
        return auth == f"Bearer {self.token}"

    # -- routing (pure; unit-testable) --------------------------------------

    def handle(self, method: str, path: str, headers: dict, body: str | None = None):
        """Return (status:int, content_type:str, body:str)."""
        raw_path, _, query = path.partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)

        if method == "GET" and raw_path in ("/", "/console"):
            return 200, "text/html", _CONSOLE_HTML
        if method == "GET" and raw_path == "/healthz":
            return 200, "application/json", json.dumps(
                {"ok": True, "audit_ok": self.agent.verify_audit().ok})

        if not raw_path.startswith("/api/"):
            return 404, "application/json", json.dumps({"error": "not found"})
        if not self._authorized(headers):
            return 401, "application/json", json.dumps({"error": "unauthorized"})

        endpoint = raw_path[len("/api"):]
        try:
            return self._route(method, endpoint, params, body)
        except Exception as e:  # noqa: BLE001 - never leak a stack trace over HTTP
            return 500, "application/json", json.dumps({"error": type(e).__name__})

    def _route(self, method: str, endpoint: str, params: dict, body: str | None):
        j = lambda code, obj: (code, "application/json", json.dumps(obj, default=str))

        if method == "GET" and endpoint == "/posture":
            return j(200, self.agent.program_posture())
        if method == "GET" and endpoint == "/findings":
            findings = self.agent.load_findings()
            limit = int(params.get("limit", 100))
            sev = params.get("severity")
            out = [f.to_dict() for f in sorted(findings, key=lambda f: f.severity.rank)]
            if sev:
                out = [f for f in out if f["severity"] == sev]
            return j(200, out[:limit])
        if method == "GET" and endpoint == "/incidents":
            return j(200, [i.to_dict() for i in self.agent.soc.casebook.all_incidents()])
        if method == "GET" and endpoint == "/decisions":
            return j(200, self.agent.pending_decisions())
        if method == "GET" and endpoint == "/controls":
            return j(200, self.agent.ccm_assess()["summary"])
        if method == "POST" and endpoint.startswith("/decisions/") and endpoint.endswith("/resolve"):
            did = endpoint[len("/decisions/"):-len("/resolve")]
            data = json.loads(body or "{}")
            result = self.agent.resolve_decision(
                did, data.get("decision", "deny"),
                resolver=data.get("resolver", "api"), role=data.get("role", "responder"),
                note=data.get("note", ""))
            return j(200, result)
        return j(404, {"error": "unknown endpoint"})


def serve(agent, host: str = "127.0.0.1", port: int = 8787, token: str | None = None):  # pragma: no cover
    """Run the API server (blocking). Localhost by default."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    api = Api(agent, token=token)

    class Handler(BaseHTTPRequestHandler):
        def _do(self, method):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8") if length else None
            status, ctype, out = api.handle(method, self.path, dict(self.headers), body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(out.encode("utf-8"))

        def do_GET(self): self._do("GET")
        def do_POST(self): self._do("POST")
        def log_message(self, *a): pass

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"virgent API on http://{host}:{port}  (console at /)")
    server.serve_forever()
