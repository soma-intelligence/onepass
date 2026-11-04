# Local test login (identifier, password, code) for SafariAutofillUITests. Test data only.
# Any password signs in, except one starting with "Refuse": the form comes back with an error.
# Run: python3 -I safari-test-site.py site.pem site.key  (serves https://localhost:8443,
# or the port in ONEPASS_TEST_PORT)
# Certificate: a throwaway root CA trusted in the simulator only
#   (`xcrun simctl keychain <udid> add-root-cert ca.pem`) and a localhost leaf it signs with
#   subjectAltName=DNS:localhost,IP:127.0.0.1 and extendedKeyUsage=serverAuth. Keep keys out of git.
import html, os, ssl, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STYLE = """<meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font:17px -apple-system,system-ui;margin:0;background:#f5f5f7;color:#1d1d1f}
main{max-width:420px;margin:48px auto;padding:0 20px}h1{font-size:28px;margin:0 0 6px}
p{color:#6e6e73;margin:0 0 24px}label{display:block;font-size:14px;font-weight:600;margin:0 0 6px}
input{box-sizing:border-box;width:100%;height:48px;border:1px solid #d2d2d7;border-radius:12px;padding:0 14px;font-size:17px;background:#fff;margin-bottom:16px}
button{width:100%;height:50px;border:0;border-radius:12px;background:#0071e3;color:#fff;font-size:17px;font-weight:600}
.who{font-weight:600;color:#1d1d1f}.err{color:#d70015;font-weight:600}</style>"""

def page(title, sub, body):
    return f"<!doctype html><html lang=fr><head><title>{title}</title>{STYLE}</head><body><main><h1>{title}</h1><p>{sub}</p>{body}</main></body></html>"

class H(BaseHTTPRequestHandler):
    def send(self, text, code=200, loc=None):
        b = text.encode()
        self.send_response(code)
        if loc: self.send_header("Location", loc)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        who = html.escape(q.get("u", ""))
        if u.path == "/":
            self.send(page("Atlas Cloud", "Connecte-toi à ton espace.",
                "<form method=post action=/identifier><label for=u>E-mail</label>"
                "<input id=u name=username type=email autocomplete=username placeholder='nom@exemple.com'>"
                "<button type=submit>Continuer</button></form>"))
        elif u.path == "/password":
            wrong = "<p class=err role=alert>Mot de passe incorrect.</p>" if q.get("e") == "1" else ""
            self.send(page("Mot de passe", f"Compte <span class=who>{who}</span>", wrong +
                f"<form method=post action=/password><input type=hidden name=username autocomplete=username value='{who}'>"
                "<label for=p>Mot de passe</label><input id=p name=password type=password autocomplete=current-password>"
                "<button type=submit>Se connecter</button></form>"))
        elif u.path == "/otp":
            self.send(page("Vérification", "Saisis le code à 6 chiffres de ton app d'authentification.",
                "<form method=post action=/otp><label for=c>Code</label>"
                "<input id=c name=code inputmode=numeric autocomplete=one-time-code maxlength=6>"
                "<button type=submit>Vérifier</button></form>"))
        elif u.path == "/done":
            self.send(page("Bienvenue", "Tu es connecté à Atlas Cloud.", ""))
        else:
            self.send("not found", 404)

    def do_POST(self):
        f = self.form()
        if self.path == "/identifier":
            self.send("", 303, "/password?u=" + urllib.parse.quote(f.get("username", "")))
        elif self.path == "/password":
            # A refused sign-in, as on a real site: back to the same form with an error.
            if f.get("password", "").startswith("Refuse"):
                self.send("", 303, "/password?e=1&u=" + urllib.parse.quote(f.get("username", "")))
            else:
                self.send("", 303, "/otp")
        elif self.path == "/otp":
            self.send("", 303, "/done")
        else:
            self.send("not found", 404)

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.command, self.path))

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
# ONEPASS_TEST_PORT: another port when several simulators run the page at once.
srv = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("ONEPASS_TEST_PORT", "8443"))), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
