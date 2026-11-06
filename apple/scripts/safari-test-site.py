# Local test sites for SafariAutofillUITests and the user-test phase. Test data only.
#
# Several sites on one HTTPS server: the first label of the host names the site
# (atlas.localhost is "Atlas", borealis.localhost "Borealis"...; *.localhost resolves to
# loopback in the simulator and on the Mac). SITES lists the names the certificate covers.
#
# Pages (on every site):
#   /pages     the list below, with links
#   /          sign-in in three steps: identifier, then /password, then /otp (TOTP checked
#              against TOTP_SECRET, the demo secret of the UI tests' login), then /done
#   /login     e-mail and password on one page, then /welcome
#   /signup    name, e-mail, username (pattern [a-z0-9_.]{3,20}, maxlength 20, so no '@'),
#              password with passwordrules, confirmation; refused (form again, with the
#              reason) when a rule fails
#   /address   shipping address (name, address, postal code, city, country, phone, e-mail)
#   /card      card form, all fields on this page (same origin): name, number, expiry, code;
#              refused when the number fails the Luhn check
# Any password signs in, except one starting with "Refuse": the form comes back with an error.
#
# Run:  python3 -I safari-test-site.py site.pem site.key  (serves https://<site>.localhost:8443,
#       or the port in ONEPASS_TEST_PORT)
# Certificate: python3 -I safari-test-site.py --cert DIR writes DIR/ca.pem (a throwaway root
#   CA, trust it in the simulator only: `xcrun simctl keychain <udid> add-root-cert DIR/ca.pem`),
#   DIR/site.pem and DIR/site.key (leaf for localhost, 127.0.0.1 and every <site>.localhost,
#   serverAuth). Needs openssl. Keep keys out of git.
import base64, hashlib, hmac, html, os, re, ssl, struct, subprocess, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SITES = ["atlas", "borealis", "cobalt", "dune", "eden"]
# Demo secret (RFC 6238 test style, public): the UI tests put it in the Atlas login.
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
USERNAME_PATTERN = "[a-z0-9_.]{3,20}"
PASSWORD_RULES = "minlength: 12; required: lower; required: upper; required: digit; required: [-_!.];"

STYLE = """<meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font:17px -apple-system,system-ui;margin:0;background:#f5f5f7;color:#1d1d1f}
main{max-width:420px;margin:48px auto;padding:0 20px}h1{font-size:28px;margin:0 0 6px}
p{color:#6e6e73;margin:0 0 24px}label{display:block;font-size:14px;font-weight:600;margin:0 0 6px}
input,select{box-sizing:border-box;width:100%;height:48px;border:1px solid #d2d2d7;border-radius:12px;padding:0 14px;font-size:17px;background:#fff;margin-bottom:16px}
button{width:100%;height:50px;border:0;border-radius:12px;background:#0071e3;color:#fff;font-size:17px;font-weight:600}
.row{display:flex;gap:12px}.row>div{flex:1}small{display:block;color:#6e6e73;margin:-10px 0 16px}
li{margin:0 0 10px}a{color:#0071e3}
.who{font-weight:600;color:#1d1d1f}.err{color:#d70015;font-weight:600}</style>"""


def page(title, sub, body):
    return f"<!doctype html><html lang=fr><head><title>{title}</title>{STYLE}</head><body><main><h1>{title}</h1><p>{sub}</p>{body}</main></body></html>"


def err(text):
    return f"<p class=err role=alert>{html.escape(text)}</p>" if text else ""


def totp(secret, at, step=30, digits=6):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(at // step)), hashlib.sha1).digest()
    o = mac[-1] & 15
    code = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return str(code).zfill(digits)


def totp_ok(code):
    now = time.time()
    return any(hmac.compare_digest(totp(TOTP_SECRET, now + d * 30), code.strip()) for d in (-1, 0, 1))


def luhn_ok(number):
    digits = re.sub(r"[\s-]", "", number)
    if not re.fullmatch(r"\d{12,19}", digits):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def password_problem(pw):
    if len(pw) < 12:
        return "Le mot de passe doit faire au moins 12 caractères."
    for test, what in ((r"[a-z]", "une minuscule"), (r"[A-Z]", "une majuscule"), (r"\d", "un chiffre"), (r"[-_!.]", "un de - _ ! .")):
        if not re.search(test, pw):
            return f"Le mot de passe doit contenir {what}."
    return ""


SIGNUP_FORM = (
    "<form method=post action=/signup><label for=n>Nom complet</label>"
    "<input id=n name=name autocomplete=name>"
    "<label for=e>E-mail</label><input id=e name=email type=email autocomplete=email>"
    "<label for=un>Nom d'utilisateur</label>"
    f"<input id=un name=username autocomplete=username pattern='{USERNAME_PATTERN}' maxlength=20"
    " title='3 à 20 caractères : minuscules, chiffres, point ou tiret bas'>"
    "<small>3 à 20 caractères : minuscules, chiffres, point ou tiret bas.</small>"
    "<label for=p>Mot de passe</label><input id=p name=password type=password autocomplete=new-password"
    f" minlength=12 passwordrules='{PASSWORD_RULES}'>"
    "<small>12 caractères au moins, avec minuscule, majuscule, chiffre et un de - _ ! .</small>"
    "<label for=c>Confirme le mot de passe</label><input id=c name=confirm type=password autocomplete=new-password>"
    "<button type=submit>Créer mon compte</button></form>"
)

ADDRESS_FORM = (
    "<form method=post action=/address><div class=row>"
    "<div><label for=gn>Prénom</label><input id=gn name=given autocomplete='shipping given-name'></div>"
    "<div><label for=fn>Nom</label><input id=fn name=family autocomplete='shipping family-name'></div></div>"
    "<label for=a1>Adresse</label><input id=a1 name=line1 autocomplete='shipping address-line1'>"
    "<label for=a2>Complément</label><input id=a2 name=line2 autocomplete='shipping address-line2'>"
    "<div class=row><div><label for=pc>Code postal</label><input id=pc name=postal autocomplete='shipping postal-code'></div>"
    "<div><label for=ci>Ville</label><input id=ci name=city autocomplete='shipping address-level2'></div></div>"
    "<label for=co>Pays</label><select id=co name=country autocomplete='shipping country'>"
    "<option value=''>Choisir</option><option value=FR>France</option><option value=BE>Belgique</option>"
    "<option value=CH>Suisse</option><option value=US>États-Unis</option></select>"
    "<label for=te>Téléphone</label><input id=te name=tel type=tel autocomplete='shipping tel'>"
    "<label for=em>E-mail</label><input id=em name=email type=email autocomplete=email>"
    "<button type=submit>Continuer vers le paiement</button></form>"
)

CARD_FORM = (
    "<form method=post action=/card><label for=cn>Titulaire</label>"
    "<input id=cn name=holder autocomplete=cc-name>"
    "<label for=num>Numéro de carte</label><input id=num name=number inputmode=numeric autocomplete=cc-number>"
    "<div class=row><div><label for=exp>Expiration (MM/AA)</label><input id=exp name=exp autocomplete=cc-exp placeholder='MM/AA'></div>"
    "<div><label for=csc>Code</label><input id=csc name=csc inputmode=numeric autocomplete=cc-csc maxlength=4></div></div>"
    "<button type=submit>Payer 12,00 €</button></form>"
)


class H(BaseHTTPRequestHandler):
    def send(self, text, code=200, loc=None):
        b = text.encode()
        self.send_response(code)
        if loc:
            self.send_header("Location", loc)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))

    def site(self):
        host = (self.headers.get("Host") or "localhost").split(":")[0]
        label = host.split(".")[0] if host.endswith(".localhost") else ""
        return html.escape(label.capitalize()) if label else "Atlas Cloud"

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        who = html.escape(q.get("u", ""))
        name = self.site()
        if u.path == "/pages":
            port = os.environ.get("ONEPASS_TEST_PORT", "8443")
            links = "".join(
                f"<li><a href='{p}'>{label}</a></li>" for p, label in (
                    ("/", "Connexion en trois étapes (identifiant, mot de passe, code)"),
                    ("/login", "Connexion sur une page"), ("/signup", "Création de compte"),
                    ("/address", "Adresse de livraison"), ("/card", "Paiement par carte")))
            others = "".join(f"<li><a href='https://{s}.localhost:{port}/pages'>{s.capitalize()}</a></li>" for s in SITES)
            self.send(page(name, "Pages de test (données fictives).", f"<ul>{links}</ul><p>Autres sites :</p><ul>{others}</ul>"))
        elif u.path == "/login":
            wrong = "Mot de passe incorrect." if q.get("e") == "1" else ""
            self.send(page(name, "Connecte-toi à ton compte.", err(wrong) +
                "<form method=post action=/login><label for=u>E-mail</label>"
                "<input id=u name=username type=email autocomplete=username placeholder='nom@exemple.com'>"
                "<label for=p>Mot de passe</label><input id=p name=password type=password autocomplete=current-password>"
                "<button type=submit>Se connecter</button></form>"))
        elif u.path == "/signup":
            self.send(page(name, "Crée ton compte.", SIGNUP_FORM))
        elif u.path == "/address":
            self.send(page(name, "Où livrer ta commande ?", ADDRESS_FORM))
        elif u.path == "/card":
            self.send(page(name, "Paiement de ta commande.", CARD_FORM))
        elif u.path == "/paid":
            self.send(page("Merci", f"Paiement accepté par {name}, carte se terminant par <span class=who>{who}</span>.", ""))
        elif u.path == "/shipped":
            self.send(page("Adresse enregistrée", f"Livraison à <span class=who>{who}</span>.", "<a href='/card'>Passer au paiement</a>"))
        elif u.path == "/welcome":
            self.send(page("Bienvenue", f"Compte <span class=who>{who}</span> connecté à {name}.", ""))
        elif u.path == "/":
            self.send(page(name, "Connecte-toi à ton espace.",
                "<form method=post action=/identifier><label for=u>E-mail</label>"
                "<input id=u name=username type=email autocomplete=username placeholder='nom@exemple.com'>"
                "<button type=submit>Continuer</button></form>"))
        elif u.path == "/password":
            wrong = "Mot de passe incorrect." if q.get("e") == "1" else ""
            self.send(page("Mot de passe", f"Compte <span class=who>{who}</span>", err(wrong) +
                f"<form method=post action=/password><input type=hidden name=username autocomplete=username value='{who}'>"
                "<label for=p>Mot de passe</label><input id=p name=password type=password autocomplete=current-password>"
                "<button type=submit>Se connecter</button></form>"))
        elif u.path == "/otp":
            wrong = "Code incorrect." if q.get("e") == "1" else ""
            self.send(page("Vérification", "Saisis le code à 6 chiffres de ton app d'authentification.", err(wrong) +
                "<form method=post action=/otp><label for=c>Code</label>"
                "<input id=c name=code inputmode=numeric autocomplete=one-time-code maxlength=6>"
                "<button type=submit>Vérifier</button></form>"))
        elif u.path == "/done":
            self.send(page("Bienvenue", f"Tu es connecté à {name}.", ""))
        else:
            self.send("not found", 404)

    def do_POST(self):
        f = self.form()
        name = self.site()
        if self.path == "/login":
            user = urllib.parse.quote(f.get("username", ""))
            if f.get("password", "").startswith("Refuse"):
                self.send("", 303, "/login?e=1")
            else:
                self.send("", 303, "/welcome?u=" + user)
        elif self.path == "/signup":
            pw = f.get("password", "")
            problem = ""
            if not re.fullmatch(USERNAME_PATTERN, f.get("username", "")):
                problem = "Nom d'utilisateur refusé : 3 à 20 minuscules, chiffres, point ou tiret bas."
            elif password_problem(pw):
                problem = password_problem(pw)
            elif pw != f.get("confirm"):
                problem = "Les deux mots de passe ne sont pas identiques."
            if problem:
                # Refused, as a real site: the form again, with the reason.
                self.send(page(name, "Crée ton compte.", err(problem) + SIGNUP_FORM))
            else:
                self.send("", 303, "/welcome?u=" + urllib.parse.quote(f.get("username", "")))
        elif self.path == "/address":
            if not f.get("line1") or not f.get("postal") or not f.get("city"):
                self.send(page(name, "Où livrer ta commande ?", err("Adresse incomplète.") + ADDRESS_FORM))
            else:
                self.send("", 303, "/shipped?u=" + urllib.parse.quote(f"{f.get('line1')}, {f.get('postal')} {f.get('city')}"))
        elif self.path == "/card":
            if not luhn_ok(f.get("number", "")):
                self.send(page(name, "Paiement de ta commande.", err("Numéro de carte refusé.") + CARD_FORM))
            else:
                self.send("", 303, "/paid?u=" + re.sub(r"\D", "", f.get("number", ""))[-4:])
        elif self.path == "/identifier":
            self.send("", 303, "/password?u=" + urllib.parse.quote(f.get("username", "")))
        elif self.path == "/password":
            # A refused sign-in, as on a real site: back to the same form with an error.
            if f.get("password", "").startswith("Refuse"):
                self.send("", 303, "/password?e=1&u=" + urllib.parse.quote(f.get("username", "")))
            else:
                self.send("", 303, "/otp")
        elif self.path == "/otp":
            self.send("", 303, "/done" if totp_ok(f.get("code", "")) else "/otp?e=1")
        else:
            self.send("not found", 404)

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.command, self.path))


def make_cert(out):
    os.makedirs(out, exist_ok=True)
    ca_key, ca, key, csr, leaf = (os.path.join(out, n) for n in ("ca.key", "ca.pem", "site.key", "site.csr", "site.pem"))
    ext = os.path.join(out, "site.ext")
    names = ["DNS:localhost", "IP:127.0.0.1"] + [f"DNS:{s}.localhost" for s in SITES]
    with open(ext, "w") as fh:
        fh.write("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                 f"extendedKeyUsage=serverAuth\nsubjectAltName={','.join(names)}\n")
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca, "-days", "30",
        "-subj", "/CN=OnePass test CA (throwaway)")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=localhost")
    run("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-out", leaf, "-days", "30", "-extfile", ext)
    os.remove(csr)
    print(f"{ca}\n{leaf}\n{key}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--cert":
        make_cert(sys.argv[2])
        sys.exit(0)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[1], sys.argv[2])
    # ONEPASS_TEST_PORT: another port when several simulators run the page at once.
    srv = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("ONEPASS_TEST_PORT", "8443"))), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
