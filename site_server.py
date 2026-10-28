#!/usr/bin/env python3
"""Site AntiDDoS : connexion par IP + espace admin. Lancer : py site_server.py [--port 8080]
Derrière HTTPS (Cloudflare/nginx) : SITE_HTTPS=1 SITE_TRUST_PROXY=1 py site_server.py"""
import collections, hashlib, hmac, ipaddress, json, os, re, secrets, sys, threading, time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = os.environ.get("SITE_DATA", "site_data.json")
HTTPS, PROXY = os.environ.get("SITE_HTTPS") == "1", os.environ.get("SITE_TRUST_PROXY") == "1"
WEEK, ADMIN_TTL = 7 * 86400, 1800
# Derrière un proxy : SITE_IP_HEADER=CF-Connecting-IP (Cloudflare) ou, à défaut, X-Forwarded-For avec
# SITE_PROXY_HOPS = nombre de proxys devant le site (1 = nginx/Caddy seul ; 2 = Cloudflare + nginx).
IP_HEADER = os.environ.get("SITE_IP_HEADER", "")
HOPS = max(1, int(os.environ.get("SITE_PROXY_HOPS", "1") or 1))
HOST = os.environ.get("SITE_HOST", "0.0.0.0")   # derrière un proxy sur la même machine : SITE_HOST=127.0.0.1
MAX_USERS, MAX_PER_IP = 5000, 3                  # comptes au total / par IP
RATE_MAX, RATE_WINDOW = 300, 60                  # requêtes par IP et par minute
L = threading.RLock()
db = {"users": {}, "sessions": {}, "key": secrets.token_urlsafe(32), "log": [],
      "admin": None, "approval": False, "gbans": [], "notice": "", "minlevel": 0}
dirty = False
rates = {}    # ip -> horodatages récents (limite de débit)
SEM = threading.BoundedSemaphore(300)   # connexions traitées en même temps
adm = {}      # sessions admin (mémoire) : token -> dernier usage
fails = {}    # ip -> (échecs, bloqué jusqu'à)

def load():
    if os.path.exists(DATA):
        with open(DATA, encoding="utf-8") as f:
            db.update(json.load(f))
def flush():
    global dirty
    with L:
        if not dirty: return
        dirty = False
        tmp = DATA + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f: json.dump(db, f, indent=1)
        os.replace(tmp, DATA)
def save():
    """Marque les données à écrire : le disque n'est écrit qu'une fois toutes les 2 s (pas à chaque requête)."""
    global dirty
    dirty = True
def saver():
    while True:
        time.sleep(2)
        try: flush()
        except Exception as e: print("Sauvegarde impossible :", e, file=sys.stderr)
def ensure_admin():
    """Pas de mot de passe écrit dans le code : SITE_ADMIN_PASSWORD, sinon un mot de passe aléatoire affiché une fois."""
    if db.get("admin"): return
    pw = os.environ.get("SITE_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    salt = secrets.token_hex(16); db["admin"] = {"salt": salt, "hash": H(pw, salt)}
    if not os.environ.get("SITE_ADMIN_PASSWORD"):
        print(f"\n  Mot de passe admin créé (affiché une seule fois, change-le dans l'admin) : {pw}\n")
def log(msg):
    db["log"].insert(0, {"t": time.strftime("%d/%m %H:%M:%S"), "msg": msg}); del db["log"][300:]
def H(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex()
def sh(tok): return hashlib.sha256(tok.encode()).hexdigest()
def active(u, now): return u["status"] == "approved" and not u["banned"] and now - u["seen"] < WEEK
def purge(now):
    for k in [k for k, s in db["sessions"].items() if now - s["last"] > WEEK]: del db["sessions"][k]

def net_or_ip(x, own=None):
    try: n = ipaddress.ip_network(str(x).strip(), strict=False)
    except ValueError: raise ValueError("IP ou réseau invalide")
    if n.prefixlen < (16 if n.version == 4 else 48): raise ValueError("réseau trop large (/16 minimum)")
    if own and ipaddress.ip_address(own) in n: raise ValueError("ça contient ta propre IP")
    return str(n.network_address) if n.num_addresses == 1 else str(n)
def ulog(u, m):
    u.setdefault("ulog", []).insert(0, {"t": time.strftime("%d/%m %H:%M"), "msg": m}); del u["ulog"][30:]
def view(u, now):
    r = u.get("rep") or {}
    return {"name": u["name"], "ip": u["ip"], "status": u["status"], "banned": u["banned"], "seen": u["seen"], "level": u.get("level", 0),
            "nb": len(u.get("bans", [])), "online": bool(r) and now - r["t"] < 120, "attack": bool(r.get("attack")), "total": r.get("total", 0)}

PAGE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "page.html"), encoding="utf-8").read()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    timeout = 15   # une connexion qui ne dit rien est coupée (sinon quelques sockets suffisent à bloquer le site)
    def handle(self):
        if not SEM.acquire(blocking=False): return   # surcharge : on refuse plutôt que de s'effondrer
        try: super().handle()
        finally: SEM.release()
    def ip(self):
        if PROXY:
            try:
                if IP_HEADER:
                    x = self.headers.get(IP_HEADER, "").strip()
                else:
                    parts = [p.strip() for p in self.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
                    x = parts[-HOPS] if len(parts) >= HOPS else ""
                if x: return str(ipaddress.ip_address(x))
            except ValueError: pass
        return self.client_address[0]
    def allow(self):
        """Limite de débit par IP (anti-spam du site lui-même)."""
        now, ip = time.time(), self.client_address[0] if not PROXY else self.ip()
        with L:
            if len(rates) > 20000: rates.clear()
            q = rates.setdefault(ip, collections.deque())
            while q and now - q[0] > RATE_WINDOW: q.popleft()
            if len(q) >= RATE_MAX: return False
            q.append(now); return True
    def out(self, code, obj, ctype="application/json", cookie=None):
        data = (obj if isinstance(obj, str) else json.dumps(obj)).encode()
        self.send_response(code)
        for k, v in (("Content-Type", ctype + "; charset=utf-8"), ("Content-Length", len(data)), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
                     ("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")):
            self.send_header(k, v)
        if HTTPS: self.send_header("Strict-Transport-Security", "max-age=31536000")
        for c in cookie or []: self.send_header("Set-Cookie", c)
        self.end_headers(); self.wfile.write(data)
    def ck(self, name):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c[name].value if name in c else ""
    def cookie(self, name, val, age=None):
        s = f"{name}={val}; Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if HTTPS else "")
        return s + (f"; Max-Age={age}" if age is not None else "")
    def is_admin(self):
        t, now = self.ck("adm"), time.time()
        if t in adm and now - adm[t] < ADMIN_TTL: adm[t] = now; return True
        adm.pop(t, None); return False
    def pub(self, u):
        return {"ip": u["ip"], "status": u["status"], "level": u.get("level", 0), "bans": u.get("bans", []),
                "rep": u.get("rep"), "haskey": bool(u.get("key")), "trust": u.get("trust", []),
                "ulog": u.get("ulog", []), "notice": db["notice"], "minlevel": db["minlevel"]}
    def by_key(self):
        h = sh(self.headers.get("X-Site-Key", ""))
        for u in db["users"].values():
            if u.get("key") and hmac.compare_digest(u["key"], h) and u["status"] == "approved" and not u["banned"]: return u
    def me(self, now):
        s = db["sessions"].get(sh(self.ck("sid") or "-"))
        if s and now - s["last"] < (WEEK if s.get("rem") else 21600) and s["uid"] in db["users"]: return s, db["users"][s["uid"]]
        return None, None

    def do_GET(self):
        if not self.allow(): return self.out(429, {"error": "trop de requêtes, patiente un peu"})
        p, now = self.path.split("?")[0], time.time()
        if p == "/": return self.out(200, PAGE, "text/html")
        with L:
            if p == "/api/allowlist":
                if not hmac.compare_digest(self.headers.get("X-Site-Key", ""), db["key"]): return self.out(401, {"error": "clé invalide"})
                return self.out(200, {"ips": sorted({u["ip"] for u in db["users"].values() if active(u, now)})})
            if p == "/api/sync":
                u = self.by_key()
                if not u: return self.out(401, {"error": "clé invalide"})
                return self.out(200, {"ips": sorted({x["ip"] for x in db["users"].values() if active(x, now)}),
                                      "bans": [x["ip"] for x in u.get("bans", [])] + db["gbans"], "trust": u.get("trust", []), "me": u["ip"],
                                      "level": max(u.get("level", 0), db["minlevel"])})
            if self.headers.get("X-Req") != "1": return self.out(400, {"error": "requête refusée"})
            if p == "/api/me":
                s, u = self.me(now)
                if u and not u["banned"]:   # connexion automatique : l'IP du moment est appliquée
                    cur = self.ip()
                    if cur != u["ip"] and u["status"] == "approved": log(f"{u['name']} : IP {u['ip']} → {cur} (auto)"); u["ip"] = cur
                    u["seen"] = s["last"] = now; save()
                    return self.out(200, {"user": self.pub(u)})
                return self.out(200, {"ip": self.ip()})
            if p == "/api/admin/data":
                if not self.is_admin(): return self.out(401, {"error": "admin requis"})
                v = {k: view(u, now) for k, u in db["users"].items()}
                return self.out(200, {"users": v, "log": db["log"], "approval": db["approval"], "gbans": db["gbans"], "notice": db["notice"],
                                      "minlevel": db["minlevel"], "active": sum(active(u, now) for u in db["users"].values()),
                                      "online": sum(x["online"] for x in v.values()), "attacks": sum(x["online"] and x["attack"] for x in v.values()),
                                      "bans": sum(x["total"] for x in v.values())})
        self.out(404, {"error": "introuvable"})

    def do_POST(self):
        if not self.allow(): return self.out(429, {"error": "trop de requêtes, patiente un peu"})
        if self.headers.get("X-Req") != "1": return self.out(400, {"error": "requête refusée"})
        try:
            lim = 32768 if self.path.split("?")[0] == "/api/report" else 4096   # le rapport de l'appli peut contenir 100 IP bannies
            b = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), lim)) or b"{}")
            assert isinstance(b, dict)
        except Exception: return self.out(400, {"error": "format invalide"})
        p, now, me = self.path.split("?")[0], time.time(), self.ip()
        try:
            with L:
                purge(now)
                if len(fails) > 5000: fails.clear()
                r = self.route(p, b, now, me)
                save(); return r
        except (ValueError, TypeError, KeyError) as e: self.out(400, {"error": str(e)})

    def route(self, p, b, now, me):
        if p == "/api/login":
            f = fails.get(me, (0, 0))
            if now < f[1]: raise ValueError("trop d'essais, patiente un peu")
            name, ip = str(b.get("pseudo", "")).strip(), str(b.get("ip", "")).strip()
            try: ip = str(ipaddress.ip_address(ip))
            except ValueError: raise ValueError("IP invalide")
            if not re.fullmatch(r"[\w .-]{2,24}", name): raise ValueError("pseudo : 2 à 24 caractères (lettres, chiffres, . - _)")
            if ip != str(ipaddress.ip_address(me)):
                fails[me] = (f[0] + 1, now + (60 if f[0] >= 4 else 0)); raise ValueError(f"cette IP n'est pas la tienne (la tienne : {me})")
            uid, u = name.lower(), db["users"].get(name.lower())
            if u and u["banned"]: raise ValueError("accès refusé")
            if not u:
                if len(db["users"]) >= MAX_USERS: raise ValueError("inscriptions fermées pour le moment")
                if sum(x["ip"] == ip for x in db["users"].values()) >= MAX_PER_IP: raise ValueError("trop de comptes pour cette IP")
                u = db["users"][uid] = {"name": name, "ip": ip, "status": "pending" if db["approval"] else "approved", "banned": False, "seen": now, "created": now}
                log(f"Nouvel utilisateur {name} ({ip})")
            elif u["ip"] != ip:   # pseudo déjà pris par quelqu'un d'autre : on ne touche PAS au compte
                log(f"{name} : connexion refusée depuis {ip} (pseudo déjà lié à une autre IP)")
                raise ValueError("ce pseudo est déjà pris, choisis-en un autre (ou demande à l'admin de corriger ton IP)")
            u["seen"] = now
            rem = bool(b.get("remember")); tok = secrets.token_urlsafe(32)
            db["sessions"][sh(tok)] = {"uid": uid, "last": now, "rem": rem}
            ck = [self.cookie("sid", tok, WEEK if rem else None)]
            return self.out(200, {"ok": True}, cookie=ck)
        if p == "/api/report":
            u = self.by_key()
            if not u: return self.out(401, {"error": "clé invalide"})
            bl = [{"ip": str(x.get("ip"))[:45], "left": int(x.get("left", 0))} for x in list(b.get("banned", []))[:100] if isinstance(x, dict)]
            u["rep"] = {"t": now, "attack": bool(b.get("attack")), "total": int(b.get("total", 0)), "banned": bl,
                        "conns": int(b.get("conns", 0)), "syn": int(b.get("syn", 0)),
                        "top": [{"ip": str(x.get("ip"))[:45], "n": int(x.get("n", 0))} for x in list(b.get("top", []))[:8] if isinstance(x, dict)],
                        "kinds": {str(k)[:30]: int(v) for k, v in list(dict(b.get("kinds", {})).items())[:10]},
                        "hist": [int(x) for x in list(b.get("hist", []))[-60:]]}
            return self.out(200, {"ok": True})
        if p == "/api/panel":
            _, u = self.me(now)
            if not u or u["banned"] or u["status"] != "approved": raise ValueError("accès refusé")
            a = b.get("action")
            if a == "level":
                if b.get("level") not in (0, 1, 2): raise ValueError("niveau invalide")
                u["level"] = b["level"]
            elif a == "ban":
                ip = net_or_ip(b.get("ip", ""), u["ip"])
                bans = u.setdefault("bans", [])
                if len(bans) >= 200: raise ValueError("200 IP maximum")
                if not any(x["ip"] == ip for x in bans): bans.append({"ip": ip, "note": str(b.get("note", ""))[:40], "t": now})
            elif a == "unban": u["bans"] = [x for x in u.get("bans", []) if x["ip"] != b.get("ip")]
            elif a == "key":
                k = secrets.token_urlsafe(24); u["key"] = sh(k); log(f"{u['name']} : nouvelle clé appli")
                return self.out(200, {"key": k})
            elif a == "trust":
                try: ip = str(ipaddress.ip_address(str(b.get("ip", "")).strip()))
                except ValueError: raise ValueError("IP invalide")
                t = u.setdefault("trust", [])
                if len(t) >= 50: raise ValueError("50 IP maximum")
                if ip not in t: t.append(ip)
            elif a == "untrust": u["trust"] = [x for x in u.get("trust", []) if x != b.get("ip")]
            else: raise ValueError("action inconnue")
            ulog(u, f"{a} {str(b.get('ip', '') or b.get('level', ''))[:45]}")
            return self.out(200, {"ok": True})
        if p == "/api/logout":
            db["sessions"].pop(sh(self.ck("sid") or "-"), None)
            return self.out(200, {"ok": True}, cookie=[self.cookie("sid", "", 0)])
        if p == "/api/admin/login":
            f = fails.get(me, (0, 0))
            if now < f[1]: raise ValueError(f"trop d'essais, réessaie dans {int(f[1] - now) + 1} s")
            if not hmac.compare_digest(H(str(b.get("password", "")), db["admin"]["salt"]), db["admin"]["hash"]):
                n = f[0] + 1; fails[me] = (n, now + min(30 * 2 ** (n // 5), 3600) if n % 5 == 0 else 0)
                log(f"Échec connexion admin depuis {me}"); raise ValueError("mot de passe incorrect")
            fails.pop(me, None); t = secrets.token_urlsafe(32); adm[t] = now; log(f"Connexion admin depuis {me}")
            return self.out(200, {"ok": True}, cookie=[self.cookie("adm", t)])
        if not p.startswith("/api/admin/") or not self.is_admin(): return self.out(401, {"error": "admin requis"})
        if p == "/api/admin/logout": adm.pop(self.ck("adm"), None); return self.out(200, {"ok": True})
        if p == "/api/admin/password":
            if not hmac.compare_digest(H(str(b.get("old", "")), db["admin"]["salt"]), db["admin"]["hash"]): raise ValueError("ancien mot de passe incorrect")
            new = str(b.get("new", ""))
            if len(new) < 10: raise ValueError("10 caractères minimum")
            s = secrets.token_hex(16); db["admin"] = {"salt": s, "hash": H(new, s)}; adm.clear(); log("Mot de passe admin changé")
            return self.out(200, {"ok": True})
        if p == "/api/admin/act":
            a = b.get("action")
            if a == "approval": db["approval"] = bool(b.get("ip")); return self.out(200, {"ok": True})
            if a == "approve_all":
                for x in db["users"].values():
                    if x["status"] != "approved" and not x["banned"]: x["status"] = "approved"
                log("Admin : tout valider"); return self.out(200, {"ok": True})
            if a == "purge":
                dead = [k for k, x in db["users"].items() if now - x["seen"] > 30 * 86400]
                for k in dead: del db["users"][k]
                log(f"Admin : {len(dead)} comptes inactifs supprimés"); return self.out(200, {"ok": True})
            if a == "gban":
                t = net_or_ip(b.get("ip", ""))
                if t not in db["gbans"] and len(db["gbans"]) < 1000: db["gbans"].append(t)
                log(f"Admin : ban global {t}"); return self.out(200, {"ok": True})
            if a == "gunban": db["gbans"] = [x for x in db["gbans"] if x != b.get("ip")]; return self.out(200, {"ok": True})
            if a == "notice": db["notice"] = str(b.get("ip", ""))[:200]; log("Admin : message général modifié"); return self.out(200, {"ok": True})
            if a == "minlevel":
                if b.get("ip") not in (0, 1, 2): raise ValueError("niveau invalide")
                db["minlevel"] = b["ip"]; log(f"Admin : niveau minimum {b['ip']}"); return self.out(200, {"ok": True})
            u = db["users"].get(str(b.get("id")))
            if not u: raise ValueError("utilisateur introuvable")
            if a == "approve": u["status"] = "approved"
            elif a in ("ban", "unban"): u["banned"] = a == "ban"
            elif a == "delete": del db["users"][str(b["id"])]
            elif a == "setip":
                try: u["ip"] = str(ipaddress.ip_address(str(b.get("ip", ""))))
                except ValueError: raise ValueError("IP invalide")
            elif a != "revoke": raise ValueError("action inconnue")
            if a in ("revoke", "delete", "ban"):
                for k in [k for k, s in db["sessions"].items() if s["uid"] == str(b["id"])]: del db["sessions"][k]
            log(f"Admin : {a} → {str(b['id'])}")
            return self.out(200, {"ok": True})
        self.out(404, {"error": "introuvable"})

if __name__ == "__main__":
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8080
    load(); ensure_admin(); dirty = True; flush()
    threading.Thread(target=saver, daemon=True).start()
    import atexit; atexit.register(flush)
    class Srv(ThreadingHTTPServer):
        request_queue_size = 256
        daemon_threads = True
    print(f"Site AntiDDoS sur http://{HOST}:{port}  (données : {DATA})")
    try: Srv((HOST, port), Handler).serve_forever()
    except KeyboardInterrupt: flush()
