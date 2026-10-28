#!/usr/bin/env python3
"""
AntiDDoS pour Windows - application de bureau (fenêtre + protection).

Surveille les connexions TCP entrantes sur les ports choisis, détecte les IP
abusives et les bloque via le Pare-feu Windows (règle « AntiDDoS-Block »).
Le tableau de bord s'ouvre dans une vraie fenêtre (pywebview).

Lancement :
    AntiDDoS.exe                 (double-clic, demande les droits administrateur)
    py antiddos_win.py           (depuis les sources)
    py antiddos_win.py --dry-run (simulation : détecte sans rien bloquer)
"""

import argparse
import atexit
import ctypes
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from collections import Counter, defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

try:
    import psutil
except ImportError:  # message clair plutôt qu'un crash silencieux
    psutil = None

APP_NAME = "AntiDDoS"
RULE_NAME = "AntiDDoS-Block"
RULE_CHUNK = 350            # IP par règle pare-feu (limite de longueur de la commande netsh)
MAX_RULES = 8               # règles AntiDDoS-Block, -1, -2... : 8 x 350 = 2800 IP bloquées au maximum
MAX_RULE_IPS = RULE_CHUNK * MAX_RULES
OFFENSE_FORGET = 7 * 86400  # une IP sans récidive pendant 7 jours repart de zéro
MEMBER_LENIENCY = 4         # une IP membre du site a des limites x4 (mais n'est plus intouchable)

DEFAULT_CONFIG = {
    # Ports locaux protégés (connexions TCP entrantes comptées sur ces ports)
    "ports": [80, 443, 30120],
    "max_established_per_ip": 100,    # connexions simultanées par IP
    "max_syn_recv_per_ip": 30,        # demi-connexions (SYN flood) par IP
    # Détection HTTP via un log d'accès (IP en début de ligne : nginx/apache).
    # Mettre un chemin, par exemple "C:/nginx/logs/access.log", ou null.
    "access_log": None,
    "http_window_seconds": 10,
    "max_requests_per_window": 200,
    "ban_seconds": 600,               # durée du 1er ban
    "max_ban_seconds": 86400,         # plafond pour les récidivistes
    # Mode attaque : limites par IP divisées par 2 et bans 2x plus longs
    "attack_total_connections": 1500,
    "attack_total_syn": 200,
    "attack_total_requests": 3000,
    "attack_calm_seconds": 60,
    "check_interval": 1.0,
    "whitelist": ["127.0.0.1", "::1"],   # ajoute ici TON IP publique
    "ignore_private_ranges": True,       # ne jamais bannir 10.x, 192.168.x...
    "dry_run": False,
    "max_new_conn_per_sec": 25,      # rafale de nouvelles connexions par IP
    "max_timewait_per_ip": 300,      # connexions ouvertes puis fermées vite (flood « court ») par IP
    "subnet_max_connections": 300,   # connexions cumulées d'un même réseau (/24, /64)
    "permanent_after": 5,            # infractions avant un ban de 30 jours
    "site_url": "",      # ex. https://mon-site.fr  (laisser vide pour désactiver)
    "site_key": "",      # clé affichée dans l'espace admin du site
    "admin_salt": "",    # mot de passe admin (haché), créé au premier lancement avec --admin
    "admin_hash": "",
}

EDITABLE = {  # réglages modifiables depuis le dashboard : (min, max)
    "max_established_per_ip": (5, 500),
    "max_syn_recv_per_ip": (3, 200),
    "max_requests_per_window": (10, 2000),
    "ban_seconds": (30, 3600),
}

ADMIN_INT_LIMITS = {   # réglages avancés de l'espace admin : (min, max)
    "attack_total_connections": (50, 100000),
    "attack_total_syn": (10, 100000),
    "attack_total_requests": (100, 1000000),
    "attack_calm_seconds": (10, 3600),
    "max_ban_seconds": (60, 604800),
    "max_new_conn_per_sec": (1, 1000),
    "max_timewait_per_ip": (30, 100000),
    "subnet_max_connections": (20, 100000),
    "permanent_after": (2, 50),
}

log = logging.getLogger("antiddos")
_mutex_handle = None  # garde le mutex d'instance unique en vie


# --------------------------------------------------------------------------- #
# Utilitaires système
# --------------------------------------------------------------------------- #
def fatal(msg):
    """Affiche une erreur (boîte de dialogue sous Windows) et quitte."""
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(None, msg, APP_NAME, 0x10)
        except Exception:
            pass
    else:
        print(msg, file=sys.stderr)
    sys.exit(1)


def base_dir():
    """Dossier des ressources (dashboard.html), y compris dans l'exe PyInstaller."""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def data_dir():
    root = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(root, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def is_admin():
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Relance le programme avec la demande UAC. Retourne True si accepté."""
    try:
        if getattr(sys, "frozen", False):
            params = subprocess.list2cmdline(sys.argv[1:])
        else:
            params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return rc > 32
    except Exception:
        return False


def single_instance():
    """Empêche d'ouvrir deux fois l'application (elles se disputeraient la règle)."""
    global _mutex_handle
    if os.name != "nt":
        return True
    _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\AntiDDoSApp")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def config_path():
    return os.path.join(data_dir(), "config.json")


def default_site_url():
    try:
        with open(os.path.join(base_dir(), "site_url.txt"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    cfg["site_url"] = default_site_url()
    path = config_path()
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except (OSError, ValueError) as e:
            log.warning("Config illisible (%s), valeurs par défaut utilisées", e)
        if not cfg.get("site_url"):
            cfg["site_url"] = default_site_url()
    else:
        save_config(cfg)
    return cfg


def save_config(cfg):
    try:
        with open(config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except OSError as e:
        log.warning("Impossible d'enregistrer la config : %s", e)


# --------------------------------------------------------------------------- #
# Lecture des connexions et du log d'accès
# --------------------------------------------------------------------------- #
def read_connections(ports):
    """Retourne (established, syn_recv, ensemble des connexions, time_wait) par IP source."""
    established, syn, cset, tw = Counter(), Counter(), set(), Counter()
    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError):
        return established, syn, cset, tw
    for c in conns:
        if not c.laddr or not c.raddr or c.laddr.port not in ports:
            continue
        try:
            ip = ipaddress.ip_address(c.raddr.ip)
        except ValueError:
            continue
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if c.status == psutil.CONN_ESTABLISHED:
            established[ip] += 1
            cset.add((ip, c.raddr.port, c.laddr.port))
        elif c.status == psutil.CONN_SYN_RECV:
            syn[ip] += 1
        elif c.status == psutil.CONN_TIME_WAIT:
            tw[ip] += 1
    return established, syn, cset, tw


class LogWatcher:
    """Suit un fichier de log (détecte la rotation par la taille) et compte les requêtes par IP."""

    LINE_RE = re.compile(r"^(\S+) ")

    def __init__(self, path, window):
        self.path = path
        self.window = window
        self.hits = defaultdict(deque)
        self.pos = None

    def poll(self):
        now = time.time()
        try:
            size = os.path.getsize(self.path)
        except OSError:
            size = None
        if size is not None:
            if self.pos is None:
                self.pos = size            # on démarre à la fin du fichier
            elif size < self.pos:
                self.pos = 0               # fichier tronqué / roté
            if size > self.pos:
                try:
                    with open(self.path, "rb") as f:
                        f.seek(self.pos)
                        raw = f.read(4_000_000)
                    self.pos += len(raw)
                    for line in raw.decode("utf-8", errors="ignore").splitlines():
                        m = self.LINE_RE.match(line)
                        if not m:
                            continue
                        try:
                            self.hits[ipaddress.ip_address(m.group(1))].append(now)
                        except ValueError:
                            continue
                except OSError:
                    pass
        counts, cutoff = Counter(), now - self.window
        for ip in list(self.hits):
            dq = self.hits[ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if dq:
                counts[ip] = len(dq)
            else:
                del self.hits[ip]
        return counts

    def forget(self, ip):
        self.hits.pop(ip, None)


# --------------------------------------------------------------------------- #
# Pare-feu Windows
# --------------------------------------------------------------------------- #
class WinFirewall:
    """Règles entrantes « AntiDDoS-Block », « AntiDDoS-Block-1 »... (350 IP chacune).
    Les règles existantes sont mises à jour sur place (`set rule`) : il n'y a jamais de trou
    pendant lequel un attaquant n'est plus bloqué."""

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.rules_used = None   # inconnu au démarrage : clear() supprime alors toutes les règles possibles

    @staticmethod
    def _name(i):
        return RULE_NAME if i == 0 else f"{RULE_NAME}-{i}"

    def _netsh(self, *args):
        cmd = ["netsh", "advfirewall", "firewall", *args]
        if self.dry_run:
            log.debug("[simulation] %s", " ".join(cmd))
            return True
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30, creationflags=flags)
        except (OSError, subprocess.SubprocessError) as e:
            log.error("netsh a échoué : %s", e)
            return False
        return res.returncode == 0

    def _add(self, i, remote):
        return self._netsh("add", "rule", f"name={self._name(i)}", "dir=in", "action=block",
                           "enable=yes", "profile=any", f"remoteip={remote}")

    def clear(self):
        """Supprime toutes les règles (sans erreur si elles n'existent pas)."""
        n = MAX_RULES if self.rules_used is None else self.rules_used
        for i in range(n):
            self._netsh("delete", "rule", f"name={self._name(i)}")
        self.rules_used = 0

    def apply(self, ips):
        """Fait correspondre les règles à exactement cette liste d'IP."""
        chunks = [ips[i:i + RULE_CHUNK] for i in range(0, len(ips), RULE_CHUNK)][:MAX_RULES]
        known, ok = self.rules_used or 0, True
        for i, chunk in enumerate(chunks):
            remote = ",".join(chunk)
            if i < known:
                done = self._netsh("set", "rule", f"name={self._name(i)}", "new", f"remoteip={remote}")
                if not done:   # la règle a disparu : on la recrée
                    self._netsh("delete", "rule", f"name={self._name(i)}")
                    done = self._add(i, remote)
            else:
                done = self._add(i, remote)
            ok = ok and done
        for i in range(len(chunks), known):   # règles devenues inutiles
            self._netsh("delete", "rule", f"name={self._name(i)}")
        self.rules_used = len(chunks)   # jamais de règle sans IP : remoteip vide bloquerait tout le monde
        if not ok:
            log.error("Impossible de mettre à jour la règle de pare-feu (droits administrateur ?)")
        return ok


# --------------------------------------------------------------------------- #
# Espace administrateur (mot de passe + session)
# --------------------------------------------------------------------------- #
class Admin:
    """Accès aux réglages avancés. Actif seulement si l'appli est lancée avec --admin."""

    SESSION_TTL = 1800   # 30 min d'inactivité

    def __init__(self, cfg, enabled):
        self.cfg, self.enabled = cfg, enabled
        self.session, self.last_used = None, 0.0
        self.fails, self.locked_until = 0, 0.0
        self.lock = threading.Lock()

    @staticmethod
    def _hash(pw, salt):
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()

    def configured(self):
        return bool(self.cfg.get("admin_hash"))

    def _new_session(self):
        self.session, self.last_used, self.fails = secrets.token_urlsafe(24), time.time(), 0
        return self.session

    def _store(self, pw):
        salt = secrets.token_hex(16)
        self.cfg["admin_salt"], self.cfg["admin_hash"] = salt, self._hash(pw, salt)
        save_config(self.cfg)

    def _verify(self, pw):
        return hmac.compare_digest(self._hash(pw, self.cfg["admin_salt"]), self.cfg["admin_hash"])

    def setup(self, pw):
        with self.lock:
            if self.configured():
                raise ValueError("un mot de passe existe déjà")
            if len(pw) < 6:
                raise ValueError("6 caractères minimum")
            self._store(pw)
            log.info("Mot de passe administrateur créé")
            return self._new_session()

    def login(self, pw):
        with self.lock:
            now = time.time()
            if now < self.locked_until:
                raise ValueError(f"trop d'essais, réessaie dans {int(self.locked_until - now) + 1} s")
            if not self.configured():
                raise ValueError("aucun mot de passe créé")
            if self._verify(pw):
                log.info("Espace administrateur déverrouillé")
                return self._new_session()
            self.fails += 1
            if self.fails >= 5:
                self.fails, self.locked_until = 0, now + 30
                log.warning("5 mots de passe admin incorrects : accès bloqué 30 s")
            raise ValueError("mot de passe incorrect")

    def change_password(self, old, new):
        with self.lock:
            if not self._verify(old):
                raise ValueError("ancien mot de passe incorrect")
            if len(new) < 6:
                raise ValueError("6 caractères minimum")
            self._store(new)
            log.info("Mot de passe administrateur modifié")

    def check(self, token):
        with self.lock:
            if not self.session or not token or not hmac.compare_digest(token, self.session):
                return False
            if time.time() - self.last_used > self.SESSION_TTL:
                self.session = None
                return False
            self.last_used = time.time()
            return True

    def logout(self):
        with self.lock:
            self.session = None


# --------------------------------------------------------------------------- #
# Moteur de détection
# --------------------------------------------------------------------------- #
class EventBuffer(logging.Handler):
    """Garde les derniers événements pour le journal du dashboard."""

    def __init__(self):
        super().__init__(logging.INFO)
        self.events = deque(maxlen=150)

    def emit(self, record):
        self.events.appendleft({
            "t": time.strftime("%H:%M:%S", time.localtime(record.created)),
            "level": record.levelname,
            "msg": record.getMessage(),
        })


def parse_nets(items):
    """Liste d'IP/réseaux -> objets réseau ; une entrée invalide est ignorée (au lieu de planter au démarrage)."""
    out = []
    for x in items or []:
        try:
            out.append(ipaddress.ip_network(str(x).strip(), strict=False))
        except ValueError:
            log.warning("Entrée de liste blanche ignorée (invalide) : %r", x)
    return out


class Engine:
    def __init__(self, cfg, events, dry_run=False):
        self.cfg = cfg
        self.events = events
        self.dry_run = dry_run
        self.fw = WinFirewall(dry_run)
        self.ports = set(cfg["ports"])
        self.whitelist = parse_nets(cfg["whitelist"])
        self.lock = threading.RLock()
        self.stop_evt = threading.Event()
        self.banned_until = {}
        self.offenses = Counter()
        self.ban_kinds = Counter()
        self.history = deque(maxlen=150)   # (timestamp, established, syn, http, rx, tx)
        self.top_conn, self.top_http = [], []
        self.watcher = (LogWatcher(cfg["access_log"], cfg["http_window_seconds"])
                        if cfg.get("access_log") else None)
        self.attack_mode = False
        self.last_hot = 0.0
        self.started = time.time()
        self.total_bans = 0
        self.net_prev = None
        self.dirty = False
        self._closed = False
        self.site_ips, self.trust_ips = set(), set()   # membres du site (limites x4) / IP de confiance (intouchables)
        self.site_bans, self.level = set(), 0
        self.last_offense = {}
        self.fw_evt, self.fw_lock, self.fw_pending = threading.Event(), threading.Lock(), None
        self.prev_conns = None

    # -- règles de protection ------------------------------------------------
    def net_protected(self, net):
        if net.is_loopback or net.is_private:
            return True
        if any(net.overlaps(w) for w in self.whitelist if w.version == net.version):
            return True
        return any(ipaddress.ip_address(x) in net for x in self.trust_ips
                   if ipaddress.ip_address(x).version == net.version)

    def is_protected(self, ip):
        if hasattr(ip, "network_address"):
            return self.net_protected(ip)
        if ip.is_loopback or ip.is_unspecified:
            return True
        if self.cfg["ignore_private_ranges"] and ip.is_private:
            return True
        if str(ip) in self.trust_ips:
            return True
        return any(ip in net for net in self.whitelist if net.version == ip.version)

    def leniency(self, ip):
        """Un membre du site a des limites plus larges, mais un membre qui inonde est quand même banni."""
        return MEMBER_LENIENCY if str(ip) in self.site_ips else 1

    def ban(self, ip, reason, kind):
        if self.is_protected(ip):
            return False
        now = time.time()
        if self.banned_until.get(ip, 0) > now:
            return False
        if now - self.last_offense.get(ip, now) > OFFENSE_FORGET:
            self.offenses.pop(ip, None)   # pas de récidive depuis 7 jours : on repart de zéro
        self.offenses[ip] += 1
        base = self.cfg["ban_seconds"] * (2 if self.attack_mode else 1) * (1, 2, 4)[self.level]
        duration = min(base * 2 ** min(self.offenses[ip] - 1, 20), self.cfg["max_ban_seconds"])
        if self.offenses[ip] >= self.cfg["permanent_after"]:
            duration = 30 * 86400
        self.banned_until[ip] = now + duration
        self.last_offense[ip] = now + duration
        self.total_bans += 1
        self.ban_kinds[kind] += 1
        self.dirty = True
        if self.watcher:
            self.watcher.forget(ip)
        log.warning("BAN %s pour %ds (infraction n°%d)%s : %s", ip, duration, self.offenses[ip],
                    " [simulation]" if self.dry_run else "", reason)
        return True

    def sync_firewall(self):
        """Demande la mise à jour des règles Windows (faite par un thread à part : netsh est lent
        et ne doit jamais retarder la détection)."""
        if not self.dirty:
            return
        self.dirty = False
        ips = [str(ip) for ip, _ in sorted(self.banned_until.items(), key=lambda x: -x[1])]
        if len(ips) > MAX_RULE_IPS:
            log.warning("Plus de %d IP bannies : seules les %d bans les plus longs sont dans le pare-feu",
                        MAX_RULE_IPS, MAX_RULE_IPS)
            ips = ips[:MAX_RULE_IPS]
        self.fw_pending = ips
        self.fw_evt.set()

    def fw_worker(self):
        while True:
            self.fw_evt.wait()
            if self.stop_evt.is_set():
                break
            self.fw_evt.clear()
            ips, self.fw_pending = self.fw_pending, None
            if ips is None:
                continue
            try:
                with self.fw_lock:
                    if not self.stop_evt.is_set():
                        self.fw.apply(ips)
            except Exception:
                log.exception("Erreur pendant la mise à jour du pare-feu")

    def update_attack_mode(self, established, syn, http):
        cfg, now = self.cfg, time.time()
        hot = (sum(established.values()) > cfg["attack_total_connections"]
               or sum(syn.values()) > cfg["attack_total_syn"]
               or sum(http.values()) > cfg["attack_total_requests"])
        if hot:
            self.last_hot = now
            if not self.attack_mode:
                self.attack_mode = True
                log.warning("MODE ATTAQUE activé : limites par IP divisées par 2")
        elif self.attack_mode and now - self.last_hot > cfg["attack_calm_seconds"]:
            self.attack_mode = False
            log.info("Retour au calme : mode attaque désactivé")

    def read_net(self):
        """Débit réseau entrant/sortant en Mb/s (hors boucle locale)."""
        rx = tx = 0
        try:
            for name, c in psutil.net_io_counters(pernic=True).items():
                if "loopback" in name.lower() or name == "lo":
                    continue
                rx, tx = rx + c.bytes_recv, tx + c.bytes_sent
        except OSError:
            return 0.0, 0.0
        now, prev = time.time(), self.net_prev
        self.net_prev = (now, rx, tx)
        if not prev:
            return 0.0, 0.0
        dt = max(now - prev[0], 0.001)
        return (rx - prev[1]) * 8 / dt / 1e6, (tx - prev[2]) * 8 / dt / 1e6

    def tick(self):
        cfg = self.cfg
        established, syn, cset, tw = read_connections(self.ports)
        http = self.watcher.poll() if self.watcher else Counter()
        with self.lock:
            self.update_attack_mode(established, syn, http)
            f = (0.5 if self.attack_mode else 1.0) * (1, 0.6, 0.35)[self.level]
            max_est = max(15, int(cfg["max_established_per_ip"] * f))
            max_syn = max(6, int(cfg["max_syn_recv_per_ip"] * f))
            max_http = max(40, int(cfg["max_requests_per_window"] * f))

            max_tw = max(60, int(cfg["max_timewait_per_ip"] * f))
            for ip, n in established.items():
                if n > max_est * self.leniency(ip):
                    self.ban(ip, f"{n} connexions simultanées (limite {max_est})",
                             "Connexions simultanées")
            for ip, n in syn.items():
                if n > max_syn * self.leniency(ip):
                    self.ban(ip, f"{n} demi-connexions SYN_RECV (limite {max_syn})", "Flood SYN")
            for ip, n in http.items():
                if n > max_http * self.leniency(ip):
                    self.ban(ip, f"{n} requêtes HTTP en {cfg['http_window_seconds']}s "
                                 f"(limite {max_http})", "Flood HTTP")

            for ip, n in tw.items():   # flood « court » : connexions ouvertes puis fermées aussitôt
                if n > max_tw * self.leniency(ip):
                    self.ban(ip, f"{n} connexions récemment fermées (limite {max_tw})", "Rotation de connexions")
            if self.prev_conns is not None:   # rafales de nouvelles connexions
                lim = max(10, int(cfg["max_new_conn_per_sec"] * f * cfg["check_interval"]))
                for ip, n in Counter(i for i, _, _ in cset - self.prev_conns).items():
                    if n > lim * self.leniency(ip):
                        self.ban(ip, f"{n} nouvelles connexions en {cfg['check_interval']:g}s (limite {lim})",
                                 "Rafale de connexions")
            self.prev_conns = cset
            groups, cnt = defaultdict(set), Counter()   # flood venant d'un même réseau (botnet)
            for ip, n in (established + syn).items():
                net = ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False)
                groups[net].add(ip)
                cnt[net] += n
            lim = max(20, int(cfg["subnet_max_connections"] * f))
            for net, n in cnt.items():
                if n > lim and len(groups[net]) >= 5:
                    self.ban(net, f"{n} connexions depuis {len(groups[net])} IP du réseau {net} (limite {lim})",
                             "Flood de réseau")

            now = time.time()
            for ip in [i for i, t in self.banned_until.items() if t <= now]:
                del self.banned_until[ip]
                self.dirty = True
                log.info("Ban expiré : %s", ip)
            for ip in [i for i, t in self.last_offense.items() if now - t > OFFENSE_FORGET]:
                self.last_offense.pop(ip, None)   # libère la mémoire des vieilles infractions
                self.offenses.pop(ip, None)

            self.top_conn = [(str(i), n) for i, n in established.most_common(8)]
            self.top_http = [(str(i), n) for i, n in http.most_common(8)]
            rx, tx = self.read_net()
            self.history.append((int(now), sum(established.values()), sum(syn.values()),
                                 sum(http.values()), round(rx, 2), round(tx, 2)))
            self.sync_firewall()

    def sync_site(self):
        """Toutes les 30 s : récupère ton niveau, tes bans et les IP protégées du site, puis lui envoie l'activité."""
        import urllib.request

        def call(path, data=None):
            hdr = {"X-Site-Key": self.cfg["site_key"], "X-Req": "1", "Content-Type": "application/json"}
            req = urllib.request.Request(self.cfg["site_url"].rstrip("/") + path, headers=hdr,
                                         data=json.dumps(data).encode() if data is not None else None)
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.load(r)

        while not self.stop_evt.is_set():
            if self.cfg.get("site_url") and self.cfg.get("site_key"):
                try:
                    s = call("/api/sync")
                    members = {str(ipaddress.ip_address(x)) for x in s["ips"]}
                    trust = {str(ipaddress.ip_address(x))
                             for x in list(s.get("trust", [])) + ([s["me"]] if s.get("me") else [])}
                    bans = set()
                    for x in s["bans"]:
                        n = ipaddress.ip_network(x, strict=False)
                        bans.add(n.network_address if n.num_addresses == 1 else n)
                    with self.lock:
                        now, before = time.time(), set(self.banned_until)
                        self.site_ips, self.trust_ips = members, trust
                        self.level = min(2, max(0, int(s.get("level", 0))))
                        for ip in self.site_bans - bans:
                            self.banned_until.pop(ip, None)
                        for ip in bans:
                            if not self.is_protected(ip):
                                self.banned_until[ip] = now + 30 * 86400
                        self.site_bans = bans
                        for x in list(self.banned_until):
                            if str(x) in trust:
                                del self.banned_until[x]
                        if set(self.banned_until) != before:
                            self.dirty = True
                        last = self.history[-1] if self.history else (0, 0, 0)
                        rep = {"attack": self.attack_mode, "total": self.total_bans, "conns": last[1], "syn": last[2],
                               "top": [{"ip": i, "n": n} for i, n in self.top_conn[:6]], "kinds": dict(self.ban_kinds),
                               "hist": [x[1] for x in list(self.history)[-60:]],
                               "banned": [{"ip": str(i), "left": int(t - now)} for i, t in self.banned_until.items()
                                          if i not in bans and t > now][:100]}
                    call("/api/report", rep)
                except Exception as e:
                    log.warning("Synchro avec le site impossible : %s", e)
            self.stop_evt.wait(30)

    def run(self):
        threading.Thread(target=self.sync_site, daemon=True).start()
        threading.Thread(target=self.fw_worker, daemon=True).start()
        with self.fw_lock:
            self.fw.clear()   # supprime les règles laissées par un arrêt brutal
        log.info("AntiDDoS démarré | ports=%s | log=%s | %s", sorted(self.ports),
                 self.cfg.get("access_log"),
                 "SIMULATION (rien n'est bloqué)" if self.dry_run else "blocage réel")
        while not self.stop_evt.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("Erreur pendant la vérification")
            self.stop_evt.wait(self.cfg["check_interval"])

    def shutdown(self):
        """Arrêt propre : on retire la règle, donc plus aucune IP n'est bloquée."""
        if self._closed:
            return
        self._closed = True
        self.stop_evt.set()
        self.fw_evt.set()
        with self.fw_lock:
            self.fw.clear()
        log.info("Arrêt : règle de pare-feu supprimée, toutes les IP sont débannies")

    # -- actions depuis le dashboard -----------------------------------------
    def set_config(self, key, value):
        if key not in EDITABLE:
            raise ValueError("réglage inconnu")
        lo, hi = EDITABLE[key]
        v = int(value)
        if not lo <= v <= hi:
            raise ValueError(f"la valeur doit être comprise entre {lo} et {hi}")
        with self.lock:
            self.cfg[key] = v
            save_config(self.cfg)
        log.info("Réglage modifié : %s = %d", key, v)

    def manual_ban(self, ip_str):
        ip = ipaddress.ip_address(ip_str)
        with self.lock:
            if self.is_protected(ip):
                raise ValueError("IP protégée (liste blanche / privée / loopback)")
            self.ban(ip, "ban manuel depuis le dashboard", "Ban manuel")
            self.sync_firewall()

    def unban(self, ip_str):
        ip = ipaddress.ip_address(ip_str)
        with self.lock:
            self.banned_until.pop(ip, None)
            self.offenses.pop(ip, None)
            self.last_offense.pop(ip, None)
            self.dirty = True
            self.sync_firewall()
        log.info("DÉBAN manuel : %s", ip)

    def unban_all(self):
        with self.lock:
            n = len(self.banned_until)
            self.banned_until.clear()
            self.offenses.clear()
            self.last_offense.clear()
            self.dirty = True
            self.sync_firewall()
        log.info("DÉBAN de toutes les IP (%d) depuis l'espace admin", n)

    def admin_get(self):
        with self.lock:
            c = self.cfg
            out = {k: c[k] for k in ("ports", "whitelist", *ADMIN_INT_LIMITS)}
            out["access_log"] = c.get("access_log") or ""
            out["dry_run"] = self.dry_run
            return out

    def admin_set(self, body):
        if not isinstance(body, dict):
            raise ValueError("format invalide")
        with self.lock:
            new = {}
            if "ports" in body:
                ports = body["ports"]
                if not isinstance(ports, list) or not 1 <= len(ports) <= 50:
                    raise ValueError("indique entre 1 et 50 ports")
                ports = sorted({int(p) for p in ports})
                if not all(1 <= p <= 65535 for p in ports):
                    raise ValueError("un port doit être compris entre 1 et 65535")
                new["ports"] = ports
            if "access_log" in body:
                path = str(body["access_log"] or "").strip()
                if len(path) > 260:
                    raise ValueError("chemin du log trop long")
                new["access_log"] = path or None
            if "whitelist" in body:
                wl = body["whitelist"]
                if not isinstance(wl, list) or len(wl) > 200:
                    raise ValueError("liste blanche invalide (200 entrées maximum)")
                clean = [str(x).strip() for x in wl if str(x).strip()]
                for x in clean:
                    try:
                        ipaddress.ip_network(x, strict=False)
                    except ValueError:
                        raise ValueError(f"adresse invalide : {x}")
                for must in ("::1", "127.0.0.1"):
                    if must not in clean:
                        clean.insert(0, must)
                new["whitelist"] = clean
            for k, (lo, hi) in ADMIN_INT_LIMITS.items():
                if k in body:
                    v = int(body[k])
                    if not lo <= v <= hi:
                        raise ValueError(f"{k} : valeur entre {lo} et {hi}")
                    new[k] = v
            if "dry_run" in body:
                want = bool(body["dry_run"])
                if not want and not is_admin():
                    raise ValueError("relance l'application en administrateur pour bloquer pour de vrai")
                new["dry_run"] = want
            # tout est valide : on applique
            self.cfg.update(new)
            if "ports" in new:
                self.ports = set(new["ports"])
            if "whitelist" in new:
                self.whitelist = parse_nets(new["whitelist"])
            if "access_log" in new:
                self.watcher = (LogWatcher(new["access_log"], self.cfg["http_window_seconds"])
                                if new["access_log"] else None)
            if "dry_run" in new:
                if new["dry_run"] and not self.dry_run:
                    with self.fw_lock:
                        self.fw.clear()      # on retire les règles avant de passer en simulation
                self.dry_run = self.fw.dry_run = new["dry_run"]
                self.dirty = not new["dry_run"]   # repasse en réel : on réapplique les bans
            save_config(self.cfg)
        log.info("Réglages avancés modifiés : %s", ", ".join(sorted(new)) or "aucun")

    def state(self):
        now = time.time()
        with self.lock:
            banned = [{"ip": str(ip), "remaining": int(t - now), "offenses": self.offenses[ip]}
                      for ip, t in sorted(self.banned_until.items(), key=lambda x: -x[1])
                      if t > now]
            cfg = self.cfg
            return {
                "uptime": int(now - self.started),
                "dry_run": self.dry_run,
                "attack": self.attack_mode,
                "banned": banned,
                "total_bans": self.total_bans,
                "history": list(self.history),
                "top_conn": self.top_conn,
                "top_http": self.top_http,
                "events": list(self.events.events),
                "config": {k: cfg[k] for k in EDITABLE},
                "triggers": {"conn": cfg["attack_total_connections"],
                             "syn": cfg["attack_total_syn"],
                             "http": cfg["attack_total_requests"]},
                # L'onglet « Pare-feu » du dashboard réutilise ce format
                "shield": {"active": not self.dry_run,
                           "counters": {k: [v, 0] for k, v in self.ban_kinds.items()}},
                "limits": {
                    "Connexions/IP": cfg["max_established_per_ip"],
                    "SYN_RECV/IP": cfg["max_syn_recv_per_ip"],
                    "Requêtes HTTP/IP": f'{cfg["max_requests_per_window"]} par {cfg["http_window_seconds"]}s',
                    "Durée de ban": f'{cfg["ban_seconds"]}s',
                    "Ports": ", ".join(map(str, cfg["ports"])),
                },
            }


# --------------------------------------------------------------------------- #
# Serveur local du dashboard (127.0.0.1 uniquement, protégé par jeton)
# --------------------------------------------------------------------------- #
SITE_WIDGET = """<style>#sw-b{position:fixed;right:18px;bottom:18px;z-index:99;border:0;border-radius:99px;padding:11px 18px;font-weight:600;cursor:pointer;color:#fff;background:linear-gradient(135deg,#5b8cff,#8b5cf6);box-shadow:0 8px 24px rgba(0,0,0,.35)}
#sw-m{position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.55);display:none;place-items:center}#sw-m div{background:#0f1730;color:#e8edff;border:1px solid #2a3560;border-radius:18px;padding:24px;width:min(92vw,440px);font:14px system-ui}
#sw-m input{width:100%;margin:6px 0 12px;padding:11px;border-radius:10px;border:1px solid #2a3560;background:#0b1230;color:#e8edff;box-sizing:border-box}#sw-m button{border:0;border-radius:10px;padding:10px 16px;font-weight:600;cursor:pointer;margin-right:8px}</style>
<button id="sw-b">🔗 Mon site</button><div id="sw-m"><div><h3 style="margin:0 0 6px">Relier au site AntiDDoS</h3>
<p style="color:#8e9bc4;margin:0 0 12px">Colle l'adresse du site et ta clé (panel du site, « Connecter mon appli »).</p>
<label>Adresse du site</label><input id="sw-u" placeholder="https://mon-site.fr"><label>Ma clé</label><input id="sw-k" type="password" placeholder="Colle ta clé ici">
<p id="sw-s" style="color:#8e9bc4;min-height:20px;margin:0 0 10px"></p><button id="sw-ok" style="background:#5b8cff;color:#fff">Enregistrer</button><button id="sw-x" style="background:#222c52;color:#e8edff">Fermer</button></div></div>
<script>(()=>{const T=new URLSearchParams(location.search).get("token")||"",$=i=>document.getElementById(i),H={"X-Token":T,"Content-Type":"application/json"};
$("sw-b").onclick=async()=>{$("sw-m").style.display="grid";const r=await(await fetch("/api/site",{headers:H})).json();$("sw-u").value=r.url||"";$("sw-s").textContent=r.has_key?"Une clé est déjà enregistrée (laisse vide pour la garder).":""};
$("sw-x").onclick=()=>$("sw-m").style.display="none";
$("sw-ok").onclick=async()=>{const r=await fetch("/api/site",{method:"POST",headers:H,body:JSON.stringify({url:$("sw-u").value,key:$("sw-k").value})});const j=await r.json();
$("sw-s").textContent=r.ok?"✓ Enregistré : synchronisation dans moins de 30 secondes.":(j.error||"Erreur")};})();</script>"""


def load_page():
    try:
        with open(os.path.join(base_dir(), "dashboard.html"), "rb") as f:
            return f.read().replace(b"</body>", SITE_WIDGET.encode() + b"</body>", 1)
    except OSError:
        return "<h1>dashboard.html introuvable</h1>"


def make_handler(engine, token, admin):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _auth(self):
            return hmac.compare_digest(self.headers.get("X-Token", ""), token)

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src data:; style-src 'unsafe-inline'; "
                             "script-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                return self._send(200, load_page(), "text/html")
            if path == "/api/state":
                if not self._auth():
                    return self._send(401, json.dumps({"error": "non autorisé"}))
                return self._send(200, json.dumps(engine.state()))
            if path == "/api/site":
                if not self._auth():
                    return self._send(401, json.dumps({"error": "non autorisé"}))
                return self._send(200, json.dumps({"url": engine.cfg.get("site_url", ""),
                                                   "has_key": bool(engine.cfg.get("site_key"))}))
            if path == "/api/admin/status":
                if not self._auth():
                    return self._send(401, json.dumps({"error": "non autorisé"}))
                return self._send(200, json.dumps({"enabled": admin.enabled,
                                                   "configured": admin.configured()}))
            self._send(404, json.dumps({"error": "introuvable"}))

        def _admin(self, action, body):
            if not admin.enabled:
                return self._send(403, json.dumps({"error": "mode administrateur désactivé"}))
            if not isinstance(body, dict):
                raise ValueError("format invalide")
            if action in ("login", "setup"):
                pw = str(body.get("password", ""))
                token_ = admin.login(pw) if action == "login" else admin.setup(pw)
                return self._send(200, json.dumps({"session": token_}))
            if not admin.check(self.headers.get("X-Admin", "")):
                return self._send(401, json.dumps({"error": "session administrateur expirée, reconnecte-toi"}))
            if action == "config_get":
                return self._send(200, json.dumps(engine.admin_get()))
            if action == "config_set":
                engine.admin_set(body)
            elif action == "unban_all":
                engine.unban_all()
            elif action == "password":
                admin.change_password(str(body.get("old", "")), str(body.get("new", "")))
            elif action == "logout":
                admin.logout()
            else:
                return self._send(404, json.dumps({"error": "introuvable"}))
            self._send(200, json.dumps({"ok": True}))

        def do_POST(self):
            path = urlparse(self.path).path
            if not self._auth():
                return self._send(401, json.dumps({"error": "non autorisé"}))
            try:
                length = min(int(self.headers.get("Content-Length", 0)), 16384)
                body = json.loads(self.rfile.read(length) or b"{}")
                if path == "/api/site":
                    url, key = str(body.get("url", "")).strip(), str(body.get("key", "")).strip()
                    if not re.fullmatch(r"https?://[^\s/]+(/\S*)?", url) or len(url) > 200:
                        raise ValueError("adresse invalide (ex. https://mon-site.fr)")
                    with engine.lock:
                        engine.cfg["site_url"] = url.rstrip("/")
                        if key:
                            engine.cfg["site_key"] = key[:200]
                        save_config(engine.cfg)
                    log.info("Site relié : %s", url)
                    return self._send(200, json.dumps({"ok": True}))
                if path.startswith("/api/admin/"):
                    return self._admin(path[len("/api/admin/"):], body)
                if path == "/api/ban":
                    engine.manual_ban(body["ip"])
                elif path == "/api/unban":
                    engine.unban(body["ip"])
                elif path == "/api/config":
                    engine.set_config(body["key"], body["value"])
                else:
                    return self._send(404, json.dumps({"error": "introuvable"}))
                self._send(200, json.dumps({"ok": True}))
            except (ValueError, KeyError, TypeError) as e:
                self._send(400, json.dumps({"error": f"requête invalide : {e}"}))

    return Handler


# --------------------------------------------------------------------------- #
# Point d'entrée
# --------------------------------------------------------------------------- #
def wait_forever():
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def run_window(url):
    """Ouvre la fenêtre de l'application (bloque jusqu'à sa fermeture)."""
    try:
        import webview
    except ImportError:
        fatal("Le module pywebview est manquant.\nInstalle-le avec : py -m pip install pywebview")
    webview.create_window(APP_NAME, url, width=1280, height=820, min_size=(900, 600),
                          background_color="#060a15")
    webview.start()


def main():
    ap = argparse.ArgumentParser(description="AntiDDoS pour Windows")
    ap.add_argument("--dry-run", action="store_true", help="détecte sans rien bloquer")
    ap.add_argument("--no-gui", action="store_true", help="sans fenêtre (affiche l'URL du dashboard)")
    ap.add_argument("--browser", action="store_true", help="ouvre le dashboard dans le navigateur")
    ap.add_argument("--admin", action="store_true", help="active l'espace administrateur (réservé au propriétaire)")
    ap.add_argument("--no-elevate", action="store_true", help="ne demande pas les droits admin")
    args = ap.parse_args()

    if psutil is None:
        fatal("Le module psutil est manquant.\nInstalle-le avec : py -m pip install psutil")

    cfg = load_config()
    dry_run = args.dry_run or bool(cfg.get("dry_run"))
    forced_sim = False
    if not dry_run and not is_admin():
        if os.name == "nt" and not args.no_elevate and relaunch_as_admin():
            return   # la version administrateur prend le relais
        dry_run = forced_sim = True

    if not single_instance():
        fatal("AntiDDoS est déjà ouvert.")

    events = EventBuffer()
    handlers = [events]
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler())
    try:
        handlers.append(logging.FileHandler(os.path.join(data_dir(), "antiddos.log"), encoding="utf-8"))
    except OSError:
        pass
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        handlers=handlers)
    if forced_sim:
        log.warning("Droits administrateur absents : mode SIMULATION, rien ne sera bloqué")

    engine = Engine(cfg, events, dry_run)
    admin = Admin(cfg, args.admin)
    atexit.register(engine.shutdown)
    token = secrets.token_urlsafe(16)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(engine, token, admin))
    url = f"http://127.0.0.1:{server.server_address[1]}/?token={token}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=engine.run, daemon=True).start()

    try:
        if args.no_gui or args.browser:
            print(f"\n  Dashboard : {url}\n  (Ctrl+C pour arrêter)\n", flush=True)
            if args.browser:
                webbrowser.open(url)
            wait_forever()
        else:
            run_window(url)
    finally:
        engine.shutdown()
        server.shutdown()


if __name__ == "__main__":
    main()
