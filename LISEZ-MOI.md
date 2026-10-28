# MISE EN LIGNE EN 3 ÉTAPES (le plus important)

**1. Le site (sur un serveur / VPS, allumé en permanence)**
Copie `site_server.py` et `page.html` dans le même dossier, puis : `SITE_HTTPS=1 SITE_TRUST_PROXY=1 py site_server.py --port 8080`
et mets-le derrière HTTPS (Cloudflare, nginx ou Caddy). Ouvre-le, clique « Admin », connecte-toi avec le mot de passe affiché dans la console au premier lancement, puis **change-le**.

**2. L'appli Windows (le .exe que tout le monde télécharge)**
Un .exe Windows ne peut être construit que sur Windows : GitHub le fait gratuitement pour toi.
a. Crée un dépôt GitHub et envoies-y tout ce dossier (y compris `.github`).
b. Dépôt, Settings, Secrets and variables, Actions, onglet Variables : crée `SITE_URL` = l'adresse de ton site (https://...). Elle sera embarquée dans l'exe.
c. Onglet Releases, « Create a new release », tag `v1.0.0`, Publish. Après quelques minutes, `AntiDDoS-Setup.exe` apparaît dans la release : c'est le lien que tu donnes à tout le monde.

**3. Pour chaque utilisateur**
Il télécharge et installe `AntiDDoS-Setup.exe`, se connecte sur ton site avec son IP, génère sa clé dans son panel,
puis dans l'appli clique « 🔗 Mon site » (en bas à droite), colle la clé : c'est relié.

---

# AntiDDoS pour Windows

Application de bureau : une fenêtre avec le tableau de bord, et une protection qui
bloque les IP abusives via le **Pare-feu Windows**.

## Créer l'installateur pour tout le monde (le plus simple : GitHub le fait pour toi)
1. Crée un dépôt GitHub et envoie-y **tout le contenu de ce dossier** (y compris le dossier `.github`).
2. Onglet **Releases**, puis « Create a new release », tag `v1.0.0`, puis « Publish ».
   (Ou onglet **Actions**, puis « Construire AntiDDoS », puis « Run workflow ».)
3. Au bout de quelques minutes, **`AntiDDoS-Setup.exe`** apparaît dans la release.
   Les gens le téléchargent, double-cliquent, « Suivant », « Installer » : c'est prêt,
   avec raccourci Bureau et menu Démarrer.

## Ou le créer sur ton PC
1. Installe **Python 3.12** (python.org, coche « Add python.exe to PATH »)
   et **Inno Setup 6** (jrsoftware.org/isinfo.php).
2. Double-clique sur **`build.bat`** : il crée `dist\AntiDDoS.exe`
   et `installer_output\AntiDDoS-Setup.exe`.

## Utiliser
- Double-clique sur `AntiDDoS.exe` et accepte la demande administrateur (nécessaire pour le pare-feu).
- Sans droits administrateur, l'appli démarre en **mode simulation** : elle détecte, mais ne bloque rien.
- Pour tester sans risque : `AntiDDoS.exe --dry-run`.
- Quand tu fermes la fenêtre, la règle de pare-feu est supprimée et toutes les IP sont débannies.
  Si l'appli est tuée de force, la règle reste jusqu'au prochain lancement (qui la nettoie).

## Espace administrateur (pour toi seulement)
- Les utilisateurs lancent l'appli normalement : ils n'ont **pas** d'onglet Admin.
- Toi, fais un raccourci vers `AntiDDoS.exe` (clic droit, « Créer un raccourci »), puis dans ses
  Propriétés ajoute **` --admin`** à la fin de la « Cible ». Avec ce raccourci, un onglet **Admin** apparaît.
- Au premier lancement, tu y crées ton mot de passe (6 caractères minimum). Ensuite il te le demande à chaque fois.
- Dedans : ports surveillés, fichier de log, liste blanche, seuils du mode attaque, passage Simulation / Blocage réel,
  « Débannir toutes les IP », changement de mot de passe. La session se verrouille après 30 min d'inactivité,
  et 5 mauvais mots de passe bloquent l'accès 30 secondes.
- Limite honnête : ce verrou protège **cette installation**. Il ne te donne pas la main sur les PC des autres
  (pour ça il faudrait un serveur central).

## Réglages
- Depuis l'onglet « Réglages » du dashboard (seuils et durée de ban).
- Le reste (ports, liste blanche, log d'accès) se change dans `%APPDATA%\AntiDDoS\config.json`.
  Ajoute **ton IP publique** dans `whitelist`. Ports surveillés par défaut : 80, 443, 30120.

## Distribuer
Mets `AntiDDoS.exe` dans une « Release » GitHub : tout le monde a un lien de téléchargement.
Windows affichera « Windows a protégé votre ordinateur » tant que l'exe n'est pas signé
(« Informations complémentaires » puis « Exécuter quand même »). Les exe créés avec PyInstaller
sont parfois signalés à tort par des antivirus : prévois de publier aussi le code source.

## Limites à connaître
- Seules les connexions **TCP** sont surveillées. Le trafic **UDP** (une grande partie du jeu FiveM) n'est pas vu.
- Une attaque qui ssature ta connexion doit être filtrée **en amont** (hébergeur, Cloudflare, etc.) :
  aucun logiciel sur le PC ne peut l'arrêter.
- Maximum 2800 IP bannies en même temps (8 règles de pare-feu de 350 IP, mises à jour sur place, sans trou).
- Testé ici sur Linux avec un faux `netsh` : fais un premier essai en `--dry-run`, puis en réel.

## Site de connexion par IP + admin (nouveau : `site_server.py`)
1. Sur ton serveur : `py site_server.py --port 8080` (Python seul, rien à installer).
   Derrière HTTPS (Cloudflare / nginx) : `SITE_HTTPS=1 SITE_TRUST_PROXY=1 py site_server.py`.
2. L'utilisateur ouvre le site, met pseudo + IP, coche « Se souvenir de moi » : connexion automatique ensuite,
   et son IP est mise à jour toute seule si elle change. Sans connexion pendant 7 jours : il doit remettre son IP.
3. Admin : lien « Admin » en bas de page. Mot de passe initial : au tout premier lancement le site en génère un au hasard et l'affiche **une seule fois** dans la console (ou utilise `SITE_ADMIN_PASSWORD=...`). **Change-le dans l'admin.** Plus aucun mot de passe, même haché, n'est écrit dans le code.
   Tu peux valider / bannir / débannir / déconnecter / supprimer, corriger une IP, activer la validation manuelle,
   voir le journal et la clé de synchro.
4. Une fois connecté, l'utilisateur ouvre son **panel** : niveau de protection (Normal / Renforcé / Maximum), IP à bannir, activité de son appli.
   Pour relier son appli : « Générer ma clé », puis dans `%APPDATA%\AntiDDoS\config.json` : `"site_url"` (adresse du site) et `"site_key"` (sa clé).
   L'appli se synchronise toutes les 30 s (niveau, bans, IP protégées) et envoie son activité au panel.

Sécurité : IP saisie = IP réellement vue par le serveur (sinon refus), cookies HttpOnly + SameSite, jetons hachés,
mot de passe admin haché (PBKDF2), blocage progressif après échecs, en-têtes CSP. **Mets le site en HTTPS** : sans ça rien n'est vraiment sûr.

## Protection renforcée (v2)
- **Rafales** : trop de nouvelles connexions par seconde pour une IP (`max_new_conn_per_sec`, 25 par défaut) → ban.
- **Flood de réseau** : 5 IP ou plus d'un même réseau (/24, /64) dépassent ensemble `subnet_max_connections` (300) → ban du réseau entier (botnet).
  Jamais si le réseau contient une IP en liste blanche ou un utilisateur du site.
- **Récidive** : après `permanent_after` infractions (5), ban de 30 jours.
- **Niveaux** (choisis dans le panel) : Renforcé = limites -40 % et bans x2, Maximum = limites -65 % et bans x4.
- Ces réglages se changent dans `config.json` ou l'espace admin de l'appli.
- Panel : trafic en direct, IP de confiance, bans de réseaux (ex. 203.0.113.0/24), historique. Admin : bans globaux, niveau minimum imposé,
  message à tous, validation en masse, purge des inactifs, export CSV.

## Audit de sécurité (v3) : ce qui a été corrigé
**Site (`site_server.py`)**
- Un pseudo existant ne peut plus être « volé » : se connecter avec le pseudo de quelqu'un depuis une autre IP est refusé et le compte n'est plus modifié.
- Maximum 3 comptes par IP et 5000 comptes au total (sinon un attaquant remplissait la liste des IP protégées).
- Une connexion qui n'envoie rien est coupée après 15 s, 300 connexions simultanées maximum, 300 requêtes/minute par IP (le site pouvait être bloqué par quelques sockets ouverts).
- Les données sont écrites sur disque au plus toutes les 2 s (avant : à chaque requête).
- Le mot de passe admin n'est plus dans le code (voir plus haut).
- Derrière un proxy : `SITE_IP_HEADER=CF-Connecting-IP` (Cloudflare) ou `SITE_PROXY_HOPS=2` (Cloudflare + nginx). Si le proxy est sur la même machine : `SITE_HOST=127.0.0.1`.

**Appli (`antiddos_win.py`)**
- Les membres du site ne sont plus intouchables : limites x4, mais un membre qui inonde est banni. Seules ta liste blanche, tes « IP de confiance » et ta propre IP sont intouchables.
- Mise à jour du pare-feu en arrière-plan et sur place (`set rule`) : plus de trou pendant lequel un attaquant n'est plus bloqué, et la détection n'attend plus `netsh`.
- Jusqu'à 2800 IP bloquées (avant : 400, les autres semblaient bannies mais ne l'étaient pas).
- Nouvelle détection des floods « courts » (connexions ouvertes puis fermées aussitôt) : `max_timewait_per_ip`.
- Planchers de détection relevés (un navigateur normal ne se fait plus bannir au niveau Maximum).
- Les infractions sont oubliées après 7 jours sans récidive. Une liste blanche invalide ne fait plus planter l'appli. L'adresse du site embarquée dans l'exe n'est plus écrasée par une config vide.

**À faire de ton côté**
- Active « validation manuelle » dans l'admin du site : seules les IP validées par toi seront connues des autres utilisateurs.
- Si tu protèges un serveur derrière Cloudflare, ajoute les plages Cloudflare à la liste blanche, sinon tout le trafic légitime vient de quelques IP.
