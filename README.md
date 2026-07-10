# 3DS Presence Server

Serveur HTTP en Rust qui fait le pont entre des clients légers (Nintendo 3DS, ESP32) et Discord Rich Presence. Basé sur `discord_social_rpc`.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  presence-server                     │
│                                                      │
│  HTTP API (axum) ←→ SessionManager ←→ DiscordSocialRpc ←→ Discord Gateway WSS
│       ↕                           ↕
│  Database (sea-orm)          Background Tasks
│  - SQLite / PostgreSQL        - Timeout (60s)
│                               - Token refresh (6/7)
└─────────────────────────────────────────────────────┘
```

Le client envoie des requêtes HTTP `application/x-www-form-urlencoded` (léger, sans JSON) :
- `/register` : créer un compte (échange d'un code OAuth2 Discord)
- `/login` : débuter un challenge d'authentification (reçoit un nonce)
- `/login/verify` : prouver son identité (nonce chiffré avec AES-256-CBC)
- `/activity` : mettre à jour ou arrêter l'activité Discord

## Sécurité

### Anti-replay protocol

| Phase | Mécanisme |
|-------|-----------|
| **Register** | Le serveur génère une clé AES-256 unique et un UUID. La clé n'est transmise qu'une seule fois (réponse du register). |
| **Login** | Le serveur génère un nonce aléatoire (8 bytes, u64). Usage unique : supprimé après verify. |
| **Login Verify** | Le client chiffre le nonce + padding PKCS7 avec AES-256-CBC (IV=0) et renvoie le ciphertext. Le serveur déchiffre et valide. Prouve la possession de la clé AES. |
| **Activity** | Chaque message contient `counter` (monotone croissant) + `auth_hex` = AES-256-CBC(counter (8 bytes) \|\| SHA256(fields) (32 bytes)). Le serveur vérifie : counter > dernier vu, hash correspond aux champs. Un attaquant ne peut ni rejouer (counter), ni modifier (hash). |

### Rate limiting

- `ACTIVITY_COOLDOWN_SECS` (défaut: 5s) : temps minimum entre deux activity pour le même client
- `MAX_CLIENTS_PER_IP` (défaut: 8) : nombre maximum de sessions simultanées par adresse IP

### Gestion des tokens

- Les tokens Discord OAuth2 expirent après 7 jours
- Une tâche de fond rafraîchit automatiquement les tokens au 6/7ème de leur durée de vie (1 jour avant expiration)
- Les tokens sont stockés en base de données, jamais exposés au client

## Installation

### Prérequis

- Rust (nightly ou stable récent)
- OpenSSL (libssl-dev sur Debian/Ubuntu)
- SQLite (libsqlite3-dev) ou PostgreSQL

### Compilation

```bash
git clone <url>
cd 3ds-presence
cp presence-server/.env.example .env
# Éditer .env avec vos credentials Discord
cargo build --release -p presence-server
```

### Exécution

```bash
cargo run --release -p presence-server
```

## Configuration (.env)

```env
# --- Discord (obligatoire) ---
CLIENT_ID=1485716832420888746
CLIENT_SECRET=votre_secret_ici
REDIRECT_URI=http://localhost:5555/

# --- Base de données ---
# SQLite (par défaut)
DATABASE_URL=sqlite:presence.db?mode=rwc
# PostgreSQL (décommenter et ajouter la feature dans Cargo.toml)
# DATABASE_URL=postgres://user:pass@localhost/presence_db

# --- Serveur ---
LISTEN_ADDR=0.0.0.0:5555

# --- Rate limiting ---
ACTIVITY_COOLDOWN_SECS=5
MAX_CLIENTS_PER_IP=8
```

## API Endpoints

Toutes les requêtes et réponses sont en `application/x-www-form-urlencoded`.

### POST /register

Créer un compte en échangeant un code OAuth2 Discord.

**Requête :**
```
code=F6wQAb8FYLrgOrelrLMHNL1PY9DAku
```

**Réponse succès (200) :**
```
uuid=a1b2c3d4-...&aes_key_hex=4e6f7890...
```

**Réponse erreur :**
```
error=discord_error&message=Discord+returned+400
```

### POST /login

Démarrer le challenge d'authentification.

**Requête :**
```
uuid=a1b2c3d4-...
```

**Réponse (200) :**
```
nonce=1234567890
```

### POST /login/verify

Prouver la possession de la clé AES en envoyant le nonce chiffré.

**Calcul côté client (3DS/ESP32) :**
```
nonce:       u64 (8 bytes)
block[0..8]  = nonce en big-endian
block[8..16] = 0x08 (padding PKCS7)
cipher = AES-256-CBC(block, key, IV=0)
cipher_hex = hex(cipher)  // 32 caractères hex
```

**Requête :**
```
uuid=a1b2c3d4-...&cipher_hex=abcdef1234...
```

**Réponse (200) :**
```
success=true&nonce=1234567890
```

### POST /activity

Mettre à jour l'activité Discord, ou l'arrêter (activity_type=255).

**Calcul côté client :**
```
counter:     u64 = dernière valeur + 1 (démarre à nonce+1)
hash = SHA256(state || details || activity_type)  // 32 bytes, concaténation brute
auth_input = counter (8 bytes BE) || hash (32 bytes)  // 40 bytes
padded = auth_input + PKCS7 padding  // 48 bytes
auth_hex = hex(AES-256-CBC(padded, key, IV=0))  // 96 caractères hex
```

**Requête :**
```
uuid=a1b2c3d4-...&counter=1234567891&auth_hex=...&state=Joue+a+Mario&details=Niveau+1-1&activity_type=0
```

**Réponse (200) :**
```
success=true
```

Pour arrêter l'activité : envoyer `activity_type=255`. La session sera supprimée.

**Erreurs possibles :**

| Code HTTP | error | Raison |
|-----------|-------|--------|
| 401 | `session_expired` | Session inactive > 60s ou inexistante |
| 403 | `replay_detected` | Counter déjà utilisé |
| 403 | `auth_failed` | Signature AES/SHA256 invalide |
| 429 | `cooldown` | Trop tôt (attendre ACTIVITY_COOLDOWN_SECS) |

## Client 3DS (C avec libctru)

Le service `ps:ps` de la 3DS fournit les fonctions cryptographiques matérielles :

```c
// Générer bytes aléatoires
PS_GenerateRandomBytes(buf, len);

// AES-256-CBC (clé stockée dans un slot, normal ou local)
// IV = 16 bytes de zéros
u8 iv[16] = {0};
PS_EncryptDecryptAes(16, input, output, AES_256_CBC, NORMAL_KEY, iv);

// SHA256 logiciel : utiliser une implémentation C légère (ex: mbedtls)
```

Protocole côté 3DS :
1. `POST /register` → stocker uuid et aes_key
2. `POST /login` → recevoir nonce
3. Chiffrer nonce avec `PS_EncryptDecryptAes` → `POST /login/verify`
4. Boucle : construire `auth_input` → chiffrer avec `PS_EncryptDecryptAes` → `POST /activity`
5. Envoyer au moins une fois par minute, sinon le serveur coupe la session

## Client ESP32 (C avec mbedtls)

```c
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

mbedtls_aes_context aes;
mbedtls_aes_setkey_enc(&aes, aes_key, 256);

// Chiffrement AES-256-CBC
u8 iv[16] = {0};
mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output);

// SHA256
u8 hash[32];
mbedtls_sha256_ret(data, len, hash, 0);
```

## Structure du code

```
presence-server/src/
├── main.rs              # Entrypoint, initialisation, routes
├── config.rs            # Lecture .env
├── db.rs                # Accès base de données (sea-orm)
├── models.rs            # Entité sea-orm (table users)
├── crypto.rs            # AES-256-CBC, SHA256, nonce
├── session.rs           # Gestion des sessions en mémoire
├── routes/
│   ├── mod.rs
│   ├── register.rs      # POST /register
│   ├── login.rs         # POST /login
│   ├── login_verify.rs  # POST /login/verify
│   └── activity.rs      # POST /activity
└── tasks/
    ├── mod.rs
    ├── timeout.rs       # Timeout 60s des sessions inactives
    └── token_refresh.rs # Rafraîchissement des tokens OAuth2
```

## Base de données

Par défaut : **SQLite** (aucun processus supplémentaire).
Pour **PostgreSQL** : changer la feature dans `Cargo.toml` :
```toml
sea-orm = { version = "1", features = ["sqlx-postgres", "runtime-tokio", "macros"] }
```
Et modifier `DATABASE_URL` dans `.env`.

### Table : `users`

| Colonne | Type | Description |
|---------|------|-------------|
| uuid | TEXT (PK) | UUID v4 |
| aes_key | BLOB (32) | Clé AES-256 unique |
| access_token | TEXT | Token d'accès Discord |
| refresh_token | TEXT | Token de rafraîchissement Discord |
| token_expires_at | INTEGER | Timestamp d'expiration du token (secondes) |
| created_at | INTEGER | Timestamp de création du compte (secondes) |

## Ajouter une route (ex: /ping)

1. Créer `routes/ping.rs`
2. Définir le handler en réutilisant `verify_activity_auth` depuis `crypto.rs`
3. Appeler `session_manager.update_activity()` avec des champs vides (juste pour le keepalive)
4. Ajouter dans `routes/mod.rs` et `main.rs`

## Licence

MIT