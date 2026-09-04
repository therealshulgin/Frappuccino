# Plan Lot 3 — Fermeture D-1 (transport obfusqué) + bascule domaine + break-glass 2-pins

> **Statut : ✅ LIVRÉ + FIELD-VALIDÉ (A+B+C), HEAD `0532792`. D-1 & D-2 fermés.**
> Worktree `xenodochial-morse`. Faits vérifiés sur pièces + état relais lu en SSH 2026-06-27.
> Modèle : Opus 4.8. Décisions therealshulgin prises (voir §0).
>
> **Commits** : A break-glass 2-pins `c03aa31` · B1 marqueur `transport_used` `35f0e71` · B4 flip release ObfQuic `f3d648a` · B1-PSK rotation PSK `12c7c83` · C bascule domaine (β self-signed) `0532792`.
> Field-validé 2 chipsets (OnePlus CPH2653 + Seeker MediaTek) : `transport=obfquic`, 0 fallback / 0 erreur.
> **Stratégie C = β** (cert auto-signé break-glass sur le domaine, PAS de LE — MITM identique car on épingle ; β plus sûr : pas de `system` anchor, pas de footgun renouvellement 90j ; α LE écarté).
> **Clarif claim motto** : une saisie du relais n'expose **aucun** témoignage/identité (E2E + aveugle ; clés TLS relais = transport seul ; même un MITM ne déchiffre pas le `.strm`). Le résidu = forward-MITM/dispo, récupérable via 3ᵉ clé.
> **Prochaine session** : M-1 (noms report-directory opaques `H(report_master‖n)`) + 3ᵉ clé break-glass (réserve off-host jamais sur le relais). **Droppé** : enveloppe de trafic (coût bande-passante). **Reporté au serveur final** : D-1(2) destination-non-reliable (Tor exclu = trop lent).

Ce plan remédie les deux trouvailles HIGH structurelles de l'audit design 2026-06-26
(critique de design du 2026-06-26, rapport interne non publié) qui touchent au motto réseau :

- **D-1** : le binaire release parle en TLS direct vers l'IP brute `136.244.101.236:8443`
  (`RustUploadTransport.kt:42-44` = `DIRECT_TLS`). Le DPI voit *quand* et *que* tu uploades vers le relais.
- **D-2** : pin TLS unique sans backup (`pin.rs:59` `pin_sha256:[u8;32]`), mono-IP, mono-relais.
  Toute rotation de cert brique le parc → le téléphone redevient un coffre faute de canal de sortie.

Plus la bascule vers le nom de domaine `relay.shake-document-protect.org` (axe disponibilité, ROADMAP 1.2/1.3).

**Contrainte motto + ratchet** : rien dans ce plan ne touche le ratchet ni `crypto-core`.
Le verifier passe de pin-unique à pin-set (additif, constant-time préservé) ; le transport
est un sélecteur de mode. **Ratchet intouché. Jamais de rustine : la clé unifiée est le design
long-terme qui supprime tout flag-day futur.**

---

## 0. Décisions cadrantes (therealshulgin, 2026-06-27)

1. **Clé break-glass = clé unique unifiée.** Une seule clé EC P-256 pré-générée + backupée
   off-host sert à la fois (a) le 2ᵉ pin break-glass (cert auto-signé + ancre embarquée) ET
   (b) le futur cert LE (`certbot --reuse-key` → même SPKI). Conséquence : le cutover domaine
   ne change **aucun pin**, juste le host.
2. **Domaine partout + Salamander sur le chemin principal.** On accepte qu'en cas de blocage
   UDP, le fallback DirectTls fuite `SNI=domaine` en clair ; on mise sur ObfQuic comme chemin
   principal (qui XOR le ClientHello) + un nom de domaine aussi neutre que possible. Un seul
   host à maintenir.

---

## 1. État vérifié du relais (SSH read, 2026-06-27)

L'infra de transport obfusqué est **déjà déployée et vivante** sur `136.244.101.236` :

| Port | Process | Rôle | État |
|---|---|---|---|
| `:8443/tcp` | nginx | DirectTls (chemin release **actuel**) | live |
| `:8444/tcp+udp` | caddy (`frappuccino-quic-front`, docker) | front QUIC h3 (terminaison TLS) | Up 5 j |
| `:8445/udp` | `frappuccino-obfs-proxy` (systemd) | Salamander de-obfs → forward `:8444` | **active** (pid vivant) |

- Binaire obfs : `/opt/frappuccino/obfs/frappuccino-obfs-proxy` ; secret : `/opt/frappuccino/obfs/obfs.env` (perm 600).
- Unité systemd : `crypto-rs/obfs-proxy/deploy/frappuccino-obfs-proxy.service`
  (`ExecStart=… 0.0.0.0:8445 127.0.0.1:8444`).

**Conséquence majeure pour le scope** : les commentaires de `quic.rs:61-67,112` étaient exacts
(le serveur obfs tourne). La trouvaille D-1 vise spécifiquement le **binaire client release**
qui reste `DIRECT_TLS`. **Fermer D-1 est donc surtout une bascule client**, pas un stand-up
serveur. Le Lot 3 s'en trouve fortement allégé.

---

## 2. La colonne vertébrale : une seule clé (décision 0.1)

Pré-générer **une** clé EC P-256, la backuper off-host chiffrée (`age`), et l'utiliser pour tout :

```
                         clé EC P-256 "next" (pré-générée, backup age off-host)
                          │
        ┌─────────────────┼──────────────────────┐
        ▼                                          ▼
  Break-glass (A)                            Futur LE (C)
  cert auto-signé sous cette clé            certbot --reuse-key sur cette même clé
  → 2ᵉ pin SPKI semé dans le parc           → cert public, MÊME SPKI que le pin déjà semé
  → ancre embarquée @raw/frappuccino_ca_next → cutover domaine = host-only, 0 nouveau pin
```

Le SPKI d'une clé est invariant par renouvellement de cert tant que la clé ne change pas
(`pin.rs` hashe `subject_pki.raw`). Donc : pin semé une fois (A), réutilisé tel quel à la
bascule LE (C). Zéro flag-day, zéro re-pré-semage.

**Geste opérateur (therealshulgin, hors auto-guard)** : générer la clé + cert auto-signé, backup `age`,
me transmettre le SPKI base64. Commande de référence (à valider ensemble en B/A) :
```bash
openssl ecparam -name prime256v1 -genkey -noout -out next.key
openssl req -new -x509 -key next.key -days 3650 -out next.crt \
  -subj "/CN=Frappuccino Relay" -addext "subjectAltName=DNS:relay.shake-document-protect.org,IP:136.244.101.236"
# SPKI pin (ce que je câble côté client) :
openssl x509 -in next.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64
age -p -o next.key.age next.key && shred -u next.key   # backup chiffré off-host, source détruite
```

---

## 3. Workstream A — Break-glass 2-pins (ferme D-2) · sans-regret, local

Convertit le pin unique en **pin-set qui accepte l'union** (le peer matche n'importe lequel),
dans toutes les couches enforce. Ne faiblit pas MITM (2ᵉ clé qu'on contrôle, pas un fallback CA).

### A.1 Rust `crypto-rs/stream/src/pin.rs`
- `PinnedCertVerifier` : `pin_sha256: [u8; 32]` → `pins: Vec<[u8; 32]>` (`:59`).
- `verify_server_cert` (`:134-172`) : itérer sur `pins`, `ct_eq` par pin, **OR sans early-exit**
  (constant-time : comparer contre **chaque** pin, ne pas court-circuiter), accept si un match,
  hard-fail si aucun. RT-01 (vérif signature `:174-195`) **inchangé**.
- `new()` : construit le set depuis `const PIN_PRIMARY` (= `QnGK0KvRC1vt2C4rrxwHIj0/pUbogVtTCesBK3sZXKY=`)
  + `const PIN_NEXT` (= SPKI de la clé §2).
- `with_pin_and_host` (tests + QUIC self-signed) : reste mono-pin (vec à 1 élément).
- `prod_target()` QUIC (`quic.rs:107-120`) : adopte le set (sinon ObfQuic en release ignorerait
  le break-glass une fois B livré).
- Tests : ajouter un cas « peer matche le 2ᵉ pin → accept » + « peer ne matche aucun → BadPin »,
  en gardant `embedded_cert_spki_matches_pin` et le RT-01 E2E.

### A.2 Android NSC `mobile/src/main/res/xml/network_security_config.xml`
- 2ᵉ `<pin>` dans `<pin-set>` (`:33-35`).
- **Subtilité que le runbook §6 occulte** : côté NSC/OkHttp le pin est vérifié **après** la
  validation de chaîne contre `<trust-anchors>`. Un cert break-glass auto-signé sous une autre
  clé ne chaîne **pas** à `@raw/frappuccino_ca` → la validation échouerait malgré un pin OK.
  Donc embarquer le cert break-glass comme **2ᵉ ancre** : `<certificates src="@raw/frappuccino_ca_next"/>`
  (`:30-32`) + fichier `mobile/src/main/res/raw/frappuccino_ca_next.crt`.
  (Le chemin Rust/rustls, lui, bypass la chaîne et ne pinne que le SPKI → pas d'ancre nécessaire
  côté Rust ; mais NSC + OkHttp en ont besoin.)

### A.3 OkHttp `mobile/.../util/jobs/UploadHttpClient.kt`
- 2ᵉ `const NEXT_PIN = "sha256/…"` + 2ᵉ `.add(SERVER_HOST, NEXT_PIN)` (`:70`, `:75-76`).

### A.4 Fixtures + `.so` + gate
- Copier le cert break-glass dans les fixtures embarquées (cf. les 6 localisations §6).
- Régén `.so` toutes-ABI (`TARGETS=arm64-v8a,armeabi-v7a,x86_64 bash crypto-rs/build-android.sh`).
- **Combler le trou « `checkRustSoFresh` = mtime only »** : ajouter au gate un value-grep
  vérifiant que les 6 localisations **et** le `.so` portent les **deux** pins (primary + next).

### A.5 Qui fait quoi / gates
- therealshulgin : génère + backup la clé §2, transmet le SPKI. (Geste destructif/secret → ton GO.)
- Moi : plomberie pin-set (local, sous GO). Gates : `cargo clippy -p frappuccino-crypto-stream
  --all-targets -- -D warnings` + `cargo test -p frappuccino-crypto-stream` + `assembleDebug`.
- Field-test : unlock + 1 enregistrement + drain OK sur Seeker **et** OnePlus (le 2ᵉ pin est
  dormant tant que le relais sert le cert primary → 0 régression attendue ; on valide juste que
  la plomberie ne casse pas le chemin courant).

---

## 4. Workstream B — Ferme D-1 (1) · bascule client (infra serveur déjà live, cf. §1)

### B.0 Reads de vérification (avant tout changement)
- Confirmer que Caddy `:8444` présente bien le **SPKI pinné** `QnGK0K…` (sinon ObfQuic échoue
  le pin) : lire le Caddyfile / probe TLS du `:8444`.
- Vérifier la **parité PSK** : client `prod_target` (`quic.rs:116-118`, `c35bd9…991`) ↔ relais
  `/opt/frappuccino/obfs/obfs.env` (comparer **sans échoer** le secret, ex. via SHA-256 des deux).
- Probe end-to-end à travers `:8445` (un PUT obfusqué arrive-t-il à Caddy puis au server ?).

### B.1 Re-provisioning PSK (publication)
- Générer un PSK frais (32 octets hex). therealshulgin : l'écrit dans `obfs.env` + restart
  `frappuccino-obfs-proxy` (gestes serveur, ton GO). Moi : le câble dans `prod_target`.
- Le PSK est un secret d'obfuscation app-embarqué (pas une clé per-user) ; sa rotation propre à
  la publi évite que le PSK de dev fuite dans le binaire public.

### B.2 PoC débit lossy (ROADMAP §10.9) — gate de qualité avant flip
- Valider le **goodput ObfQuic** sur un lien réellement perdant (ex. `tc netem loss 5%`),
  vs DirectTls, avant de basculer le release. Le cap MTU `−8` (Salamander `SALT_LEN`) est déjà
  géré (`quic.rs:565-570`, `initial_mtu(1200)` + `upper_bound(1444)`).

### B.3 Flip release (GO-gated)
- `RustUploadTransport.kt:42-44` : branche release `DIRECT_TLS` → `OBF_QUIC`.
- **Garder le fallback automatique QUIC→DirectTls** (latch `QUIC_DEGRADED`, `quic.rs:165-230`) :
  un réseau UDP-bloqué retombe en DirectTls **dans Rust** (même bearer, heap-0) sans perte.

### B.4 Résidu honnête (à documenter, pas à masquer)
- Sous blocage UDP, le fallback DirectTls **ré-expose le signal IP-directe**.
- D-1 sous-objectif **(2) destination-non-reliable** (front partagé/CDN « foule » ou rotation
  d'IP) reste **ouvert** : ni B ni C ne le ferment. À porter explicitement dans POSITIONNEMENT
  (« le binaire ne cache pas *que* tu parles au relais quand l'UDP est bloqué »).

---

## 5. Workstream C — Domaine `relay.shake-document-protect.org` + LE (1.2/1.3)

### C.1 Pré-requis
- DNS A-record `relay.shake-document-protect.org` → `136.244.101.236` (vérifier qu'il est posé).
- `certbot --reuse-key` sur la **clé §2** → cert LE public, **SPKI = le 2ᵉ pin déjà semé** (A).
  Ex. : `certbot certonly --webroot -d relay.shake-document-protect.org --key-type ecdsa
  --elliptic-curve secp256r1 --reuse-key` (ou CSR construit sur la clé fixe). Confirmer
  `SPKI(cert LE) == PIN_NEXT` avant tout ship. **Sans `--reuse-key`, chaque renouvellement ~90j
  reminte une clé → nouveau SPKI → rebuild trimestriel (pire que le statu quo) : footgun à éviter.**

### C.2 Changement de host (cutover one-time)
- 4 défauts d'URL Kotlin (host:port) : `StreamRecordingService.kt:51`, `StreamSettingsActivity.kt:278`,
  `OnBoardSetPinFragment.kt:329`, `UploadHttpClient.kt:63` (host OkHttp).
- Host compile-time du pin : `pin.rs:39` `PINNED_HOST` ; NSC `<domain>` (`:29`).
- **Rework trust-anchor NSC** : LE est publiquement-trusté → re-ajouter une ancre publique
  (`system`) ou pinner l'intermédiaire LE, et revoir `expiration` (cf. NSC commentaire `:24-27`).
  Le `PIN_NEXT` reste le pin enforce (SPKI de la clé) → MITM toujours fermé.

### C.3 SNI (décision 0.2 : accepté)
- Aujourd'hui DirectTls→IP n'envoie **aucun SNI** (IP littérale). Au domaine, DirectTls→domaine
  enverra `SNI=domaine` en clair. Salamander ne masque le SNI que sur le chemin **ObfQuic**
  (ClientHello XOR'd). Décision : on accepte la fuite sur le fallback, ObfQuic est le chemin
  principal, domaine aussi neutre que possible. À documenter dans POSITIONNEMENT.

---

## 6. Référentiel — les localisations à garder synchrones

**6 localisations de pin** (runbook §4, à porter les 2 pins) :
1. `crypto-rs/stream/src/pin.rs:36` (+ `PIN_NEXT`)
2. `mobile/src/main/res/xml/network_security_config.xml:34` (+ 2ᵉ `<pin>` + 2ᵉ ancre)
3. `mobile/.../util/jobs/UploadHttpClient.kt:70` (+ `NEXT_PIN`)
4. `crypto-rs/stream/assets/frappuccino_ca.crt` (+ `_next`)
5. `mobile/src/main/res/raw/frappuccino_ca.crt` (+ `frappuccino_ca_next.crt`)
6. `mobile/src/main/jniLibs/*/libuniffi_frappuccino.so` (régén, pas édité main)
   (+ fixture androidTest `stream-crypto/src/androidTest/...` déjà en DRIFT, test-only, à resync.)

**4 localisations de host-URL** (cutover domaine, C.2) : `StreamRecordingService.kt:51`,
`StreamSettingsActivity.kt:278`, `OnBoardSetPinFragment.kt:329`, `UploadHttpClient.kt:63`
+ `pin.rs:39` `PINNED_HOST` + NSC `<domain>` `:29`.

---

## 7. Séquencement + GO-gates

```
A (break-glass, sans-regret, local)
  └─ therealshulgin génère/backup la clé §2 → SPKI
  └─ plomberie pin-set + ancre + .so + gate CI       [GO build local]
  └─ field-test Seeker + OnePlus (2ᵉ pin dormant)
        │
B (ferme D-1(1), bascule client ; infra serveur déjà live)
  └─ B.0 reads (Caddy SPKI, parité PSK, probe e2e)   [reads]
  └─ B.1 re-provision PSK                             [GO serveur therealshulgin]
  └─ B.2 PoC débit lossy §10.9                        [gate qualité]
  └─ B.3 flip release OBF_QUIC + fallback             [GO]
        │
C (domaine + LE ; SPKI inchangé grâce à §2)
  └─ certbot --reuse-key, vérif SPKI==PIN_NEXT        [GO serveur therealshulgin]
  └─ cutover host one-time + rework ancre NSC         [GO]
```

Tout est **GO-gated et lié à la publication 8.2.5** (push à la publi, repo sans remote).
Aucune écriture serveur par moi (auto-guard) : je prépare, therealshulgin lance, je vérifie en reads.

---

## 8. Hors scope (documenté)

- **D-1 sous-objectif (2)** destination-non-reliable (front partagé/CDN ou rotation IP) :
  axe distinct, plus lourd ; documenté comme résidu, pas traité dans ce lot.
- **H-1** (route oracle `GET /auth/v2/status/{ed25519_pk}`, `auth_v2.py:375-391`, HIGH, fix
  trivial serveur, le client ne l'appelle pas) : **adjacent**, traitable en parallèle si souhaité.
- R-SRV-8 backup `age` du keystore relais : geste opérateur (recoupe la clé §2).

---

## 9. Matrice de field-test (à remplir au fil des lots)

| Lot | Device | Scénario | Résultat | Statut |
|---|---|---|---|---|
| A | OnePlus (P2) | unlock + 33 min/396 chunks + drain | 0 régression, `transport=rust` SUCCESS (2ᵉ pin dormant) | ✅ |
| B2 | OnePlus + Seeker | enr sur ObfQuic prod | `transport=obfquic` ×26 / ×40, 0 fallback/erreur | ✅ |
| B1-PSK | OnePlus + Seeker | enr avec PSK frais | `transport=obfquic` ×13 / ×10, parité SHA-256 OK | ✅ |
| C | OnePlus + Seeker | cutover domaine, enr | `transport=obfquic` ×9 / ×17 via le domaine, 0 erreur host/pin/DNS | ✅ |
