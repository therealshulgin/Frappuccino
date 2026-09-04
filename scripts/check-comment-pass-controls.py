#!/usr/bin/env python3
"""Controles negatifs de `check-comment-pass.py`.

Un gate qui ne peut pas echouer ne prouve rien. Ce script le met en echec
volontairement, une fois par famille de violation, et verifie qu'il leve bien.
Sans lui, "le gate est valide" resterait une affirmation de message de commit.

    uv run python scripts/check-comment-pass-controls.py

Chaque controle mute un fichier reel, lance le gate, puis restaure les octets
d'origine dans un `finally`. La lecture et l'ecriture se font en BINAIRE :
passer par le mode texte reecrirait les fins de ligne CRLF en LF et laisserait
l'arbre sale apres un controle cense ne rien changer.

LA BASE DE COMPARAISON EST `HEAD`, PAS `main`
---------------------------------------------
Le gate, lui, se compare a `main` : c'est ce qui l'interesse, l'ecart entre la
branche et le tronc. Ces controles ont besoin de l'inverse. Pour qu'un controle
prouve quelque chose, il faut que la mutation qu'il vient d'ecrire soit le SEUL
ecart que le gate puisse voir ; sinon le travail deja commite sur la branche
suffit a rendre le gate rouge, et les controles qui attendent un vert echouent
sans rien avoir teste. C'est arrive : au troisieme lot, quatre controles sont
tombes parce que la branche portait 53 fichiers reecrits, et pas du tout parce
que le gate se trompait. Passer une autre base en argument reste possible, mais
il faut alors que l'arbre soit propre par rapport a elle.

DEUX SORTES DE CONTROLES, ET IL FAUT SAVOIR POURQUOI
----------------------------------------------------
Les controles EPINGLES citent une chaine precise du depot. Ils sont lisibles :
on voit ce qui est teste. Mais ils pourrissent, et ils pourrissent d'autant plus
vite que la passe fait bien son travail : trois d'entre eux sont tombes en
SETUP KO au troisieme lot, parce que la passe avait reformule les commentaires
sur lesquels ils s'ancraient. Un controle qui ne tourne plus ne dit rien, et il
ne le dit pas bruyamment.

Les controles DECOUVERTS cherchent leur cible dans le depot au moment de tourner,
a partir de la FORME dont ils ont besoin : une ligne de commentaire quelconque,
un identifiant present deux fois dans un meme fichier, un identifiant unique dans
tout le depot. Ils sont moins lisibles, et c'est le prix ; en echange ils
survivent a la reecriture des commentaires, ce qui est exactement ce que ce
depot leur demande.

Regle : quand un controle epingle tombe en SETUP KO, ne le re-epingle pas sur une
autre chaine. Convertis-le en controle decouvert, sinon il retombera au lot
suivant.

La notion d'identifiant est IMPORTEE du gate, jamais recopiee : un controle qui
testerait sa propre definition ne testerait pas le gate.
"""
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "scripts", "check-comment-pass.py")

_spec = importlib.util.spec_from_file_location("comment_pass_gate", GATE)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

METRICS = "mobile/src/main/java/rs/readahead/washington/mobile/util/MetricsFileLogger.kt"
SERVICE = "mobile/src/main/java/rs/readahead/washington/mobile/service/StreamRecordingService.kt"
REGISTRY = "server/app/ratchet_registry.py"
CRYPTO = "crypto-rs/core/src/lib.rs"
HELPSH = "server/deploy/backup-state.sh"
HARDENING = "server/tests/test_relay_blind_hardening.py"
MONITOR = "server/deploy/monitor-health.sh"
STORAGE = "server/app/storage.py"

ANALYSABLES = tuple(sorted(gate.C_LIKE | gate.HASH_LIKE | gate.XML_LIKE))
PREFIXES = ("//", "/*", "*", "#", "<!--")


def sh(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def suivis():
    return [p.strip() for p in sh("git", "ls-files").stdout.splitlines() if p.strip()]


def modifies(base):
    out = sh("git", "diff", "--name-only", base).stdout
    return {p.strip() for p in out.splitlines() if p.strip()}


def lisible(path):
    try:
        with open(os.path.join(ROOT, path.replace("/", os.sep)), "rb") as handle:
            return handle.read().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def candidats(base):
    """Fichiers ou muter est SANS AMBIGUITE.

    On ecarte ce que la passe a deja modifie par rapport a la base : dans un tel
    fichier, le signal du gate melangerait la mutation du controle et le travail
    de la passe, et un controle dont on ne sait pas ce qu'il mesure ne mesure
    rien.
    """
    bouges = modifies(base)
    out = []
    for path in suivis():
        if path.startswith(gate.FORBIDDEN) or path in bouges:
            continue
        if os.path.splitext(path)[1].lower() not in ANALYSABLES:
            continue
        out.append(path)
    return out


def lignes_de_commentaire(src):
    """Index des lignes qui portent du commentaire, par leur forme.

    Heuristique de prefixe, et non l'analyseur du gate : celui-ci retire les
    commentaires sans conserver le nombre de lignes, donc il ne dit pas OU ils
    sont. Une cible mal choisie fait echouer le controle bruyamment, ce qui est
    le comportement voulu.
    """
    return [(i, l) for i, l in enumerate(src.splitlines())
            if l.strip().startswith(PREFIXES)]


def trouve_ligne_de_commentaire(base):
    """C1 : une ligne de commentaire sans identifiant, qu'on allonge."""
    for path in candidats(base):
        src = lisible(path)
        if not src:
            continue
        for _, ligne in lignes_de_commentaire(src):
            nu = ligne.strip()
            if len(nu) < 12 or gate.identifiers(ligne):
                continue
            if src.count(ligne) != 1:
                continue
            return ("C1 commentaire seul (decouvert)", path, ligne,
                    ligne + " (controle negatif)", 1, 1, 0, None)
    return None


def trouve_identifiant_repete(base):
    """C4 : un identifiant present deux fois dans un fichier ; on en retire un.

    Le gate doit alors AVERTIR sans bloquer : l'identifiant existe toujours.
    """
    for path in candidats(base):
        src = lisible(path)
        if not src:
            continue
        vus = {}
        for _, ligne in lignes_de_commentaire(src):
            for ident in gate.identifiers(ligne):
                vus.setdefault(ident, 0)
                vus[ident] += 1
        for ident, n in sorted(vus.items()):
            if n >= 2 and src.count(ident) == n:
                return ("C4 occurrence en baisse (decouvert)", path, ident,
                        "l'audit", n, 1, 0, "Avertissement")
    return None


def trouve_identifiant_unique(base):
    """C11 : un identifiant a prefixe long, unique dans TOUT le depot.

    C'est le trou qui avait echappe au gate jusqu'au deuxieme lot : les
    prefixes de trois lettres et plus n'etaient pas reconnus, et un identifiant
    present a un seul endroit pouvait disparaitre en silence. Sa disparition
    doit BLOQUER.
    """
    total, ou = {}, {}
    for path in suivis():
        if path.startswith(gate.FORBIDDEN):
            continue
        if os.path.splitext(path)[1].lower() not in ANALYSABLES:
            continue
        src = lisible(path)
        if not src:
            continue
        for _, ligne in lignes_de_commentaire(src):
            for ident in gate.identifiers(ligne):
                total[ident] = total.get(ident, 0) + 1
                ou.setdefault(ident, path)
    bouges = modifies(base)
    for ident, n in sorted(total.items()):
        prefixe = ident.split("-")[0]
        if n != 1 or len(prefixe) < 3 or not prefixe.isalpha():
            continue
        path = ou[ident]
        if path in bouges:
            continue
        src = lisible(path)
        if src and src.count(ident) == 1:
            return ("C11 identifiant unique a prefixe long (decouvert)", path,
                    ident, "l'audit", 1, 1, 1, "TRACABILITE")
    return None


# (nom, fichier, ancien, nouveau, occurrences attendues, remplacements,
#  code attendu, marqueur)
# `ancien` vaut None pour un simple ajout en fin de fichier.
# `remplacements` vaut 0 pour tout remplacer, n pour n'en remplacer que n.
EPINGLES = [
    ("C2 litteral de chaine", METRICS,
     'append("  ")', 'append("   ")', 1, 0, 1, "HORS COMMENTAIRE"),
    ("C3 identifiant R-10 disparu", SERVICE,
     "R-10", "l'audit", 3, 0, 1, "TRACABILITE"),
    ("C5 zone interdite crypto-rs", CRYPTO,
     None, "\n// controle negatif\n", 0, 0, 1, "ZONE INTERDITE"),
    ("C6 identifiant en docstring", REGISTRY,
     "R-SRV-3", "audit serveur", 3, 0, 1, "TRACABILITE"),
    ("C7 en-tete imprime par --help", HELPSH,
     "# Backs up the TWO named Docker volumes",
     "# Sauvegarde les DEUX volumes Docker nommes", 1, 0, 1, "SORTIE UTILISATEUR"),
    ("C8 identifiant A-2 disparu", HARDENING,
     "A-2", "l'audit", 2, 0, 1, "TRACABILITE"),
    ("C9 shebang modifie", MONITOR,
     "#!/usr/bin/env bash", "#!/bin/bash", 1, 0, 1, "HORS COMMENTAIRE"),
    ("C10 commentaire a apostrophe", MONITOR,
     "# when uvicorn's asyncio loop wedges",
     "# when uvicorn's event loop wedges", 1, 0, 0, None),
    ("C12 nom technique homonyme", STORAGE,
     "SHA-256 (hex) of the object", "empreinte hex de l'objet", 1, 0, 0, None),
]

def trouve_kdoc_kotlin(base):
    """C13 : un glob de chemin ecrit dans un commentaire de bloc Kotlin.

    Kotlin IMBRIQUE les commentaires de bloc. Ecrire `dossier/*.ext` dans un
    KDoc ouvre un commentaire de plus ; le `*/` du KDoc ne referme que celui-la,
    et tout le reste du fichier devient du commentaire. C'est arrive pour de vrai
    sur StreamUploadManager.kt : la compilation a leve, le gate est reste vert
    parce qu'il retirait les commentaires sans connaitre la regle. Ce controle
    existe pour que cela ne puisse plus repasser en silence.
    """
    for path in candidats(base):
        if not path.endswith(".kt"):
            continue
        src = lisible(path)
        if not src:
            continue
        dans_bloc = False
        for ligne in src.splitlines():
            nu = ligne.strip()
            if not dans_bloc:
                if nu.startswith("/*") and "*/" not in nu:
                    dans_bloc = True
                continue
            if "*/" in nu:
                dans_bloc = False
                continue
            # une ligne de prose a l'interieur du bloc, unique dans le fichier
            if nu.startswith("*") and len(nu) > 24 and src.count(ligne) == 1:
                return ("C13 glob dans un KDoc Kotlin (decouvert)", path, ligne,
                        ligne + " (voir `stream_provenance/*.ots`)", 1, 1, 1,
                        "jamais referme")
    return None


DECOUVERTS = [trouve_ligne_de_commentaire, trouve_identifiant_repete,
              trouve_identifiant_unique, trouve_kdoc_kotlin]


def tracked_changes():
    out = sh("git", "status", "--porcelain", "--untracked-files=no").stdout
    return [line[3:] for line in out.splitlines() if line.strip()]


def joue(controle, base):
    nom, rel, old, new, count, limite, want_code, want_mark = controle
    path = os.path.join(ROOT, rel.replace("/", os.sep))
    with open(path, "rb") as handle:
        original = handle.read()
    try:
        if old is None:
            mutated = original + new.encode("utf-8")
        else:
            needle = old.encode("utf-8")
            seen = original.count(needle)
            if seen != count:
                print("[SETUP KO] {} : '{}' vu {}x, attendu {}x".format(
                    nom, old, seen, count))
                return False
            remplacement = new.encode("utf-8")
            mutated = (original.replace(needle, remplacement, limite) if limite
                       else original.replace(needle, remplacement))
        with open(path, "wb") as handle:
            handle.write(mutated)
        proc = sh("uv", "run", "python", "scripts/check-comment-pass.py", base)
        code, out = proc.returncode, proc.stdout + proc.stderr
    finally:
        with open(path, "wb") as handle:
            handle.write(original)

    ok = code == want_code and (want_mark is None or want_mark in out)
    print("[{}] {:<44} code={} (attendu {}){}".format(
        "OK  " if ok else "ECHEC", nom, code, want_code,
        "" if want_mark is None else "  marqueur {} {}".format(
            want_mark, "present" if want_mark in out else "ABSENT")))
    if not ok:
        for line in out.splitlines():
            print("        {}".format(line))
    return ok


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
    before = tracked_changes()
    if before:
        print("ATTENTION : {} fichier(s) modifie(s) par rapport a {}. Les controles "
              "qui attendent un gate vert vont echouer sans rien prouver ; commite "
              "ou remise avant de les jouer.\n".format(len(before), base))

    controles = list(EPINGLES)
    for chercheur in DECOUVERTS:
        trouve = chercheur(base)
        if trouve is None:
            print("[INTROUVABLE] {} : aucune cible de cette forme dans le depot"
                  .format(chercheur.__doc__.splitlines()[0]))
            continue
        controles.append(trouve)

    manquants = len(EPINGLES) + len(DECOUVERTS) - len(controles)
    echecs = manquants
    for controle in sorted(controles, key=lambda c: int(
            "".join(ch for ch in c[0].split()[0] if ch.isdigit()) or 0)):
        if not joue(controle, base):
            echecs += 1

    leftovers = [p for p in tracked_changes() if p not in before]
    print("\nArbre restaure : {}".format(
        "oui" if not leftovers else "NON -> {}".format(leftovers)))
    print("Controles joues : {} sur {}".format(
        len(controles), len(EPINGLES) + len(DECOUVERTS)))
    print("Controles en echec : {}".format(echecs))
    return 1 if echecs or leftovers else 0


if __name__ == "__main__":
    sys.exit(main())
