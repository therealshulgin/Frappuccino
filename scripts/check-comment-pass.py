#!/usr/bin/env python3
"""Gate de la passe de lisibilite des commentaires.

Prouve mecaniquement qu'une passe editoriale n'a touche QUE des commentaires.
Si ce script sort en 0, les octets executes sont identiques a ceux de la base :
aucune revalidation terrain n'est requise, meme si du code de capture est
concerne. C'est la propriete qui rend la passe peu risquee, et c'est exactement
celle qu'une substitution mecanique detruit, parce qu'elle traverse les
litteraux de chaine.

    uv run python scripts/check-comment-pass.py [BASE_REF]     # defaut : main

Quatre familles de violations, toutes bloquantes :

  1. ZONE INTERDITE   un fichier hors perimetre de la passe a ete modifie.
  2. SORTIE UTILISATEUR le script imprime son propre en-tete en reponse a
     --help : ces commentaires sont de la sortie, donc du comportement, et le
     retrait des commentaires les effacerait avant comparaison.
  3. HORS COMMENTAIRE une difference subsiste apres retrait des commentaires
     (chaine de log, nom de test, message d'assertion, valeur de config).
  4. TRACABILITE      un identifiant stable a DISPARU du fichier. F-C1,
     R-SRV-1, BT-HIGH-10, les renvois de section relient un finding au test
     qui le verrouille ; les perdre casse la piste qu'un auditeur suivra.
     Une simple baisse d'occurrences (l'identifiant subsiste) sort en
     avertissement non bloquant : c'est la trace normale d'une fusion de
     deux blocs redondants, precisement l'edition qu'on veut encourager.

Le retrait des commentaires respecte les litteraux de chaine : un `//` dans une
URL n'est pas un commentaire. Pour Python, la comparaison porte sur l'AST
docstrings retires, ce qui prouve l'equivalence semantique plutot que
textuelle : une docstring est de la documentation, donc nettoyable.
"""
import ast
import re
import subprocess
import sys

# Hors perimetre de la passe : perimetre d'audit declare (AUDIT_SCOPE_RUST.md),
# entrees de preuve et portes de securite. 16 % du bruit, 100 % du risque.
FORBIDDEN = ("crypto-rs/", ".semgrep/")

C_LIKE = {".rs", ".kt", ".java", ".gradle", ".kts", ".scss", ".c", ".h"}
HASH_LIKE = {".py", ".sh", ".toml", ".yaml", ".yml", ".properties", ".cfg"}
XML_LIKE = {".xml", ".html", ".svg"}
HASH_NAMES = {"Dockerfile", "docker-compose.yml"}

# Recensement 2026-08-27 : le vocabulaire d'audit du depot compte 84 identifiants
# distincts de la forme <lettres>-<chiffres>, bien au-dela des prefixes qu'on
# croyait exhaustifs. A cote de F-C1 / R-SRV-1 / BT-HIGH-09 vivent A-2, E-1, L-9,
# M-1, RT-07, C-03, KT-50518. Enumerer les prefixes un par un revenait a en
# oublier, on reconnait donc la FORME. Les trois premieres alternatives vont du
# plus long au plus court pour que R-SRV-1 ne se fasse pas tronquer.
#
# Le \b initial suffit a ecarter les acronymes techniques : UTF-8, SHA-256 et
# AES-256 ont trois lettres, la forme n'en accepte que deux. P-256 et KT-50518
# passent, et c'est tres bien : un nom de courbe et un numero de bug amont sont
# eux aussi des faits qu'une reecriture ne doit pas dissoudre.
# Deuxieme elargissement (2026-08-27, cartographie stream-crypto) : les prefixes
# de trois lettres et plus echappaient a tout. `Red MED-5` n'existe qu'a UN seul
# endroit du depot, dans un commentaire de ChunkUploadQueue.kt : ce commentaire
# est le seul depositaire du finding, et sa disparition passait en vert.
SECTION = "§"
IDENTIFIERS = re.compile(
    r"\b[A-Z]{1,2}-[A-Z]+-\d+"
    r"|\b[A-Z]{1,2}-[A-Z]+\d+"
    r"|\b[A-Z]{2,6}-[A-Z]\d+(?:-\d+)?"   # IMP-R1-4, SPEED-R1-1, FRAG-R1-4, STRM-E2
    r"|\b[A-Z]{1,6}-\d+"                 # MED-5, HIGH-7, CRIT-01, GATE-2, A-2
    r"|\bWP-[A-G]\b"
    r"|" + SECTION + r"\d+(?:\.\d+)*"
    r"|[①-⑳]"  # audit ①..⑳, renvois vers la suite formelle du ROADMAP
)

# Meme forme qu'un identifiant d'audit sans en etre un. Les retirer d'un
# commentaire qu'on resserre est une edition legitime, pas une piste coupee, et
# les proteger rendrait le gate bruyant : BIP-39 apparait 274 fois, SHA-256 147.
# Les CVE, elles, restent protegees : une reference CVE EST de la tracabilite.
NOT_IDENTIFIERS = frozenset((
    "BIP-39", "SHA-1", "SHA-256", "SHA-512", "UTF-8", "UTF-16", "AES-128",
    "AES-256", "ISO-8859", "P-256", "AGPL-3", "BSD-2", "BSD-3", "BSL-1",
    "MIT-0", "MPL-2", "HTTP-0", "HTTP-1", "HTTP-2", "HTTP-3",
))


def identifiers(text):
    """Identifiants d'audit du texte, noms techniques homonymes ecartes."""
    return [i for i in IDENTIFIERS.findall(text) if i not in NOT_IDENTIFIERS]

# Un script qui imprime son propre en-tete : `sed -n '1,40p' "$0"` en reponse a
# --help. Ces lignes de commentaire SONT la sortie utilisateur, donc du
# comportement. C'est le seul cas connu ou la garantie centrale du gate est
# fausse : le retrait des commentaires les efface avant comparaison, la passe
# reecrit le texte d'aide, et rien ne leve. Trouve par la cartographie du
# 2026-08-27 sur trois scripts de server/deploy/.
SELF_READ = ("sed ", "head ", "awk ")

QUOTES = ('"', "'")


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


# Langages ou les commentaires de bloc S'IMBRIQUENT. Kotlin et Rust comptent les
# ouvertures ; Java, C et Groovy ferment sur le premier `*/` rencontre. La
# distinction n'est pas theorique : une passe commentaires a ecrit un glob de
# chemin dans un KDoc, la sequence `/*` de `stream_provenance/*.ots` a ouvert un
# commentaire de plus, le `*/` du KDoc n'a referme que celui-la, et 500 lignes de
# code sont devenues du commentaire. La compilation a leve, pas ce gate : il
# retirait les commentaires sans connaitre la regle, donc il comparait deux
# versions amputees de la meme facon et concluait « identique ». Sa garantie
# centrale etait fausse sur ce fichier.
NESTED_BLOCK_COMMENTS = {".kt", ".kts", ".rs"}


def block_comment_depth(src, nested):
    """Profondeur de commentaire de bloc en fin de fichier, 0 si equilibre.

    Une profondeur non nulle veut dire qu'un `/*` n'est jamais referme : tout ce
    qui suit est avale. On la mesure a part pour pouvoir le DIRE, au lieu de
    laisser l'auditeur deviner devant un « difference hors commentaire ».
    """
    depth, i, n = 0, 0, len(src)
    while i < n:
        c = src[i]
        if depth == 0 and c == "r" and i + 1 < n and src[i + 1] in ('"', "#"):
            j, hashes = i + 1, 0
            while j < n and src[j] == "#":
                hashes, j = hashes + 1, j + 1
            if j < n and src[j] == '"':
                term = '"' + "#" * hashes
                end = src.find(term, j + 1)
                if end == -1:
                    break
                i = end + len(term)
                continue
        if depth == 0 and c in QUOTES:
            quote, j = c, i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == quote or src[j] == "\n":
                    break
                j += 1
            i = j + 1
            continue
        if depth == 0 and c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            if depth == 0 or nested:
                depth += 1
            i += 2
            continue
        if depth > 0 and c == "*" and i + 1 < n and src[i + 1] == "/":
            depth -= 1
            i += 2
            continue
        i += 1
    return depth


def strip_c_like(src, nested=False):
    """Retire les commentaires // et /* */ en preservant les litteraux.

    `nested` suit la regle du langage : voir NESTED_BLOCK_COMMENTS.
    """
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        # raw string Rust : r"..." ou r#"..."#
        if c == "r" and i + 1 < n and (src[i + 1] == '"' or src[i + 1] == "#"):
            j, hashes = i + 1, 0
            while j < n and src[j] == "#":
                hashes, j = hashes + 1, j + 1
            if j < n and src[j] == '"':
                term = '"' + "#" * hashes
                end = src.find(term, j + 1)
                if end == -1:
                    out.append(src[i:])
                    break
                out.append(src[i:end + len(term)])
                i = end + len(term)
                continue
        if c in QUOTES:
            quote, j = c, i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == quote or src[j] == "\n":
                    break
                j += 1
            out.append(src[i:j + 1])
            i = j + 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            if not nested:
                j = src.find("*/", i + 2)
                i = n if j == -1 else j + 2
                continue
            depth, i = 1, i + 2
            while i < n and depth:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth, i = depth + 1, i + 2
                    continue
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth, i = depth - 1, i + 2
                    continue
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_hash(src):
    """Retire les commentaires #.

    Une ligne ENTIEREMENT commentaire part quelles que soient ses apostrophes.
    La parite des quotes ne sert qu'a decider d'un commentaire de FIN de ligne,
    ou couper au mauvais endroit amputerait du code. Faire l'inverse rendait le
    gate faussement rouge des qu'un commentaire contenait "aren't" ou "therealshulgin's"
    (parite impaire), c'est-a-dire sur la moitie de la prose anglaise et sur la
    quasi-totalite de la prose francaise.

    Le shebang est du comportement, pas un commentaire : il reste.
    """
    res = []
    for index, line in enumerate(src.splitlines()):
        head = line.lstrip()
        if head.startswith("#"):
            # Le shebang commence par # mais choisit l'interpreteur : il doit
            # survivre au retrait, sinon le passage de /usr/bin/env bash a
            # /bin/sh serait invisible. Trou pre-existant : la branche
            # commentaire-de-fin-de-ligne coupait a l'index 0 et le vidait.
            res.append(line if index == 0 and head.startswith("#!") else "")
            continue
        if line.count("'") % 2 == 0 and line.count('"') % 2 == 0:
            idx = line.find("#")
            if idx != -1:
                line = line[:idx]
        res.append(line)
    return "\n".join(res)


def prints_own_header(src):
    """Renvoie la ligne fautive si le script relit son propre source."""
    for line in src.splitlines():
        if '"$0"' in line and any(tool in line for tool in SELF_READ):
            return line.strip()
    return None


def strip_xml(src):
    out, i = [], 0
    while True:
        j = src.find("<!--", i)
        if j == -1:
            out.append(src[i:])
            return "".join(out)
        out.append(src[i:j])
        k = src.find("-->", j)
        if k == -1:
            return "".join(out)
        i = k + 3


def norm(text):
    return "\n".join(x.strip() for x in text.splitlines() if x.strip())


def py_equivalent(old, new):
    """Compare deux sources Python, docstrings retires. Renvoie (ok, erreur)."""
    def clean(src):
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
                body = node.body
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    node.body = body[1:] or [ast.Pass()]
        return ast.dump(tree)

    try:
        return clean(old) == clean(new), None
    except SyntaxError as exc:
        return False, "syntaxe invalide : {}".format(exc)


def extension_of(path):
    name = path.rsplit("/", 1)[-1]
    if "." in name:
        return "." + name.rsplit(".", 1)[-1].lower(), name
    return "", name


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "main"
    if sh("git", "rev-parse", "--verify", base).returncode != 0:
        print("Base introuvable : {}".format(base))
        return 2

    changed = [p for p in sh("git", "diff", "--name-only", base).stdout.splitlines()
               if p.strip()]
    if not changed:
        print("Aucun fichier modifie par rapport a {}.".format(base))
        return 0

    forbidden, non_comment, lost, warned, printed = [], [], [], [], []
    checked = 0

    for path in changed:
        if path.startswith(FORBIDDEN):
            forbidden.append(path)
            continue

        before = sh("git", "show", "{}:{}".format(base, path))
        if before.returncode != 0:
            continue  # fichier ajoute par la passe : aucune base de comparaison
        old = before.stdout
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                new = handle.read()
        except OSError:
            continue

        ext, name = extension_of(path)

        culprit = prints_own_header(old) or prints_own_header(new)
        if culprit:
            printed.append((path, culprit))
            continue

        if ext == ".py":
            ok, err = py_equivalent(old, new)
            if not ok:
                non_comment.append((path, err or "AST different"))
        elif ext in C_LIKE:
            nested = ext in NESTED_BLOCK_COMMENTS
            depth = block_comment_depth(new, nested)
            if depth:
                non_comment.append((path, "commentaire de bloc jamais referme "
                                          "(profondeur {} en fin de fichier) : "
                                          "tout ce qui suit est avale".format(depth)))
            elif norm(strip_c_like(old, nested)) != norm(strip_c_like(new, nested)):
                non_comment.append((path, "difference hors commentaire"))
        elif ext in HASH_LIKE or name in HASH_NAMES:
            if norm(strip_hash(old)) != norm(strip_hash(new)):
                non_comment.append((path, "difference hors commentaire"))
        elif ext in XML_LIKE:
            if norm(strip_xml(old)) != norm(strip_xml(new)):
                non_comment.append((path, "difference hors commentaire"))
        else:
            non_comment.append((path, "type non analysable, a revoir a la main"))
        checked += 1

        # Bloquant : l'identifiant a disparu du fichier, la piste est coupee.
        # Simple avertissement : il a perdu des occurrences mais subsiste, ce
        # qui est le resultat NORMAL d'une fusion de deux blocs redondants.
        # Bloquer la-dessus rendrait le gate bruyant sur l'edition meme qu'on
        # cherche a encourager, et un gate bruyant finit contourne.
        old_ids = identifiers(old)
        new_ids = identifiers(new)
        gone = sorted(set(old_ids) - set(new_ids))
        if gone:
            lost.append((path, gone))
        thinned = sorted((ident, old_ids.count(ident), new_ids.count(ident))
                         for ident in set(old_ids) & set(new_ids)
                         if old_ids.count(ident) > new_ids.count(ident))
        if thinned:
            warned.append((path, thinned))

    print("Base : {}   fichiers modifies : {}   analyses : {}".format(
        base, len(changed), checked))

    if forbidden:
        print("\nZONE INTERDITE ({}) : hors perimetre de la passe".format(len(forbidden)))
        for path in forbidden:
            print("   {}".format(path))
    if printed:
        print("\nSORTIE UTILISATEUR ({}) : le commentaire est imprime par le "
              "script lui-meme".format(len(printed)))
        for path, culprit in printed:
            print("   {}\n      {}".format(path, culprit))
    if non_comment:
        print("\nHORS COMMENTAIRE ({}) : le comportement peut avoir change".format(
            len(non_comment)))
        for path, why in non_comment:
            print("   {}  [{}]".format(path, why))
    if lost:
        print("\nTRACABILITE ({}) : identifiants disparus".format(len(lost)))
        for path, ids in lost:
            print("   {}  -> {}".format(path, ", ".join(ids)))
    if warned:
        print("\nAvertissement ({}) : occurrences en baisse, identifiant "
              "toujours present (fusion de blocs ? a confirmer a l'oeil)".format(
                  len(warned)))
        for path, items in warned:
            detail = ", ".join("{} {}->{}".format(i, a, b) for i, a, b in items)
            print("   {}  {}".format(path, detail))

    if forbidden or printed or non_comment or lost:
        print("\nGATE : ECHEC")
        return 1

    print("\nGATE : OK  (seuls des commentaires ont change ; "
          "octets executes identiques)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
