#!/usr/bin/env python3
"""
test_route_surface.py — la surface HTTP du relais est un inventaire figé.

Un auditeur lit les routes en premier. Jusqu'au 2026-09-03 il en trouvait deux
qui ne servaient à rien : `GET /p/{slug}` et `GET /{slug}`, compat Tella,
répondant un enregistrement de projet constant derrière un JWT, sans aucun
appelant dans l'arbre. La seconde était un **fourre-tout à la racine**.

Elles ont été retirées. Ce fichier est ce qui les empêche de revenir sans que
personne ne s'en aperçoive, sur le modèle du compte de harnais de `run-kani.sh` :
on n'assertе pas que « rien n'a cassé », on assertе **exactement ce qui doit
exister**. Une route ajoutée ou retirée fait rougir ce test, donc quelqu'un
regarde. C'est délibérément rigide : le coût est une ligne à mettre à jour quand
la surface change vraiment, le bénéfice est qu'elle ne change jamais par accident.

Le second test porte sur la forme, pas sur l'inventaire :
**aucune route ne doit être un paramètre de chemin à la racine.** Trois
commentaires de `main.py` ont longtemps affirmé que l'ordre de montage des
routers protégeait `/api/v2/archive/*` et `/api/v2/timestamp` du fourre-tout.
C'était faux : un paramètre de chemin Starlette compile en `[^/]+` ancré, donc
`^/(?P<slug>[^/]+)$` ne peut pas matcher un chemin à six segments. **Cet**
ordre-là ne protégeait rien.

Mais il reste une contrainte d'ordre, une vraie, et elle n'a rien à voir avec les
routes à un segment : dans `archive.py`, `/reports/{report_id}/blobs` doit être
déclarée **avant** `/reports/{report_id}/{filename}`. Les deux ont quatre
segments ; si l'ordre s'inversait, le littéral `blobs` serait capté par
`{filename}` et lister un rapport deviendrait le téléchargement d'un fichier
nommé « blobs ». Aucune erreur, une réponse plausible et fausse. Le quatrième
test l'épingle, parce qu'une garde qui déclare « l'ordre n'est plus porteur »
alors qu'il l'est encore quelque part autorise précisément la permutation qui
casse.
"""

import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))

from app.main import app  # noqa: E402


# L'inventaire complet, méthode par méthode. FastAPI ajoute lui-même les quatre
# routes de documentation ; elles sont listées parce qu'un inventaire partiel
# n'est pas un inventaire.
SURFACE_ATTENDUE = {
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("GET", "/redoc"),
    ("GET", "/health"),
    ("PUT", "/file/{report_id}/{filename}"),
    ("POST", "/auth/challenge"),
    ("POST", "/auth/v2/enroll"),
    ("POST", "/auth/v2/verify"),
    ("POST", "/auth/v2/rotate-batch"),
    ("POST", "/auth/v2/logout"),
    ("GET", "/api/v2/archive/reports/{report_id}/blobs"),
    ("GET", "/api/v2/archive/reports/{report_id}/{filename}"),
    ("POST", "/api/v2/timestamp"),
}


def _surface_reelle():
    """(méthode, chemin) pour chaque route servie. HEAD est ignoré : Starlette
    l'ajoute d'office à côté de GET sur les routes de documentation."""
    out = set()
    for route in app.routes:
        chemin = getattr(route, "path", None)
        if chemin is None:
            continue
        for methode in sorted(getattr(route, "methods", None) or []):
            if methode == "HEAD":
                continue
            out.add((methode, chemin))
    return out


def test_la_surface_http_est_exactement_celle_attendue():
    reelle = _surface_reelle()
    en_trop = reelle - SURFACE_ATTENDUE
    manquantes = SURFACE_ATTENDUE - reelle
    assert not en_trop, (
        "Routes servies mais non déclarées ici : %s. Si l'ajout est voulu, "
        "ajoute-la à SURFACE_ATTENDUE en connaissance de cause." % sorted(en_trop)
    )
    assert not manquantes, (
        "Routes déclarées ici mais plus servies : %s. Un retrait volontaire se "
        "reflète ici ; sinon c'est une régression." % sorted(manquantes)
    )


def test_aucun_fourre_tout_a_la_racine():
    """Aucune route ne doit être un paramètre de chemin au premier segment.

    C'est la forme qui compte, pas le nom : `/{slug}`, `/{project}`, `/{id}`
    seraient tous des fourre-tout captant n'importe quelle requête à un segment,
    y compris celles qu'une route future voudrait servir.
    """
    fautives = [
        r.path
        for r in app.routes
        if getattr(r, "path", "").startswith("/{")
    ]
    assert not fautives, (
        "Fourre-tout à la racine : %s. Une route à un segment paramétré capte "
        "tout ce qui n'est pas déjà pris et rend l'ordre de montage porteur, ce "
        "qu'il n'est pas aujourd'hui." % fautives
    )


def test_lister_les_blobs_reste_declare_avant_le_telechargement():
    """Contrainte d'ordre réelle, dans `archive.py`.

    `/reports/{report_id}/blobs` et `/reports/{report_id}/{filename}` ont le même
    nombre de segments. Starlette prend la **première** route qui matche, donc si
    la seconde était déclarée d'abord, `{filename}` avalerait le littéral `blobs`
    et la route de listing deviendrait injoignable, en silence et avec une réponse
    plausible.
    """
    chemins = [getattr(r, "path", "") for r in app.routes]
    liste = "/api/v2/archive/reports/{report_id}/blobs"
    telechargement = "/api/v2/archive/reports/{report_id}/{filename}"
    assert liste in chemins and telechargement in chemins, chemins
    assert chemins.index(liste) < chemins.index(telechargement), (
        "`%s` doit être déclarée avant `%s` (archive.py) : sinon le littéral "
        "`blobs` est capté par `{filename}`." % (liste, telechargement)
    )


def test_aucune_route_montee_ni_websocket():
    """L'inventaire ci-dessus ne voit que les routes portant des méthodes HTTP.

    Un `Mount` ou un `WebSocketRoute` n'expose pas `methods`, ne produirait aucune
    entrée, et passerait donc l'inventaire sans le faire rougir. Il n'y en a aucun
    aujourd'hui ; ce test est ce qui rend cette phrase vérifiable plutôt que crue.
    """
    exotiques = [
        (type(r).__name__, getattr(r, "path", "?"))
        for r in app.routes
        if not getattr(r, "methods", None)
    ]
    assert not exotiques, (
        "Routes sans méthodes HTTP (Mount, WebSocketRoute, ...) : %s. "
        "L'inventaire de ce fichier ne les couvre pas." % exotiques
    )


def test_les_seules_routes_a_un_segment_sont_enregistrees_avant_les_routers():
    """Corollaire vérifiable du test précédent, sur les chemins littéraux.

    Une route à un seul segment n'est pas interdite (`/health` en est une), mais
    elle doit être connue. Si un router en ajoutait une, l'ordre de montage
    redeviendrait porteur et les commentaires retirés de `main.py` redeviendraient
    une vraie question.
    """
    un_segment = {
        r.path
        for r in app.routes
        if getattr(r, "path", "").count("/") == 1 and r.path != "/"
    }
    assert un_segment == {"/openapi.json", "/docs", "/redoc", "/health"}, un_segment
