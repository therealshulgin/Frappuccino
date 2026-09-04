from fastapi import Header, HTTPException
from app import auth


async def require_auth(authorization: str = Header(...)) -> str:
    """Extract and verify JWT from Authorization header. Returns the subject (user id or pk).

    Ne pas câbler cette fonction sur une nouvelle route : elle ne regarde pas
    le claim `scope`, donc tout JWT correctement signé passe. La Red Team R-H2
    a montré qu'un JWT au scope incorrect franchissait ainsi un cloisonnement.
    Utiliser `require_stream_auth`, qui refuse un scope étranger en 403.

    La migration est terminée, et depuis le retrait des routes de compat Tella
    (2026-09-03) cette fonction n'a plus **aucun** appelant : reports.py était le
    dernier module à l'importer, sous l'alias `require_auth`, pour deux routes qui
    n'existent plus. Elle est conservée délibérément comme repoussoir documenté,
    pas par oubli : la garder nommée et commentée vaut mieux que la supprimer et
    voir quelqu'un ré-écrire un jour la même vérification sans le claim `scope`.
    Les lectures archive sont id-free, sans JWT du tout — voir archive.py.
    """
    payload = auth.verify_jwt(authorization)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload["sub"]


async def require_stream_auth(authorization: str = Header(...)) -> str:
    """Require a streaming-scope JWT.

    En pratique aucun token en circulation ne porte de claim `scope` :
    `create_jwt` ne pose que sub/iat/exp, et le JWT de scope archive a été
    retiré avec l'archive id-free. Durcir ce contrôle en exigeant
    `scope == "stream"` invaliderait donc tous les tokens vivants — la valeur
    `"stream"` acceptée plus bas n'est qu'un emplacement réservé, rien ne
    l'émet.

    Le 403 est de la défense en profondeur (Red Team R-H2) : si un token scopé
    venait à être frappé un jour, celui qui porte un scope étranger ne doit pas
    atteindre un upload ni une création de report.
    """
    payload = auth.verify_jwt(authorization)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    scope = payload.get("scope")
    if scope is not None and scope != "stream":
        raise HTTPException(
            status_code=403,
            detail=f"Token scope '{scope}' not allowed on streaming endpoint",
        )
    return payload["sub"]


# Phase C (relay-blind reports) — `require_archive_auth` REMOVED. Archive reads
# are identity-free (the 128-bit report_id IS the read capability); there is no
# archive-scope JWT anymore. See app/routes/archive.py.
