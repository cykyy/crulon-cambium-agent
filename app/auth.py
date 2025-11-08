from fastapi import HTTPException, Header, Query

from app.config import API_TOKEN


def require_token(
    x_api_token: str | None = Header(None, alias="X-API-Token"),
    token_query: str | None = Query(None, alias="api_token")
):
    """Validate provided token either via X-API-Token header or api_token query param.

    API_TOKEN must be set in the environment; otherwise the app refuses requests.
    """
    if not API_TOKEN:
        raise HTTPException(status_code=500, detail="Server misconfiguration: API_TOKEN not set")
    supplied = x_api_token or token_query
    if not supplied or supplied != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing API token")
