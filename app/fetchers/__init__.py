import httpx

from app.fetchers.base import BaseFetcher
from app.fetchers.chrome import ChromeFetcher
from app.fetchers.edge import EdgeFetcher
from app.fetchers.vscode import VSCodeFetcher


def get_fetcher(store: str, client: httpx.AsyncClient) -> BaseFetcher:
    if store == "chrome":
        return ChromeFetcher(client)
    if store == "vscode":
        return VSCodeFetcher(client)
    if store == "edge":
        return EdgeFetcher(client)
    raise ValueError(f"Unknown store: {store!r}")
