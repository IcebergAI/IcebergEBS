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
    return EdgeFetcher(client)
