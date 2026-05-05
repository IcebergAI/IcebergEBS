from abc import ABC, abstractmethod
from datetime import datetime

import httpx
from pydantic import BaseModel


class ExtensionMetadata(BaseModel):
    name: str
    publisher: str
    description: str | None = None
    version: str
    install_count: int | None = None
    last_updated: datetime | None = None
    store_url: str
    publisher_verified: bool | None = None  # VS Code only


class FetchError(Exception):
    pass


class BaseFetcher(ABC):
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    @abstractmethod
    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        ...

    @abstractmethod
    async def download_package(self, extension_id: str) -> bytes:
        ...

    async def fetch(self, extension_id: str) -> tuple[ExtensionMetadata, bytes | None]:
        """Fetch metadata and attempt package download. Package failure is non-fatal."""
        metadata = await self.fetch_metadata(extension_id)
        try:
            package = await self.download_package(extension_id)
        except Exception:
            package = None
        return metadata, package
