import logging
from abc import ABC, abstractmethod
from datetime import datetime

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_MAX_PACKAGE_DOWNLOAD_BYTES = 64 * 1024 * 1024  # bytes on the wire


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
    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata: ...

    @abstractmethod
    async def download_package(self, extension_id: str) -> bytes: ...

    async def fetch(self, extension_id: str) -> tuple[ExtensionMetadata, bytes | None]:
        """Fetch metadata and attempt package download. Package failure is non-fatal."""
        metadata = await self.fetch_metadata(extension_id)
        try:
            package = await self.download_package(extension_id)
        except (FetchError, httpx.HTTPError) as exc:
            # Best-effort download: a network/HTTP failure is non-fatal (we still
            # score from metadata). Narrow the catch so genuine programming errors
            # propagate and surface instead of silently degrading scores (M5 / #10).
            logger.warning(
                "Package download failed for %s (%s) — continuing without static analysis",
                extension_id,
                exc,
            )
            package = None
        return metadata, package

    async def _get_package_bytes(self, url: str) -> bytes:
        """Download a package with an explicit cap before it enters memory."""
        async with self.client.stream("GET", url, follow_redirects=True) as resp:
            if resp.status_code != 200:
                raise FetchError(f"Package download returned {resp.status_code}")

            content_length = resp.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > _MAX_PACKAGE_DOWNLOAD_BYTES:
                        raise FetchError("Package download too large")
                except ValueError:
                    pass

            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > _MAX_PACKAGE_DOWNLOAD_BYTES:
                    raise FetchError("Package download too large")
                chunks.append(chunk)
            return b"".join(chunks)
