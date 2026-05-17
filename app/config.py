from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    admin_username: str
    admin_password: SecretStr
    secret_key: SecretStr
    database_url: str = "sqlite+aiosqlite:///./marvin.db"
    session_cookie_name: str = "marvin_session"
    session_max_age: int = 86400
    secure_cookies: bool = True
    fetch_interval_minutes: int = 60
    httpx_timeout: float = 15.0
    app_base_url: str = ""  # e.g. "https://marvin.example.com" — used in webhook payloads

    model_config = SettingsConfigDict(env_file=".env", env_prefix="MARVIN_")


settings = Settings()
