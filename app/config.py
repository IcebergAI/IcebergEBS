from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    admin_username: str
    admin_password: str
    secret_key: str
    database_url: str = "sqlite+aiosqlite:///./marvin.db"
    session_cookie_name: str = "marvin_session"
    session_max_age: int = 86400
    fetch_interval_minutes: int = 60
    httpx_timeout: float = 15.0

    model_config = SettingsConfigDict(env_file=".env", env_prefix="MARVIN_")


settings = Settings()
