from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    EDITOR_PASSWORD: str
    DEFAULT_PATH: str = "."  # какой путь открывать, если ?path= не передан
    HOST: str = "0.0.0.0"
    PORT: int = 8000


env = Settings()
