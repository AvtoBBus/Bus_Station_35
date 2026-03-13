from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Any
from typing import Literal


class Settings(BaseSettings):
    PROJECT_NAME: str = "XSSDetectorAPI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development",
                         "staging", "production"] = "development"

    API_STR: str = "/api"

    DATABASE_URL: str = ""  # "mysql+aiomysql://root:root@localhost:3306/newschema"

    @property
    def database_url(self) -> str:
        """Динамическое формирование DATABASE_URL из компонентов"""
        return f"mysql+aiomysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: float = 11

    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        env_prefix="APP_",
        extra="ignore"
    )


settings = Settings()
