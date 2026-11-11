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

    DB_HOST: str = "mysql"
    DB_PORT: int = 3306
    DB_USER: str = "root"
    DB_PASSWORD: str = "root"
    DB_NAME: str = "new_schema"

    @property
    def database_url(self) -> str:
        """Готовый DSN: DATABASE_URL, либо собранный из компонентов DB_*"""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"mysql+aiomysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"

    # Заполнять БД базовыми мок-данными при старте (если таблица пуста)
    SEED_DATA: bool = True


    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://client:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        env_prefix="APP_",
        extra="ignore"
    )


settings = Settings()
