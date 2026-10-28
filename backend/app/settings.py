import secrets

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CloudBridge"
    environment: str = "development"
    database_url: str = "sqlite:///./cloudbridge.db"
    jwt_secret_key: str = Field(default="", min_length=32)
    jwt_access_token_minutes: int = 30
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def generate_development_secret(cls, values):
        values = dict(values or {})
        environment = values.get("environment", "development")
        if not values.get("jwt_secret_key") and environment == "development":
            values["jwt_secret_key"] = secrets.token_urlsafe(48)
        return values

    @model_validator(mode="after")
    def validate_production_secret(self):
        if self.environment != "development" and "replace-with-a-long-random-secret" in self.jwt_secret_key:
            raise ValueError("Set JWT_SECRET_KEY to a unique secret before running outside development")
        return self


settings = Settings()
