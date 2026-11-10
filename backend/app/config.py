from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Gemma 4 AI
    gemma_api_key: str = ""
    gemma_api_url: str = ""
    gemma_model: str = "google/gemma-4-27b-it"

    # DigitalOcean
    digitalocean_api_token: str = ""

    # Backend
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    cors_origins: str = "http://localhost:3000,http://localhost:3001"
    max_code_size_kb: int = 512
    log_level: str = "info"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ai_available(self) -> bool:
        if not (self.gemma_api_key and self.gemma_api_url):
            return False
        if "your_api_key" in self.gemma_api_key.lower() or "your-gradient-endpoint" in self.gemma_api_url.lower():
            return False
        return True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
