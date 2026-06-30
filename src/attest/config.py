import base64

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    attest_signing_key: str
    attest_verify_key: str
    groq_api_key: str
    groq_model: str = "llama-3.3-70b-versatile"

    @property
    def signing_key_bytes(self) -> bytes:
        return base64.b64decode(self.attest_signing_key)

    @property
    def verify_key_bytes(self) -> bytes:
        return base64.b64decode(self.attest_verify_key)


settings = Settings()