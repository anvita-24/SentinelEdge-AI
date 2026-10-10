import os
from dataclasses import dataclass, field


def _keys() -> dict:
    raw = os.getenv(
        "SE_API_KEYS",
        "viewer:viewer-key,operator:operator-key,admin:admin-key,device:device-key",
    )
    return {k.strip(): r.strip() for r, k in (p.split(":", 1) for p in raw.split(","))}


@dataclass
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./sentineledge.db")
    redis_url: str = os.getenv("REDIS_URL", "")
    mqtt_host: str = os.getenv("MQTT_HOST", "")
    mqtt_port: int = int(os.getenv("MQTT_PORT", "1883"))
    signing_secret: str = os.getenv("SE_SIGNING_SECRET", "dev-signing-secret-change-me")
    risk_threshold: float = float(os.getenv("SE_RISK_THRESHOLD", "0"))  # 0 = use calibrated
    model_path: str = os.getenv("SE_MODEL_PATH", "./model.joblib")
    train_rows: int = int(os.getenv("SE_TRAIN_ROWS", "20000"))
    anthropic_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    cors_origins: list = field(
        default_factory=lambda: os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    )
    api_keys: dict = field(default_factory=_keys)


settings = Settings()
