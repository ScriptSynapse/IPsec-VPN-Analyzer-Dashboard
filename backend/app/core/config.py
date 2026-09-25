from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IPSEC_ANALYZER_")

    app_name: str = "IPsec VPN Analyzer"

    database_url: str = f"sqlite:///{BACKEND_ROOT / 'data' / 'app.db'}"

    pcap_storage_dir: Path = BACKEND_ROOT / "data" / "pcaps"
    dataset_dir: Path = BACKEND_ROOT / "data" / "datasets"
    ml_artifacts_dir: Path = BACKEND_ROOT / "app" / "ml" / "artifacts"

    tshark_path: str = "tshark"


settings = Settings()
