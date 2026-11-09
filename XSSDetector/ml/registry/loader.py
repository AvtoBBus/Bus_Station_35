import json
import os
from pathlib import Path

class ModelRegistry:
    def __init__(self, manifest_path: str = None):
        if manifest_path is None:
            # По умолчанию ищем рядом с этим файлом
            manifest_path = os.path.join(os.path.dirname(__file__), "manifest.json")
        
        self.manifest_path = Path(manifest_path)
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict:
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Манифест реестра не найден: {self.manifest_path}")
            
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_active_model_info(self, model_name: str) -> dict:
        """Возвращает пути к артефактам активной модели."""
        active_models = self.manifest.get("active_models", {})
        if model_name not in active_models:
            raise ValueError(f"Модель '{model_name}' отсутствует в реестре.")
        return active_models[model_name]