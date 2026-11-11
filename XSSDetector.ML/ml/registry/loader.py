import json
import logging
from pathlib import Path

logger = logging.getLogger("uvicorn")

# ml/ — корень, от которого считаются относительные пути из manifest.json
ML_ROOT = Path(__file__).resolve().parents[1]
_NON_PATH_KEYS = {"version"}


def _artifact_present(path: Path) -> bool:
    """Файл существует; папка (например, best_model/) существует и не пустая."""
    if path.is_dir():
        return any(True for _ in path.iterdir())
    return path.exists()


class ModelRegistry:
    def __init__(self, manifest_path: str = None):
        if manifest_path is None:
            manifest_path = Path(__file__).resolve().parent / "manifest.json"

        self.manifest_path = Path(manifest_path)
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict:
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Манифест реестра не найден: {self.manifest_path}")

        with open(self.manifest_path, "r", encoding="utf-8-sig") as f:
            return json.load(f)

    def get_active_model_info(self, model_name: str, warn: bool = True) -> dict:
        """Возвращает АБСОЛЮТНЫЕ пути к артефактам активной модели.

        Пути в manifest.json задаются относительно папки ml/, поэтому
        результат не зависит от текущей рабочей директории (локально/в Docker).
        """
        active_models = self.manifest.get("active_models", {})
        if model_name not in active_models:
            raise ValueError(f"Модель '{model_name}' отсутствует в реестре.")

        info = dict(active_models[model_name])
        for key, value in info.items():
            if key in _NON_PATH_KEYS or not isinstance(value, str):
                continue
            path = Path(value)
            if not path.is_absolute():
                path = ML_ROOT / path
            info[key] = str(path)
            if warn and not path.exists():
                logger.warning("Артефакт модели %s не найден: %s (%s)", model_name, path, key)
        return info

    @property
    def available_models(self) -> list[str]:
        """Модели, все артефакты которых реально лежат на диске.

        Сервис должен подниматься и отвечать, даже если часть моделей не
        обучена или не попала в образ (например, lite-сборка без TF/torch).
        """
        available = []
        for model_name in self.manifest.get("active_models", {}):
            try:
                info = self.get_active_model_info(model_name, warn=False)
            except Exception as exc:
                logger.warning("Модель %s пропущена: %s", model_name, exc)
                continue
            artifact_paths = [
                value
                for key, value in info.items()
                if key not in _NON_PATH_KEYS and isinstance(value, str)
            ]
            if artifact_paths and all(_artifact_present(Path(path)) for path in artifact_paths):
                available.append(model_name)
        return available