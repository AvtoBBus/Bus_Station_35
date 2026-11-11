import importlib
import sys
from pathlib import Path
from typing import Dict, List

# Добавляем корень проекта в sys.path для импорта адаптеров и утилит
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from ml.registry.loader import ModelRegistry

# torch обязан быть импортирован раньше tensorflow: иначе TF и PyTorch
# конфликтуют из-за общей библиотеки LLVM/MLIR и процесс падает с
# "LLVM ERROR: inconsistency in registered CommandLine options".
# В lite-сборке torch может отсутствовать — это нормально.
try:
    import torch  # noqa: F401
except ImportError:  # pragma: no cover - lite-сборка без transformer
    pass

# Тяжёлые адаптеры импортируются лениво: если tensorflow/torch/transformers
# не установлены, сервис продолжает работать на доступных моделях.
_ADAPTERS = {
    "catboost": ("ml.models.catboost", "CatBoostAdapter"),
    "logistic_regression": ("ml.models.logistic_regression", "LogisticRegressionAdapter"),
    "svm": ("ml.models.svm", "SVMAdapter"),
    "random_forest": ("ml.models.random_forest", "RandomForestAdapter"),
    "lstm": ("ml.models.lstm", "LSTMAdapter"),
    "bilstm": ("ml.models.bilstm", "BiLSTMAdapter"),
    "char_cnn": ("ml.models.char_cnn", "CharCNNAdapter"),
    "transformer": ("ml.models.transformer", "TransformerAdapter"),
}


def _adapter_class(model_name: str):
    """Импортирует класс адаптера при первом обращении к модели."""
    module_name, class_name = _ADAPTERS[model_name]
    return getattr(importlib.import_module(module_name), class_name)


class ModelManager:
    def __init__(self):
        self.registry = ModelRegistry()
        self.loaded_models = {}

    @property
    def supported_models(self) -> List[str]:
        """Модели, артефакты которых есть на диске (до фактической загрузки)."""
        return self.registry.available_models

    def get_model(self, model_name: str):
        """Ленивая загрузка модели при первом обращении."""
        if model_name in self.loaded_models:
            return self.loaded_models[model_name]

        if model_name not in _ADAPTERS:
            print(f"Неизвестная модель: {model_name}")
            return None

        try:
            info = self.registry.get_active_model_info(model_name)
        except Exception as e:
            print(f"Модель {model_name} недоступна: {e}")
            return None

        # Проверяем, существует ли файл перед загрузкой
        model_path = info.get("path")
        if model_path and not Path(model_path).exists():
            # Если пути относительные, возможно, нужно добавить корень проекта
            # Но в нашем manifest.json пути указаны от корня
            pass

        print(f"Загрузка модели {model_name} из {model_path}...")

        try:
            adapter_class = _adapter_class(model_name)

            if model_name == "catboost":
                adapter = adapter_class(model_path, info["metadata"])
            elif model_name == "logistic_regression":
                adapter = adapter_class(model_path, info["scaler"])
            elif model_name == "svm":
                adapter = adapter_class(model_path, info["scaler"])
            elif model_name == "random_forest":
                adapter = adapter_class(model_path)
            elif model_name == "lstm":
                adapter = adapter_class(model_path, info["tokenizer"])
            elif model_name == "bilstm":
                adapter = adapter_class(model_path, info["tokenizer"])
            elif model_name == "char_cnn":
                adapter = adapter_class(model_path, info["config"])
            elif model_name == "transformer":
                adapter = adapter_class(model_path, info["tokenizer"])
            else:
                raise ValueError(f"Неизвестная модель: {model_name}")

            self.loaded_models[model_name] = adapter
            return adapter
        except ImportError as e:
            print(f"Модель {model_name} пропущена: не установлена зависимость ({e})")
            return None
        except Exception as e:
            print(f"Ошибка загрузки модели {model_name}: {e}")
            return None

    def predict_ensemble(self, text: str, model_names: List[str] = None) -> Dict:
        """
        Делает предсказание ансамблем моделей (усреднение вероятностей).
        Если model_names не указан, используются все модели, артефакты
        которых есть на диске.
        """
        if model_names is None:
            model_names = self.supported_models

        results = {}
        valid_probs = []
        skipped = []
        
        for name in model_names:
            model = self.get_model(name)
            if not model:
                skipped.append(name)
                continue
                
            try:
                # Для классических моделей (CatBoost, RF, LR, SVM) нужны фичи
                if name in ["catboost", "random_forest", "logistic_regression", "svm"]:
                    from ml.features.extract_features import extract_features
                    import pandas as pd
                    # Извлекаем фичи (флаг False как в ноутбуках)
                    feats = extract_features(text, False)
                    feats_df = pd.DataFrame([feats])
                    prob = model.predict_proba(feats_df)[0][1]
                else:
                    # Для нейросетей (LSTM, BiLSTM, Transformer, CharCNN)
                    prob = model.predict_proba([text])[0]
                    if hasattr(prob, '__len__') and len(prob) > 1: # Если вернулся массив [prob_0, prob_1]
                        prob = prob[1]
                        
                results[name] = float(prob)
                valid_probs.append(float(prob))
            except Exception as e:
                print(f"Ошибка предсказания для {name}: {e}")
                skipped.append(name)
                
        if not valid_probs:
            return {
                "error": "Ни одна модель не смогла сделать предсказание",
                "details": results,
                "skipped_models": skipped,
            }
            
        # Средняя вероятность
        avg_prob = sum(valid_probs) / len(valid_probs)
        
        return {
            "is_xss": bool(avg_prob >= 0.5),
            "probability": round(avg_prob, 4),
            "model_scores": {k: round(v, 4) for k, v in results.items()},
            "skipped_models": skipped,
        }

# Глобальный экземпляр для использования в FastAPI
model_manager = ModelManager()