import sys
from pathlib import Path
from typing import Dict, List

# Добавляем корень проекта в sys.path для импорта адаптеров и утилит
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from ml.registry.loader import ModelRegistry

from ml.models.catboost import CatBoostAdapter
from ml.models.logistic_regression import LogisticRegressionAdapter
from ml.models.svm import SVMAdapter
from ml.models.random_forest import RandomForestAdapter
from ml.models.lstm import LSTMAdapter
from ml.models.bilstm import BiLSTMAdapter
from ml.models.char_cnn import CharCNNAdapter
from ml.models.transformer import TransformerAdapter

class ModelManager:
    def __init__(self):
        self.registry = ModelRegistry()
        self.loaded_models = {}
        
    def get_model(self, model_name: str):
        """Ленивая загрузка модели при первом обращении."""
        if model_name in self.loaded_models:
            return self.loaded_models[model_name]
            
        info = self.registry.get_active_model_info(model_name)
        
        # Проверяем, существует ли файл перед загрузкой
        model_path = info.get("path")
        if model_path and not Path(model_path).exists():
            # Если пути относительные, возможно, нужно добавить корень проекта
            # Но в нашем manifest.json пути указаны от корня
            pass
            
        print(f"Загрузка модели {model_name} из {model_path}...")
        
        try:
            if model_name == "catboost":
                adapter = CatBoostAdapter(model_path, info["metadata"])
            elif model_name == "logistic_regression":
                adapter = LogisticRegressionAdapter(model_path, info["scaler"])
            elif model_name == "svm":
                adapter = SVMAdapter(model_path, info["scaler"])
            elif model_name == "random_forest":
                adapter = RandomForestAdapter(model_path)
            elif model_name == "lstm":
                adapter = LSTMAdapter(model_path, info["tokenizer"])
            elif model_name == "bilstm":
                adapter = BiLSTMAdapter(model_path, info["tokenizer"])
            elif model_name == "char_cnn":
                adapter = CharCNNAdapter(model_path, info["config"])
            elif model_name == "transformer":
                adapter = TransformerAdapter(model_path, info["tokenizer"])
            else:
                raise ValueError(f"Неизвестная модель: {model_name}")
                
            self.loaded_models[model_name] = adapter
            return adapter
        except Exception as e:
            print(f"Ошибка загрузки модели {model_name}: {e}")
            return None

    def predict_ensemble(self, text: str, model_names: List[str] = None) -> Dict:
        """
        Делает предсказание ансамблем моделей (усреднение вероятностей).
        Если model_names не указан, используются все доступные в реестре.
        """
        if model_names is None:
            model_names = list(self.registry.manifest.get("active_models", {}).keys())
            
        results = {}
        valid_probs = []
        
        for name in model_names:
            model = self.get_model(name)
            if not model:
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
                
        if not valid_probs:
            return {"error": "Ни одна модель не смогла сделать предсказание", "details": results}
            
        # Средняя вероятность
        avg_prob = sum(valid_probs) / len(valid_probs)
        
        return {
            "is_xss": bool(avg_prob >= 0.5),
            "probability": round(avg_prob, 4),
            "model_scores": {k: round(v, 4) for k, v in results.items()}
        }

# Глобальный экземпляр для использования в FastAPI
model_manager = ModelManager()