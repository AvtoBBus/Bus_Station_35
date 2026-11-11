import joblib
import pandas as pd
from catboost import CatBoostClassifier, Pool

class CatBoostAdapter:
    def __init__(self, model_path: str, metadata_path: str):
        self.model = CatBoostClassifier()
        self.model.load_model(model_path)
        self.metadata = joblib.load(metadata_path)

    def _prepare_pool(self, features_df: pd.DataFrame) -> Pool:
        """Подготавливает Pool для CatBoost, добавляя 'text' и приводя типы."""
        features_df = features_df.copy()
        expected_features = self.metadata['feature_names']
        cat_features = self.metadata.get('cat_features', [])
        
        # 1. Добавляем недостающие колонки
        for feature in expected_features:
            if feature not in features_df.columns:
                if feature == 'text':
                    features_df[feature] = ''
                else:
                    features_df[feature] = 0.0
                    
        # 2. Выстраиваем правильный порядок
        features_df = features_df[expected_features]
        
        # 3. Приводим категориальные и текстовые признаки к строкам
        for col in cat_features:
            if col in features_df.columns:
                features_df[col] = features_df[col].astype(str)
                
        if 'text' in features_df.columns:
            features_df['text'] = features_df['text'].astype(str)

        text_features = ['text'] if 'text' in features_df.columns else None
        
        return Pool(
            features_df,
            feature_names=list(features_df.columns),
            cat_features=cat_features,
            text_features=text_features
        )

    def predict(self, features_df):
        pool = self._prepare_pool(features_df)
        return self.model.predict(pool)

    def predict_proba(self, features_df):
        pool = self._prepare_pool(features_df)
        return self.model.predict_proba(pool)