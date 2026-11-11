import joblib

class RandomForestAdapter:
    def __init__(self, model_path: str):
        self.model = joblib.load(model_path)

    def predict(self, features_df):
        return self.model.predict(features_df)

    def predict_proba(self, features_df):
        return self.model.predict_proba(features_df)