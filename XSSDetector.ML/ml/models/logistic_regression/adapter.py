import joblib

class LogisticRegressionAdapter:
    def __init__(self, model_path: str, scaler_path: str):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

    def predict(self, features_df):
        scaled_features = self.scaler.transform(features_df)
        return self.model.predict(scaled_features)

    def predict_proba(self, features_df):
        scaled_features = self.scaler.transform(features_df)
        return self.model.predict_proba(scaled_features)