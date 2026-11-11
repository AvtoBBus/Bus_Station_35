import joblib
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from ml.features.preprocess import preprocess_for_sequence_model

class BiLSTMAdapter:
    def __init__(self, model_path: str, tokenizer_path: str, max_len: int = 64):
        self.model = load_model(model_path)
        self.tokenizer = joblib.load(tokenizer_path)
        self.max_len = max_len

    def predict_proba(self, texts):
        if isinstance(texts, str): texts = [texts]
        
        # Важно: используем тот же препроцессинг, что и при обучении
        decoded_texts = [preprocess_for_sequence_model(str(t)) for t in texts]
        seq = self.tokenizer.texts_to_sequences(decoded_texts)
        pad = pad_sequences(seq, maxlen=self.max_len, padding='post', truncating='post')
        return self.model.predict(pad)