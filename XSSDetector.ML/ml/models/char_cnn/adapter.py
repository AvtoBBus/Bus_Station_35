import json
import numpy as np
from tensorflow.keras.models import load_model
from ml.features.preprocess import preprocess_for_sequence_model, classify_injection_context, context_one_hot
from ml.models.char_cnn.sequence import encode_texts

class CharCNNAdapter:
    def __init__(self, model_path: str, meta_path: str):
        self.model = load_model(model_path)
        with open(meta_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)
        self.max_len = self.config.get("max_len", 64)

    def predict_proba(self, texts):
        if isinstance(texts, str): texts = [texts]
        
        # Подготовка текстового канала
        x_tokens = encode_texts(texts, max_len=self.max_len)
        
        # Подготовка контекстного канала
        c_context = np.asarray(
            [context_one_hot(classify_injection_context(str(t))) for t in texts],
            dtype=np.float32
        )
        
        return self.model.predict([x_tokens, c_context])