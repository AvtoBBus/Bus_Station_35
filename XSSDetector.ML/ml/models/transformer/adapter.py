import torch
from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast

class TransformerAdapter:
    def __init__(self, model_path: str, tokenizer_path: str, max_len: int = 64):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(tokenizer_path)
        self.model = DistilBertForSequenceClassification.from_pretrained(model_path).to(self.device)
        self.model.eval()
        self.max_len = max_len

    def predict_proba(self, texts):
        if isinstance(texts, str): texts = [texts]
        
        inputs = self.tokenizer(texts, return_tensors="pt", truncation=True, padding=True, max_length=self.max_len)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            logits = self.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
            
        return probs