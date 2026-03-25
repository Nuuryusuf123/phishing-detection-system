from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_DIR = Path("models/bert_sms_model")

def bert_available():
    return (MODEL_DIR / "config.json").exists()

def predict_sms_bert(text: str):
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.eval()
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)[0]
        score = float(probs[1].item())
    label = "Threat Detected" if score >= 0.5 else "Safe"
    return label, score
