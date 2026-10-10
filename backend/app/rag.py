"""Tiny RAG: TF-IDF retrieval over runbook/policy sections."""
import re
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

KB_DIR = Path(__file__).resolve().parent.parent / "knowledge"
_chunks, _vec, _mat = [], None, None


def _load():
    global _chunks, _vec, _mat
    if _vec is not None:
        return
    for f in sorted(KB_DIR.glob("*.md")):
        for m in re.finditer(r"^## (\w+)\n(.*?)(?=^## |\Z)", f.read_text(), re.S | re.M):
            _chunks.append({"id": f"{f.stem}#{m.group(1)}", "section": m.group(1), "text": m.group(2).strip()})
    _vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
    _mat = _vec.fit_transform([c["section"].replace("_", " ") + " " + c["text"] for c in _chunks])


def retrieve(query: str, k: int = 3) -> list[dict]:
    _load()
    sims = cosine_similarity(_vec.transform([query.replace("_", " ")]), _mat)[0]
    return [{**_chunks[i], "score": round(float(sims[i]), 3)} for i in sims.argsort()[::-1][:k] if sims[i] > 0]
