import json
import os
import re

try:
    import requests
except Exception:
    requests = None

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")

EVENT_TYPES = ["data_leak", "access_sale", "attack_claim", "ransomware", "vuln_disclosure",
               "phishing_fraud", "malware", "regulation", "tool_release", "other"]


def available():
    if requests is None:
        return False
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _generate(prompt, timeout=60):
    if requests is None:
        return None
    try:
        r = requests.post(f"{OLLAMA_URL}/api/generate", timeout=timeout, json={
            "model": MODEL, "prompt": prompt, "stream": False,
            "format": "json", "options": {"temperature": 0},
        })
        if r.status_code == 200:
            return r.json().get("response", "")
    except Exception:
        return None
    return None


def _extract_json(s):
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def classify_llm(text):
    prompt = (
        "Ты аналитик киберугроз. Определи ОДИН тип события для публикации.\n"
        f"Допустимые типы: {', '.join(EVENT_TYPES)}.\n"
        "Верни строго JSON: {\"event_type\": \"...\", \"confidence\": 0..1}.\n\n"
        f"Публикация:\n\"\"\"{text[:1200]}\"\"\""
    )
    out = _extract_json(_generate(prompt))
    if not out or out.get("event_type") not in EVENT_TYPES:
        return None
    return {"event_type": out["event_type"],
            "confidence": float(out.get("confidence", 0.7)), "classifier": "llm"}


def ner_llm(text):
    prompt = (
        "Извлеки из публикации названия организаций/компаний/продуктов, которые фигурируют "
        "как ЖЕРТВЫ, цели или затронутые (не авторов новости). Также домены и идентификаторы CVE.\n"
        "Верни строго JSON: {\"companies\": [...], \"domains\": [...], \"cves\": [...]}.\n\n"
        f"Публикация:\n\"\"\"{text[:1200]}\"\"\""
    )
    out = _extract_json(_generate(prompt))
    if not out:
        return None
    return {
        "companies": [str(x) for x in out.get("companies", [])][:15],
        "domains": [str(x).lower() for x in out.get("domains", [])][:15],
        "cves": [str(x).upper() for x in out.get("cves", [])][:10],
    }
