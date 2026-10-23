import re
import unicodedata

EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF←-⇿⬀-⯿️]"
)
URL = re.compile(r"https?://\S+")
MULTISPACE = re.compile(r"\s+")


def strip_emoji(text):
    return EMOJI.sub(" ", text)


def normalize(text):
    text = unicodedata.normalize("NFKC", text)
    text = URL.sub(" ", text)
    text = strip_emoji(text)
    text = text.lower()
    text = re.sub(r"[^0-9a-zа-яё\s]", " ", text)
    return MULTISPACE.sub(" ", text).strip()


def shingles(text, k=4):
    words = normalize(text).split()
    if len(words) < k:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def detect_lang(text):
    cyr = len(re.findall(r"[а-яё]", text.lower()))
    lat = len(re.findall(r"[a-z]", text.lower()))
    if cyr == 0 and lat == 0:
        return "unknown"
    return "ru" if cyr >= lat else "en"
