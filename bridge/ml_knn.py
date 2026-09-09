"""Lightweight ML for PS26155 — TF-IDF char n-grams + KNN (Pattern Recognition / classical NLP)
Runs PARALLEL to deterministic regex DecisionEngine, never replaces it.

Training corpus: KNOWN_PATTERNS (Cisco/Juniper/Generic) + config/vendor_training_map.json entries.
Model: TfidfVectorizer(analyzer='char_wb', 3-5) + KNeighborsClassifier(k=3, cosine, distance weighting)
Artifact: config/ml_model.pkl + config/ml_vectorizer.pkl (retrain on every POST /train, no redeploy)
Advisory only: predict(line) -> {label, confidence} or None if < THRESH; scorer remains authoritative.
Fallback: if sklearn missing or corpus <5, returns None gracefully — ingestion falls back to regex only.
"""
from pathlib import Path
import json
import pickle
import re

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.neighbors import KNeighborsClassifier
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Roots — support both bridge/ and bridge.ml_knn import paths
try:
    from bridge.config import TRINETRA_ROOT as _ROOT
except ImportError:
    try:
        from config import TRINETRA_ROOT as _ROOT
    except ImportError:
        _ROOT = str(Path(__file__).resolve().parents[1])

ROOT = Path(_ROOT)
CONFIG_DIR = ROOT / "config"
VENDOR_MAP = CONFIG_DIR / "vendor_training_map.json"
MODEL_PATH = CONFIG_DIR / "ml_model.pkl"
VEC_PATH = CONFIG_DIR / "ml_vectorizer.pkl"
CORPUS_PATH = CONFIG_DIR / "ml_corpus.json"

K = 3
THRESH = 0.55  # cosine distance 0..2 → confidence 1..-1; 0.55 = 45% distance
# Min samples — KNN needs >= K; we gate train at >=5
MIN_SAMPLES = 5

# Seed corpus mirroring src/TrinetraConfigIngestor KNOWN_PATTERNS + explicit Cisco IOS examples
# Each entry: (text, label) where label is security_category or V-code — we train on category for Training UI suggestions
SEED_PATTERNS = [
    # Cisco — V-013 / AAA / password
    ("enable secret 5 $1$abc", "V-013"),
    ("username admin privilege 15 secret 5 $1$xyz", "V-013"),
    ("username operator password 0 cisco123", "V-013"),
    ("aaa new-model", "V-013"),
    ("service password-encryption", "V-013"),
    # V-006 TLS/SSH
    ("ip ssh version 1", "V-006"),
    ("ip ssh version 2", "V-006"),
    ("set system services ssh protocol-version v1", "V-006"),
    ("set system services ssh protocol-version v2", "V-006"),
    # V-071 admin interface / HTTP / telnet
    ("ip http server", "V-071"),
    ("no ip http server", "V-071"),
    ("transport input telnet", "V-071"),
    ("transport input ssh", "V-071"),
    ("exec-timeout 0 0", "V-071"),
    ("exec-timeout 5 0", "V-071"),
    ("set system services telnet", "V-071"),
    # V-057 SNMP
    ("snmp-server community public RO", "V-057"),
    ("snmp-server community private RW", "V-057"),
    ("set snmp community public authorization read-only", "V-057"),
    # V-058 logging
    ("logging host 10.10.1.100", "V-058"),
    ("logging trap informational", "V-058"),
    ("set system syslog host 10.10.1.100", "V-058"),
    # V-003 open service
    ("ip source-route", "V-003"),
    ("service pad", "V-003"),
    ("no ip source-route", "V-003"),
    # V-107 IAM
    ("username test privilege 15 password 0 test", "V-107"),
    ("username test privilege 5 secret 9 $9$abc", "V-107"),
    # Generic variants for robustness
    ("password 7 0822445D0A16", "V-013"),
    ("telnet 10.0.0.1", "V-071"),
    # Juniper distinctive
    ("set system host-name juniper-lab-01", "V-003"),
    ("set system login user admin class super-user", "V-013"),
    ("set system login idle-timeout 10", "V-071"),
]


def _load_vendor_entries():
    entries = []
    if VENDOR_MAP.exists():
        try:
            data = json.loads(VENDOR_MAP.read_text(encoding="utf-8"))
            for e in data.get("entries", []):
                pat = (e.get("pattern") or "").strip()
                # label = security_category preferred, fallback to first control or V-code
                label = (e.get("security_category") or "").strip()
                if not label:
                    cms = e.get("control_mapping") or []
                    label = cms[0] if cms else ""
                # also try to map category → V-code for scorer usefulness; keep human label if present
                # we store both: use category if present else V-code
                if pat and label:
                    # expand regex pattern to example-ish text: strip regex meta for training text
                    # keep raw pattern too; TF-IDF char n-grams handles regex chars okay, but we also add cleaned
                    cleaned = re.sub(r"[\.\*\+\?\^\$\{\}\(\)\[\]\\\|]", " ", pat)
                    cleaned = re.sub(r"\s+", " ", cleaned).strip()
                    if cleaned and len(cleaned) > 3:
                        entries.append((cleaned, label))
                    # also add raw pattern as-is for literal matches
                    entries.append((pat, label))
        except Exception:
            pass
    return entries


def build_corpus():
    """Build corpus list [(text, label)] from seed + vendor map, dedup, write to ml_corpus.json"""
    corpus = list(SEED_PATTERNS)
    corpus.extend(_load_vendor_entries())
    # dedup exact pairs, keep order
    seen = set()
    uniq = []
    for t, l in corpus:
        key = (t.strip().lower(), l.strip().lower())
        if key[0] and key[1] and key not in seen:
            seen.add(key)
            uniq.append((t.strip(), l.strip()))
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CORPUS_PATH.write_text(json.dumps([{"text": t, "label": l} for t, l in uniq], indent=2), encoding="utf-8")
    except Exception:
        pass
    return uniq


def train(force: bool = False) -> bool:
    """Train TF-IDF + KNN, persist to config/ml_*.pkl. Returns True on success."""
    if not HAS_SKLEARN:
        return False
    corpus = build_corpus()
    if len(corpus) < MIN_SAMPLES and not force:
        # not enough variety — still try if force
        if len(corpus) < 2:
            return False
    texts, labels = zip(*corpus)
    # char_wb captures `ip ssh` vs `set system` with tolerance to numbers/priv levels
    vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), lowercase=True, min_df=1)
    try:
        X = vec.fit_transform(texts)
    except ValueError:
        return False
    # KNN — distance weighting so closer neighbor matters more
    n = min(K, len(corpus))
    try:
        clf = KNeighborsClassifier(n_neighbors=n, metric='cosine', weights='distance')
        clf.fit(X, labels)
    except Exception:
        return False
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(clf, f)
        with open(VEC_PATH, "wb") as f:
            pickle.dump(vec, f)
        return True
    except Exception:
        return False


def _load_model():
    if not HAS_SKLEARN or not MODEL_PATH.exists() or not VEC_PATH.exists():
        return None, None
    try:
        clf = pickle.load(open(MODEL_PATH, "rb"))
        vec = pickle.load(open(VEC_PATH, "rb"))
        return clf, vec
    except Exception:
        return None, None


def predict(line: str, vendor: str | None = None):
    """Advisory prediction for one config line. Returns {label, confidence, source} or None."""
    if not line or not line.strip() or len(line.strip()) < 3:
        return None
    if not HAS_SKLEARN:
        return None
    clf, vec = _load_model()
    if clf is None:
        # auto-train on first call if model missing
        if not train():
            return None
        clf, vec = _load_model()
        if clf is None:
            return None
    text = line.strip()[:500]  # cap
    try:
        X = vec.transform([text])
        # kneighbors to get distance for confidence
        dist, _ = clf.kneighbors(X, n_neighbors=1)
        d = float(dist[0][0])  # cosine distance 0..2
        # cosine distance → confidence: 0→1.0, 0.45→0.55, 1.0→0.0
        confidence = max(0.0, 1.0 - d)
        # also get proba via predict
        pred = clf.predict(X)[0]
        # require some lexical overlap — very short or all-punct lines should not fire
        if len(text) < 5:
            return None
        if confidence < THRESH:
            return None
        return {"label": str(pred), "confidence": round(confidence, 3), "source": "knn_tfidf_char3-5_cosine"}
    except Exception:
        return None


def predict_batch(lines: list):
    """Batch advisory for Training UI — returns {line: prediction or None}"""
    out = {}
    for l in lines or []:
        out[l] = predict(l)
    return out


# CLI for manual check: python3 -m bridge.ml_knn "ip ssh version 1"
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] in ("train", "--train", "retrain"):
        ok = train(force=True)
        print(f"train: {'ok' if ok else 'failed'}; corpus={len(build_corpus())} has_sklearn={HAS_SKLEARN} model={MODEL_PATH.exists()}")
    else:
        q = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "ip ssh version 1"
        if not MODEL_PATH.exists():
            train()
        print(json.dumps({"query": q, "prediction": predict(q)}, indent=2))
