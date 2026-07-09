"""Local PII Redactor — Tier 2 privacy tool.

Detects and anonymizes sensitive data (Spanish + international) BEFORE you paste
text into any external LLM (ChatGPT, Claude, Copilot…). Runs 100% on your machine:
nothing is sent anywhere, no API key, no cost.

Workflow:
  1. Paste text with sensitive data.
  2. redact() replaces each entity with a stable token ([CARD_1], [DNI_2], …)
     and returns the clean text + a mapping.
  3. Paste the clean text into whatever LLM you use.
  4. (Optional) rehydrate() puts the real values back into the model's answer.

Also flags a suggested sensitivity TIER so you know whether redaction is enough
(Tier 2) or the content shouldn't leave your machine at all (Tier 3).

Everything here is deterministic regex + checksum validation. No dependency.
"""

import re

# ---------------------------------------------------------------- dummy pools

# Realistic fake values so the clean text reads naturally for an LLM.
DUMMY_NAMES = [
    "Carlos Gómez", "Elena Ruiz", "Miguel Torres", "Laura Sánchez", "David Moreno",
    "Ana Castro", "Javier Díaz", "Marta Vidal", "Sergio Romero", "Lucía Navarro",
    "Pablo Herrero", "Sofía Ramos", "Andrés Gil", "Clara Ortega", "Raúl Márquez",
]
DUMMY_ORGS = [
    "Empresa Delta", "Compañía Norte", "Grupo Ibérica", "Corporación Vega",
    "Sociedad Aurora", "Industrias Meridian", "Global Ceningsa", "Grupo Altair",
]

# NER model is optional. If spaCy + the Spanish model are installed, name/company
# recall improves a lot. If not, we fall back to honorific + suffix + custom terms.
_nlp = None
_nlp_tried = False


def _get_nlp():
    global _nlp, _nlp_tried
    if _nlp_tried:
        return _nlp
    _nlp_tried = True
    try:
        import spacy
        # Prefer the more accurate medium model; fall back to small if that's what's installed.
        for model in ("es_core_news_md", "es_core_news_sm"):
            try:
                _nlp = spacy.load(model)
                break
            except Exception:
                continue
    except Exception:
        _nlp = None
    return _nlp


# Common Spanish words the small NER model frequently mis-tags as names/orgs.
# Anything here is never treated as a proper name, even if NER flags it.
_NER_STOPWORDS = {
    "también", "tenemos", "quiero", "seguro", "claro", "bueno", "está", "sino",
    "yo", "creo", "quedado", "tienes", "venía", "vendría", "veníría", "exacto",
    "toda", "todo", "hola", "gracias", "saludos", "buenos", "buenas", "vale",
    "entonces", "además", "aunque", "porque", "cuando", "donde", "como", "esto",
    "eso", "aquello", "nada", "algo", "mucho", "poco", "siempre", "nunca",
    "hoy", "ayer", "mañana", "ahora", "luego", "them", "ward", "gentnet",
    "gisen", "pukai", "veniría", "bizum", "siem",
}


def _ner_entities(text: str):
    """Return [(label, text)] for high-confidence person/company names only.

    Filters aggressively for PRECISION: an entity must be tagged as a proper noun
    (PROPN) by the POS tagger and not be a common word. This removes the verbs,
    adverbs and sentence-initial words the small model over-flags.
    """
    nlp = _get_nlp()
    if nlp is None:
        return []
    out = []
    for ent in nlp(text).ents:
        if ent.label_ not in ("PER", "PERSON", "ORG"):
            continue
        txt = ent.text.strip()
        if len(txt) < 3:
            continue
        # must be an actual proper noun, not a verb/adverb mis-tagged as a name
        if ent.root.pos_ != "PROPN":
            continue
        # drop common words and single-token entries that are just capitalized words
        words = txt.split()
        if any(w.lower() in _NER_STOPWORDS for w in words):
            continue
        # single-token PERSON names are risky; require it to look like a name
        # (title-case, alphabetic). Multi-token always allowed.
        if len(words) == 1 and not (txt[0].isupper() and txt[1:].islower() and txt.isalpha()):
            continue
        label = "NAME" if ent.label_ in ("PER", "PERSON") else "ORG"
        out.append((label, txt))
    return out


# ---------------------------------------------------------------- detectors

def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _dni_ok(dni: str) -> bool:
    m = re.fullmatch(r"(\d{8})([A-Za-z])", dni.strip())
    if not m:
        return False
    letters = "TRWAGMYFPDXBNJZSQVHLCKE"
    return letters[int(m.group(1)) % 23] == m.group(2).upper()


# order matters: most specific first
DETECTORS = [
    # label, regex, optional validator
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?\d{4}){3,7}\b"), None),
    ("CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b"), _luhn_ok),
    ("DNI", re.compile(r"\b\d{8}[A-Za-z]\b"), _dni_ok),
    ("NIE", re.compile(r"\b[XYZ]\d{7}[A-Za-z]\b"), None),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), None),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), None),
    ("PHONE", re.compile(r"(?<!\d)(?:(?:\+|00)\d{1,3}[ -]?)?\d(?:[ -]?\d){7,12}(?!\d)"),
     lambda v: 9 <= len(re.sub(r"\D", "", v)) <= 15),
    ("URL", re.compile(r"\bhttps?://[^\s]+\b"), None),
]

# Person names: honorific-triggered (high precision, low recall — intentional).
NAME_RE = re.compile(r"\b(?:Sr\.?|Sra\.?|D\.?|D[ñn]a\.?|Mr\.?|Ms\.?|Mrs\.?|Dr\.?)\s+"
                     r"([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){0,2})")

# Company names: legal-suffix-triggered (captures the name preceding the suffix).
COMPANY_RE = re.compile(
    r"\b([A-ZÁÉÍÓÚÑ][\wÁÉÍÓÚÑáéíóúñ&.\-]*(?:\s+[A-ZÁÉÍÓÚÑ][\wÁÉÍÓÚÑáéíóúñ&.\-]*){0,4})\s+"
    r"(S\.?L\.?U\.?|S\.?A\.?U\.?|S\.?L\.?|S\.?A\.?|S\.?L\.?N\.?E\.?|Inc\.?|Ltd\.?|L\.?L\.?C\.?|"
    r"GmbH|B\.?V\.?|PLC|S\.?p\.?A\.?|S\.?à\.?r\.?l\.?|Sarl|Corp\.?|Co\.?|N\.?V\.?|A\.?G\.?)"
    r"(?=\s|$|[.,;:)])")

# Tier-3 escalation keywords: if present, redaction alone may not be enough.
TIER3_HINTS = re.compile(r"\b(confidential|nda|no[- ]disclosure|under embargo|not public|"
                         r"unreleased|internal only|secreto|confidencial|bajo nda)\b", re.I)


def redact(text: str, min_phone_len: int = 9, custom_terms=None, use_ner: bool = True) -> dict:
    """Return {clean, mapping, entities, tier, tier_reason, legend}.

    Names and companies are replaced with realistic DUMMY values (Juan Pérez →
    Carlos Gómez); structured identifiers (DNI, card, IBAN…) use [TOKEN]s. The
    'mapping' (replacement -> original) and 'legend' are LOCAL reference only —
    never append them to the text you send out.

    custom_terms: exact strings (client, project codename, your own company) to
      always replace, case-insensitive.
    use_ner: if True and spaCy + es_core_news_sm are installed, also detect
      person/company names without a title (higher recall).
    """
    mapping = {}          # replacement -> original
    seen = {}             # original -> replacement
    counters = {}
    entities = []

    def repl_for(label, value):
        value = value.strip()
        if value in seen:
            return seen[value]
        counters[label] = counters.get(label, 0) + 1
        n = counters[label]
        if label == "NAME":
            rep = DUMMY_NAMES[(n - 1) % len(DUMMY_NAMES)] + ("" if n <= len(DUMMY_NAMES) else f" {n}")
        elif label == "ORG":
            rep = DUMMY_ORGS[(n - 1) % len(DUMMY_ORGS)] + ("" if n <= len(DUMMY_ORGS) else f" {n}")
        else:
            rep = f"[{label}_{n}]"
        seen[value] = rep
        mapping[rep] = value
        entities.append({"label": label, "value": value, "replacement": rep})
        return rep

    def replace_exact(clean, value, label):
        if not value.strip():
            return clean
        rx = re.compile(r"(?<!\w)" + re.escape(value.strip()) + r"(?!\w)", re.IGNORECASE)
        return rx.sub(lambda m, l=label, v=value.strip(): repl_for(l, v), clean)

    clean = text

    # 0) Custom terms first (user knows exactly what to hide — highest priority)
    for term in sorted(filter(None, (t.strip() for t in (custom_terms or []))), key=len, reverse=True):
        clean = replace_exact(clean, term, "ORG")

    # 1) NER (optional): person + company names without a title, precision-filtered
    if use_ner:
        for label, value in sorted(_ner_entities(text), key=lambda lv: len(lv[1]), reverse=True):
            clean = replace_exact(clean, value, label)

    # 2) Honorific-triggered names (title + name)
    def _name_sub(m):
        return m.group(0).replace(m.group(1), repl_for("NAME", m.group(1)))
    clean = NAME_RE.sub(_name_sub, clean)

    # 3) Company names by legal suffix
    clean = COMPANY_RE.sub(lambda m: repl_for("ORG", m.group(0)), clean)

    # 4) Structured detectors (tokens)
    for label, rx, validator in DETECTORS:
        def _sub(m, label=label, validator=validator):
            val = m.group(0)
            if label == "PHONE" and len(re.sub(r"\D", "", val)) < min_phone_len:
                return val
            if validator and not validator(val):
                return val
            return repl_for(label, val)
        clean = rx.sub(_sub, clean)

    # 5) Sensitivity tier
    if TIER3_HINTS.search(text):
        tier, reason = 3, "Contains confidentiality markers (NDA/confidential/unreleased) — even redacted, this may not be safe to send externally."
    elif entities:
        tier, reason = 2, "Sensitive identifiers detected and replaced — safe to send the CLEAN text to an external LLM."
    else:
        tier, reason = 1, "No sensitive identifiers detected — low risk. Still review context before sending."

    # Local legend (real ↔ dummy) — for YOUR reference / rehydration. DO NOT SEND.
    legend = [{"replacement": e["replacement"], "original": e["value"], "type": e["label"]} for e in entities]

    return {"clean": clean, "mapping": mapping, "entities": entities,
            "tier": tier, "tier_reason": reason, "legend": legend}


def rehydrate(text: str, mapping: dict) -> str:
    """Replace tokens in an LLM answer with the original values."""
    for tok, val in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(tok, val)
    return text


if __name__ == "__main__":
    sample = ("Reunión con Banco Acme S.L. y su filial Acme Seguros S.A. sobre la "
              "incidencia del Sr. Juan Pérez, DNI 12345678Z, tarjeta 4111 1111 1111 1111, "
              "email juan.perez@bancoacme.es. El proyecto interno se llama Fénix.")
    # custom_terms: nombres/alias que solo tú conoces (cliente, proyecto…)
    r = redact(sample, custom_terms=["Fénix"])
    print("ORIGINAL:\n", sample)
    print("\nCLEAN (para pegar en el LLM):\n", r["clean"])
    print(f"\nTIER {r['tier']}: {r['tier_reason']}")
    print("\nLEYENDA (solo para ti — NO enviar):")
    for e in r["legend"]:
        print(f"  {e['replacement']}  ←  {e['original']}  ({e['type']})")
