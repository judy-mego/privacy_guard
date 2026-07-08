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


def redact(text: str, min_phone_len: int = 9, custom_terms=None) -> dict:
    """Return {clean, mapping, entities, tier, tier_reason}.

    custom_terms: optional list of exact strings (company names, project codenames,
    aliases) to always redact as [ORG_n], case-insensitive.
    """
    mapping = {}          # token -> original
    seen = {}             # original -> token
    counters = {}
    entities = []

    def token_for(label, value):
        value = value.strip()
        if value in seen:
            return seen[value]
        counters[label] = counters.get(label, 0) + 1
        tok = f"[{label}_{counters[label]}]"
        seen[value] = tok
        mapping[tok] = value
        entities.append({"label": label, "value": value, "token": tok})
        return tok

    clean = text

    # 0) Custom terms first (user knows exactly what to hide — highest priority)
    for term in sorted(filter(None, (t.strip() for t in (custom_terms or []))), key=len, reverse=True):
        rx = re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.IGNORECASE)
        clean = rx.sub(lambda m, t=term: token_for("ORG", t), clean)

    # 1) Names (before generic patterns eat capitals)
    def _name_sub(m):
        return m.group(0).replace(m.group(1), token_for("NAME", m.group(1)))
    clean = NAME_RE.sub(_name_sub, clean)

    # 2) Company names by legal suffix
    def _org_sub(m):
        return token_for("ORG", m.group(0))
    clean = COMPANY_RE.sub(_org_sub, clean)

    # 3) Structured detectors
    for label, rx, validator in DETECTORS:
        def _sub(m):
            val = m.group(0)
            if label == "PHONE" and len(re.sub(r"\D", "", val)) < min_phone_len:
                return val
            if validator and not validator(val):
                return val
            return token_for(label, val)
        clean = rx.sub(_sub, clean)

    # 3) Sensitivity tier suggestion
    if TIER3_HINTS.search(text):
        tier, reason = 3, "Contains confidentiality markers (NDA/confidential/unreleased) — even redacted, this may not be safe to send externally."
    elif entities:
        tier, reason = 2, "Sensitive identifiers detected and redacted — safe to send the CLEAN text to an external LLM."
    else:
        tier, reason = 1, "No sensitive identifiers detected — low risk. Still review context before sending."

    return {"clean": clean, "mapping": mapping, "entities": entities,
            "tier": tier, "tier_reason": reason}


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
    print("\nCLEAN:\n", r["clean"])
    print(f"\nTIER {r['tier']}: {r['tier_reason']}")
    print("\nENTITIES:")
    for e in r["entities"]:
        print(f"  {e['token']} = {e['value']}")
