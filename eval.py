"""Evaluate PII detection quality.

Measures whether each expected entity is detected (recall) and flags any
sensitive value that leaked into the clean text. Run:  python eval.py
"""

import redactor

# (text, [expected values that MUST be redacted])
CASES = [
    ("Cliente Sr. Juan Pérez, DNI 12345678Z", ["Juan Pérez", "12345678Z"]),
    ("Tarjeta 4111 1111 1111 1111 caducada", ["4111 1111 1111 1111"]),
    ("Escríbeme a maria.lopez@empresa.com", ["maria.lopez@empresa.com"]),
    ("Mi IBAN es ES91 2100 0418 4502 0005 1332", ["ES91 2100 0418 4502 0005 1332"]),
    ("Llámame al 612 345 678 o al +34 600 11 22 33", ["612 345 678", "+34 600 11 22 33"]),
    ("NIE X1234567L para el trámite", ["X1234567L"]),
    ("Servidor caído: 10.20.30.40", ["10.20.30.40"]),
    ("Reunión con Dña. Marta Ruiz mañana", ["Marta Ruiz"]),
    ("Contrato con Banco Acme S.L. y Tech Solutions Ltd", ["Banco Acme S.L.", "Tech Solutions Ltd"]),
    ("Sin datos sensibles aquí, solo una nota general.", []),
]

# Custom-terms case: (text, custom_terms, [expected redacted])
CUSTOM_CASE = ("El proyecto Fénix avanza en Iberdrola", ["Fénix", "Iberdrola"], ["Fénix", "Iberdrola"])

# Values that should NOT be flagged (avoid false positives)
NEGATIVE = [
    "El año 2024 fue bueno",         # year, not an ID
    "Pedido número 12345",            # short number
    "La versión 3.14.15 del software",  # not an IP
]


def main():
    total_expected, detected, leaked = 0, 0, 0
    print("=== Detection recall ===")
    for text, expected in CASES:
        r = redactor.redact(text)
        clean = r["clean"]
        for val in expected:
            total_expected += 1
            if val not in clean:               # redacted → good
                detected += 1
            else:
                leaked += 1
                print(f"  ✗ LEAKED: '{val}' still visible in: {clean}")
    recall = detected / total_expected if total_expected else 1.0
    print(f"Recall: {detected}/{total_expected} = {recall:.0%}   (leaks: {leaked})")

    print("\n=== False-positive check ===")
    fp = 0
    for text in NEGATIVE:
        r = redactor.redact(text)
        if r["entities"]:
            fp += 1
            print(f"  ⚠ false positive in '{text}': {[e['value'] for e in r['entities']]}")
    print(f"False positives: {fp}/{len(NEGATIVE)}")

    print("\n=== Tier classification ===")
    t3 = redactor.redact("CONFIDENTIAL bajo NDA: cifras no públicas")
    print(f"  NDA text → Tier {t3['tier']} (expected 3): {'✓' if t3['tier']==3 else '✗'}")
    t1 = redactor.redact("Resumen general de la reunión de producto")
    print(f"  Clean text → Tier {t1['tier']} (expected 1): {'✓' if t1['tier']==1 else '✗'}")

    print("\n=== Custom terms (company / project names) ===")
    text, terms, expected = CUSTOM_CASE
    r = redactor.redact(text, custom_terms=terms)
    ok = all(v not in r["clean"] for v in expected)
    print(f"  '{text}' + {terms} → {r['clean']}")
    print(f"  {'✓' if ok else '✗'} all custom terms redacted")

    print(f"\n{'✅ PASS' if recall==1.0 and leaked==0 and ok else '⚠ REVIEW'}")


if __name__ == "__main__":
    main()
