# 🔒 Local PII Redactor (Tier 2)

**Anonymize sensitive data on your own machine before pasting anything into an external LLM.**

Paste text with personal data (meeting notes, incident reports, customer details) → it's replaced with stable tokens (`[NAME_1]`, `[CARD_1]`, `[DNI_1]`) **locally in your browser/machine** → copy the clean text and paste it into ChatGPT, Claude, Copilot, or any tool. Nothing is ever sent to an external service. No API key. No cost.

Built by [Judith Medina González](https://www.linkedin.com/in/judith-medina-gonzalez-1373b925/) — Senior Solutions Engineer. Companion to the [API Security Copilot](../api-security-copilot) and [Discovery Agent](../discovery-agent).

## The idea: a tiered data-governance workflow

Redaction removes *identifiers* but not always *sensitivity*, so this tool suggests a tier:

| Tier | What it means | What to do |
|:----:|---------------|------------|
| **1** | No sensitive identifiers found | Low risk — use your best cloud LLM directly |
| **2** | PII detected and redacted | Safe to send the **clean** text to an external LLM (this is the sweet spot) |
| **3** | Confidentiality markers (NDA, "not public", "confidential") | Even redacted, may not be safe to send out — use a **local** model or don't use an LLM |

This mirrors how a mature enterprise governs LLM usage: default to redact-then-frontier-model, reserve fully local processing for the crown jewels.

## What it detects

Spanish + international identifiers, all with deterministic rules:

- **DNI** (with checksum letter validation), **NIE**
- **Credit cards** (Luhn-validated — avoids false positives on random digits)
- **IBAN**, **email**, **phone** (Spanish + international formats), **IP address**, **URL**
- **Person names** (honorific-triggered: "Sr. / Dña. / Mr. / Dr. …" — high precision by design)
- **Company names** two ways: by **legal suffix** (`S.L.`, `S.A.`, `Inc.`, `Ltd`, `GmbH`, `B.V.`, `LLC`…) and by a **custom terms list** you provide (the client's name, a project codename, your own company) — always redacted, case-insensitive. This is the most reliable route because you know exactly what to hide.

Everything is regex + checksum validation. Detection quality is measured — see `eval.py`.

## Quickstart

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
# open http://localhost:8000 → paste text → Anonimizar → copy the clean text
```

Command-line / library use:

```python
import redactor
r = redactor.redact("Reunión con Banco Acme S.L. y el Sr. Juan Pérez sobre el proyecto Fénix",
                    custom_terms=["Fénix"])
print(r["clean"])     # "Reunión con [ORG_2] y el Sr. [NAME_1] sobre el proyecto [ORG_1]"
print(r["tier"])      # 2
# later, put real values back into the LLM's answer:
redactor.rehydrate("Escrito a [NAME_1]", r["mapping"])   # "Escrito a Juan Pérez"
```

## Evals

```bash
python3 eval.py
```

Reports detection recall, leak count (sensitive value that slipped into the clean text), false positives, and tier-classification checks. Current: 100% recall, 0 leaks, 0 false positives on the test set.

## Why this matters (and why it's a strong SE artifact)

The number-one enterprise blocker to LLM adoption is "we can't send our data out." This tool is the practical answer to that objection: you keep frontier-model quality while sensitive identifiers never leave the machine. It's the same guardrail architecture an SE designs for a customer — here shrunk to a personal tool you can actually use every day.

## Honest limitations

- **Redaction ≠ safety.** Context can re-identify even without names ("a 10M-customer Spanish bank leaving Cloudflare"). The Tier-3 flag exists precisely because redaction isn't a magic safe button.
- Regex-based detection favors **precision over recall** on names (honorific-triggered) to avoid over-redacting. For higher name recall, a local NER model (spaCy) can be added — kept out here to stay dependency-light and fully offline.
- Always follow your organization's policy on what may go to an external LLM.
