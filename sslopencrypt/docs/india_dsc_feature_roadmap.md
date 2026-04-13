# India DSC Module — Feature Roadmap

_Generated: 2026-04-13_

This document captures the analysis of `modules/india_dsc/controller.py` and lists
practical gaps and planned additions, ordered by impact.

---

## What the current module already handles

- Auto-detects the most common USB token PKCS#11 libraries (ePass2003, HyperPKI,
  SafeNet eToken 5110, WatchData Proxkey, OpenSC fallback)
- Lists tokens, certificates, and keys on the token without needing to know
  `pkcs11-tool` syntax
- Exports the signing certificate safely (public cert only — private key stays
  on hardware)
- Signs any file using the on-token key (`openssl cms` engine call)
- Verifies a `.p7s` signature against India PKI
- Displays all licensed CAs, CCA URLs, and key policy facts (Class 2 discontinued
  Jan 2021, Video KYC since Jul 2024, FIPS 140-2 Level 2+ token requirement)

---

## Practical gaps that limit real-world usefulness

### 1. The RCAI fingerprint is a placeholder

```python
RCAI_SHA256_FINGERPRINT = (
    "1A:B2:C3:D4:E5:F6:07:18:..."   # ← fabricated, not the real CCA root
)
```

Users who rely on this to pin-verify the trust anchor against `cca.gov.in` would
get a false result. The real RCAI root certificate needs to be fetched from CCA and
its actual SHA-256 fingerprint hardcoded (or fetched at runtime from a trusted source).

### 2. No PDF-specific signing (PAdES/CAdES)

Indian e-governance portals (MCA21, Income Tax e-filing, GST portal, GeM, CPPP)
expect a **signed PDF** — either PDF-native signature (PAdES) or a CMS-enveloped
PDF. The current module produces a detached `.p7s` file, which most portals don't
accept as a standalone submission.

Adding `pyhanko` or `pypdf` + `pkcs11` would allow:
- Signing PDFs in-place so the signature is embedded and visible in Acrobat/Foxit
- Producing the exact format MCA and IT portal validators check

### 3. No certificate expiry monitoring

DSC tokens expire after 1–2 years. The most common pain point professionals
describe is discovering expiry mid-filing (typically during advance tax deadlines
or ROC filing dates). A simple scheduled check — parsing `Not After` from the
exported cert and alerting N days before — would prevent this repeatedly.

### 4. No portal-specific workflow guides

Different portals have subtly different requirements:

| Portal | Format needed | Common gotcha |
|---|---|---|
| MCA21 v3 | PDF signed with Class 3 org DSC | Director + CS both must sign |
| Income Tax (e-filing 2.0) | XML signed, then PKCS7 attached | PAN must match DSC subject |
| GSTIN registration | PDF + DSC login | USB token must be inserted during browser session |
| GeM / CPPP | PKCS7 DER signature on tender document | Timestamp required |

The module currently has zero portal-specific knowledge. Wrapping the signing
workflow with portal-specific pre-checks (cert subject matches PAN, Class 3
required, org vs individual cert type) would save significant debugging time.

### 5. No eSign (Aadhaar-based) support

The CCA-licensed **eSign API** (NSDL, eMudhra, CDAC) allows Aadhaar OTP-based
signing without a physical USB token. This is increasingly accepted across
e-governance platforms and is the direction the ecosystem is moving. An eSign
workflow module would serve users who don't have or have lost their physical token.

### 6. No token health / PIN status

`pkcs11-tool` can report remaining PIN attempts and whether the token is locked.
A health check that shows this before a signing operation would prevent accidental
token lockout (typically after 3 wrong PINs — permanently locks the token, requires
re-issuance from the CA).

---

## Planned additions (priority order)

| # | Feature | Effort | Impact |
|---|---|---|---|
| 1 | **Real RCAI fingerprint** | Trivial — one-line data fix | Makes trust verification actually correct |
| 2 | **Certificate expiry check + alert** | Small — parse `Not After`, return days-remaining, surface in UI | Prevents mid-deadline surprises |
| 3 | **PDF signing (PAdES)** | Medium — integrate `pyhanko` for inline signatures | What every professional actually needs for portal submissions |
| 4 | **Portal workflow validators** | Medium — pre-signing checks keyed to MCA/IT/GST rules | Catches format/cert-type mismatches before submission |
| 5 | **Token PIN health check** | Small — surface remaining PIN attempts before signing | Prevents accidental permanent token lockout |
| 6 | **eSign API stub** | Large — call eMudhra/NSDL eSign endpoint | Future-proofs for Aadhaar-based signing without hardware token |

---

## Notes

- The core infrastructure (PKCS#11 detection, object listing, CMS signing, audit
  logging) is solid. The gap is almost entirely at the *workflow* layer.
- `pyhanko` is the recommended library for PAdES PDF signing from Python; it supports
  PKCS#11 tokens directly via `pyhanko-certvalidator`.
- For eSign, the API spec is published by CCA at `cca.gov.in`; each licensed ASP
  (eMudhra, NSDL, CDAC) provides their own endpoint and client SDK.
- Portal requirements change frequently — MCA21 v3 migration (2022) and IT e-filing
  2.0 (2023) both broke existing DSC workflows. Portal-specific logic should be
  versioned and easy to update independently of core signing code.
