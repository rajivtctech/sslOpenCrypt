"""
ui/panels/edu_panel.py — Module 9: Educational Hub panel.
Provides interactive tutorials, command library, and conceptual explanations.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox, QLabel, QPushButton, QScrollArea,
    QTabWidget, QTextBrowser, QTextEdit, QVBoxLayout, QWidget,
)

from .base_panel import BasePanel

TUTORIALS = {
    "Symmetric Encryption": {
        "eli5": (
            "Imagine you have a secret lockbox. You lock it with a key, "
            "and only someone who has the same key can open it. AES is the world's "
            "strongest lockbox — it would take billions of years to break."
        ),
        "beginner": (
            "Symmetric encryption uses the same key to lock (encrypt) and unlock (decrypt) data.\n\n"
            "AES-256 is the standard — used in Wi-Fi, HTTPS, WhatsApp, and disk encryption.\n\n"
            "The key must remain secret. The challenge: how do you share it securely? "
            "(Answer: asymmetric encryption!)\n\n"
            "openssl enc -aes-256-gcm -in plaintext.txt -out encrypted.bin -pass pass:mypassword -pbkdf2"
        ),
        "intermediate": (
            "AES is a block cipher operating on 128-bit (16-byte) blocks.\n\n"
            "Mode of operation determines how blocks are chained:\n"
            "  • CBC — each block XORed with previous ciphertext; requires random IV; no integrity\n"
            "  • GCM — AEAD mode; provides both confidentiality AND integrity (auth tag)\n"
            "  • CTR — stream cipher mode; parallelisable; no integrity alone\n\n"
            "Always prefer AES-256-GCM for new work. NEVER reuse GCM nonces.\n\n"
            "Key derivation from password:\n"
            "  openssl enc uses PBKDF2 with -pbkdf2 -iter 600000 (minimum)\n"
            "  For modern apps, use Argon2id instead."
        ),
        "expert": (
            "AES is a Substitution-Permutation Network (SPN) — NOT a Feistel network.\n"
            "10/12/14 rounds for 128/192/256-bit keys.\n\n"
            "GCM = CTR mode + GHASH over GF(2^128).\n"
            "Nonce reuse in GCM catastrophically leaks the authentication key H.\n"
            "  Attack: If two messages share nonce N with auth keys H=H(K), recover H from\n"
            "  (C1 XOR C2) and the two auth tags.\n\n"
            "ChaCha20-Poly1305 (RFC 8439) avoids nonce-misuse issues more gracefully because\n"
            "the Poly1305 key is derived fresh from the ChaCha20 keystream on every message.\n"
            "Still catastrophically broken on nonce reuse — but the 96-bit nonce can be\n"
            "a sequential counter, reducing accidental reuse risk vs GCM's 96-bit nonce."
        ),
    },
    "Public Key Cryptography": {
        "eli5": (
            "You have two keys: one that anyone can use to lock a box (public key), "
            "and one that only you can use to open it (private key). "
            "Anyone can send you a locked box, but only you can open it."
        ),
        "beginner": (
            "Asymmetric (public-key) cryptography uses a mathematically linked key pair:\n"
            "  • Public key: safe to share with everyone\n"
            "  • Private key: must never leave your possession\n\n"
            "If someone encrypts with your public key, only your private key can decrypt.\n"
            "If you sign with your private key, everyone can verify with your public key.\n\n"
            "RSA and ECDSA are the most common asymmetric algorithms.\n"
            "Ed25519 is modern, fast, and recommended for new systems."
        ),
        "intermediate": (
            "RSA security relies on the difficulty of factoring large integers.\n"
            "  Key generation: choose two large primes p, q; n = p*q; e=65537; d = e^-1 mod λ(n)\n"
            "  Encrypt: c = m^e mod n  |  Decrypt: m = c^d mod n\n\n"
            "ECDSA uses the elliptic curve discrete logarithm problem.\n"
            "P-256 (prime256v1) is the most widely deployed curve.\n"
            "Ed25519 uses the Edwards curve, offers resistance to timing side-channels.\n\n"
            "openssl genpkey -algorithm ed25519 -out private.pem\n"
            "openssl pkey -in private.pem -pubout -out public.pem"
        ),
        "expert": (
            "RSA: IND-CPA security requires OAEP padding (PKCS#1 v2.1). Raw RSA is deterministic.\n"
            "Bleichenbacher '98 attack on PKCS#1 v1.5 (still present in many TLS stacks).\n\n"
            "ECDSA: signature (r, s) where r = (k·G).x mod n, s = (z + r·d) / k mod n.\n"
            "k must be a fresh random nonce per signature. Reusing k leaks the private key.\n"
            "(Sony PlayStation 3 ECDSA key compromise: constant k)\n\n"
            "Ed25519: RFC 8032. Deterministic signature (k derived via SHA-512 of private key + message).\n"
            "Eliminates the k-reuse vulnerability. Cofactor 8 on Curve25519 avoids small-subgroup attacks.\n"
            "Security: 128-bit classical, ~64-bit quantum (Grover's algorithm)."
        ),
    },
    "Digital Signatures & PKI": {
        "eli5": (
            "A digital signature is like a wax seal on a letter. Only you can make it "
            "(with your private key), but anyone can check it's real (with your public key). "
            "A certificate is a letter from a trusted authority saying 'this public key really belongs to Alice'."
        ),
        "beginner": (
            "A digital signature proves:\n"
            "  1. The file was signed by someone with the private key (authentication)\n"
            "  2. The file has not changed since it was signed (integrity)\n"
            "  3. The signer cannot deny signing it (non-repudiation)\n\n"
            "A certificate is a public key + identity information, signed by a Certificate Authority.\n"
            "Your browser trusts certificates signed by a list of ~150 root CAs.\n\n"
            "openssl dgst -sha256 -sign private.pem -out sig.bin document.pdf\n"
            "openssl dgst -sha256 -verify public.pem -signature sig.bin document.pdf"
        ),
        "intermediate": (
            "X.509 v3 certificate fields (RFC 5280):\n"
            "  Subject / Issuer DN, Serial, Validity (Not Before / Not After)\n"
            "  Subject Public Key Info, Extensions:\n"
            "    - Basic Constraints (CA:TRUE or CA:FALSE)\n"
            "    - Key Usage (digitalSignature, keyEncipherment, keyCertSign, cRLSign)\n"
            "    - Subject Alternative Names (DNS, IP, email, URI)\n"
            "    - Authority Key Identifier, Subject Key Identifier\n\n"
            "Certificate chain: End-Entity → Intermediate CA → Root CA\n"
            "Root CA cert is self-signed (Issuer = Subject).\n"
            "OCSP (RFC 6960) and CRL (RFC 5280 §5) provide revocation status."
        ),
        "expert": (
            "RFC 5280 §4.2.1.9 — Basic Constraints: cA BOOLEAN, pathLenConstraint INTEGER OPTIONAL\n"
            "pathLenConstraint=0 means no further CAs below this certificate.\n\n"
            "CMS (RFC 5652) SignedData structure:\n"
            "  ContentType, DigestAlgorithms, EncapsulatedContentInfo,\n"
            "  Certificates (chain), CRLs, SignerInfos\n\n"
            "CAdES (ETSI EN 319 122) extends CMS with:\n"
            "  -B: basic (just the signature)\n"
            "  -T: adds RFC 3161 timestamp token\n"
            "  -LT: adds revocation data (OCSP/CRL)\n"
            "  -LTA: adds archive timestamp for long-term validation\n\n"
            "India DSC: Class 3 tokens use PKCS#11 interface (ePass2003, HYP2003).\n"
            "CCA root CA cross-certifies with RCAI at https://cca.gov.in/rootca.html"
        ),
    },
    "Hashing & Integrity": {
        "eli5": (
            "A hash is like a fingerprint for a file. Even the tiniest change in the file "
            "gives a completely different fingerprint. You can't reverse it — you can only "
            "check if two things have the same fingerprint."
        ),
        "beginner": (
            "A hash function takes any input and produces a fixed-size output (the hash/digest).\n"
            "  • Same input always → same output\n"
            "  • Tiny change in input → completely different output (avalanche effect)\n"
            "  • Cannot reverse a hash to get the original\n\n"
            "SHA-256 is the standard. MD5 and SHA-1 are broken — don't use for security.\n\n"
            "openssl dgst -sha256 myfile.pdf\n"
            "echo -n 'Hello World' | openssl dgst -sha256"
        ),
        "intermediate": (
            "SHA-256 security properties:\n"
            "  • Pre-image resistance: given h, finding m s.t. H(m)=h is infeasible\n"
            "  • Second pre-image: given m1, finding m2≠m1 with H(m1)=H(m2) is infeasible\n"
            "  • Collision resistance: finding any m1≠m2 with H(m1)=H(m2) is infeasible\n\n"
            "SHA-1 is broken for collision (SHAttered 2017 — practical collision found).\n"
            "MD5 is broken for both collision AND second pre-image.\n\n"
            "HMAC = H((K ⊕ opad) || H((K ⊕ ipad) || m)) — keyed, provides authenticity."
        ),
        "expert": (
            "SHA-256: Merkle-Damgård construction, Davies-Meyer compression function.\n"
            "Length-extension attack affects SHA-1/2 but NOT SHA-3 (sponge construction).\n\n"
            "BLAKE2 (RFC 7693): ARX-based, based on ChaCha stream cipher core.\n"
            "~400 MB/s vs ~300 MB/s for SHA-256 without AES-NI on 64-bit CPUs.\n\n"
            "For password storage: Argon2id (RFC 9106) — memory-hard, GPU-resistant.\n"
            "  Recommended params (2024): m=65536 KiB, t=3, p=4\n"
            "NEVER use raw SHA-256/512 for password storage — GPU can compute ~10^10 H/s."
        ),
    },
}

COMMAND_LIBRARY = [
    ("Generate RSA-4096 key pair",
     "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \\\n"
     "    -aes-256-cbc -out private.pem\n"
     "openssl pkey -in private.pem -pubout -out public.pem"),

    ("Generate Ed25519 key pair",
     "openssl genpkey -algorithm ed25519 -out private.pem\n"
     "openssl pkey -in private.pem -pubout -out public.pem"),

    ("Generate ECDSA P-256 key (PKCS#8)",
     "openssl ecparam -name prime256v1 -genkey -noout | \\\n"
     "openssl pkcs8 -topk8 -nocrypt -out private.pem\n"
     "openssl pkey -in private.pem -pubout -out public.pem"),

    ("Create self-signed certificate",
     "openssl req -x509 -newkey rsa:4096 -sha256 \\\n"
     "    -keyout key.pem -out cert.pem -days 365 -nodes \\\n"
     "    -subj '/CN=example.com/O=My Org/C=IN'"),

    ("Generate CSR",
     "openssl req -new -sha256 \\\n"
     "    -key private.pem -out request.csr \\\n"
     "    -subj '/CN=example.com/C=IN'"),

    ("Encrypt file (AES-256-GCM)",
     "openssl enc -aes-256-gcm \\\n"
     "    -in plaintext.txt -out encrypted.bin \\\n"
     "    -pass pass:MySecretPassword -pbkdf2 -iter 600000 -salt"),

    ("Decrypt file",
     "openssl enc -aes-256-gcm -d \\\n"
     "    -in encrypted.bin -out plaintext.txt \\\n"
     "    -pass pass:MySecretPassword -pbkdf2 -iter 600000"),

    ("Compute SHA-256 hash of file",
     "openssl dgst -sha256 myfile.pdf"),

    ("Compute HMAC-SHA-256",
     "openssl dgst -sha256 -hmac 'mysecretkey' myfile.pdf"),

    ("Sign file (raw ECDSA-SHA256)",
     "openssl dgst -sha256 -sign private.pem -out sig.bin firmware.bin"),

    ("Verify raw signature",
     "openssl dgst -sha256 -verify public.pem \\\n"
     "    -signature sig.bin firmware.bin"),

    ("Create PKCS#7 CMS detached signature",
     "openssl cms -sign -in document.pdf \\\n"
     "    -inkey private.pem -signer cert.pem \\\n"
     "    -md sha256 -out document.p7s -outform PEM -detached"),

    ("Verify CMS signature",
     "openssl cms -verify -in document.p7s \\\n"
     "    -content document.pdf -CAfile ca_bundle.pem"),

    ("Inspect TLS certificate chain",
     "echo | openssl s_client -connect example.com:443 -showcerts -servername example.com"),

    ("Inspect local certificate",
     "openssl x509 -in cert.pem -text -noout"),

    ("Create PKCS#12 bundle",
     "openssl pkcs12 -export \\\n"
     "    -inkey private.pem -in cert.pem \\\n"
     "    -out bundle.p12 -passout pass:bundlepassword"),

    ("Generate 32 random bytes (hex)",
     "openssl rand -hex 32"),

    ("Generate random password (20 bytes, base64)",
     "openssl rand -base64 20"),

    ("Generate DH parameters (2048-bit)",
     "openssl dhparam -out dhparam.pem 2048"),

    ("List available digest algorithms",
     "openssl list -digest-algorithms"),

    ("Check OCSP revocation status",
     "openssl ocsp -issuer issuer.pem -cert cert.pem \\\n"
     "    -url http://ocsp.example.com -text"),
]


class EduPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🎓  Educational Hub")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_tutorials_tab(), "Tutorials")
        tabs.addTab(self._build_commands_tab(), "Command Library")
        layout.addWidget(tabs, stretch=1)

    def _build_tutorials_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hdr = QComboBox()
        hdr.addItems(list(TUTORIALS.keys()))
        hdr.currentTextChanged.connect(self._load_tutorial)
        l.addWidget(hdr)
        self._tutorial_topic_combo = hdr

        tier_row = QWidget()
        tier_layout = QVBoxLayout(tier_row)
        tier_layout.setContentsMargins(0, 4, 0, 4)
        tier_label = QLabel("Explanation level:")
        tier_label.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        tier_layout.addWidget(tier_label)
        self._tier_combo = QComboBox()
        self._tier_combo.addItems(["🧒  ELI5", "🌱  Beginner", "⚙️  Intermediate", "🔬  Expert"])
        self._tier_combo.currentTextChanged.connect(lambda _: self._load_tutorial(hdr.currentText()))
        tier_layout.addWidget(self._tier_combo)
        l.addWidget(tier_row)

        self._tutorial_browser = QTextBrowser()
        self._tutorial_browser.setFont(QFont("Segoe UI", 10))
        self._tutorial_browser.setStyleSheet(
            "background:#1F2937; color:#E5E7EB; border:1px solid #374151; border-radius:4px; padding:8px;"
        )
        l.addWidget(self._tutorial_browser, stretch=1)

        # Load initial tutorial
        self._load_tutorial(list(TUTORIALS.keys())[0])
        return w

    def _load_tutorial(self, topic: str):
        tier_text = self._tier_combo.currentText()
        tier_map = {
            "🧒  ELI5": "eli5",
            "🌱  Beginner": "beginner",
            "⚙️  Intermediate": "intermediate",
            "🔬  Expert": "expert",
        }
        tier_key = tier_map.get(tier_text, "beginner")
        content = TUTORIALS.get(topic, {}).get(tier_key, "Content not available.")

        tier_colors = {
            "eli5": "#FCD34D",
            "beginner": "#34D399",
            "intermediate": "#60A5FA",
            "expert": "#F87171",
        }
        color = tier_colors.get(tier_key, "#E5E7EB")

        html = (
            f"<h2 style='color:{color};'>{topic}</h2>"
            f"<pre style='white-space:pre-wrap; color:#E5E7EB; font-family:monospace; font-size:11px;'>{content}</pre>"
        )
        self._tutorial_browser.setHtml(html)

    def _build_commands_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel("Curated library of annotated openssl commands. Click any command to copy it to clipboard.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        l.addWidget(info)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border: none;")

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(6)

        for name, cmd in COMMAND_LIBRARY:
            frame = self._make_cmd_card(name, cmd)
            container_layout.addWidget(frame)

        container_layout.addStretch()
        scroll.setWidget(container)
        l.addWidget(scroll, stretch=1)
        return w

    def _make_cmd_card(self, name: str, cmd: str) -> QWidget:
        from PyQt6.QtWidgets import QFrame, QHBoxLayout, QApplication
        card = QFrame()
        card.setStyleSheet(
            "background:#1F2937; border:1px solid #374151; border-radius:6px; margin:2px;"
        )
        cl = QVBoxLayout(card)
        cl.setContentsMargins(8, 6, 8, 6)

        title_row = QHBoxLayout()
        title_lbl = QLabel(name)
        title_lbl.setStyleSheet("font-weight:bold; color:#9CA3AF; font-size:10px;")
        title_row.addWidget(title_lbl)
        title_row.addStretch()
        btn_copy = QPushButton("Copy")
        btn_copy.setMaximumWidth(50)
        btn_copy.setStyleSheet("background:#374151; color:#D1D5DB; padding:2px 6px; font-size:9px; border-radius:3px;")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(cmd))
        title_row.addWidget(btn_copy)
        cl.addLayout(title_row)

        cmd_lbl = QLabel(cmd)
        cmd_lbl.setFont(QFont("Monospace", 8))
        cmd_lbl.setStyleSheet("color:#D1FAE5;")
        cmd_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cmd_lbl.setWordWrap(True)
        cl.addWidget(cmd_lbl)

        return card
