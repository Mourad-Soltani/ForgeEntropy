#!/usr/bin/env python3
"""
ForgeEntropy - Offline CLI for forging and auditing high-entropy secrets.
Built by Mourad.Soltani
"""
import argparse
import json
import math
import secrets
import string
import sys
from typing import Dict, List, Optional

CHARSETS = {
    "alnum": string.ascii_letters + string.digits,
    "alnum-sym": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?",
    "hex": "0123456789abcdef",
    "base64": string.ascii_letters + string.digits + "+/",
}

def calculate_entropy(s: str) -> float:
    """Shannon entropy in bits per character, then total bits."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    entropy_per_char = -sum((count / n) * math.log2(count / n) for count in freq.values())
    return entropy_per_char * n

def estimate_crack_time(entropy_bits: float, hashrate: float = 1e12) -> str:
    """Rough crack time estimate assuming 2^(entropy/2) for average case, simple model."""
    if entropy_bits <= 0:
        return "instant"
    # Simplified: time = 2^entropy / (2 * hashrate) seconds
    seconds = (2 ** entropy_bits) / (2 * hashrate)
    if seconds < 1:
        return "< 1 second"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    else:
        years = seconds / 31536000
        if years > 1e9:
            return f"{years:.2e} years"
        return f"{years:.1f} years"

def generate_secret(length: int, charset: str = "alnum-sym") -> str:
    chars = CHARSETS.get(charset, CHARSETS["alnum-sym"])
    return "".join(secrets.choice(chars) for _ in range(length))

def audit_secret(secret: str, min_entropy: float = 80.0) -> Dict:
    ent = calculate_entropy(secret)
    passes = ent >= min_entropy
    return {
        "secret_length": len(secret),
        "entropy_bits": round(ent, 2),
        "meets_policy": passes,
        "min_required": min_entropy,
        "crack_time_estimate_1e12_hps": estimate_crack_time(ent),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description="ForgeEntropy — forge & audit high-entropy secrets. Built by Mourad.Soltani")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="Generate a high-entropy secret")
    gen.add_argument("--length", type=int, default=24)
    gen.add_argument("--charset", choices=list(CHARSETS.keys()), default="alnum-sym")
    gen.add_argument("--json", action="store_true")

    aud = sub.add_parser("audit", help="Audit an existing secret")
    aud.add_argument("secret")
    aud.add_argument("--min-entropy", type=float, default=80.0)
    aud.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.cmd == "generate":
        secret = generate_secret(args.length, args.charset)
        audit = audit_secret(secret)
        result = {"secret": secret, **audit, "charset": args.charset}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Secret: {secret}")
            print(f"Entropy: {audit['entropy_bits']} bits")
            print(f"Crack time (est.): {audit['crack_time_estimate_1e12_hps']}")
    elif args.cmd == "audit":
        result = audit_secret(args.secret, args.min_entropy)
        result["secret_preview"] = args.secret[:8] + "..." if len(args.secret) > 8 else args.secret
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
