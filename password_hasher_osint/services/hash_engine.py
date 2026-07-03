"""
Educational password hashing and comparison (SRS-31–32).

Uses stdlib only — MD5, SHA-1, SHA-256, SHA-512, Base64.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "base64_encode", "base64_decode")

_ALGO_LABELS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "base64_encode": "Base64 (encode)",
    "base64_decode": "Base64 (decode)",
}


@dataclass(frozen=True)
class HashResult:
    algorithm: str
    label: str
    digest: str
    weak: bool

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "label": self.label,
            "digest": self.digest,
            "weak": self.weak,
        }


@dataclass(frozen=True)
class CompareResult:
    algorithm: str
    label: str
    computed: str
    target: str
    matched: bool

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "label": self.label,
            "computed": self.computed,
            "target": self.target,
            "matched": self.matched,
        }


def algorithm_label(algo: str) -> str:
    return _ALGO_LABELS.get(algo, algo)


def _normalize_compare_value(value: str) -> str:
    return value.strip().lower()


def compute_hash(algorithm: str, text: str) -> HashResult:
    algo = algorithm.lower()
    data = text.encode("utf-8")

    if algo == "md5":
        digest = hashlib.md5(data).hexdigest()
        weak = True
    elif algo == "sha1":
        digest = hashlib.sha1(data).hexdigest()
        weak = True
    elif algo == "sha256":
        digest = hashlib.sha256(data).hexdigest()
        weak = False
    elif algo == "sha512":
        digest = hashlib.sha512(data).hexdigest()
        weak = False
    elif algo == "base64_encode":
        digest = base64.b64encode(data).decode("ascii")
        weak = False
    elif algo == "base64_decode":
        try:
            digest = base64.b64decode(text.encode("ascii"), validate=True).decode(
                "utf-8", errors="replace"
            )
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"Invalid Base64 input: {exc}") from exc
        weak = False
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return HashResult(
        algorithm=algo,
        label=algorithm_label(algo),
        digest=digest,
        weak=weak,
    )


def compute_hashes(text: str, algorithms: list[str]) -> list[HashResult]:
    results: list[HashResult] = []
    for algo in algorithms:
        if algo not in ALGORITHMS:
            continue
        results.append(compute_hash(algo, text))
    return results


def compare_hash(algorithm: str, plaintext: str, target_hash: str) -> CompareResult:
    algo = algorithm.lower()
    if algo in ("base64_encode", "base64_decode"):
        raise ValueError("Use hex digest algorithms for compare (MD5, SHA-1, SHA-256, SHA-512).")

    computed = compute_hash(algo, plaintext).digest
    target = target_hash.strip()

    if algo != "base64_encode" and algo != "base64_decode":
        if not _HEX_RE.match(target):
            raise ValueError("Hash must be a hexadecimal string for this algorithm.")
        matched = _normalize_compare_value(computed) == _normalize_compare_value(target)
    else:
        matched = computed == target

    return CompareResult(
        algorithm=algo,
        label=algorithm_label(algo),
        computed=computed,
        target=target,
        matched=matched,
    )
