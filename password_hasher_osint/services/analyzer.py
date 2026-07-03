"""
Password hasher orchestrator — hash generation and compare (SRS-31–32).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .hash_engine import ALGORITHMS, CompareResult, HashResult, compare_hash, compute_hashes
from .input_validator import PasswordInputValidator


@dataclass
class HashJobReport:
    success: bool
    mode: str = "hash"
    error: str | None = None
    validation_failed: bool = False
    algorithms: list[str] | None = None
    hashes: list[dict[str, Any]] | None = None
    compare: dict[str, Any] | None = None
    matched: bool | None = None
    sections: dict[str, Any] | None = None
    risk_flags: list[str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "mode": self.mode,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "algorithms": self.algorithms,
            "hashes": self.hashes,
            "compare": self.compare,
            "matched": self.matched,
            "sections": self.sections,
            "risk_flags": self.risk_flags,
        }


class PasswordHasherAnalyzer:
    def __init__(self):
        self.validator = PasswordInputValidator()

    def generate_hashes(self, plaintext: str, algorithms: list[str]) -> HashJobReport:
        text_val = self.validator.validate_text(plaintext, field_name="Password / text")
        if not text_val.ok:
            return HashJobReport(
                success=False,
                error=text_val.error,
                validation_failed=True,
            )

        algo_val = self.validator.validate_algorithms(algorithms)
        if not algo_val.ok:
            return HashJobReport(
                success=False,
                error=algo_val.error,
                validation_failed=True,
            )

        selected = [a for a in algorithms if a in ALGORITHMS]
        try:
            results: list[HashResult] = compute_hashes(text_val.value, selected)
        except ValueError as exc:
            return HashJobReport(success=False, error=str(exc))

        hashes_payload = [r.to_dict() for r in results]
        weak = [r.label for r in results if r.weak]

        sections = {
            "Summary": {
                "Mode": "Generate hashes",
                "Algorithms": ", ".join(r.label for r in results),
                "Digest count": str(len(results)),
            },
        }

        flags = [
            "Plaintext is not stored — only digests are saved in your history.",
        ]
        if weak:
            flags.append(
                f"Weak algorithms used ({', '.join(weak)}) — not suitable for password storage."
            )

        return HashJobReport(
            success=True,
            mode="hash",
            algorithms=selected,
            hashes=hashes_payload,
            sections=sections,
            risk_flags=flags,
        )

    def compare(self, plaintext: str, target_hash: str, algorithm: str) -> HashJobReport:
        text_val = self.validator.validate_text(plaintext, field_name="Password / text")
        if not text_val.ok:
            return HashJobReport(
                success=False,
                error=text_val.error,
                validation_failed=True,
            )

        hash_val = self.validator.validate_text(target_hash, field_name="Target hash")
        if not hash_val.ok:
            return HashJobReport(
                success=False,
                error=hash_val.error,
                validation_failed=True,
            )

        algo = (algorithm or "").lower().strip()
        if algo not in ("md5", "sha1", "sha256", "sha512"):
            return HashJobReport(
                success=False,
                error="Compare supports MD5, SHA-1, SHA-256, or SHA-512 only.",
                validation_failed=True,
            )

        try:
            result: CompareResult = compare_hash(algo, text_val.value, hash_val.value)
        except ValueError as exc:
            return HashJobReport(success=False, error=str(exc))

        compare_payload = result.to_dict()
        sections = {
            "Summary": {
                "Mode": "Compare hash",
                "Algorithm": result.label,
                "Match": "Yes" if result.matched else "No",
            },
        }

        flags = [
            "Plaintext is not stored — only comparison metadata is saved.",
            "Use only on data you are authorized to test.",
        ]

        return HashJobReport(
            success=True,
            mode="compare",
            algorithms=[algo],
            compare=compare_payload,
            matched=result.matched,
            sections=sections,
            risk_flags=flags,
        )
