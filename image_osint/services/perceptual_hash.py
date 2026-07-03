"""
Average Hash (aHash) perceptual fingerprint — pure Python implementation.

Used for image similarity hints and investigator reference without relying on
external image-hash libraries.
"""

from __future__ import annotations

import hashlib
from io import BytesIO

from PIL import Image


class PerceptualHashEngine:
    """
    Computes 64-bit average hash (8x8 grayscale) and hex digest.
    """

    HASH_SIZE = 8

    def compute(self, file_bytes: bytes) -> dict[str, str]:
        image = Image.open(BytesIO(file_bytes))
        image = image.convert("L").resize(
            (self.HASH_SIZE, self.HASH_SIZE),
            Image.Resampling.LANCZOS,
        )
        pixels = list(image.getdata())
        image.close()

        average = sum(pixels) / len(pixels)
        bits = "".join("1" if px >= average else "0" for px in pixels)
        hex_hash = self._bits_to_hex(bits)
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        return {
            "algorithm": "aHash-8x8",
            "perceptual_hash_hex": hex_hash,
            "perceptual_hash_bits": bits,
            "sha256_file": sha256,
        }

    @staticmethod
    def hamming_distance(hex_a: str, hex_b: str) -> int:
        """Compare two perceptual hashes; lower = more similar."""
        int_a = int(hex_a, 16)
        int_b = int(hex_b, 16)
        xor = int_a ^ int_b
        return bin(xor).count("1")

    def _bits_to_hex(self, bits: str) -> str:
        value = int(bits, 2)
        return f"{value:016x}"
