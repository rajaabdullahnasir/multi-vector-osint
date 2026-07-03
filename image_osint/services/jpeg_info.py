"""
JPEG binary structure helpers (SOF / JFIF) — no external deps.
"""

from __future__ import annotations


def read_jpeg_info(file_bytes: bytes) -> dict[str, str]:
    info: dict[str, str] = {}
    if not file_bytes.startswith(b"\xff\xd8"):
        return info

    info["Encoding Process"] = "Baseline DCT, Huffman coding"

    offset = 2
    length = len(file_bytes)
    while offset < length - 1:
        if file_bytes[offset] != 0xFF:
            offset += 1
            continue
        marker = file_bytes[offset + 1]
        offset += 2
        if marker in (0xD8, 0xD9):  # SOI, EOI
            continue
        if marker == 0xDA:  # SOS — image data starts
            break
        if offset + 2 > length:
            break
        seg_len = int.from_bytes(file_bytes[offset : offset + 2], "big")
        seg_start = offset + 2
        seg_end = seg_start + seg_len - 2
        if seg_end > length:
            break

        if marker == 0xE0 and seg_len >= 7:  # JFIF
            info["JFIF Version"] = f"{file_bytes[seg_start + 2]}.{file_bytes[seg_start + 3]:02d}"
            units = file_bytes[seg_start + 4]
            unit_name = {0: "none", 1: "in", 2: "cm"}.get(units, str(units))
            xdens = int.from_bytes(file_bytes[seg_start + 5 : seg_start + 7], "big")
            ydens = int.from_bytes(file_bytes[seg_start + 7 : seg_start + 9], "big")
            info["JFIF Density"] = f"{xdens}x{ydens} ({unit_name})"

        if marker in (0xC0, 0xC1, 0xC2):  # SOF0, SOF1, SOF2
            if seg_len >= 8:
                precision = file_bytes[seg_start]
                height = int.from_bytes(file_bytes[seg_start + 1 : seg_start + 3], "big")
                width = int.from_bytes(file_bytes[seg_start + 3 : seg_start + 5], "big")
                components = file_bytes[seg_start + 5]
                info["Bits Per Sample"] = str(precision)
                info["Color Components"] = str(components)
                info["Image Width"] = str(width)
                info["Image Height"] = str(height)
                if components >= 3 and seg_len >= 8 + components * 3:
                    y_id = file_bytes[seg_start + 8]
                    cb_id = file_bytes[seg_start + 11]
                    cr_id = file_bytes[seg_start + 14]
                    cy = file_bytes[seg_start + 9]
                    cbcr = file_bytes[seg_start + 12]
                    if y_id == 1 and cb_id == 2 and cr_id == 3:
                        if cy == 0x22 and cbcr == 0x11:
                            info["Y Cb Cr Sub Sampling"] = "YCbCr4:2:0 (2 2)"
                        elif cy == 0x21 and cbcr == 0x11:
                            info["Y Cb Cr Sub Sampling"] = "YCbCr4:2:2 (2 1)"
                        elif cy == 0x11 and cbcr == 0x11:
                            info["Y Cb Cr Sub Sampling"] = "YCbCr4:4:4 (1 1)"

        offset = seg_end

    return info
