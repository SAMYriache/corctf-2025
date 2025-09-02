#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Déchiffre un BMP 24 bpp (1024x1024 typiquement) chiffré par XOR avec un
keystream factorisé par bits de rangée et de colonne (20 mini-clés Δ).
Méthode : pour chaque bit s de colonne (0..9) puis de ligne (0..9),
on prend des paires de pixels dont les indices ne diffèrent que par ce bit
et on regarde le XOR le plus fréquent pour estimer Δ_s.
Ensuite, on reconstruit le keystream complet et on XOR pour récupérer l'image.
Compatible avec BMP bottom-up (hauteur > 0) ou top-down (hauteur < 0).
"""

import argparse
import struct
from collections import Counter
from typing import Tuple, List

import numpy as np


def read_bmp_headers(buf: bytes) -> Tuple[int, int, int, int, int, int]:
    # BITMAPFILEHEADER (14 octets) + DIB
    bfType, bfSize, bfReserved1, bfReserved2, bfOffBits = struct.unpack_from("<2sIHHI", buf, 0)
    if bfType != b"BM":
        raise ValueError("Fichier non-BMP (signature != 'BM').")
    dib_header_size = struct.unpack_from("<I", buf, 14)[0]

    if dib_header_size < 40:
        raise ValueError(f"DIB header trop court/unsupported ({dib_header_size} octets).")

    (biSize, biWidth, biHeight, biPlanes, biBitCount, biCompression,
     biSizeImage, biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant) = struct.unpack_from("<IiiHHIIiiII", buf, 14)

    if biCompression != 0:
        raise ValueError("Compression BMP non supportée (biCompression != BI_RGB).")
    if biBitCount != 24:
        raise ValueError(f"Seulement 24 bpp supporté ici (trouvé {biBitCount}).")

    return bfOffBits, dib_header_size, biWidth, biHeight, biBitCount, bfSize


def row_stride_bytes(width: int, bpp: int) -> int:
    # Aligné sur 4 octets
    return ((bpp * width + 31) // 32) * 4


def estimate_deltas(triples: np.ndarray) -> Tuple[List[np.ndarray], List[np.ndarray]]:
    """
    triples: array (H, W, 3) uint8 des pixels chiffrés (tel que stocké dans le BMP)
    Retourne (delta_col[10], delta_row[10]) où chaque élément est un vecteur de 3 uint8.
    """
    H, W, _ = triples.shape

    def estimate_for_bit(bit_index: int, axis: int):
        # axis=1 -> colonnes, axis=0 -> lignes
        s = bit_index
        step = 1 << s
        if axis == 1:
            # Colonnes : paires (r, c) & (r, c+step) pour c dont le bit s vaut 0
            c0 = np.arange(0, W - step, dtype=np.int32)
            c0 = c0[(c0 & step) == 0]
            if c0.size == 0:
                return None
            A = triples[:, c0, :]
            B = triples[:, c0 + step, :]
        else:
            # Lignes : paires (r, c) & (r+step, c) pour r dont le bit s vaut 0
            r0 = np.arange(0, H - step, dtype=np.int32)
            r0 = r0[(r0 & step) == 0]
            if r0.size == 0:
                return None
            A = triples[r0, :, :]
            B = triples[r0 + step, :, :]

        X = np.bitwise_xor(A, B).reshape(-1, 3)
        # mode (3 octets)
        # conversion en bytes pour Counter
        as_bytes = [bytes(x.tolist()) for x in X]
        most_common_bytes, _ = Counter(as_bytes).most_common(1)[0]
        return np.frombuffer(most_common_bytes, dtype=np.uint8)

    delta_col = []
    for b in range(10):
        est = estimate_for_bit(b, axis=1)
        if est is None:
            raise RuntimeError(f"Impossible d'estimer Δ_col[{b}]")
        delta_col.append(est)

    delta_row = []
    for b in range(10):
        est = estimate_for_bit(b, axis=0)
        if est is None:
            raise RuntimeError(f"Impossible d'estimer Δ_row[{b}]")
        delta_row.append(est)

    return delta_col, delta_row


def precompute_table(deltas: List[np.ndarray]) -> np.ndarray:
    """ Pré-calcul de l’XOR de toutes les combinaisons 10 bits → (1024, 3) """
    table = np.zeros((1 << 10, 3), dtype=np.uint8)
    for val in range(1 << 10):
        acc = np.zeros(3, dtype=np.uint8)
        v = val
        bit = 0
        while v:
            if v & 1:
                acc ^= deltas[bit]
            v >>= 1
            bit += 1
        table[val] = acc
    return table


def decrypt_pixels(triples: np.ndarray, delta_col: List[np.ndarray], delta_row: List[np.ndarray]) -> np.ndarray:
    H, W, _ = triples.shape
    col_table = precompute_table(delta_col)  # (1024, 3)
    row_table = precompute_table(delta_row)  # (1024, 3)

    # clé(r,c) = row_table[r] XOR col_table[c]
    out = np.empty_like(triples)
    for r in range(H):
        keys_row = np.bitwise_xor(row_table[r], col_table[:W])  # (W,3)
        out[r, :, :] = np.bitwise_xor(triples[r, :, :], keys_row)
    return out


def try_extract_flag(buf: bytes) -> str:
    # Cherche des patterns corctf{...}
    try:
        s = buf.decode('latin1')  # permissif
    except Exception:
        return ""
    import re
    m = re.search(r"corctf\{[^\}\n\r]{1,100}\}", s, re.IGNORECASE)
    return m.group(0) if m else ""


def main():
    ap = argparse.ArgumentParser(description="Déchiffre un BMP chiffré par keystream factorisé (rows/cols).")
    ap.add_argument("input", help="BMP chiffré (ex: flag-enc.bmp)")
    ap.add_argument("-o", "--output", default="flag-dec.bmp", help="BMP déchiffré à écrire (défaut: flag-dec.bmp)")
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()

    bfOffBits, dib_size, width, height_raw, bpp, bfSize = read_bmp_headers(data)
    H = abs(height_raw)
    stride = row_stride_bytes(width, bpp)

    pixel_array_size = stride * H
    if bfOffBits + pixel_array_size > len(data):
        raise ValueError("Taille des pixels incohérente avec le fichier.")

    # Section pixels telle que stockée (bottom-up si height_raw>0)
    pixels_bytes = data[bfOffBits: bfOffBits + pixel_array_size]
    # On travaille sur un tableau (H, stride)
    px2d = np.frombuffer(pixels_bytes, dtype=np.uint8).reshape(H, stride)

    # On assume pas de padding (pour 24bpp : stride doit être 3*width)
    if stride != 3 * width:
        raise ValueError(
            f"Ce script suppose pas de padding (stride={stride}, attendu {3*width}). "
            f"Adapte le code si nécessaire."
        )

    triples = px2d.reshape(H, width, 3)

    # Estimer les 20 deltas (colonnes puis lignes) depuis le chiffré seul
    delta_col, delta_row = estimate_deltas(triples)

    # Déchiffrer (K_base se simplifie car on estime par différences)
    plain_triples = decrypt_pixels(triples, delta_col, delta_row)

    # Réécrire un BMP en remplaçant seulement la zone pixels
    out = bytearray(data)
    out[bfOffBits: bfOffBits + pixel_array_size] = plain_triples.reshape(-1).tobytes()

    with open(args.output, "wb") as f:
        f.write(out)

    # Tentative d’extraction du flag en clair (texte dans les octets)
    flag = try_extract_flag(bytes(out))
    if flag:
        print("Flag détecté :", flag)
    else:
        print("Déchiffrement terminé. Aucune chaîne 'corctf{...}' trouvée dans les octets.")
        print("L’image devrait cependant afficher le flag lisible visuellement.")

    print(f"Écrit : {args.output}")


if __name__ == "__main__":
    main()
