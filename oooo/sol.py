#!/usr/bin/env python3

# utilisation python3 sol.py ctfi.ng 31556 -n 300
import argparse, socket, binascii, sys, time, itertools, string
from typing import List, Optional

def recv_line(f):
    line = f.readline()
    if not line:
        raise EOFError("connexion fermée")
    return line.strip()

def get_samples(host: str, port: int, n: int) -> List[bytes]:
    s = socket.create_connection((host, port))
    f = s.makefile("rb", buffering=0)
    # Lire la bannière
    try:
        banner = recv_line(f)
    except EOFError:
        banner = b""
    samples = []
    L = None
    while len(samples) < n:
        # envoyer une ligne vide (input ignoré sauf 'exit')
        s.sendall(b"\n")
        line = recv_line(f)
        if not line:
            continue
        try:
            ct = bytes.fromhex(line.decode())
        except Exception:
            # parfois une ligne vide/sale, on lit encore
            continue
        if L is None:
            L = len(ct)
        if len(ct) != L:
            # On ignore lignes de longueur inattendue
            continue
        samples.append(ct)
    s.close()
    return samples

def bytes_list_to_int_lists(bl: List[bytes]) -> List[List[int]]:
    return [list(b) for b in bl]

def solve_flag(ciphertexts: List[List[int]]) -> List[int]:
    """
    Trouve F (liste d'octets) tel que pour chaque ligne t,
    les valeurs K_t[i] = C_t[i] ^ F[i] soient toutes distinctes.
    Backtracking + MRV.
    """
    m = len(ciphertexts)
    L = len(ciphertexts[0])

    # ensembles des valeurs déjà "prises" dans chaque ligne t
    used = [set() for _ in range(m)]
    F = [-1] * L
    remaining = set(range(L))

    # heuristique: commence par l'index qui contraint le plus (après 0)
    # on fixe F[0]=0 (on corrigera plus tard par une constante g)
    i0 = 0
    F[i0] = 0
    remaining.remove(i0)
    for t in range(m):
        used[t].add(ciphertexts[t][i0] ^ F[i0])

    # pré-calcul des "forbidden" pour un index i donné
    def forbidden_values_for(i):
        forb = set()
        for t in range(m):
            ci = ciphertexts[t][i]
            # K_t[i] != val pour tout val déjà utilisé dans la même ligne
            # donc F[i] != ci ^ val
            forb.update((ci ^ val) & 0xFF for val in used[t])
        return forb

    # choisir la variable avec le moins de valeurs possibles (MRV)
    def choose_var():
        best_i = None
        best_count = 257
        for i in remaining:
            forb = forbidden_values_for(i)
            cnt = 256 - len(forb)
            if cnt < best_count:
                best_count = cnt
                best_i = i
                if cnt == 0:
                    break
        return best_i

    sys.setrecursionlimit(10000)

    def backtrack() -> bool:
        if not remaining:
            return True
        i = choose_var()
        if i is None:
            return False
        forb = forbidden_values_for(i)
        candidates = [v for v in range(256) if v not in forb]

        # tri: essaye d'abord valeurs qui minimisent les conflits futurs
        # (simple heuristique: pas nécessairement optimal)
        def score(v):
            sc = 0
            for t in range(m):
                sc += (ciphertexts[t][i] ^ v) in used[t]
            return sc
        candidates.sort(key=score)

        remaining.remove(i)
        for v in candidates:
            # placer v et propager
            ok = True
            touched = []
            for t in range(m):
                kv = (ciphertexts[t][i] ^ v) & 0xFF
                if kv in used[t]:
                    ok = False
                    break
                used[t].add(kv)
                touched.append((t, kv))
            if ok:
                F[i] = v
                if backtrack():
                    return True
                F[i] = -1
            # undo
            for (t, kv) in touched:
                used[t].remove(kv)
        remaining.add(i)
        return False

    if not backtrack():
        raise RuntimeError("Backtracking impossible — collectez plus de lignes et réessayez.")
    return F

def adjust_with_prefix(F: List[int], want=b"corctf{") -> bytes:
    # toutes solutions sont F' = F_true ^ g ; on choisit g pour matcher le préfixe
    g_vals = [F[i] ^ want[i] for i in range(min(len(F), len(want)))]
    # vérifier cohérence
    g = max(set(g_vals), key=g_vals.count) if g_vals else 0
    # sanity: si pas cohérent partout, on s'en tient au plus fréquent
    return bytes((x ^ g) & 0xFF for x in F)

def is_printable_flag(b: bytes) -> bool:
    return b.startswith(b"corctf{") and b.endswith(b"}") and all(32 <= c < 127 for c in b)

def main():
    ap = argparse.ArgumentParser(description="Solver corCTF - oooo")
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("-n", "--num", type=int, default=300, help="nombre de lignes à collecter")
    args = ap.parse_args()

    print(f"[+] Connexion à {args.host}:{args.port} et collecte de {args.num} lignes…")
    samples = get_samples(args.host, args.port, args.num)
    L = len(samples[0])
    print(f"[+] Longueur du flag: {L} octets")

    cts = bytes_list_to_int_lists(samples)
    print("[+] Résolution par contraintes (unicité par ligne)…")
    F_guess = solve_flag(cts)
    flag = adjust_with_prefix(F_guess, b"corctf{")

    print("[+] Flag (hex):", flag.hex())
    try:
        s = flag.decode("utf-8", "strict")
    except Exception:
        s = None

    if s and is_printable_flag(flag):
        print("[+] FLAG:", s)
    else:
        # parfois besoin de plus de lignes si le backtracking a pris une autre solution équivalente;
        # l’ajustement par préfixe devrait suffire.
        print("[?] Décodage ASCII:", s if s else "<non-UTF8>")
        print("[i] Si ce n’est pas correct, relancez avec un -n plus grand (ex: 500).")

if __name__ == "__main__":
    main()
