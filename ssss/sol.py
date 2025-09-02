#!/usr/bin/env python3
from pwn import remote
from typing import List

# Modulus from the challenge (Curve25519 prime)
P = (1 << 255) - 19

HOST = "ctfi.ng"
PORT = 31555

# Small distinct nonzero points; we'll use 7 of them
XS = [1, 2, 3, 4, 5, 6, 7]
EXPS = [0, 2, 4, 6, 8, 10, 12]  # powers appearing in h(x) (plus constant 0th power)

def inv(a: int, p: int = P) -> int:
    # python3.8+ supports pow(a, -1, p); use exponent variant for compatibility
    return pow(a, p - 2, p)

def solve_weights(xs: List[int], p: int = P) -> List[int]:
    """
    Find weights w such that:
      sum_i w_i * xs[i]^0 = 1
      sum_i w_i * xs[i]^e = 0 for e in {2,4,...,12}
    i.e. A * w = b over F_p, where A_{r,i} = xs[i]^EXPS[r], b = [1,0,0,0,0,0,0]^T
    """
    n = len(xs)
    assert n == 7
    # Build augmented matrix [A | b]
    A = [[pow(xs[i], e, p) for i in range(n)] for e in EXPS]
    b = [1] + [0] * (n - 1)
    M = [A[r] + [b[r]] for r in range(n)]

    # Gaussian elimination mod p
    for col in range(n):
        # find pivot
        piv = None
        for r in range(col, n):
            if M[r][col] % p != 0:
                piv = r
                break
        if piv is None:
            raise ValueError("Singular system while solving weights")
        # swap
        if piv != col:
            M[col], M[piv] = M[piv], M[col]
        # scale pivot row
        ipiv = inv(M[col][col], p)
        for c in range(col, n + 1):
            M[col][c] = (M[col][c] * ipiv) % p
        # eliminate others
        for r in range(n):
            if r == col:
                continue
            factor = M[r][col] % p
            if factor:
                for c in range(col, n + 1):
                    M[r][c] = (M[r][c] - factor * M[col][c]) % p

    # solution vector
    w = [M[i][n] % p for i in range(n)]
    return w

def main():
    w = solve_weights(XS, P)

    r = remote(HOST, PORT)

    # read banner (e.g., "welcome to ssss")
    try:
        line = r.recvline(timeout=2)
        # print(line.decode(errors="ignore").strip())
    except EOFError:
        pass

    # Query 7 pairs: x and -x (i.e., P - x)
    ys = []  # store pairs (y_plus, y_minus)
    for x in XS:
        r.sendline(str(x).encode())
        y1 = int(r.recvline().strip())

        r.sendline(str((P - x) % P).encode())
        y2 = int(r.recvline().strip())

        ys.append((x, y1, y2))

    # Wait for the "secret? " prompt (it may come without newline)
    r.recvuntil(b"secret?", timeout=2)

    # Compute h(x_i) = (f(x)-f(-x)) * inv(2x)  (mod P)
    h = []
    TWO = 2 % P
    for (x, y1, y2) in ys:
        num = (y1 - y2) % P
        den = (TWO * x) % P
        h_i = (num * inv(den, P)) % P
        h.append(h_i)

    # SECRET S = sum_i w_i * h(x_i)  (mod P)
    S = sum((wi * hi) % P for wi, hi in zip(w, h)) % P

    # Send the recovered secret
    r.sendline(str(S).encode())

    # Print whatever comes next (ideally the flag corctf{...})
    try:
        while True:
            out = r.recvline(timeout=2)
            if not out:
                break
            print(out.decode(errors="ignore").strip())
    except EOFError:
        pass
    r.close()

if __name__ == "__main__":
    main()
