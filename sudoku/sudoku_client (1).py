#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sudoku_client.py — robust client for the "reduced 9-coloring vertex problem" Sudoku ZK challenge.

Key fixes vs earlier attempt:
- Uses a streaming line reader (socket.makefile) and a small state machine
  so prompts arriving in the same TCP packet don't get "eaten" between recv calls.
- Prints server output verbatim (so you can see context) and triggers actions when
  expected phrases appear.
- Longer, configurable timeouts.
- Deterministic base Sudoku grid (can be replaced with a real solution if needed).
"""

import socket
import sys
import json
import hashlib
import random
import re
import time
from typing import List, Tuple

HOST = "ctfi.ng"
PORT = 31122
TIMEOUT = 30.0  # seconds

# ------------------ commitments ------------------
def commit_digest(color_name: str, nonce: int) -> str:
    payload = f"{color_name}-{nonce} and some salt for fun".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def make_reveal(color_name: str, nonce: int):
    return {"commitment": commit_digest(color_name, nonce),
            "color_name": color_name,
            "nonce": nonce}

# ------------------ simple Sudoku grid ------------------
def base_grid() -> List[List[int]]:
    # Latin-like pattern; replace with a known-valid solved Sudoku if remote expects specific hints
    return [[(3*r + r//3 + c) % 9 for c in range(9)] for r in range(9)]

def p2idx(r: int, c: int) -> int:
    return r*9 + c

def lit2idx(v: int) -> int:
    return 81 + v

def build_assignment() -> Tuple[List[str], List[str], List[int], List[str]]:
    rng = random.Random(int(time.time()))
    grid = base_grid()
    colors = [f"col{d}" for d in range(9)]
    # random color permutation for digits 0..8
    perm = list(range(9))
    rng.shuffle(perm)
    digit_to_color = {d: colors[perm[d]] for d in range(9)}

    commits = [""]*90
    nonces = [0]*90
    node_color = [""]*90

    # cells 0..80
    for r in range(9):
        for c in range(9):
            idx = p2idx(r,c)
            cname = digit_to_color[grid[r][c]]
            nonce = rng.randrange(1<<61)
            commits[idx] = commit_digest(cname, nonce)
            nonces[idx] = nonce
            node_color[idx] = cname

    # literals 81..89 (ensure all different by shuffling colors again)
    lit_perm = colors[:]
    rng.shuffle(lit_perm)
    for v in range(9):
        idx = lit2idx(v)
        cname = lit_perm[v]
        nonce = rng.randrange(1<<61)
        commits[idx] = commit_digest(cname, nonce)
        nonces[idx] = nonce
        node_color[idx] = cname

    return colors, commits, nonces, node_color

# ------------------ protocol helpers ------------------
EDGE_RE = re.compile(r"\(\s*(\d+)\s*,\s*(\d+)\s*\)")

def run_client(host: str, port: int):
    colors, commits, nonces, node_color = build_assignment()

    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        f = sock.makefile("rwb", buffering=0)

        def send_line(s: str):
            f.write(s.encode("utf-8"))
            f.write(b"\n")
            f.flush()

        round_idx = 0
        need_commit_graph = False
        need_colors = False
        need_reveal = False
        last_edge = None

        while True:
            line = f.readline()
            if not line:
                break
            try:
                decoded = line.decode("utf-8", errors="ignore")
            except:
                decoded = str(line)
            sys.stdout.write(decoded)
            sys.stdout.flush()

            if "Enter the committed graph, as a json list of strings:" in decoded:
                # (1) send 90 commitments
                send_line(json.dumps(commits))
                need_commit_graph = False
                need_colors = True
                continue

            if "Also enter the names of the 9 colors you used:" in decoded:
                # (2) send color names
                send_line(json.dumps(colors))
                need_colors = False
                continue

            if "Verif" in decoded and "(" in decoded and ")" in decoded:
                # extract edge (a,b)
                m = EDGE_RE.search(decoded)
                if m:
                    a = int(m.group(1)); b = int(m.group(2))
                    last_edge = (a,b)

            if "Please reveal the commitments" in decoded:
                # (3) send reveal for the last seen edge
                if last_edge is None:
                    # try to read ahead a little to capture the edge line if it's next
                    f.flush()
                a,b = last_edge if last_edge is not None else (0,1)

                ra = make_reveal(node_color[a], nonces[a])
                rb = make_reveal(node_color[b], nonces[b])

                # if equal color (bad), try to remap b's color *within this round* by regenerating its commitment
                if ra["color_name"] == rb["color_name"]:
                    # pick any different color name
                    for alt in colors:
                        if alt != ra["color_name"]:
                            nonces[b] = random.randrange(1<<61)
                            node_color[b] = alt
                            commits[b] = commit_digest(alt, nonces[b])
                            rb = make_reveal(node_color[b], nonces[b])
                            break
                    # Note: since we already sent the commit list, this "fix" only helps if we also
                    # updated commits[b] before sending commits. In a solvable instance you rarely hit this.

                send_line(json.dumps([ra, rb]))
                need_reveal = False
                continue

            if "Round passed" in decoded:
                # Prepare next round with a fresh assignment (allowed by protocol: each round is independent)
                colors, commits, nonces, node_color = build_assignment()
                last_edge = None
                round_idx += 1
                continue

            # Exit conditions
            if "flag" in decoded.lower() or "corctf{" in decoded.lower():
                # likely done
                # Read remaining lines (best effort) then exit
                try:
                    tail = f.read()
                    if tail:
                        sys.stdout.write(tail.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
                break

if __name__ == "__main__":
    try:
        run_client(HOST, PORT)
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)
