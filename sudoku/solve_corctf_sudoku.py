#!/usr/bin/env python3
import socket
import sys
import json
import re
import time
import hashlib
import secrets
import random
from typing import List, Tuple, Optional

HOST = "ctfi.ng"
PORT = 31122

# ---------------- Commitment helpers (mirror of server) ----------------

def sha_commit(color_name: str, nonce: int) -> str:
    m = hashlib.sha256()
    m.update(f"{color_name}-{nonce} and some salt for fun".encode("utf-8"))
    return m.hexdigest()

def make_reveal_entry(color_name: str, nonce: Optional[int] = None):
    if nonce is None:
        nonce = secrets.randbelow(10**12)
    return {
        "commitment": sha_commit(color_name, nonce),
        "color_name": color_name,
        "nonce": nonce,
    }

# ---------------- Sudoku graph + solver ----------------

def p2idx(r: int, c: int) -> int:
    return r * 9 + c

def lit2idx(v: int) -> int:
    return 81 + v  # the 9 "number" vertices (indices 81..89)

def build_constraints() -> List[Tuple[int,int]]:
    game_constraints = set()
    # Sudoku cell-cell constraints
    for r in range(9):
        for c in range(9):
            a = p2idx(r,c)
            # Row
            for cc in range(9):
                if cc != c:
                    game_constraints.add(tuple(sorted((a, p2idx(r, cc)))))
            # Col
            for rr in range(9):
                if rr != r:
                    game_constraints.add(tuple(sorted((a, p2idx(rr, c)))))
            # Box
            br, bc = (r//3)*3, (c//3)*3
            for dr in range(3):
                for dc in range(3):
                    rr, cc = br+dr, bc+dc
                    if rr != r or cc != c:
                        game_constraints.add(tuple(sorted((a, p2idx(rr, cc)))))

    # 9-clique among the number vertices
    for i in range(9):
        for j in range(9):
            if i != j:
                game_constraints.add(tuple(sorted((lit2idx(i), lit2idx(j)))))

    # Hints (exactly as in the server)
    hints = [
        (p2idx(0, 3), 0),  # four "ones" (index 0)
        (p2idx(3, 0), 0),
        (p2idx(5, 8), 0),
        (p2idx(8, 5), 0),
        (p2idx(4, 4), 1),  # one "two" (index 1)
    ]
    for idx, i in hints:
        for j in range(9):
            if j != i:
                game_constraints.add(tuple(sorted((idx, lit2idx(j)))))

    # Dedup already handled by set + sorted tuples
    return sorted(game_constraints)

# We'll color with names c0..c8 and make number nodes 81..89 use c0..c8 respectively.
COLORS = [f"c{i}" for i in range(9)]

def solve_latin_sudoku_with_hints(max_tries: int = 200) -> Optional[List[str]]:
    """
    Returns a list color_of_node[0..89], where entries 0..80 are cell colors,
    and 81..89 are number-node colors. Satisfies all constraints if a solution is found.
    """
    # Enforce number-node colors to be all distinct c0..c8
    number_colors = {81+i: COLORS[i] for i in range(9)}

    # Hinted cells must equal the corresponding number-node color (only color that avoids edges to the other 8)
    # As in server: four index 0, one index 1
    forced = {
        (0,3): 0,
        (3,0): 0,
        (5,8): 0,
        (8,5): 0,
        (4,4): 1,
    }

    # Backtracking on a 9x9 grid with values 0..8 corresponding to COLORS
    def backtrack_grid(seed_shuffle=False) -> Optional[List[List[int]]]:
        grid = [[-1]*9 for _ in range(9)]
        row_used = [set() for _ in range(9)]
        col_used = [set() for _ in range(9)]
        box_used = [[set() for _ in range(3)] for __ in range(3)]

        # Place forced
        for (r,c),v in forced.items():
            grid[r][c] = v
            row_used[r].add(v)
            col_used[c].add(v)
            box_used[r//3][c//3].add(v)

        digits = list(range(9))

        def next_cell():
            # MRV heuristic
            best = None
            best_opts = None
            for r in range(9):
                for c in range(9):
                    if grid[r][c] == -1:
                        opts = set(digits) - row_used[r] - col_used[c] - box_used[r//3][c//3]
                        if best is None or len(opts) < len(best_opts):
                            best, best_opts = (r,c), opts
                            if not best_opts:
                                return best, best_opts
            return best, best_opts

        # Deterministic order is fine; allow optional seed shuffle for variety
        if seed_shuffle:
            random.shuffle(digits)

        sys.setrecursionlimit(10000)

        def rec() -> bool:
            cell, opts = next_cell()
            if cell is None:
                return True
            r,c = cell
            if seed_shuffle:
                opts = list(opts); random.shuffle(opts)
            for v in opts:
                grid[r][c] = v
                row_used[r].add(v); col_used[c].add(v); box_used[r//3][c//3].add(v)
                if rec():
                    return True
                box_used[r//3][c//3].remove(v); col_used[c].remove(v); row_used[r].remove(v)
                grid[r][c] = -1
            return False

        if rec():
            return grid
        return None

    # Try multiple restarts with different randomization seeds
    for _ in range(max_tries):
        grid = backtrack_grid(seed_shuffle=True)
        if grid is not None:
            # Build final color list
            colors = [None]*90
            # Assign cells
            for r in range(9):
                for c in range(9):
                    colors[p2idx(r,c)] = COLORS[grid[r][c]]
            # Assign number nodes
            for k,v in number_colors.items():
                colors[k] = v
            return colors
    return None

# ---------------- Networking helpers ----------------

def recv_until(sock, pattern: bytes, timeout=10.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while pattern not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

def recv_line(sock, timeout=10.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf

def run():
    # Precompute a valid coloring
    coloring = solve_latin_sudoku_with_hints(max_tries=2000)
    if coloring is None:
        print("[!] Failed to construct a 9-coloring with the given hints after many tries.")
        print("    (If this happens locally, try again; the remote server should be solvable.)")
        # As a fallback, just build any Latin Sudoku (ignoring hints) to demonstrate protocol;
        # This MAY fail if a hint-edge is chosen.
        def fallback():
            # Simple Latin Sudoku
            grid = [[(r*3 + r//3 + c) % 9 for c in range(9)] for r in range(9)]
            colors = [None]*90
            for r in range(9):
                for c in range(9):
                    colors[p2idx(r,c)] = COLORS[grid[r][c]]
            for i in range(9):
                colors[81+i] = COLORS[i]
            return colors
        coloring = fallback()

    # Establish connection
    s = socket.create_connection((HOST, PORT))
    s.settimeout(30.0)

    # Helper to parse "(a, b)" line
    edge_re = re.compile(rb"\((\d+),\s*(\d+)\)")

    round_idx = 0
    while True:
        # Read until we get the prompt for the graph list
        data = recv_until(s, b"Enter the committed graph, as a json list of strings:")
        if not data:
            break
        #print(data.decode(errors="ignore"))

        # For this round, generate commitments
        commits = []
        nonces = []
        for i in range(90):
            color = coloring[i]
            nonce = secrets.randbelow(10**12)
            commit = sha_commit(color, nonce)
            commits.append(commit)
            nonces.append(nonce)

        # Send the commitments JSON (single line)
        s.sendall((json.dumps(commits) + "\n").encode())

        # Wait for prompt for colors
        _ = recv_until(s, b"Also enter the names of the 9 colors you used:")
        # Send the 9 color names (exactly 9 unique)
        s.sendall((json.dumps(COLORS) + "\n").encode())

        # Read until it prints the edge to verify
        data = recv_until(s, b"Please reveal the commitments (in an ordered list):")
        # Extract the chosen edge
        m = edge_re.search(data)
        if not m:
            print("[!] Failed to parse edge for round", round_idx)
            print(data.decode("utf-8", errors="ignore"))
            break
        a = int(m.group(1).decode())
        b = int(m.group(2).decode())

        # Build reveal entries for a and b
        reveal = [
            {"commitment": commits[a], "color_name": coloring[a], "nonce": nonces[a]},
            {"commitment": commits[b], "color_name": coloring[b], "nonce": nonces[b]},
        ]
        s.sendall((json.dumps(reveal) + "\n").encode())

        # Read the "Round passed" line (or error)
        line = recv_line(s)
        #print(line.decode(errors="ignore").strip())
        if b"Round passed" not in line:
            # Read the rest for diagnostics
            rest = s.recv(4096)
            print("[!] Round failed:", (line+rest).decode("utf-8", errors="ignore"))
            break

        round_idx += 1
        # Optional: short sleep to be polite
        # time.sleep(0.001)

    # Print any remaining output
    try:
        final = s.recv(65535)
        if final:
            print(final.decode("utf-8", errors="ignore"))
    except Exception:
        pass

if __name__ == "__main__":
    run()
