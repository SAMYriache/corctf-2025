#!/usr/bin/env python3
import socket
import sys
import json
import re
import time
import hashlib
import secrets
import random
from typing import List, Tuple, Optional, Dict, Set

HOST = "ctfi.ng"
PORT = 31122

# ---------------- Commitment helpers (must match server) ----------------

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

# ---------------- Net I/O helpers ----------------

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

EDGE_RE = re.compile(rb"\((\d+),\s*(\d+)\)")

# ---------------- Edge collection (probing) ----------------

def collect_edges(max_sessions: int = 12000, expected_edges: int = 886, verbose: bool = True) -> Set[Tuple[int,int]]:
    """
    Repeatedly open a new session, send dummy commitments and color list,
    read the chosen edge for Round 0, store it, and close the session.
    Do this until we've likely observed all edges (default target = 886).

    Returns the set of observed undirected edges as sorted (a,b) with a<b.
    """
    edges: Set[Tuple[int,int]] = set()
    for t in range(1, max_sessions+1):
        try:
            s = socket.create_connection((HOST, PORT), timeout=15.0)
            s.settimeout(15.0)

            # Wait for "Enter the committed graph..."
            _ = recv_until(s, b"Enter the committed graph, as a json list of strings:")

            # Send 90 dummy commitments (properly formatted as hex strings)
            dummy = [f"{i:064x}" for i in range(90)]
            s.sendall((json.dumps(dummy) + "\n").encode())

            # Wait for "Also enter the names of the 9 colors you used:"
            _ = recv_until(s, b"Also enter the names of the 9 colors you used:")
            s.sendall((json.dumps([f"c{i}" for i in range(9)]) + "\n").encode())

            # Read until the "Please reveal..." prompt; the chosen edge is printed before that.
            data = recv_until(s, b"Please reveal the commitments (in an ordered list):")
            m = EDGE_RE.search(data)
            if m:
                a = int(m.group(1).decode())
                b = int(m.group(2).decode())
                if a > b: a, b = b, a
                edges.add((a,b))

            # Close without revealing (we're just probing)
            try:
                s.close()
            except:
                pass

            if verbose and (t % 100 == 0 or len(edges) >= expected_edges):
                print(f"[probe] sessions={t} unique_edges={len(edges)}")

            if len(edges) >= expected_edges:
                break
        except Exception as e:
            # transient network/timeout—continue
            if verbose:
                print(f"[probe] session {t} error: {e!r}")
            try:
                s.close()
            except:
                pass
            continue

    return edges

# ---------------- Graph coloring (DSATUR with forward checking) ----------------

def dsatur_coloring(n_vertices: int, edges: Set[Tuple[int,int]], num_colors: int = 9) -> Optional[List[int]]:
    """
    DSATUR graph coloring with forward checking.
    vertices: 0..n-1
    colors: 0..num_colors-1
    edges: set of (u,v) with u<v
    """
    adj: List[Set[int]] = [set() for _ in range(n_vertices)]
    for u,v in edges:
        adj[u].add(v); adj[v].add(u)

    # Domains: all vertices start with all colors possible
    domains: List[Set[int]] = [set(range(num_colors)) for _ in range(n_vertices)]
    assignment: List[Optional[int]] = [None]*n_vertices

    # Pre-color nothing; DSATUR picks by saturation degree
    def sat_degree(v: int) -> int:
        used = set()
        for w in adj[v]:
            c = assignment[w]
            if c is not None:
                used.add(c)
        return len(used)

    def select_vertex() -> int:
        # pick unassigned vertex with highest saturation degree; tie-break by degree
        best = None
        best_key = None
        for v in range(n_vertices):
            if assignment[v] is None:
                key = (sat_degree(v), len(adj[v]))
                if best is None or key > best_key:
                    best = v; best_key = key
        return best

    # Forward checking stack
    trail = []

    def assign(v: int, c: int) -> bool:
        if c not in domains[v]:
            return False
        # Save domain to trail
        trail.append((v, domains[v].copy()))
        domains[v] = {c}
        assignment[v] = c
        # Propagate to neighbors: remove c from their domains
        for w in adj[v]:
            if assignment[w] is None and c in domains[w]:
                trail.append((w, domains[w].copy()))
                domains[w].remove(c)
                if not domains[w]:
                    return False
        return True

    def untrail(to_index: int):
        nonlocal trail, assignment, domains
        while len(trail) > to_index:
            v, dom = trail.pop()
            domains[v] = dom
            if len(dom) > 1:
                assignment[v] = None
            else:
                # If singleton, keep assignment consistent
                only = next(iter(dom))
                if assignment[v] != only:
                    assignment[v] = None

    def backtrack(count_assigned: int = 0) -> bool:
        if count_assigned == n_vertices:
            return True
        v = select_vertex()
        order = sorted(domains[v], key=lambda c: sum((1 for w in adj[v] if c in domains[w])), reverse=True)
        snap = len(trail)
        for c in order:
            if assign(v, c):
                if backtrack(count_assigned + 1):
                    return True
            untrail(snap)
        return False

    if backtrack(0):
        return [c if c is not None else 0 for c in assignment]
    return None

# ---------------- Full run using learned edges ----------------

def prove_with_coloring(coloring: List[int], num_rounds: int = 8192, verbose: bool = True):
    """
    Use a fixed valid coloring (list of 90 ints 0..8) to run through all rounds.
    """
    COLORS = [f"c{i}" for i in range(9)]
    # Prepare a per-vertex random nonce and commitment (reuse across the session)
    nonces = [secrets.randbelow(10**12) for _ in range(len(coloring))]
    commits = [sha_commit(COLORS[coloring[i]], nonces[i]) for i in range(len(coloring))]

    s = socket.create_connection((HOST, PORT), timeout=20.0)
    s.settimeout(20.0)

    edge_re = EDGE_RE

    round_idx = 0
    try:
        while True:
            _ = recv_until(s, b"Enter the committed graph, as a json list of strings:")
            s.sendall((json.dumps(commits) + "\n").encode())

            _ = recv_until(s, b"Also enter the names of the 9 colors you used:")
            s.sendall((json.dumps(COLORS) + "\n").encode())

            data = recv_until(s, b"Please reveal the commitments (in an ordered list):")
            m = edge_re.search(data)
            if not m:
                # end?
                break
            a = int(m.group(1).decode())
            b = int(m.group(2).decode())

            reveal = [
                {"commitment": commits[a], "color_name": COLORS[coloring[a]], "nonce": nonces[a]},
                {"commitment": commits[b], "color_name": COLORS[coloring[b]], "nonce": nonces[b]},
            ]
            s.sendall((json.dumps(reveal) + "\n").encode())

            line = recv_line(s)
            if verbose:
                try:
                    msg = line.decode().strip()
                except:
                    msg = str(line)
                # print(msg)
            if b"Round passed" not in line:
                rest = s.recv(4096)
                raise RuntimeError(f"Server rejected reveal: {(line+rest).decode(errors='ignore')}")

            round_idx += 1
    finally:
        try:
            rem = s.recv(65535)
            if rem:
                try:
                    print(rem.decode())
                except:
                    print(rem)
        except:
            pass
        try:
            s.close()
        except:
            pass

def main():
    import argparse, os, pickle

    parser = argparse.ArgumentParser(description="corCTF sudoku-graph ZK: learn edges, color graph, get flag")
    parser.add_argument("--learn", action="store_true", help="probe the server to learn edges, then save edges.pkl")
    parser.add_argument("--prove", action="store_true", help="run the full 8192-round proof using learned coloring")
    parser.add_argument("--sessions", type=int, default=12000, help="max probe sessions for --learn")
    parser.add_argument("--expect", type=int, default=886, help="expected unique edges (default 886)")
    parser.add_argument("--edges", type=str, default="edges.pkl", help="where to save/load edges")
    parser.add_argument("--verbose", action="store_true", help="verbose logs")
    args = parser.parse_args()

    if args.learn:
        try:
            import pickle
            edges = collect_edges(max_sessions=args.sessions, expected_edges=args.expect, verbose=args.verbose)
            with open(args.edges, "wb") as f:
                pickle.dump(edges, f)
            print(f"[learn] collected {len(edges)} unique edges -> {args.edges}")
        except KeyboardInterrupt:
            print("\n[learn] interrupted")
            sys.exit(1)
        sys.exit(0)

    if args.prove:
        import pickle
        if not os.path.exists(args.edges):
            print(f"[prove] missing {args.edges}; run with --learn first")
            sys.exit(1)
        with open(args.edges, "rb") as f:
            edges = pickle.load(f)
        # Solve coloring for 90 vertices
        n = 90
        if len({u for e in edges for u in e}) < n:
            print(f"[warn] observed fewer than {n} vertices; continuing anyway")
        coloring = dsatur_coloring(n, edges, num_colors=9)
        if coloring is None:
            print("[prove] failed to color graph; try collecting more edges or re-run")
            sys.exit(1)
        prove_with_coloring(coloring, verbose=args.verbose)
        sys.exit(0)

    parser.print_help()

if __name__ == "__main__":
    main()
