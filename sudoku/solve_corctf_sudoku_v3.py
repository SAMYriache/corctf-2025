#!/usr/bin/env python3
import socket, sys, json, re, hashlib, secrets, random, argparse, os, pickle
from typing import Set, Tuple, List

EDGE_RE = re.compile(rb"\((\d+),\s*(\d+)\)")

def sha_commit(color_name: str, nonce: int) -> str:
    m = hashlib.sha256()
    m.update(f"{color_name}-{nonce} and some salt for fun".encode("utf-8"))
    return m.hexdigest()

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

def collect_edges(host: str, port: int, max_sessions: int, expected_edges: int, verbose: bool) -> Set[Tuple[int,int]]:
    edges: Set[Tuple[int,int]] = set()
    for t in range(1, max_sessions+1):
        s = None
        try:
            s = socket.create_connection((host, port), timeout=5.0)
            s.settimeout(5.0)
            _ = recv_until(s, b"Enter the committed graph, as a json list of strings:")

            dummy = [f"{i:064x}" for i in range(90)]
            s.sendall((json.dumps(dummy) + "\n").encode())

            _ = recv_until(s, b"Also enter the names of the 9 colors you used:")
            s.sendall((json.dumps([f"c{i}" for i in range(9)]) + "\n").encode())

            data = recv_until(s, b"Please reveal the commitments (in an ordered list):")
            m = EDGE_RE.search(data)
            if m:
                a = int(m.group(1)); b = int(m.group(2))
                if a > b: a, b = b, a
                edges.add((a,b))
        except Exception as e:
            if verbose:
                print(f"[probe] session {t} error: {e!r}")
        finally:
            try:
                if s: s.close()
            except: pass

        if verbose and (t % 50 == 0 or len(edges) >= expected_edges):
            print(f"[probe] sessions={t} unique_edges={len(edges)}")
        if len(edges) >= expected_edges:
            break
    return edges

def dsatur_coloring(n_vertices: int, edges: Set[Tuple[int,int]], num_colors: int = 9) -> List[int] | None:
    adj = [set() for _ in range(n_vertices)]
    for u,v in edges:
        adj[u].add(v); adj[v].add(u)

    assignment = [None]*n_vertices
    domains = [set(range(num_colors)) for _ in range(n_vertices)]

    def satdeg(v):
        return len({assignment[w] for w in adj[v] if assignment[w] is not None})
    def select_v():
        best, key = None, None
        for v in range(n_vertices):
            if assignment[v] is None:
                k = (satdeg(v), len(adj[v]))
                if best is None or k > key:
                    best, key = v, k
        return best

    trail = []
    def assign(v,c):
        if c not in domains[v]: return False
        trail.append((v, domains[v].copy()))
        domains[v] = {c}; assignment[v] = c
        for w in adj[v]:
            if assignment[w] is None and c in domains[w]:
                trail.append((w, domains[w].copy()))
                domains[w].remove(c)
                if not domains[w]: return False
        return True
    def untrail(n):
        while len(trail) > n:
            v, dom = trail.pop()
            domains[v] = dom
            assignment[v] = next(iter(dom)) if len(dom)==1 else None

    def bt(count=0):
        if count==n_vertices: return True
        v = select_v()
        order = sorted(domains[v], key=lambda c: sum(1 for w in adj[v] if c in domains[w]), reverse=True)
        snap = len(trail)
        for c in order:
            if assign(v,c):
                if bt(count+1): return True
            untrail(snap)
        return False

    if bt(0):
        return [c if c is not None else 0 for c in assignment]
    return None

def prove(host: str, port: int, coloring: List[int], verbose: bool, regen_each_round: bool=True):
    COLORS = [f"c{i}" for i in range(9)]
    s = socket.create_connection((host, port), timeout=10.0)
    s.settimeout(10.0)

    try:
        while True:
            _ = recv_until(s, b"Enter the committed graph, as a json list of strings:")

            if regen_each_round:
                nonces = [secrets.randbelow(10**12) for _ in range(len(coloring))]
                commits = [sha_commit(COLORS[coloring[i]], nonces[i]) for i in range(len(coloring))]
            else:
                # fallback one-time
                try:
                    commits
                except NameError:
                    nonces = [secrets.randbelow(10**12) for _ in range(len(coloring))]
                    commits = [sha_commit(COLORS[coloring[i]], nonces[i]) for i in range(len(coloring))]

            s.sendall((json.dumps(commits) + "\n").encode())

            _ = recv_until(s, b"Also enter the names of the 9 colors you used:")
            s.sendall((json.dumps(COLORS) + "\n").encode())

            data = recv_until(s, b"Please reveal the commitments (in an ordered list):")
            m = EDGE_RE.search(data); 
            if not m: break
            a = int(m.group(1)); b = int(m.group(2))

            reveal = [
                {"commitment": commits[a], "color_name": COLORS[coloring[a]], "nonce": nonces[a]},
                {"commitment": commits[b], "color_name": COLORS[coloring[b]], "nonce": nonces[b]},
            ]
            s.sendall((json.dumps(reveal) + "\n").encode())
            line = recv_line(s)
            if verbose:
                try: print(line.decode().strip())
                except: print(line)
            if b"Round passed" not in line:
                rest = s.recv(4096)
                raise RuntimeError("Server rejected reveal:\n" + (line+rest).decode(errors="ignore"))
    finally:
        try:
            rem = s.recv(65535)
            if rem:
                try: print(rem.decode())
                except: print(rem)
        except: pass
        try: s.close()
        except: pass

def main():
    ap = argparse.ArgumentParser(description="corCTF sudoku-graph ZK solver (learn + prove)")
    ap.add_argument("--host", default="ctfi.ng")
    ap.add_argument("--port", type=int, default=31122)
    ap.add_argument("--learn", action="store_true")
    ap.add_argument("--prove", action="store_true")
    ap.add_argument("--sessions", type=int, default=12000)
    ap.add_argument("--expect", type=int, default=886)
    ap.add_argument("--edges", default="edges.pkl")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.learn:
        edges = collect_edges(args.host, args.port, args.sessions, args.expect, args.verbose)
        with open(args.edges, "wb") as f:
            pickle.dump(edges, f)
        print(f"[learn] collected {len(edges)} unique edges -> {args.edges}")
        return

    if args.prove:
        if not os.path.exists(args.edges):
            print(f"[prove] missing {args.edges}; run with --learn first or provide a coloring.")
            return
        with open(args.edges, "rb") as f:
            edges = pickle.load(f)
        n = 90
        coloring = dsatur_coloring(n, edges, 9)
        if coloring is None:
            print("[prove] failed to color graph; collect more edges")
            return
        prove(args.host, args.port, coloring, verbose=args.verbose, regen_each_round=True)
        return

    ap.print_help()

if __name__ == "__main__":
    main()
