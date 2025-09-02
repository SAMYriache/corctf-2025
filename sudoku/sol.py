
import socket, json, hashlib, random, re, sys, time

HOST = "ctfi.ng"
PORT = 31122

FORCE_IPV4 = True         # force IPv4 d'abord (souvent la cause des timeouts sous Windows)
CONNECT_TRIES = 6         # nb de tentatives de connexion
PER_ADDR_TIMEOUT = 6.0    # timeout par IP essayée
SESSION_READ_TIMEOUT = 600.0

# ---------- Commitment helpers ----------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def make_commit(color_name: str, nonce: int) -> str:
    return sha256_hex(f"{color_name}-{nonce} and some salt for fun")

# ---------- Utilitaires ----------
def p2idx(r, c): return r * 9 + c
def box_index(r, c): return (r // 3) * 3 + (c // 3)

# Hints côté serveur (ceux qui t'ont permis d'aller ~500 rounds)
FOUR_ONES = {(0,3):0, (3,0):0, (5,8):0, (8,5):0}

# ---------- Solveur Sudoku (ligne par ligne via matching) ----------
def solve_sudoku_with_four_ones():
    grid = [[-1]*9 for _ in range(9)]
    row_used = [0]*9
    col_used = [0]*9
    box_used = [0]*9

    # place hints
    for (r, c), d in FOUR_ONES.items():
        bit = 1 << d
        if (row_used[r] | col_used[c] | box_used[box_index(r,c)]) & bit:
            return None
        grid[r][c] = d
        row_used[r] |= bit
        col_used[c] |= bit
        box_used[box_index(r,c)] |= bit

    def solve_row(r):
        if r == 9:
            return True

        fixed_digits = {grid[r][c] for c in range(9) if grid[r][c] != -1}
        remaining = [d for d in range(9) if d not in fixed_digits]

        allowed = [set() for _ in range(9)]
        for c in range(9):
            if grid[r][c] != -1:
                continue
            for d in remaining:
                bit = 1 << d
                if not (row_used[r] & bit) and not (col_used[c] & bit) and not (box_used[box_index(r,c)] & bit):
                    allowed[c].add(d)

        match_digit = [-1]*9  # digit -> col
        match_col   = [-1]*9  # col   -> digit

        for c in range(9):
            if grid[r][c] != -1:
                d = grid[r][c]
                if match_digit[d] != -1:
                    return False
                match_digit[d] = c
                match_col[c] = d

        sys.setrecursionlimit(10000)
        def dfs(c, seen):
            # ordre stable pour éviter des zigzags aléatoires
            for d in sorted(allowed[c]):
                if d in seen:
                    continue
                seen.add(d)
                if match_digit[d] == -1 or dfs(match_digit[d], seen):
                    match_digit[d] = c
                    match_col[c] = d
                    return True
            return False

        for c in range(9):
            if match_col[c] == -1:
                if not dfs(c, set()):
                    return False

        saved = []
        for c in range(9):
            d = match_col[c]
            if grid[r][c] == -1:
                grid[r][c] = d
                saved.append(("cell", c))
            bit = 1 << d
            ru, cu, bu = row_used[r], col_used[c], box_used[box_index(r,c)]
            row_used[r] |= bit
            col_used[c] |= bit
            box_used[box_index(r,c)] |= bit
            saved.append(("mask", c, ru, cu, bu))

        if solve_row(r+1):
            return True

        for it in reversed(saved):
            if it[0] == "cell":
                _, c = it
                grid[r][c] = -1
            else:
                _, c, ru, cu, bu = it
                row_used[r], col_used[c], box_used[box_index(r,c)] = ru, cu, bu
        return False

    return grid if solve_row(0) else None

def build_payload_from_grid(grid):
    colors = [grid[r][c] for r in range(9) for c in range(9)] + list(range(9))
    color_names = [str(i) for i in range(9)]
    commits, reveals = [], {}
    for idx, c in enumerate(colors):
        cname = color_names[c]
        nonce = random.randrange(10**12, 10**13)
        dig = make_commit(cname, nonce)
        commits.append(dig)
        reveals[idx] = {"commitment": dig, "color_name": cname, "nonce": nonce}
    return commits, color_names, reveals

# ---------- Connexion robuste (IPv4/IPv6) ----------
def resolve_all(host, port, prefer_ipv4=True):
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    # réorganise: IPv4 d'abord si demandé
    if prefer_ipv4:
        infos.sort(key=lambda t: 0 if t[0] == socket.AF_INET else 1)
    return infos

def connect_any(host, port, tries=CONNECT_TRIES, per_addr_timeout=PER_ADDR_TIMEOUT, prefer_ipv4=True):
    last_exc = None
    for attempt in range(1, tries+1):
        infos = resolve_all(host, port, prefer_ipv4=prefer_ipv4)
        for fam, socktype, proto, canonname, sockaddr in infos:
            s = None
            try:
                s = socket.socket(fam, socktype, proto)
                s.settimeout(per_addr_timeout)
                s.connect(sockaddr)
                try:
                    s.settimeout(SESSION_READ_TIMEOUT)
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
                return s
            except Exception as e:
                last_exc = e
                if s:
                    try: s.close()
                    except Exception: pass
                continue
        # backoff léger avant nouvel essai
        time.sleep(min(1.5 * attempt, 5.0))
    if last_exc:
        raise last_exc
    raise TimeoutError("Unable to connect (no exception).")

# ---------- Client ----------
EDGE_RE  = re.compile(r"\((\d+),\s*(\d+)\)")
ROUND_RE = re.compile(r"Round\s+(\d+)\s*:")

def run_once(commits, color_names, reveals, verbose=False):
    s = connect_any(HOST, PORT, prefer_ipv4=FORCE_IPV4)
    f = s.makefile("rwb", buffering=0)

    def sendline(x: str):
        f.write(x.encode("utf-8") + b"\n")
        f.flush()

    got_any = False
    a = b = None
    last_round_print = -1

    def progress_from(text: str):
        nonlocal last_round_print
        m = ROUND_RE.search(text)
        if m:
            r = int(m.group(1))
            if r % 100 == 0 and r != last_round_print:
                last_round_print = r
                print(f"[progress] {r}/8192")

    try:
        while True:
            line = f.readline()
            if not line:
                return "early_close" if not got_any else False
            text = line.decode("utf-8", "ignore")
            got_any = True
            if verbose:
                sys.stdout.write(text)
            progress_from(text)

            if "Enter the committed graph" in text:
                sendline(json.dumps(commits)); continue
            if "Also enter the names of the 9 colors" in text:
                sendline(json.dumps(color_names)); continue

            if "Verif" in text or "edge" in text:
                m = EDGE_RE.search(text)
                if not m:
                    for _ in range(12):
                        nxt = f.readline()
                        if not nxt: break
                        t2 = nxt.decode("utf-8", "ignore")
                        if verbose: sys.stdout.write(t2)
                        progress_from(t2)
                        m = EDGE_RE.search(t2)
                        if m: break
                if m:
                    a, b = map(int, m.groups())
                continue

            if "reveal" in text.lower():
                if a is None or b is None:
                    for _ in range(12):
                        nxt = f.readline()
                        if not nxt: break
                        t2 = nxt.decode("utf-8", "ignore")
                        if verbose: sys.stdout.write(t2)
                        progress_from(t2)
                        m = EDGE_RE.search(t2)
                        if m:
                            a, b = map(int, m.groups()); break
                if a is None or b is None:
                    raise RuntimeError("Edge non parsée (reveal).")
                sendline(json.dumps([reveals[a], reveals[b]]))
                a = b = None
                continue

            if "corctf{" in text or "flag{" in text:
                print(text.strip())
                try:
                    rem = f.read()
                    if rem:
                        print(rem.decode("utf-8", "ignore").strip())
                except Exception:
                    pass
                return True
    finally:
        try: f.close()
        except Exception: pass
        try: s.close()
        except Exception: pass

def main():
    print("[*] Construction d’une solution compatible (4 hints)…")
    grid = solve_sudoku_with_four_ones()
    if grid is None:
        print("[!] Impossible de construire une grille avec ces 4 hints (anormal).")
        sys.exit(1)

    commits, color_names, reveals = build_payload_from_grid(grid)
    print("[+] OK. Connexion au service…")

    # Réessaie si le serveur ferme direct
    for attempt in range(1, 6+1):
        try:
            res = run_once(commits, color_names, reveals, verbose=False)
        except Exception as e:
            print(f"[warn] Connexion échouée (tentative {attempt}/6): {e.__class__.__name__}: {e}")
            time.sleep(2*attempt)
            continue
        if res is True:
            return
        if res == "early_close":
            print(f"[warn] Serveur fermé immédiatement (tentative {attempt}/6). Retente…")
            time.sleep(2*attempt)
            continue
        print("[!] Session terminée sans flag. Nouvelle tentative…")
        time.sleep(2*attempt)

    print("[!] Trop d'échecs de connexion. Vérifie réseau/pare-feu/IPv6 et réessaie.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.")
        sys.exit(130)
