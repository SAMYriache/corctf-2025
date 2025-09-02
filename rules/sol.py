#!/usr/bin/env python3
from pwn import *
import json, re, time, os, subprocess

HOST, PORT = "ctfi.ng", 31126
context.log_level = "info"     # "debug" si tu veux tout voir
PAYLOAD = json.dumps([119]*1024).encode()  # 0x77

def run_pow(cmd: str, timeout=180):
    """
    Exécute la ligne donnée par le serveur:
      curl -sSfL https://pwn.red/pow | sh -s s.AAATiA==.<TOKEN>
    Retourne la DERNIÈRE ligne non vide (souvent 's.xxxxx...').
    Si le solveur met 'solution: ...', on strip le préfixe.
    """
    # On passe par /bin/sh pour conserver la ligne telle qu'affichée
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        raise TimeoutError("PoW local a expiré")
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("PoW n'a rien renvoyé")
    token = lines[-1]
    if token.lower().startswith("solution:"):
        token = token.split(":",1)[1].strip()
    if not token.startswith("s.") or len(token) < 10:
        raise ValueError(f"PoW token suspect: {token[:40]}...")
    log.info(f"PoW token ok ({len(token)} chars)")
    return token

def try_once():
    # timeout réseau large pour laisser au serveur le temps de vérifier le PoW
    r = remote(HOST, PORT, timeout=300)
    try:
        # 1) Lire la ligne du PoW
        line = r.recvline(timeout=30).decode(errors="ignore")
        if "pwn.red/pow" not in line:
            # parfois il imprime "proof of work:" puis la ligne — lis encore
            line2 = r.recvline(timeout=30).decode(errors="ignore")
            line = line + line2
        log.info(line.strip())

        # Extraire exactement la commande entière (on prend la dernière occurrence)
        m = re.findall(r"(curl -sSfL https://pwn\.red/pow \| sh -s s\.AAATiA==\.[^\s]+)", line)
        while not m:
            # si la ligne est coupée sur plusieurs lignes, on continue à lire
            nxt = r.recvline(timeout=30).decode(errors="ignore")
            if not nxt:
                break
            line += nxt
            m = re.findall(r"(curl -sSfL https://pwn\.red/pow \| sh -s s\.AAATiA==\.[^\s]+)", line)
        if not m:
            raise ValueError("Impossible de parser la commande PoW")
        pow_cmd = m[-1]
        log.info(f"CMD: {pow_cmd}")

        # 2) Résoudre le PoW en local
        token = run_pow(pow_cmd)

        # 3) Attendre le prompt 'solution:' puis envoyer le token
        # (selon les versions de l'énoncé, le prompt peut déjà être affiché)
        # On lit jusqu'à voir 'solution:' ou 'Enter the bytes:' (rare si pas de PoW)
        buf = b""
        t_end = time.time() + 120
        saw_solution = False
        while time.time() < t_end:
            try:
                chunk = r.recv(timeout=2)
                if not chunk:
                    break
                buf += chunk
                s = buf.decode(errors="ignore")
                if "solution:" in s:
                    saw_solution = True
                    break
                if "Enter the bytes:" in s:
                    break
            except EOFError:
                break
            except Exception:
                pass
        if saw_solution:
            r.sendline(token.encode())
        else:
            # certains serveurs acceptent d'envoyer direct le token
            r.sendline(token.encode())

        # 4) Attendre "Enter the bytes:" (la vérif PoW peut être lente)
        r.recvuntil(b"Enter the bytes:", timeout=240)
        r.sendline(PAYLOAD)

        # 5) Attendre "Make a guess:" puis envoyer []
        r.recvuntil(b"Make a guess:", timeout=60)
        r.sendline(b"[]")

        # 6) Lire le résultat
        t_end = time.time() + 60
        data = b""
        flag = None
        while time.time() < t_end:
            try:
                chunk = r.recv(timeout=2)
                if not chunk:
                    break
                data += chunk
                s = data.decode(errors="ignore")
                if "Here is your flag:" in s:
                    # ex: "Here is your flag: corctf{...}"
                    flag = re.search(r"Here is your flag:\s*([a-z0-9_{}\-\[\]A-Z]+)", s)
                    if flag:
                        return flag.group(1)
                    # sinon on renvoie tout et on laisse le caller parser
                if "Incorrect!" in s or "incorrect" in s:
                    return None
            except Exception:
                pass
        return None
    finally:
        r.close()

def main():
    attempt = 0
    while True:
        attempt += 1
        log.info(f"Attempt #{attempt}")
        try:
            flag = try_once()
            if flag:
                print("\n[✓] FLAG:", flag, "\n")
                break
            else:
                log.warning("Pas cette fois (k impair ou reset). On retente...")
                time.sleep(0.4)
        except Exception as e:
            log.warning(f"Erreur: {e} — retry...")
            time.sleep(0.6)

if __name__ == "__main__":
    main()
