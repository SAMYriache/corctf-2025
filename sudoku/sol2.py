
import socket, hashlib, re, threading, time

HOST, PORT = "ctfi.ng", 31122
COLORS_JSON = b'["c1","c2","c3","c4","c5","c6","c7","foo","foo-"]\n'

def sha(color, nonce):
    h = hashlib.sha256()
    h.update(f"{color}-{nonce} and some salt for fun".encode())
    return h.hexdigest()

def recv_until(s, token: bytes) -> bytes:
    buf = bytearray()
    while token not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)

def reader(sock: socket.socket, out_buf: list, stop_flag: dict):
    """Continuously drain socket. Set flags on EOF. Print milestones."""
    try:
        passed = 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                print("\n[reader] Server closed connection (EOF).")
                stop_flag["closed"] = True
                break
            out_buf.append(chunk)
            # progress hints
            cnt = chunk.count(b"Round passed")
            if cnt:
                passed += cnt
                if passed % 128 == 0:
                    print(f"[reader] Round passed x{passed}")
    except Exception as e:
        print(f"\n[reader] Error: {e!r}")
        stop_flag["error"] = True

def main():
    s = socket.create_connection((HOST, PORT))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)

    # read banner up to first prompt; parse rounds if present
    banner = recv_until(s, b"Enter the committed graph")
    m = re.search(rb"using\s+(\d+)\s+rounds", banner)
    rounds = int(m.group(1)) if m else 8192
    print(f"[main] Parsed rounds = {rounds}")

    # fixed per-round payload
    n = 123456789012
    h = sha("foo", -n)
    elt = '"' + h + '"'
    graph_json = ("[" + (elt + ",")*89 + elt + "]\n").encode()
    reveal_json = (
        f'[{{"commitment":"{h}","color_name":"foo","nonce":{-n}}},'
        f'{{"commitment":"{h}","color_name":"foo-","nonce":{n}}}]\n'
    ).encode()
    one_round = graph_json + COLORS_JSON + reveal_json

    # start reader thread to drain server output
    out_buf = []
    flags = {"closed": False, "error": False}
    t = threading.Thread(target=reader, args=(s, out_buf, flags), daemon=True)
    t.start()

    # stream rounds with micro-batching; interleave small sleeps to yield
    batch = 128
    full = one_round * batch
    q = rounds
    sent = 0
    try:
        while q >= batch and not flags.get("closed"):
            s.sendall(full)
            sent += batch
            q -= batch
            if sent % 512 == 0:
                print(f"[main] Sent {sent}/{rounds}")
            # tiny yield so reader can run even on busy CPUs
            time.sleep(0.001)
        if q and not flags.get("closed"):
            s.sendall(one_round * q)
            sent += q
            print(f"[main] Sent {sent}/{rounds}")
    except (BrokenPipeError, ConnectionResetError) as e:
        print(f"[main] Send failed: {e!r}")
        flags["closed"] = True
    except Exception as e:
        print(f"[main] Unexpected send error: {e!r}")
        flags["error"] = True

    # wait for server to finish and print the rest (flag)
    t.join(timeout=10)
    if t.is_alive():
        print("[main] Reader thread still alive after timeout; ending anyway.")
    try:
        print(b"".join(out_buf).decode("utf-8", "ignore"), end="")
    except Exception:
        pass
    s.close()
    if flags.get("error"):
        print("[main] Completed with read error.")
    elif flags.get("closed"):
        print("[main] Completed: server closed connection.")
    else:
        print("[main] Completed.")

if __name__ == "__main__":
    main()