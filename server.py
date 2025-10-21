# server.py
import socket, threading, json
from typing import Dict, Tuple

HOST = "127.0.0.1"
PORT = 9000

# Bookkeeping: username -> (conn, pubkey_pem_str)
clients: Dict[str, Tuple[socket.socket, str]] = {}

def send_json(conn: socket.socket, obj: dict) -> None:
    conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))

def handle(conn: socket.socket, addr):
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line:
                    continue
                msg = json.loads(line.decode("utf-8"))
                t = msg.get("type")

                # Server logs ONLY encrypted payloads
                if t == "msg":
                    print(f"[Server] Incoming message (encrypted): {msg.get('ciphertext')}")
                elif t == "key":
                    print(f"[Server] Incoming key (encrypted): {msg.get('enc_key')}")
                elif t == "register":
                    print(f"[Server] Registration from {msg.get('user')}")
                elif t == "pubkey_req":
                    print(f"[Server] PubKey request for {msg.get('target')} from {msg.get('user')}")

                if t == "register":
                    user = msg["user"]
                    pubkey = msg["pubkey"]
                    clients[user] = (conn, pubkey)
                    send_json(conn, {"type": "register_ok", "user": user})

                elif t == "pubkey_req":
                    target = msg["target"]
                    if target in clients:
                        _, pub = clients[target]
                        send_json(conn, {"type": "pubkey_res", "target": target, "pubkey": pub})
                    else:
                        send_json(conn, {"type": "error", "error": f"unknown target {target}"})

                elif t in ("key", "msg"):
                    to_user = msg["to"]
                    if to_user in clients:
                        target_conn, _ = clients[to_user]
                        send_json(target_conn, msg)  # forward as-is (encrypted)
                    else:
                        send_json(conn, {"type": "error", "error": f"user {to_user} not connected"})
                else:
                    send_json(conn, {"type": "error", "error": "unknown message type"})
    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        # Clean up any mapping pointing to this conn
        for u, (c, _) in list(clients.items()):
            if c is conn:
                del clients[u]
                print(f"[Server] {u} disconnected")
        conn.close()

def main():
    print(f"[Server] Listening on {HOST}:{PORT}")
    # Cross-platform server socket (Windows-friendly)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow quick restart after crash/stop
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    finally:
        s.close()

if __name__ == "__main__":
    main()
