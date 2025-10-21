# sender.py
import socket, json, argparse, sys, threading, os
from datetime import datetime
from typing import Optional
from crypto_utils import generate_rsa_keypair, rsa_encrypt_oaep, b64e, AesSession

def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

def recv_lines(sock: socket.socket):
    buf = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line:
                yield json.loads(line.decode("utf-8"))

def append_log(path: str, entry: dict):
    arr = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                arr = json.load(f)
        except Exception:
            arr = []
    arr.append(entry)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(arr, f, indent=2)

def main():
    ap = argparse.ArgumentParser(description="E2EE Sender Console")
    ap.add_argument("--user", default="Alice")
    ap.add_argument("--to", default="Bob")
    ap.add_argument("--server", default="127.0.0.1:9000")
    ap.add_argument("--log", default=None)
    args = ap.parse_args()

    log_path = args.log or f"messages_{args.user}.json"

    host, port = args.server.split(":")
    port = int(port)

    # Generate RSA keys and register
    priv, pub_pem = generate_rsa_keypair()

    s = socket.create_connection((host, port))
    send_json(s, {"type":"register","user":args.user,"pubkey":pub_pem.decode("utf-8")})

    # Ask for receiver's pubkey
    send_json(s, {"type":"pubkey_req","user":args.user,"target":args.to})

    aes: Optional[AesSession] = None

    # Listen thread (for acks / errors)
    def listen():
        nonlocal aes
        for msg in recv_lines(s):
            if msg.get("type") == "pubkey_res":
                target_pub = msg["pubkey"].encode("utf-8")
                aes = AesSession.new()
                enc_key = rsa_encrypt_oaep(target_pub, aes.key)
                send_json(s, {
                    "type":"key",
                    "from":args.user, "to":args.to,
                    "enc_key": b64e(enc_key)
                })
                print(f"[Sender] Session key sent to {args.to}. You can start typing messages.")
            elif msg.get("type") == "error":
                print(f"[Sender] ERROR: {msg['error']}")
            # ignore other types for sender
    threading.Thread(target=listen, daemon=True).start()

    # Input loop
    try:
        while True:
            plaintext = input(f"{args.user}> ").encode("utf-8")
            if aes is None:
                print("[Sender] Waiting for session key exchange to complete...")
                continue
            aad = f"{args.user}|{args.to}".encode("utf-8")
            nonce, ct = aes.encrypt(plaintext, aad=aad)
            payload = {
                "type":"msg",
                "from":args.user, "to":args.to,
                "nonce": b64e(nonce),
                "ciphertext": b64e(ct),
            }
            send_json(s, payload)

            append_log(log_path, {
                "ts": datetime.utcnow().isoformat() + "Z",
                "direction": "out",
                "to": args.to,
                "plaintext": plaintext.decode("utf-8"),
                "ciphertext": payload["ciphertext"],
                "nonce": payload["nonce"]
            })
    except (EOFError, KeyboardInterrupt):
        print("\n[Sender] Bye.")
    finally:
        s.close()

if __name__ == "__main__":
    main()
