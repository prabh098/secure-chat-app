# receiver.py
import socket, json, argparse, os
from datetime import datetime
from typing import Optional
from crypto_utils import generate_rsa_keypair, rsa_decrypt_oaep, b64d, AesSession

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
    ap = argparse.ArgumentParser(description="E2EE Receiver Console")
    ap.add_argument("--user", default="Bob")
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

    aes: Optional[AesSession] = None

    print(f"[Receiver] Waiting for messages as {args.user}...")
    try:
        for msg in recv_lines(s):
            t = msg.get("type")
            if t == "key" and msg.get("to") == args.user:
                enc_key = b64d(msg["enc_key"])
                key = rsa_decrypt_oaep(priv, enc_key)
                aes = AesSession(key=key)
                print("[Receiver] Session key received and installed.")
            elif t == "msg" and msg.get("to") == args.user:
                ct_b64 = msg["ciphertext"]
                nonce_b64 = msg["nonce"]
                print(f"Received (encrypted): {ct_b64}")

                if aes is None:
                    print("[Receiver] ERROR: Missing session key; cannot decrypt.")
                    continue
                aad = f"{msg['from']}|{msg['to']}".encode("utf-8")
                plaintext = aes.decrypt(b64d(nonce_b64), b64d(ct_b64), aad=aad).decode("utf-8")
                print(f"Decrypted: {plaintext}")

                append_log(log_path, {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "direction": "in",
                    "from": msg["from"],
                    "ciphertext": ct_b64,
                    "nonce": nonce_b64,
                    "plaintext": plaintext
                })
            elif t == "error":
                print(f"[Receiver] ERROR: {msg['error']}")
            # ignore others
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
        print("\n[Receiver] Bye.")

if __name__ == "__main__":
    main()
