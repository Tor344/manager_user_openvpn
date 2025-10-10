#!/usr/bin/env python3
"""
Автоматическое создание клиента OpenVPN и сборка .ovpn файла.
Требует: easy-rsa (с pki в указанной папке).
"""

import subprocess
import os
import shutil
from pathlib import Path

# ---------- НАСТРОЙКИ (отредактируйте под ваш сервер) ----------
EASYRSA_DIR = Path("/etc/openvpn/easy-rsa")   # где лежит easy-rsa и pki
PKI_DIR = EASYRSA_DIR / "pki"
OUTPUT_DIR = Path("/root/ovpn_out")           # куда складывать .ovpn
SERVER_ADDR = "vpn.example.com"               # адрес/домен сервера
SERVER_PORT = 1194
PROTO = "udp"
DEV = "tun"
CIPHER = "AES-256-CBC"                        # пример
AUTH = "SHA256"
TLS_AUTH = True                               # True если используете ta.key
TA_KEY_PATH = Path("/etc/openvpn/ta.key")     # путь к ta.key (если есть)
# ---------------------------------------------------------------

def run_easyrsa_build_client(username: str):
    cmd = [str(EASYRSA_DIR / "easyrsa"), "build-client-full", username, "nopass"]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, cwd=EASYRSA_DIR, check=True)

def read_text(path: Path) -> str:
    with open(path, "r") as f:
        return f.read()

def build_ovpn(username: str) -> str:
    # пути в PKI
    ca = PKI_DIR / "ca.crt"
    cert = PKI_DIR / "issued" / f"{username}.crt"
    key = PKI_DIR / "private" / f"{username}.key"
    ta = TA_KEY_PATH if TLS_AUTH else None

    if not (ca.exists() and cert.exists() and key.exists()):
        raise FileNotFoundError("Не найден один из файлов CA/CRT/KEY в pki")

    ca_txt = read_text(ca)
    cert_txt = read_text(cert)
    key_txt = read_text(key)
    ta_txt = read_text(ta) if ta and ta.exists() else None

    template = f"""
client
dev {DEV}
proto {PROTO}
remote {SERVER_ADDR} {SERVER_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher {CIPHER}
auth {AUTH}
verb 3
# optionally add: setenv opt block-outside-dns (for windows)
<ca>
{ca_txt.strip()}
</ca>

<cert>
{cert_txt.strip()}
</cert>

<key>
{key_txt.strip()}
</key>
"""
    if ta_txt:
        template += f"""
<tls-auth>
{ta_txt.strip()}
</tls-auth>
key-direction 1
"""
    return template.strip() + "\n"

def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def main(username: str):
    ensure_output_dir()
    # 1) Создать клиента через easy-rsa
    run_easyrsa_build_client(username)

    # 2) Собрать .ovpn
    ovpn_content = build_ovpn(username)
    out_file = OUTPUT_DIR / f"{username}.ovpn"
    with open(out_file, "w") as f:
        f.write(ovpn_content)
    print("Сгенерирован файл:", out_file)
    # поменяйте права, чтобы приватный ключ был защищён
    os.chmod(out_file, 0o600)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Использование: python3 make_client.py <username>")
        sys.exit(2)
    username = sys.argv[1]
    main(username)
