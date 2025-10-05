#!/usr/bin/env python3
"""
create_openvpn_user.py

Пример: python3 create_openvpn_user.py --name alice --easyrsa /etc/openvpn/easy-rsa --template ./client-template.ovpn --out /root/ovpns
"""

import argparse
import subprocess
import os
import shutil
import sys
from datetime import datetime

def run(cmd, cwd=None, check=True):
    print(">>", " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def file_contents(path):
    with open(path, "r") as f:
        return f.read()

def create_client(easyrsa_dir, name, nopass=True):
    easyrsa_bin = os.path.join(easyrsa_dir, "easyrsa")
    if not os.path.exists(easyrsa_bin):
        # иногда easyrsa вызывают из /usr/share/easy-rsa/easyrsa
        easyrsa_bin = "easyrsa"  # надеемся на PATH
    cmd = [easyrsa_bin, "build-client-full", name]
    if nopass:
        cmd.append("nopass")
    # запуск из директории easy-rsa (важно, чтобы PKI путями совпадали)
    return run(cmd, cwd=easyrsa_dir)

def assemble_ovpn(template_path, ca_path, cert_path, key_path, ta_path=None):
    tpl = file_contents(template_path)
    ca = file_contents(ca_path)
    cert = file_contents(cert_path)
    key = file_contents(key_path)
    out = tpl
    # Вставим CA, CERT, KEY в блоки
    out += "\n\n<ca>\n" + ca.strip() + "\n</ca>\n"
    out += "<cert>\n" + cert.strip() + "\n</cert>\n"
    out += "<key>\n" + key.strip() + "\n</key>\n"
    if ta_path and os.path.exists(ta_path):
        ta = file_contents(ta_path)
        out += "<tls-auth>\n" + ta.strip() + "\n</tls-auth>\n"
    return out

def main():
    p = argparse.ArgumentParser(description="Создать клиента OpenVPN (easy-rsa 3) и собрать .ovpn")
    p.add_argument("--name", required=True, help="Имя клиента (CN)")
    p.add_argument("--easyrsa", required=False, default="/etc/openvpn/easy-rsa",
                   help="Папка easy-rsa (с pki). Пример: /etc/openvpn/easy-rsa")
    p.add_argument("--template", required=False, default="./client-template.ovpn",
                   help="Путь к шаблону клиента .ovpn (см. пример ниже)")
    p.add_argument("--out", required=False, default="./out_ovpns", help="Куда положить готовые .ovpn")
    p.add_argument("--nopass", action="store_true", default=True, help="Генерировать ключ без пароля (по умолчанию)")
    args = p.parse_args()

    name = args.name
    easyrsa_dir = args.easyrsa
    template = args.template
    out_dir = args.out
    nopass = args.nopass

    # Проверки
    if not os.path.isdir(easyrsa_dir):
        print("Ошибка: easy-rsa папка не найдена:", easyrsa_dir, file=sys.stderr)
        sys.exit(2)
    pki_dir = os.path.join(easyrsa_dir, "pki")
    if not os.path.isdir(pki_dir):
        print("Ошибка: PKI (pki) не найдена в:", pki_dir, file=sys.stderr)
        sys.exit(2)
    ensure_dir(out_dir)

    cert_path = os.path.join(pki_dir, "issued", f"{name}.crt")
    key_path = os.path.join(pki_dir, "private", f"{name}.key")
    ca_path = os.path.join(pki_dir, "ca.crt")
    ta_path_candidates = [
        os.path.join("/etc/openvpn", "ta.key"),
        os.path.join(easyrsa_dir, "ta.key"),
        os.path.join(pki_dir, "ta.key"),
    ]
    ta_path = None
    for cand in ta_path_candidates:
        if os.path.exists(cand):
            ta_path = cand
            break

    if os.path.exists(cert_path) or os.path.exists(key_path):
        print(f"Клиент {name} уже существует (найдены cert/key). Выход.")
        sys.exit(1)

    # 1) Создаём клиента (easyrsa)
    try:
        res = create_client(easyrsa_dir, name, nopass=nopass)
    except subprocess.CalledProcessError as e:
        print("Ошибка при запуске easyrsa:", e.stderr, file=sys.stderr)
        sys.exit(3)
    print("easyrsa output:", res.stdout)

    # Проверяем что после команды появились файлы
    if not (os.path.exists(cert_path) and os.path.exists(key_path) and os.path.exists(ca_path)):
        print("Не удалось найти одно из необходимых файлов (cert/key/ca).", file=sys.stderr)
        sys.exit(4)

    # 2) Сборка .ovpn
    if not os.path.exists(template):
        print("Шаблон .ovpn не найден:", template, file=sys.stderr)
        sys.exit(5)

    ovpn_content = assemble_ovpn(template, ca_path, cert_path, key_path, ta_path)

    out_file = os.path.join(out_dir, f"{name}.ovpn")
    with open(out_file, "w") as f:
        f.write("# Generated: " + datetime.utcnow().isoformat() + "Z\n")
        f.write(ovpn_content)

    print("Готово. .ovpn сохранён в:", out_file)
    print("Совет: выдавайте .ovpn пользователю по защищённому каналу (scp/sftp), не через e-mail в открытом виде.")

if __name__ == "__main__":
    main()
