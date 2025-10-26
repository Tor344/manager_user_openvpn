import subprocess
import os
import sys

TEMPLATES = """
proto tcp-client
remote 23.177.185.179 1194
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server_WwCKfMPF7IEi08EA name
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3

<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
<tls-crypt>
{tls_crypt}
</tls-crypt>
"""

EASY_RSA_PATH = "/etc/openvpn/easy-rsa"

def add_user(name_user:str)->str:
    try:
        subprocess.run([f"{EASY_RSA_PATH}/easyrsa", "gen-req", name_user, "nopass",] , input= b"\n")
        subprocess.run([f"{EASY_RSA_PATH}/easyrsa", "sign-req", "client", name_user ], input= b"yes")

        with open(f"{EASY_RSA_PATH}/pki/ca.crt", "r") as f:
            ca = f.read()
        with open(f"{EASY_RSA_PATH}/pki/issued/{name_user}.crt","r") as f:
            cert = f.read()
        with open(f"{EASY_RSA_PATH}/pki/private/{name_user}.key","r") as f:
            key = f.read()
        with open(f"/etc/openvpn/ta.key","r") as f:
            tls_crypt = f.read()

        data_openvpn = TEMPLATES.format(ca=ca, cert=cert, key=key,tls_crypt=tls_crypt)

        return data_openvpn

    except Exception as e:
        print(e)
        return ""

def delete_user(name_user:str)->None:
    pass


def manager_user_openvpn():
    name_user = input("Enter your name: ")
    while True:
        actin = input("1.add or 2.delete user?\n>>")
        if actin == "add":
            data_openvpn = add_user(name_user)

            with open(f"{name_user}.ovpn", "w") as f:
                f.write(data_openvpn)

            print(f"File is in path: {os.getcwd()}/{name_user}.ovpn")

        elif actin == "delete":
            delete_user(name_user)

        elif actin == "exit":
            sys.exit(0)
        else:
            print("Unknown action")



if __name__ == "__main__":
    manager_user_openvpn()