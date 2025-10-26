import subprocess
import os

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
"""

EASY_RSA_PATH = "/etc/openvpn/easy-rsa"

def add_user(name_user:str)->str:
    try:
        subprocess.run(["easyrsa", "gen-req", name_user, "nopass",], cwd=EASY_RSA_PATH, input= b"\n")
        subprocess.run(["easyrsa", "sign-req", "client", name_user, ], cwd=EASY_RSA_PATH, input= b"yes")

        with open("/etc/openvpn/easy-rsa/pki/ca.crt", "r") as f:
            ca = f.read()
        with open(f"/etc/openvpn/easy-rsa/pki/issued/{name_user}.crt","r") as f:
            cert = f.read()
        with open(f"/etc/openvpn/easy-rsa/pki/private/{name_user}.key") as f:
            key = f.read()

        data_openvpn = TEMPLATES.format(ca=ca, cert=cert, key=key)
        return data_openvpn

    except Exception as e:
        print(e)
        return ""

def delete_user(name_user:str)->None:
    pass


def manager_user_openvpn():
    name_user = input("Enter your name: ")
    actin = input("1.add or 2.delete user?\n>>")
    if actin == "add":
        data_openvpn = add_user(name_user)

        with open(f"{name_user}.ovpn", "w") as f:
            f.write(data_openvpn)

        print(f"File is in path: {os.getcwd()}{name_user}.ovpn")

    elif actin == "delete":
        delete_user(name_user)




if __name__ == "__main__":
    manager_user_openvpn()