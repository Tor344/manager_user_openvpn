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


def add_user(name_user:str)->str:

    subprocess.run(["easyrsa", "gen-req", name_user, "nopass", "/etc/openvpn/easy-rsa"])
    subprocess.run(["easyrsa", "sign-req", "client", name_user, "/etc/openvpn/easy-rsa"])

    with open("/etc/openvpn/easy-rsa/pki/ca.crt", "r") as f:
        ca = f.read()
    with open(f"/etc/openvpn/easy-rsa/pki/issued/{name_user}.crt","r") as f:
        cert = f.read()
    with open(f"/etc/openvpn/easy-rsa/pki/private/{name_user}.key") as f:
        key = f.read()

    data_openvpn = TEMPLATES.format(ca=ca, cert=cert, key=key)
    return data_openvpn



def delete_user(name_user:str)->None:
    subprocess.run(["EASY_RSA_PATH}/easyrsa", "revoke", name_user], input= b"yes",cwd=EASY_RSA_PATH)
    subprocess.run(["EASY_RSA_PATH}/easyrsa", "gen-crl"] ,cwd=EASY_RSA_PATH)
    subprocess.run(["pkill", "-HUP", "openvpn"])


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