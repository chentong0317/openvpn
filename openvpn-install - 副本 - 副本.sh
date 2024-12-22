#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2013 Nyr. Released under the MIT License.


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this OpenVPN road warrior installer!'
	# 默认使用 0.0.0.0，不再从系统中获取 IP 地址
    ip="0.0.0.0" # 设置默认IPv4地址为0.0.0.0
	
	
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
echo "Using default configuration for protocol, port, DNS, and client name."

# 使用默认协议 UDP
protocol="udp" # 设置默认协议为UDP

# 使用默认端口 1194
port="3306" # 设置默认端口为1194

# 使用默认 DNS 选项（当前系统解析器）
dns="2" # 设置默认DNS为当前系统解析器

# 使用默认客户端名称 "client"
unsanitized_client="client" # 设置默认客户端名称为client

echo
echo "Configuration selected:"
echo "IPv6: $ip6"
echo "Protocol: $protocol"
echo "Port: $port"
echo "DNS: $dns"
echo "Client Name: $unsanitized_client"
	#read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	#read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	# 使用现有证书内容替代动态生成的证书
# 定义现有的 CA 证书内容/etc/openvpn/server/ca.crt
ca_cert_content='-----BEGIN CERTIFICATE-----
MIIDNTCCAh2gAwIBAgIJAJlO0/acV2ZNMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
BAMMC0Vhc3ktUlNBIENBMB4XDTIzMDkyNDAzMTkwOVoXDTMzMDkyMTAzMTkwOVow
FjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC9uGZQZQHGMf5B12JNFAFIwm86F6p+NT1HvpXFHdm22M7cyR/gsGVy
k0aF8w6gmbSYux/GnY5l0NR0GrtQ83i+rjLs2Jzp7SD1a388L17jqxofNPnTws9w
Fod5c3l6Utuiv3RVVoOZKcPOftp8d6tHTr0ksbyEHJynkMJbu+XQ3P1CV4S/XlB2
pSOkxZ85KurbKwbOGYaenlGeHtpn4840p/S4iY3OF7PimCFFB2cZpAgGMibwOVe3
NxGSU/9Z3IJ1BVNNMKwUkLCAPTl17NHP17DuLn3qBrXRrZXtR0jDI2+l2DtgVb5F
Q4IPWyXoVaQhTj76llWUkPRyQaFmNLSBAgMBAAGjgYUwgYIwDAYDVR0TBAUwAwEB
/zAdBgNVHQ4EFgQUGGEHmcmDStuBysPaGZ00LbekJm0wRgYDVR0jBD8wPYAUGGEH
mcmDStuBysPaGZ00LbekJm2hGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBggkA
mU7T9pxXZk0wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQAyRU2TkHX6
6U7NOuMKwCsbFVyLXIu8tQv7nBcTJPU76jGY5Ngrw3W5+GBshQyzbMihYqVW2EeV
YCsrbFfsRSfxGnFhldSLnmcXoAfXErwWPzkcARuNUDgkvx/NntUGEfvSFIQ8tlO1
wnP+IHFvzPwotC+6z6OafFoEronM3zadwABHQnCO6f3qP4ayhJ85wxGK+jhjgYfC
DJ+SQXjkYB4zZXND1RGa9oaeHNDNOKK+QhufuhpPDffzkD74XKdq1oXB0/WCDAUh
moiS8KVYH0BngEAK00keW8Dxp8kjxp9/bHV8nHOJafEOVxNFmsQsD0FyRYodZDYt
bS1wKqVVk8BU
-----END CERTIFICATE-----'

# 定义现有的服务器证书/etc/openvpn/server/server.crt
server_cert_content='Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            57:cb:8a:61:ea:e0:b4:bb:80:a6:cb:d7:04:8b:c6:40
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Easy-RSA CA
        Validity
            Not Before: Sep 24 03:19:09 2023 GMT
            Not After : Sep 21 03:19:09 2033 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ba:bc:5b:8f:c2:8e:cc:0f:95:08:6c:54:3a:e3:
                    41:53:6c:8a:e5:f2:f4:57:91:09:a0:8a:f5:c0:86:
                    20:da:5b:f3:2c:b7:eb:f2:12:22:ed:1a:bd:4b:b4:
                    59:16:f6:9f:8d:bf:f2:86:71:d2:8a:45:2d:c3:64:
                    17:20:eb:46:7d:2e:d7:02:ed:3a:80:3c:43:19:28:
                    4a:00:86:05:2e:7c:f7:68:be:6f:ef:88:d2:4c:3e:
                    09:41:99:b6:5b:9f:b8:1d:3d:a6:bc:f6:15:57:6b:
                    8f:86:d0:94:ca:16:c7:b4:04:ee:f9:59:06:43:e9:
                    f0:f4:bf:3a:3e:3c:39:ef:b8:4c:99:11:25:39:18:
                    72:57:f8:f0:1e:b0:23:8c:0a:92:93:ea:d1:70:75:
                    bd:d8:8c:59:fb:d9:99:ab:ff:29:16:53:c0:5c:77:
                    aa:11:08:1f:3e:80:10:f6:f1:4e:e4:3a:c4:51:03:
                    6a:51:23:be:a3:e4:ec:7a:39:50:c0:f1:17:49:55:
                    76:2a:c9:1e:c7:0e:9b:9d:1e:c8:bd:1a:d6:0d:06:
                    4b:63:be:97:65:6b:6d:7b:69:ec:58:66:36:1f:5b:
                    7b:1c:e0:19:9d:67:2c:c0:0f:67:f8:a2:a9:2e:33:
                    f1:cc:0f:d1:37:f7:b7:56:69:93:b7:9f:a4:5c:59:
                    4f:87
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                84:B2:5B:F2:27:4C:8C:93:CD:86:57:0D:55:1C:23:3B:E0:44:3B:4A
            X509v3 Authority Key Identifier: 
                keyid:18:61:07:99:C9:83:4A:DB:81:CA:C3:DA:19:9D:34:2D:B7:A4:26:6D
                DirName:/CN=Easy-RSA CA
                serial:99:4E:D3:F6:9C:57:66:4D

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         76:7b:5c:ec:08:4d:88:9b:88:82:b4:07:bf:b1:e1:13:21:89:
         d8:0b:4a:67:b0:a1:5d:5f:92:63:1a:53:06:34:7b:63:78:b5:
         73:65:0d:65:3c:b2:5c:66:3f:60:ec:84:65:b0:5e:e5:66:45:
         e4:90:c2:6a:98:65:4a:d5:82:4b:97:9a:30:e5:92:40:dc:f3:
         8c:d3:c8:3a:0c:79:79:85:a0:92:cf:db:5d:bc:6d:b3:e8:d0:
         2a:7e:dd:3d:6d:42:82:b5:2c:54:e5:7a:ce:84:2f:c8:eb:bc:
         df:05:11:42:99:c9:01:48:43:f7:b6:98:7e:dd:54:dd:1d:90:
         ce:61:c9:24:ff:51:d6:6d:db:95:22:eb:d9:f1:9e:e0:26:5f:
         3b:85:23:06:7b:28:d3:96:af:28:d1:7b:aa:e9:47:06:c4:ea:
         8b:af:be:d9:29:e0:49:61:66:77:c9:03:9f:e0:6d:71:7f:c7:
         b3:b8:e4:88:80:b8:4b:d7:50:a5:d0:94:96:0e:89:0c:da:d0:
         d0:ac:ca:62:56:2a:bb:28:91:80:14:81:96:a4:49:80:25:2b:
         95:f0:9d:36:12:98:bc:f1:82:d1:fa:75:95:eb:79:57:0a:df:
         2a:fd:91:2f:be:cb:5a:dd:75:49:84:95:7f:6f:b4:e3:2f:00:
         5a:b2:3e:6e
-----BEGIN CERTIFICATE-----
MIIDXDCCAkSgAwIBAgIQV8uKYergtLuApsvXBIvGQDANBgkqhkiG9w0BAQsFADAW
MRQwEgYDVQQDDAtFYXN5LVJTQSBDQTAeFw0yMzA5MjQwMzE5MDlaFw0zMzA5MjEw
MzE5MDlaMBExDzANBgNVBAMMBnNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBALq8W4/CjswPlQhsVDrjQVNsiuXy9FeRCaCK9cCGINpb8yy36/IS
Iu0avUu0WRb2n42/8oZx0opFLcNkFyDrRn0u1wLtOoA8QxkoSgCGBS5892i+b++I
0kw+CUGZtlufuB09prz2FVdrj4bQlMoWx7QE7vlZBkPp8PS/Oj48Oe+4TJkRJTkY
clf48B6wI4wKkpPq0XB1vdiMWfvZmav/KRZTwFx3qhEIHz6AEPbxTuQ6xFEDalEj
vqPk7Ho5UMDxF0lVdirJHscOm50eyL0a1g0GS2O+l2VrbXtp7FhmNh9bexzgGZ1n
LMAPZ/iiqS4z8cwP0Tf3t1Zpk7efpFxZT4cCAwEAAaOBqjCBpzAJBgNVHRMEAjAA
MB0GA1UdDgQWBBSEslvyJ0yMk82GVw1VHCM74EQ7SjBGBgNVHSMEPzA9gBQYYQeZ
yYNK24HKw9oZnTQtt6QmbaEapBgwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0GCCQCZ
TtP2nFdmTTATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAwEQYDVR0R
BAowCIIGc2VydmVyMA0GCSqGSIb3DQEBCwUAA4IBAQB2e1zsCE2Im4iCtAe/seET
IYnYC0pnsKFdX5JjGlMGNHtjeLVzZQ1lPLJcZj9g7IRlsF7lZkXkkMJqmGVK1YJL
l5ow5ZJA3POM08g6DHl5haCSz9tdvG2z6NAqft09bUKCtSxU5XrOhC/I67zfBRFC
mckBSEP3tph+3VTdHZDOYckk/1HWbduVIuvZ8Z7gJl87hSMGeyjTlq8o0Xuq6UcG
xOqLr77ZKeBJYWZ3yQOf4G1xf8ezuOSIgLhL11Cl0JSWDokM2tDQrMpiViq7KJGA
FIGWpEmAJSuV8J02Epi88YLR+nWV63lXCt8q/ZEvvsta3XVJhJV/b7TjLwBasj5u
-----END CERTIFICATE-----'

# 定义现有的服务器私钥/etc/openvpn/server/server.key
server_key_content='----------BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6vFuPwo7MD5UI
bFQ640FTbIrl8vRXkQmgivXAhiDaW/Mst+vyEiLtGr1LtFkW9p+Nv/KGcdKKRS3D
ZBcg60Z9LtcC7TqAPEMZKEoAhgUufPdovm/viNJMPglBmbZbn7gdPaa89hVXa4+G
0JTKFse0BO75WQZD6fD0vzo+PDnvuEyZESU5GHJX+PAesCOMCpKT6tFwdb3YjFn7
2Zmr/ykWU8Bcd6oRCB8+gBD28U7kOsRRA2pRI76j5Ox6OVDA8RdJVXYqyR7HDpud
Hsi9GtYNBktjvpdla217aexYZjYfW3sc4BmdZyzAD2f4oqkuM/HMD9E397dWaZO3
n6RcWU+HAgMBAAECggEAT1+bB8tqSUDiV1c8ol9QuDYuADo6NDJ5Rh1rAm/A7TAi
eEKhbx7Ya7Ju/gvlxoYEIguR+iXNmWp4XlJgJmT7bGCJkjvmHvX+i2X9tqVA9Ja3
z3ULPWUKBtBjvNeqlN2aNAutoSp0vdkBhAuLAy+VqWZjceeuaxW4jz/tcODGu6cA
M5OhAmRp0BWqQCXUwISUFXo8kmvvcfXKsxT6U+1qZ5KIg1xOAUYJd1JqDimjDjF7
mXN98Qk4ZGQ+Qdxj6+33VJqEUY5dL5CCeRj4Oa57jDhFcbp7/QXfdolR7iJWxBQo
T9gi22a7jox9ajQMcneHv/Zo6ONRU5rsUWKs2XYtwQKBgQDfx/6jZ2aZfpaGNQ+2
CVypvjqdol4mg6tLal82gKapSNv0CC9ibkqJfoObRWRyCRJDd5qRXqEp4ShRybTG
m+P/z99F6cWA31rkFPdGkVKjUwdUNyF+WfSKJGZztv2avPSBCOSDbmA5uzvRtZjO
cRVNzYl40Z3KRzjKx60JVQ42JwKBgQDVnvZAlvyH1iniXWrTHA3MqIbWsn2Upit6
nSI51/zKj8liY+p1OI+z5fpVW8tADWAfMKEHvKNWuVbEJySN5Cdj9wz+YVsdfNPa
cDOgeRR9XAzmfFE/dm9SBJn8i7ferWj3q5nbITf6KnoGCkTWdfRDtVFEKUFlgF6m
4IlVmS5XoQKBgDbZLwlf657Njxk/4iTs8IBONtGyHT91YEOww7t5FuBBEmAirXKD
s9M1Zg5lmLP2kzpkE0d0GS5JmHdLZ/qR9PUbPw9Et/rZQ87JcL4kGkwbqp0ykgwF
AlHlkBLmlAwcKhWCV3f7UqxzvrqsttJKlz0lln89aV5NzJavEDNMXJpbAoGBAImZ
OPllyAgfNR9wGO0etuzK6P/GPQnQ91SlfnRP4a8AazGLNmyHIFk6m8L7u7Hoa6/r
fO4k3flwrKjwpaUX/x9u9NmuECiwTS348+g71azh7BVSomsEeLQV7rIztR4kCObv
i80QWqQzVCIr3yddFxe95TjIci1VQKKxIwUWBDnBAoGAP/3VxJ4gHCnEwcjvFf6x
nRx1QAqtsG+emmYQy6ljigpnW3Ba59qShNeiT/ZHayqkO1kAKynSZBRJqdfbFxzq
uUfzwuUDQ0WEvF0v3lp/tdCPmInMCsYJfpDtkiFw2xDXmG5hmOqd8vJmqe1EIEk2
tb/NjQID8ac/QIpFmWG33CE=
-----END PRIVATE KEY-----'

# 定义现有的 TLS 密钥 (tc.key)/etc/openvpn/server/tc.key
tls_key_content='-----BEGIN OpenVPN Static key V1-----
fee1eb8f7864574a68382656294d9d80
0096e9cf69df6618404de38b24231ce5
395957ed19a367ad801010d9f1db1b7e
4c0ce3a86b7bf3917cb3d2c20b18d055
a8af949e9b17e5c28d41fe1c2ef2d515
90197b299f5cc2910439f0a492cd058f
3d03d01054cc07b7a9c8b5644ad36899
16d5e4950ef91a5a42cea790268d56b4
374cced317873efc1f53becdde5b07a4
f450323edc5f5b3389788160619e3adc
f5d5543b1109bc647d1fbdd8389b2c3b
53c893f396f334c25850b837a7f04e28
27b210092bf3d7c63819dc8cdab8e1ed
2b028c158307c48a0c36dfe9ec9391b3
984a2b39b0ed38333ad311b5240cf58b
6e92990212de34718fb05cf6505d0fd5
-----END OpenVPN Static key V1-----'

# 如果有 CRL（证书吊销列表），可以如下定义/etc/openvpn/server/crl.pem
crl_content='-----BEGIN X509 CRL-----
MIIBqzCBlAIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtFYXN5LVJTQSBD
QRcNMjMwOTI0MDMxOTA5WhcNMzMwOTIxMDMxOTA5WqBKMEgwRgYDVR0jBD8wPYAU
GGEHmcmDStuBysPaGZ00LbekJm2hGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENB
ggkAmU7T9pxXZk0wDQYJKoZIhvcNAQELBQADggEBAAv3/YK1tNTSc8bFovHuuKzV
NmDc4vX+UeXT1IDjN+pT9YF4iPBZiCkI5jK3E0/fW5j33f8QMrFZ3Tr+jkQdTHGW
3NU1jH8PNIssw7YevVvIfywxZ5CkdFjyajjAzrt+nZl2DItJoThJPgEHQkUnyCYI
pK+UIPSNlhcH1A2UOXXvPr8KMXcuSj52i5HUJBcBzitjIrijp7D2aXVr7M0OpZoC
WkCfmgtZL/kueOd8dGmwv+Wr4G7eycxZNurduYUgJHM8Y44KP3WbDa4IiYrAJ3jd
Jjftd9cAlIjiK2KBf/APj2LYHFJKXHmfA5uA/MyoADnjWcY1mnIjIiZ3Y8Lyeho=
-----END X509 CRL-----
'

# 替换动态生成 CA 和服务器证书的逻辑
# Create the PKI, set up the CA and the server and client certificates
# ./easyrsa init-pki
# ./easyrsa --batch build-ca nopass
# EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
# EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
# EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

# 使用现有证书内容写入文件
# 将现有的 CA 证书内容写入文件
echo "$ca_cert_content" > /etc/openvpn/server/ca.crt

# 将现有的服务器证书写入文件
echo "$server_cert_content" > /etc/openvpn/server/server.crt

# 将现有的服务器私钥写入文件
echo "$server_key_content" > /etc/openvpn/server/server.key

# 将现有的 TLS 密钥写入文件
echo "$tls_key_content" > /etc/openvpn/server/tc.key

# 如果适用，将 CRL 内容写入文件
if [[ -n "$crl_content" ]]; then
    echo "$crl_content" > /etc/openvpn/server/crl.pem
fi

# 确保权限设置正确
# CRL 是在 OpenVPN 降权为 nobody 后读取的
chown nobody:"$group_name" /etc/openvpn/server/crl.pem
# 没有 +x 权限，OpenVPN 无法对 CRL 文件运行 stat() 操作
chmod o+x /etc/openvpn/server/

# 删除动态生成 Diffie-Hellman 参数的部分，保留静态内容
# Generate key for tls-crypt
# openvpn --genkey --secret /etc/openvpn/server/tc.key
# Create the DH parameters file using the predefined ffdhe2048 group
echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem

# 后续逻辑保持不变
# Generate server.conf
echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem
duplicate-cn
max-clients 10000" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# Generates the custom client.ovpn
	new_client
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" ~/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
			# Generates the custom client.ovpn
			new_client
			echo
			echo "$client added. Configuration available in:" ~/"$client.ovpn"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to revoke:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client revoked!"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
