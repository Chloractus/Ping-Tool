from scapy.all import *
import socket

def grab(target, port, payload=None):

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((target, port))

		if payload:
			s.send(payload.encode())

		banner = s.recv(1024)
		s.close()
		return banner.decode("utf-8", errors="ignore")

	except (socket.timeout, ConnectionRefusedError, OSError) as e:
		return None

def scan(target, ports):

	payloads = {

		80: "GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n",
		443: "GET /HTTP/1.1\r\nHost: " + target + "\r\n\r\n",
		21: None,
		22: None,
		25: None
	}

	print(f"\n[*] Scanning {target}...")

	for port in ports:
		payload = payloads.get(port, None)

		banner = grab(target, port, payload)
		if banner:
			print(f"[+] Port {port} open - Banner:")
			print(banner[:500])

		else:
			print(f"[-] Port {port} - No response/closed")

if __name__ == "__main__":

	target = "172.18.0.2"
	portsToScan = [21, 22, 25, 80, 443, 8080]
	scan(target, portsToScan)
