import argparse
import sys
import datetime

from scapy.all import ARP, Ether, srp, conf

conf.verb = 0

KnownDevices = {
	"ff:ff:ff:ff:ff:ff"
}

def scan(subnet: str, timeout: int = 1) -> list[dict]:

	frame = Ether(dst="ff:ff:ff:ff:ff:ff")

	arpRequest = ARP(pdst=subnet)

	packet = frame / arpRequest

	print(f"\n[*] Scanning subnet: {subnet}")
	print(f"[*] Waiting up to {timeout}s for ARP replies...\n")

	ans, unans = srp(packet, timeout=timeout, multi=True)

	totalS = len(ans) + len(unans)
	totalR = len(ans)
	print(f"[*] Sent {totalS} ARP requests - got {totalR} replies\n")

	devices = []

	for sent, recieved in ans:

		ip = recieved[ARP].psrc
		mac = recieved[Ether].src
		macL = mac.lower()
		isKnown = macL in KnownDevices

		devices.append({
			"ip": ip,
			"mac": mac,
			"known": isKnown
		})

	devices.sort(key=lambda d:tuple(int(x) for x in d["ip"].split(".")))

	return devices

def display(device: list[dict], subnet: str) -> None:

	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print("=" * 60)
	print(f"  NETWORK MAP - {subnet}")
	print(f"  Scanned at: {timestamp}")
	print("=" * 60)
	print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} STATUS")
	print("-" * 60)

	if not devices:
		print("  No devices found. Check your subnet or try a longer timeout.")

	else:
		for device in devices:
			status = "[$]  Known" if device["known"] else "[!] UNKNOWN"
			print(f"  {device['ip']:<18} {device['mac']:<20} {status}")

	print("-" * 60)
	total = len(devices)
	unknown = sum(1 for d in devices if not d["known"])
	print(f"  Total devices found : {total}")
	print(f"  Unknown devices     : {unknown}")
	print("=" * 60)

	if unknown > 0:
		print(f"  [!] WARNING: {unknown} unrecognized device(s) found on your network!")
		print("    Add trusted MACs to KnownDevices at the top of this script.")

		for d in devices:
			if not d["known"]:
				print(f"      -> {d['ip']:>15}   MAC: {d['mac']}")

	print()

def parse_args() -> argparse.Namespace:

	parser = argparse.ArgumentParser(
		description="ARP Network Scanner — discover devices on your LAN",
		epilog="Example: sudo python3 arp_scanner.py --subnet 192.168.0.0/24"
	)

	parser.add_argument(
		"--subnet",
		type=str,
		default="192.168.1.0/24",
		help="Target subnet in CIDR notation (default: 192.168.1.0/24)"
	)

	parser.add_argument(
		"--timeout",
		type=int,
		default=1,
		help="Seconds to wait for ARP replies (default: 1)"
	)

	return parser.parse_args()

if __name__ == "__main__":

	args = parse_args()

	try:
		devices = scan(subnet=args.subnet, timeout=args.timeout)
		display(devices, subnet=args.subnet)

	except PermissionError:
		print("\n[!] Permission denied. Please run with sudo:")
		print(f"   sudo python3 {sys.argv[0]}\n")
		sys.exit(1)

	except KeyboardInterrupt:
		print("\n\n[!] Scan interrupted by user. Goodbye!\n")
		sys.exit(0)
