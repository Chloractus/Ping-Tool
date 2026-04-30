from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap, Ether
from collections import defaultdict
import datetime
import threading
import sys
import termios
import time

duration = 5
maxRoT = 100

IP_Timestamps = defaultdict(list)
MAC_Timestamps = defaultdict(list)

AIP = set()
AMAC = set()

pCount, sCount = 0, 0

BADLOG = "SuspiciousAction.log"
GOODLOG = "Output.log"

savedPcap = "output.pcap"

STOP = threading.Event()

def logGood(p, sr, sp, ds, dp):
	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	entry = f"[{p}] {sr}:{sp} -> {ds}:{dp} - [{timestamp}]\n"

	with open(GOODLOG, "a") as log:
		log.write(entry)

def logBad(reason, summary):

	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	entry = f"[{timestamp}] {reason} | {summary}\n"

	with open(BADLOG, "a") as log:
		log.write(entry)

def handler(packet):
	global pCount
	global sCount

	pCount += 1

	if not packet.haslayer(IP):
		return

	layer = packet[IP]
	src = layer.src
	dst = layer.dst

	proto = "OTHER"
	sport, dport = None, None

	if packet.haslayer(TCP):
		proto = "TCP"
		sport = packet[TCP].sport
		dport = packet[TCP].dport

	elif packet.haslayer(UDP):
		proto = "UDP"
		sport = packet[UDP].sport
		dport = packet[UDP].dport

	logGood(proto, src, sport, dst, dport)

	if packet.haslayer(Raw):

		payload = packet[Raw].load

		try:

			text = payload.decode("utf-8", errors="ignore")

			if text.startswith("GET ") or text.startswith("POST"):
				lines = text.split("\r\n")
				method = lines[0]
				host = ""

				for line in lines:
					if line.startswith("Host:"):
						host = line.split(":", 1)[1].strip()
				url = f"http://{host}{method.split()[1]}"

				print(f"  [HTTP] {method.split()[0]} {url}")

		except Exception:
			pass


	if dport in (23, 21, 4444, 1337):

		reason = f"Suspicious port {dport}"
		logBad(reason, packet.summary())
		print(f"  Suspicious: {reason}")

		if proto == "TCP" and dport == 23:
			logBad("Telnet detected! (HIGH RISK)", packet.summary())
		sCount += 1

	checkForDoS(src, IP_Timestamps, AIP, "IP")

	if packet.haslayer(Ether):
		macSource = packet[Ether].src
		checkForDoS(macSource, MAC_Timestamps, AMAC, "MAC")

	wrpcap(savedPcap, packet, append=True)

def checkForDoS(id, tracker, alerted, label):
	timestamp = datetime.datetime.now().timestamp()

	tracker[id].append(timestamp)
	tracker[id] = [t for t in tracker[id] if timestamp - t <= duration]

	count = len(tracker[id])

	if count >= maxRoT and id not in alerted:
		alerted.add(id)

		reason = (
			f"Possible DoS detected from {label} {id} - "
			f"{count} packets in {duration}s"
		)

		print(f"[!] {reason}")
		logBad(reason, f"{label}: {id}")

	if count < maxRoT and id in alerted:
		alerted.discard(id)

		print(f"[^] {label} {id} back under threshold.")

def start():
	while not STOP.is_set():
		sniff(prn=handler, store=False, count=0, timeout=0.1)

def hide():
	inputDes = sys.stdin.fileno()
	termSettings = termios.tcgetattr(inputDes)
	termSettings[3] &= ~termios.ECHOCTL
	termios.tcsetattr(inputDes, termios.TCSANOW, termSettings)

def show():
	inputDes = sys.stdin.fileno()
	termSettings = termios.tcgetattr(inputDes)
	termSettings[3] |= termios.ECHOCTL
	termios.tcsetattr(inputDes, termios.TCSANOW, termSettings)

if __name__ == "__main__":
	print("[*] Sniffing started. Press Ctrl+C to stop. \n")

	mainThread = threading.Thread(target=start)
	mainThread.start()
	hide()
	start = time.perf_counter_ns()

	try:
		mainThread.join()

	except KeyboardInterrupt:
		STOP.set()
		mainThread.join()
		end = time.perf_counter_ns()
		show()
		print(f"\n[*] Sniffing stopped.")
		print(f"[*] Total packets captured: {pCount}")
		print(f"[*] Total suspicious packets: {sCount}")

		if sCount > 0:
			print("[!] Please check SuspiciousAction.log")

		print(f"\n[*] Capture time: {(end - start) / 1000000000} Seconds.")
