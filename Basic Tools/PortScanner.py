# =====================
# TCP SYN Port Scanner
# =====================

from scapy.all import IP, TCP, sr1, conf
import socket
import threading
from queue import Queue
import sys
import time

conf.verb = 0
open_ports = []
lock = threading.Lock()

def getService(port):

	try:
		return socket.getservbyport(port)

	except:
		return "unknown"

def scan(target, port):
	packet = IP(dst=target) / TCP(dport=port, flags="S")
	res = sr1(packet, timeout=0.3)

	if res is None:
		stat = "filtered"

	elif res.haslayer(TCP):
		recievedRes = res.getlayer(TCP)

		if recievedRes.flags == 0x12:

			stat = "open"

		elif recievedRes.flags == 0x14:

			stat = "closed"

		else:

			stat = "unknown"

	else:

		stat = "unknown"

	if stat == "open":

		serv = getService(port)
		with lock:
			open_ports.append((port, service))
			print(f"[+] Port {port:5d} OPEN -> {service}")

def worker(target, queue):

	while not queue.empty():
		port = queue.get()
		scan(target, port)
		queue.task_done()

def run(target, startP=1, endP=1024, num_threads=100):

	timeS = time.perf_counter_ns()
	print(f"\nScanning {target} | Ports {startP} - {endP} | Threads: {num_threads}\n")

	q = Queue()
	for port in range(startP, endP):
		q.put(port)

	threads = []

	for _ in range(num_threads):
		t = threading.Thread(target=worker, args=(target, q))
		t.daemon = True
		t.start()
		threads.append(t)

	q.join()

	print(f"Scan complete. {len(open_ports)} open port(s) found.")
	timeE = time.perf_counter_ns()

	print(f"Completed in {(timeE - timeS) / 1000000}ms")

if __name__ == "__main__":
	target_ip = "127.0.0.1"
	run(target_ip, startP=1, endP=1024, num_threads=45)
