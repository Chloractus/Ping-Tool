from scapy.all import *
import time

TARGET = "8.8.8.8"

COUNT = 4

TIMEOUT = 2

def ping(target, count, timeout):

	print(f"\n\t\t--- PingTool.py ---\n")
	results = []
	for i in range(count):
		packet = IP(dst=target) / ICMP()

		start_time = time.perf_counter_ns()
		reply = sr1(packet, timeout=timeout, verbose=0)
		end_time = time.perf_counter_ns()

		if reply is None:
			print(f"Seq {i + 1}: Request timeout")

		elif reply.haslayer(ICMP):
			return_time = (end_time - start_time) / 100000
			results.append(return_time)
			print(f"Seq {i + 1}: Reply from {reply.src} Return Time = {return_time:.2f} ms")

	sent = count
	recieved = len(results)
	loss = (sent - recieved) / sent * 100

	print(f"\n\t\t--- {target} ping stats ---")
	print(f"{sent} sent, {recieved} recieved, {loss:.0f}% loss")

	if results:
		average = sum(results) / len(results)
		print(f"Return Time: min={min(results):.2f}ms, avg={average:.2f}ms, max={max(results):.2f} ms")

if __name__ == "__main__":
	ping(TARGET, COUNT, TIMEOUT)
