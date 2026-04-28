# Banner-Grabber
Basic Python Banner Grabbing Script using Scapy.

This Python script uses Scapy and Socket in order to send SYN packets to a target device. The target device then sends a SYN/ACK packet back which contains some basic information about the target device. Since the script looks through multiple ports, there are many chances for it to find an open port and obtain some basic system information. The script then closes the TCP connection by sending a final ACK packet and closing the socket connection.
