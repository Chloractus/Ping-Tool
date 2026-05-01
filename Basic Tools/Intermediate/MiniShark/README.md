# Mini-Shark
  Intermediate Python Packet Capture Script using Scapy.

  This Python script utilizes Scapy, Termios, and Threading to cleanly capture packets in a thread and add them to different files based on certain criteria. For instance, this script checks the port of each packet moveing through the network to see if any of them are going through vulnerable/important ports like 21 and 23. This script also has simple DoS Detection, 2 seperate logs for dangerous and safe packets, and a pcap file to hold all capture packets.
