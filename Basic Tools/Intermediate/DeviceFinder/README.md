# Device-Finder
  Intermediate Python ARP Request Script using Scapy.

  This Python script crafts ARP packets using Scapy and sends them out via a Broadcast on a specified subnet. This specific script requires administrative permissions and is able to accept arguments to change how the script works (Type "sudo python3 DeviceFinder.py -h" for more details). This script also keeps track of known devices on the network based on the Mac address of the devices that respond to the ARP request. 
