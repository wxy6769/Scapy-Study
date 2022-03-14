from scapy.all import *

count = 0


def print_packet(packet):
    global count
    ip_layer = packet.getlayer(IP)
    print("[!] New Packet: {src} -> {dst}".format(
        src=ip_layer.src, dst=ip_layer.dst))
    count += 1
    print(count)


print("[*] Start sniffing...")
sniff(iface="Local-Test", filter="ip", prn=print_packet)
print("[*] Stop sniffing")
