from scapy.all import *

DUT_MAC = "88:dc:96:88:d5:32"
DUT_IPv6 = "2021:1::20"

NETWORK_ADAPTER = "Local-Test"
NETWORK_ADAPTER_MAC = "00:E0:4C:68:14:21"
NETWORK_ADAPTER_IPv6 = "2021:1::10"

pkt_list = []
pkt_list.append(Ether(src=NETWORK_ADAPTER_MAC, dst=DUT_MAC)/IPv6(src=NETWORK_ADAPTER_IPv6, dst=DUT_IPv6)/ICMPv6EchoRequest())
pkt_list.append(Ether(src="00:E0:4C:68:14:22", dst=DUT_MAC)/IPv6(src="2021:1::11", dst=DUT_IPv6)/ICMPv6EchoRequest())
pkt_list.append(Ether(src="00:E0:4C:68:14:23", dst=DUT_MAC)/IPv6(src="2021:1::12", dst=DUT_IPv6)/ICMPv6EchoRequest())

print(pkt_list)

ans, unans = srp(pkt_list, iface=NETWORK_ADAPTER, timeout=10)

print("\n")

print("============= Got answered! =============")
print(ans)
print(type(ans))
print("List lengh: {}".format(len(ans)))
print(ans[0])
print(type(ans[0]))
print("------------------")
print(ans[0][0].show())
print(ans[0][1].show())
print("=========================================")
print("\n")

print("=========== Remaining packets ===========")
print(unans)
print("List lengh: {}".format(len(unans)))
print(unans[0].show())
# print(len(unans[0][1]))
print(unans[1].show())
# print(unans[1][0].show())
print("=========================================")
