import random
from scapy.all import *

nic = "Local-Test"

PC_IP = "192.168.0.155"
DUT_IP = "192.168.0.241"

def send_l2(dut_mac, qunatity):

    # Gen the packets you want to gen
    for i in range(1, qunatity + 1):
        hex_i = str(hex(i))[2:]
        if len(hex_i) == 1:
            eth_mac = "00:00:00:00:00:0{}".format(hex_i)
        elif len(hex_i) == 2:
            eth_mac = "00:00:00:00:00:{}".format(hex_i)
        elif len(hex_i) == 3:
            eth_mac = "00:00:00:00:0{}:{}".format(hex_i[:1], hex_i[1:])
        elif len(hex_i) == 4:
            eth_mac = "00:00:00:00:{}:{}".format(hex_i[:2], hex_i[2:])
        elif len(hex_i) == 5:
            eth_mac = "00:00:00:0{}:{}:{}".format(hex_i[:1], hex_i[1:3], hex_i[3:])

        print(i)
        print(eth_mac)

        test_packet = Ether(dst=dut_mac, src=eth_mac)
        sendp(test_packet, iface=nic)


def send_l2_in_burst(dut_mac, qunatity):

    test_packet = []
    # Gen the packets you want to gen
    for i in range(1, qunatity + 1):
        hex_i = str(hex(i))[2:]
        if len(hex_i) == 1:
            eth_mac = "00:00:00:00:00:0{}".format(hex_i)
        elif len(hex_i) == 2:
            eth_mac = "00:00:00:00:00:{}".format(hex_i)
        elif len(hex_i) == 3:
            eth_mac = "00:00:00:00:0{}:{}".format(hex_i[:1], hex_i[1:])
        elif len(hex_i) == 4:
            eth_mac = "00:00:00:00:{}:{}".format(hex_i[:2], hex_i[2:])
        elif len(hex_i) == 5:
            eth_mac = "00:00:00:0{}:{}:{}".format(hex_i[:1], hex_i[1:3], hex_i[3:])

        print(i)
        print(eth_mac)

        test_packet.append(Ether(dst=dut_mac, src=eth_mac))

    sendp(test_packet, iface=nic)


def send_ipv6(dut_mac, dut_ipv6, src_ipv6, qunatity):

    # 目前先根據Test Plan寫死，日後會再進行擴充
    # IPv6 format: 2021:1::xxxx
    # minimum = 2021:1::200
    print(src_ipv6)

    # Gen the packets you want to gen
    for i in range(1, qunatity + 1):
        hex_i = str(hex(i))[2:]
        print(hex_i)
        if len(hex_i) == 1:
            src_ipv6 = "2021:1::20{}".format(hex_i)
        elif len(hex_i) == 2:
            src_ipv6 = "2021:1::2{}".format(hex_i)
        elif len(hex_i) == 3:
            # hex_i = 2xx
            src_ipv6 = "2021:1::{}{}".format(str(2 + int(hex_i[:1], 16)), hex_i[1:])

        print(i)
        print(src_ipv6)

        test_packet = IPv6(dst=dut_mac, src=src_ipv6)
        send(test_packet, iface=nic)


def send_dhcp_discover(_mac, _host_name, t_f):

    client_mac_addr = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'.hex()

    # Gen pakcet depends on True or false
    if t_f.upper() == "F":
        # Gen fake MAC address as 00:00:00:00:00:01
        format_mac = '000000000001'
        print('[INFO] Gen fake MAC address [{}]'.format(format_mac))

    elif t_f.upper() == "T":
        # DUT MAC will be tucked into packet
        format_mac = _mac.replace(":", "")
        print('[INFO] MAC address [{}]'.format(format_mac))

    # Reverse Hex string into Bytes
    format_mac += client_mac_addr[12:]
    print('This is the data we gen [{}]'.format(format_mac))
    format_mac_bytes = bytes.fromhex(format_mac)
    print('This is the data (hex) would put in packet [{}]'.format(format_mac_bytes))

    # Gen every random value we need
    ip_id = random.randint(0, 65535)
    bootp_xid = random.randint(1, 9999999999)
    bootp_secs = random.randint(0, 65535)

    # Build the packet
    test_packet = scapy.all.Ether(src=_mac, dst="ff:ff:ff:ff:ff:ff", type='IPv4') /\
                  scapy.all.IP(id=ip_id, src="0.0.0.0", dst="255.255.255.255") /\
                  scapy.all.UDP(sport=68, dport=67) /\
                  scapy.all.BOOTP(op=1, xid=bootp_xid, secs=bootp_secs, flags=32768,
                                  chaddr=format_mac_bytes) /\
                  scapy.all.DHCP(options=[('message-type', 1),
                                          ('hostname', _host_name),
                                          ('param_req_list', [53, 12, 55]),
                                          'end'])

    sendp(test_packet, iface=nic)


def send_ipv4_icmp_request(src_ip, dst_ip):

    test_packet = (scapy.all.IP(src=src_ip, dst=dst_ip, tos=55) /
                   scapy.all.ICMP(id=1))

    ans, unans = sr(test_packet, iface=nic, timeout=5)

    print(len(unans))

    for pkt in ans:
        if ans[0][0]:
            print(ans[0][0].show())
    print(unans)


def send_ipv4_tcp(src_ip, dst_ip, src_port, dst_port):

    # TCP flag default is SYN
    test_packet = (scapy.all.IP(src=src_ip, dst=dst_ip) /
                   scapy.all.TCP(sport=60888, dport=23))
                   
    ans, unans = sr(test_packet, iface=nic, timeout=5)

    print(len(unans))

    for pkt in ans:
        if ans[0][0]:
            ans[0][0].show()
    print(unans)


def send_ipv6_icmp_request(src_ip, dst_ip):
    test_packet = (scapy.all.IPv6(src=src_ip, dst=dst_ip, tc=220) /
                   scapy.all.ICMPv6EchoRequest(id=1))
    
    print(len(unans))

    for pkt in ans:
        if ans[0][0]:
            ans[0][0].show()
    print(unans)


if __name__ == "__main__":
    # DUT_MAC = '00:02:6F:00:00:00'
    # DUT_MAC = '2c:b8:ed:4b:1e:7c'
    # DUT_IPv6 = 'fe80::8adc:96ff:fe53:49de'
    # SRC_IPv6 = '2021:1::200'
    # send_l2(DUT_MAC, 16000)
    # send_l2_in_burst(DUT_MAC, 16000)
    # send_ipv6(DUT_MAC, DUT_IPv6, SRC_IPv6, 512)
    # send_dhcp_discover("88:dc:96:82:d5:87", "ECS2512FP", "T")
    # send_igmp_v3_join()

    send_ipv4_icmp_request(PC_IP, DUT_IP)

    # print(len(test_packet))
    # print(type(test_packet))
    # print(packet[0].show())
