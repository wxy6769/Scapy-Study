elif Params.PACKET_GENERATOR == "TRex":
    if checkpoint == 1:
        pass
    elif checkpoint == 2:
        t.sleep(10)
        packet_list = []

        # 暫時先針對此Case寫死，日後會再進行統整
        # Generate 512 MAC address and IPv6 address
        for i in range(1, 81):

            # Define src mac
            hex_i = str(hex(i))[2:]
            # print(hex_i)
            if len(hex_i) == 1:
                src_mac = "00:00:00:00:00:0{}".format(hex_i)
                src_ipv6 = "2021:1::20{}".format(hex_i)
            elif len(hex_i) == 2:
                src_mac = "00:00:00:00:00:{}".format(hex_i)
                src_ipv6 = "2021:1::2{}".format(hex_i)
            elif len(hex_i) == 3:
                src_mac = "00:00:00:00:0{}:{}".format(hex_i[:1], hex_i[1:])
                src_ipv6 = "2021:1::{}{}".format(str(2 + int(hex_i[:1], 16)), hex_i[1:])
            logging.debug(i)
            logging.debug(src_ipv6)
            logging.debug(src_mac)

            # Define ICMPv6 Neighbor Solicitation packet content
            packets = (scapy.all.Ether(dst=port_mac, src=src_mac) /
                       scapy.all.IPv6(src=src_ipv6, dst=Params.DUT_IPv6) /
                       scapy.all.ICMPv6ND_NS(tgt=Params.DUT_IPv6) /
                       scapy.all.ICMPv6NDOptSrcLLAddr(lladdr=src_mac))

            packet_list.append(packets)

        logging.debug(len(packet_list))
        scapy.all.sendp(packet_list, iface=Params.SCAPY_NETWORK_ADAPTER, inter=0.05)

    if fail_count == 0:
        return_data = {
            "Result": True,
            "Fail Count": 0,
            "Fail Reason": ""
        }
    else:
        return_data = {
            "Result": False,
            "Fail Count": fail_count,
            "Fail Reason": fail_reason
        }

    return return_data
