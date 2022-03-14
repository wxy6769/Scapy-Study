# 需要導入模塊: from scapy.layers import l2 [as 別名]
from scapy.layers.l2 import Ether
from scapy.all import *


def make_reply(self, req):
        mac = req.src
        if type(self.pool) is list:
            if not self.leases.has_key(mac):
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool

        repb = req.getlayer(BOOTP).copy()
        repb.op = "BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        del(repb.payload)
        rep = Ether(dst=mac) / IP(dst=ip) / UDP(sport=req.dport, dport=req.sport) / repb
        return rep


if __name__ == "__main__":
    test = make_reply("00-E0-4C-68-14-21")
    print(test)
