
from scapy.all import *
import sys, os

TYPE_Probe = 0xA0
TYPE_IPV4 = 0x0800

class ProbeHeader(Packet):
    name = "ProbeHeader"
    fields_desc = [
        ShortField("P1", 0),
        ShortField("P2", 0)
    ]
    def mysummary(self):
        return self.sprintf("P1=%P1%, P2=%P2%")

bind_layers(IP, ProbeHeader, proto=TYPE_Probe)

