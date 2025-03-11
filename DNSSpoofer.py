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
    scapy_packet = scapy.IP(packet.get_payload)
    print(packet)
    packet.drop()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
