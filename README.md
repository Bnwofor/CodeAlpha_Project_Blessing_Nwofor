import scapy.all as scapy

def packet_sniffer(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print("Source IP: ", src_ip)
        print("Destination IP: ", dst_ip)
        print("Protocol: ", protocol)

        # To check for TCP packets
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print("Source Port: ", src_port)
            print("Destination Port: ", dst_port)

        # To check for UDP packets
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print("Source Port: ", src_port)
            print("Destination Port: ", dst_port)

        # To check for ICMP packets
        elif packet.haslayer(scapy.ICMP):
            print("ICMP Packet")
            print("------------------------")

# To define network interface, here am using Ethernet 3
iface = "Ethernet 3" 

# Let Start sniffing, to avoid continuous capturing, i will like it stop at 10 packets only
scapy.sniff(iface=iface, prn=packet_sniffer, store=0, count=10)
