import argparse
import pyshark

# Process captured packets
def process_packet(packet):
    try:
        ip_src = ip_dst = None
        
        if hasattr(packet, 'ip'):
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            
        elif hasattr(packet, 'ipv6'):
            ip_src = packet.ipv6.src
            ip_dst = packet.ipv6.dst
        
        if ip_dst:
            print(f"Captured Packet: Src IP: {ip_src}, Dest IP: {ip_dst}")

            # TCP protocol
            if hasattr(packet, 'tcp'):
                tcp_pkt = packet.tcp
                print(f"TCP Packet: Src Port: {tcp_pkt.srcport}, Dest Port: {tcp_pkt.dstport}")
                if hasattr(packet, 'http'):
                    print(f"Data (HTTP Example): {packet.http.get_field_by_showname('Full Request URI')}")
            
            # UDP protocol
            elif hasattr(packet, 'udp'):
                udp_pkt = packet.udp
                print(f"UDP Packet: Src Port: {udp_pkt.srcport}, Dest Port: {udp_pkt.dstport}")
                if hasattr(packet, 'dns'):
                    print(f"Data (DNS Example): {packet.dns.qry_name}")
            
            # ICMP protocol
            elif hasattr(packet, 'icmp'):
                icmp_pkt = packet.icmp
                print(f"ICMP Packet: Type: {icmp_pkt.type}, Code: {icmp_pkt.code}")

            # ICMPv6 protocol
            elif hasattr(packet, 'icmpv6'):
                icmp_pkt = packet.icmpv6
                print(f"ICMPv6 Packet: Type: {icmp_pkt.type}, Code: {icmp_pkt.code}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Continuously monitor incoming traffic
def monitor_traffic(interface):
    try:
        # Capturing packets 
        print(f"Starting capture on interface: {interface}")
        capture = pyshark.LiveCapture(interface=interface, bpf_filter='ip or ip6')

        # Process packets
        for packet in capture.sniff_continuously():
            try:
                print(f"Captured Packet: {packet}")  # Debugging line
                process_packet(packet)
            except Exception as e:
                print(f"Error processing captured packet: {e}")

    except Exception as e:
        print(f"Error starting packet capture: {e}")

def main():
    parser = argparse.ArgumentParser(description='Continuously monitor incoming traffic on a network interface.')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Network interface to use (e.g., eth0)')

    args = parser.parse_args()

    interface = args.interface

    monitor_traffic(interface)

if __name__ == "__main__":
    main()