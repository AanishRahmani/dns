import argparse
import pyshark
import json
from datetime import datetime, timedelta
import os

output_file = 'packets.json'
retention_period = timedelta(hours=24)

def initialize_json_file():
    if not os.path.exists(output_file):
        with open(output_file, 'w') as file:
            json.dump([], file)  # Initialize with an empty list

def append_to_json_file(packet_data):
    try:
        with open(output_file, 'r+') as file:
            data = json.load(file)
            data.append(packet_data)
            file.seek(0)
            json.dump(data, file, indent=4)
            file.truncate()  # Remove any remaining old data
    except Exception as e:
        print(f"Error writing to JSON file: {e}")

def perform_garbage_collection():
    try:
        now = datetime.now()
        with open(output_file, 'r+') as file:
            data = json.load(file)
            # Filter out old entries
            filtered_data = [
                entry for entry in data
                if datetime.fromisoformat(entry['timestamp']) >= now - retention_period
            ]
            file.seek(0)
            json.dump(filtered_data, file, indent=4)
            file.truncate()  # Remove any remaining old data
    except Exception as e:
        print(f"Error during garbage collection: {e}")

def process_packet(packet):
    try:
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': None,
            'dst_ip': None,
            'src_mac': None,
            'protocol': None,
            'stream_index': None,
            'rto': None,  # Add RTO field
            'details': {}
        }

        if hasattr(packet, 'eth'):
            packet_info['src_mac'] = packet.eth.src
        
        if hasattr(packet, 'ip'):
            packet_info['src_ip'] = packet.ip.src
            packet_info['dst_ip'] = packet.ip.dst
            
        elif hasattr(packet, 'ipv6'):
            packet_info['src_ip'] = packet.ipv6.src
            packet_info['dst_ip'] = packet.ipv6.dst

        if packet_info['dst_ip']:
            packet_info['protocol'] = 'Unknown'
            
            # TCP protocol
            if hasattr(packet, 'tcp'):
                tcp_pkt = packet.tcp
                packet_info['protocol'] = 'TCP'
                packet_info['stream_index'] = tcp_pkt.stream
                packet_info['details'] = {
                    'src_port': tcp_pkt.srcport,
                    'dst_port': tcp_pkt.dstport
                }
                
                # Extract RTO if available
                if hasattr(packet, 'tcp') and 'rto' in packet.tcp.field_names:
                    packet_info['rto'] = packet.tcp.rto
                
                if hasattr(packet, 'http'):
                    http_pkt = packet.http
                    packet_info['details']['http'] = {
                        'request_uri': http_pkt.get_field_by_showname('Full Request URI'),
                        'host': http_pkt.get_field_by_showname('Host')
                    }
                elif hasattr(packet, 'ssl'):
                    ssl_pkt = packet.ssl
                    packet_info['details']['ssl'] = {
                        'record_version': ssl_pkt.record_version,
                        'record_type': ssl_pkt.record_type,
                        'content_type': ssl_pkt.content_type
                    }
            
            # UDP protocol
            elif hasattr(packet, 'udp'):
                udp_pkt = packet.udp
                packet_info['protocol'] = 'UDP'
                packet_info['details'] = {
                    'src_port': udp_pkt.srcport,
                    'dst_port': udp_pkt.dstport
                }
                if hasattr(packet, 'dns'):
                    dns_pkt = packet.dns
                    packet_info['details']['dns'] = {
                        'query_name': dns_pkt.qry_name
                    }
            
            # ICMP protocol
            elif hasattr(packet, 'icmp'):
                icmp_pkt = packet.icmp
                packet_info['protocol'] = 'ICMP'
                packet_info['details'] = {
                    'type': icmp_pkt.type,
                    'code': icmp_pkt.code
                }

            # ICMPv6 protocol
            elif hasattr(packet, 'icmpv6'):
                icmp_pkt = packet.icmpv6
                packet_info['protocol'] = 'ICMPv6'
                packet_info['details'] = {
                    'type': icmp_pkt.type,
                    'code': icmp_pkt.code
                }

            # Add packet info to JSON file
            append_to_json_file(packet_info)
            
            # Perform garbage collection after adding new packet
            perform_garbage_collection()

    except Exception as e:
        print(f"Error processing packet: {e}")

# Continuously monitor incoming traffic
def monitor_traffic(interface):
    try:
        initialize_json_file()        
        print(f"Starting capture on interface: {interface}")
        capture = pyshark.LiveCapture(interface=interface, bpf_filter='ip or ip6')

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
