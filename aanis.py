import socket
import argparse
import whois
import threading
import signal
import subprocess
import sys
import time
from scapy.all import sniff, conf, IP, TCP, UDP, get_if_list

# For thread-safe connection status
connection_alive = threading.Event()
connection_alive.set()

def domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"Could not resolve domain {domain}: {e}")
        return None

def whois_lookup(value):
    try:
        return whois.whois(value)
    except Exception as e:
        print(f"Could not perform whois lookup for {value}: {e}")
        return None

def ip_to_domain(ip):
    try:
        domain, _, _ = socket.gethostbyaddr(ip)
        return domain
    except socket.herror as e:
        print(f"Could not resolve IP address {ip}: {e}")
        return None

def get_address_info(hostname, port):
    try:
        info = socket.getaddrinfo(hostname, port)
        if not info:
            print(f"No address information found for {hostname}:{port}")
            return

        for entry in info:
            family, socktype, proto, canonname, sockaddr = entry
            ip_address, port_number = sockaddr
            print(f"IP Address: {ip_address}, Port Number: {port_number}")

    except socket.gaierror as e:
        print(f"Address-related error for {hostname}:{port}: {e}")
    except socket.herror as e:
        print(f"Host-related error for {hostname}:{port}: {e}")
    except socket.timeout as e:
        print(f"Request timed out for {hostname}:{port}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred for {hostname}:{port}: {e}")

def connect_to_server(ip_address, port):
    global connection_alive
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_address, port))
        print(f"Successfully connected to {ip_address}:{port}\nshell> ", end="")
        sys.stdout.flush()

        lock = threading.Lock()
        threading.Thread(target=receive_data, args=(s, lock), daemon=True).start()

        while connection_alive.is_set():
            try:
                data = input()
                if data.lower() == 'exit':
                    print("Closing connection.")
                    break
                if data:
                    s.sendall(data.encode('utf-8'))
                    sys.stdout.flush()

            except KeyboardInterrupt:
                print("\nKeyboard interrupt received, closing connection.")
                break
            except socket.error as e:
                print(f"Socket error: {e}")
                break
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                break

        s.close()
        print("Connection closed.")

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def receive_data(s, lock):
    global connection_alive
    while connection_alive.is_set():
        try:
            response = s.recv(4096)
            if response:
                with lock:
                    print(f"\nServer response:\n{response.decode('utf-8')}\nshell> ", end="")
                    sys.stdout.flush()
            else:
                print("\nServer closed the connection.")
                connection_alive.clear()
                break
        except socket.error as e:
            print(f"Socket error while receiving data: {e}")
            connection_alive.clear()
            break
        except Exception as e:
            print(f"Error while receiving data: {e}")
            connection_alive.clear()
            break

def signal_handler(sig, frame):
    global connection_alive
    print("\nReceived interrupt signal, closing connection.")
    connection_alive.clear()

signal.signal(signal.SIGINT, signal_handler)

def run_curl_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"Error output from curl: {result.stderr}", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Error executing curl command: {e}", file=sys.stderr)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"
        else:
            src_port = dst_port = "N/A"
            protocol_name = f"Other ({protocol})"

        print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {protocol_name}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def monitor_network(ip_address, interface=None):
    # Resolve domain to IP if necessary
    if not ip_address.replace('.', '').isdigit():
        ip_address = domain_to_ip(ip_address)
        if not ip_address:
            print(f"Could not resolve domain to IP address.")
            return

    print(f"Starting network monitor for IP address: {ip_address}")

    # Set the network interface for Scapy
    if interface:
        conf.iface = interface
        print(f"Using network interface: {conf.iface}")
    else:
        print("No interface specified. Using default.")
    
    try:
        # Check if the interface exists
        available_interfaces = get_if_list()
        if interface and interface not in available_interfaces:
            print(f"Interface {interface} not found. Available interfaces are: {', '.join(available_interfaces)}")
            return

        # Sniff packets indefinitely, filtering for the specified IP address
        sniff(filter=f"host {ip_address}", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nStopping network monitoring.")
    except Exception as e:
        print(f"Error during network monitoring: {e}")

def list_interfaces():
    interfaces = get_if_list()
    print("Available network interfaces:")
    for iface in interfaces:
        print(f"- {iface}")

def main():
    parser = argparse.ArgumentParser(description="Network utility for various network operations and monitoring")

    parser.add_argument("-d", "--domain", help="Convert domain name to IP address")
    parser.add_argument("-i", "--ip", help="Convert IP address to domain name")
    parser.add_argument("-H", "--hostname", help="Used to connect to server")
    parser.add_argument("-P", "--port", type=int, help="The port number associated with the service (e.g., 80)")
    parser.add_argument("-W", "--whois", action="store_true", help="Perform whois lookup for the provided domain or IP")
    parser.add_argument("-C", "--curl", help="Execute a curl command")
    parser.add_argument("-M", "--monitor", help="IP address or domain to monitor")
    parser.add_argument("-I", "--interface", help="Network interface to use for monitoring")
    parser.add_argument("-l", "--list", action="store_true", help="List available network interfaces")

    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    if args.monitor:
        monitor_network(args.monitor, args.interface)
        return

    if args.curl:
        run_curl_command(args.curl)
        return

    if args.whois:
        value = args.domain or args.ip or args.hostname
        if value:
            res = whois_lookup(value)
            print(f"Whois lookup for {value}:")
            print(res)
        else:
            print("No domain, IP, or hostname provided for whois lookup.")
        return

    if args.domain:
        ip = domain_to_ip(args.domain)
        if ip:
            print(f"Domain: {args.domain}, IP address: {ip}")
        else:
            print(f"No IP address found for domain: {args.domain}")
        return

    if args.ip:
        domain = ip_to_domain(args.ip)
        if domain:
            print(f"IP address: {args.ip}, Domain: {domain}")
        else:
            print(f"No domain found for IP address: {args.ip}")
        return

    if args.hostname and args.port:
        get_address_info(args.hostname, args.port)
        ip_address = domain_to_ip(args.hostname)
        if ip_address:
            connect_to_server(ip_address, args.port)
        else:
            print(f"Could not resolve hostname {args.hostname} to IP address.")
    else:
        if not args.hostname:
            print("Error: Hostname is required for server connection.")
        if not args.port:
            print("Error: Port is required for server connection.")

if __name__ == "__main__":
    main()
