import socket
import argparse
import whois
import threading
import signal

def domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        print(f"Could not resolve domain: {e}")
        return None

def whois_lookup(value):   
    try:
        res = whois.whois(value)
        return res
    except Exception as e:
        print(f"Could not perform whois lookup: {e}")
        return None



def ip_to_domain(ip):
    try:
        domain, _, _ = socket.gethostbyaddr(ip)
        return domain
    except socket.herror as e:
        print(f"Could not resolve IP address: {e}")
        return None



def get_address_info(hostname, port):
    try:
        # Get address information
        info = socket.getaddrinfo(hostname, port)
        
        if not info:
            print(f"No address information found for {hostname}:{port}")
            return

        for entry in info:
            family, socktype, proto, canonname, sockaddr = entry
            ip_address, port_number = sockaddr

            protocol_name=socket.getprotobynumber(proto)
            # Print the IP address and port number
            print(f"IP Address: {ip_address}, Port Number: {port_number},protcol: {protocol_name}")

    except socket.gaierror as e:
        print(f"Address-related error: {e}")
    except socket.herror as e:
        print(f"Host-related error: {e}")
    except socket.timeout as e:
        print(f"Request timed out: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")





def connect_to_server(ip_address, port):
    global connection_alive
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server
        s.connect((ip_address, port))
        print(f"Successfully connected to {ip_address}:{port}\nshell> ", end="")

        # Lock for synchronized output
        lock = threading.Lock()

        # Start a thread to continuously receive data from the server
        threading.Thread(target=receive_data, args=(s, lock), daemon=True).start()

        # Virtual shell to send commands to the server
        while connection_alive:
            try:
                data = input()  # Virtual shell prompt
                if data.lower() == 'exit':
                    print("Closing connection.")
                    break
                
                # Send data to the server
                s.sendall(data.encode('utf-8'))
            
            except KeyboardInterrupt:
                print("\nKeyboard interrupt received, closing connection.")
                break
            except socket.error as e:
                print(f"Socket error: {e}")
                break
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                break

        # Close the connection when finished
        s.close()
        print("Connection closed.")

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        
        



#output display 
# def get_output(sock, stop_event):
    # try:
    #     while not stop_event.is_set():
    #         chunk = sock.recv(4096)  # Read data in chunks
    #         if not chunk:
    #             print("Server closed the connection.")
    #             stop_event.set() 
    #             break
    #         # Print data to the terminal
    #         print(f"Received: {chunk.decode('utf-8', errors='replace')}", end='')
    # except socket.error as e:
    #     print(f"Socket error during data display: {e}")
    # except Exception as e:
    #     print(f"Unexpected error during data display: {e}")
    #     stop_event.set()  




#signal interrupted by server
def close_connection(sock, display_thread):
    try:
        if sock:
            sock.close()
            print("Connection closed.")
        if display_thread:
            display_thread.join()  
    except Exception as e:
        print(f"Error during connection closure: {e}")



connection_alive=True

def signal_handler(sig, frame):
    global connection_alive
    print("\n received interrupt signal,closing connection")


signal.signal(signal.SIGINT,signal_handler)



def receive_data(s, lock):
    """Function to receive data from the server in a separate thread."""
    global connection_alive
    while connection_alive:
        try:
            response = s.recv(409600)  # Buffer size increased for more data
            if response:
                with lock:  # Acquire the lock to ensure thread-safe printing
                    print(f"\nServer response:\n{response.decode('utf-8')}\nshell> ", end="")
            else:
                print("\nServer closed the connection.")
                connection_alive = False
                break
        except socket.error as e:
            print(f"Socket error while receiving data: {e}")
            connection_alive = False
            break
        except Exception as e:
            print(f"Error while receiving data: {e}")
            connection_alive = False
            break



def display_output(s):
    """Function to display output from the server."""
    global connection_alive
    while connection_alive:
        try:
            response = s.recv(4096)  # Increase the buffer size to receive more data
            if response:
                print(f"Server response: {response.decode('utf-8')}")
            else:
                print("Server closed the connection.")
                connection_alive = False
                break
        except socket.error as e:
            print(f"Socket error while receiving data: {e}")
            connection_alive = False
            break
        except Exception as e:
            print(f"Error while receiving data: {e}")
            connection_alive = False
            break


def main():
    # argument parser
    parser = argparse.ArgumentParser(description="Network utility to retrieve IP address and port information, convert domain to IP, IP to domain, or perform whois lookup")

    # Mutually exclusive group: either domain or IP address must be provided
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Convert domain name to IP address")
    group.add_argument("-i", "--ip", help="Convert IP address to domain name")
    group.add_argument("-H", "--hostname", help="used to connect to server")

    
    parser.add_argument("-P", "--port", type=int, help="The port number associated with the service (e.g., 80).")
    parser.add_argument("-W", "--whois", action="store_true", help="Perform whois lookup for the provided domain or IP")
   
    args = parser.parse_args()

    if args.whois:
        value = args.domain or args.ip or args.hostname
        if value:
            res = whois_lookup(value)
            print(f"Whois lookup for {value}:")
            print(res)
        else:
            print("No domain, IP, or hostname provided for whois lookup.")
    
    if args.domain:
        ip = domain_to_ip(args.domain)
        if ip:
            print(f"Domain: {args.domain}, IP address: {ip}")
        else:
            print(f"No IP address found for domain: {args.domain}")

    if args.ip:
        domain = ip_to_domain(args.ip)
        if domain:
            print(f"IP address: {args.ip}, Domain: {domain}")
        else:
            print(f"No domain found for IP address: {args.ip}")

    if args.hostname and args.port:
        
        # while True:
        get_address_info(args.hostname, args.port)
        connect_to_server(args.hostname, args.port)
    # if args.hostname and args.port and args.network_information:
    #     get_address_info(args.hostname, args.port)
        
if __name__ == "__main__":
    main()
