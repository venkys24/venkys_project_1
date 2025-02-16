import socket
import concurrent.futures

def scan_port(ip, port):
    """Check if a port is open on the given IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[OPEN] Port {port} is open on {ip}")
                return port
            return None
    except Exception:
        return None

def scan_ports(ip):
    """Scan all ports (1-65535) on a given IP address."""
    open_ports = []
    try:
        print(f"Scanning host: {ip}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in range(1, 65536)}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        return open_ports
    except Exception as e:
        print(f"Error scanning ports: {e}")
        return []

def main():
    """Terminal-based port scanner."""
    ip_address = input("Enter the IP address of the device: ")
    open_ports = scan_ports(ip_address)
    if open_ports:
        print(f"[WARNING] Open ports detected on {ip_address}: {open_ports}")
    else:
        print("No open ports detected. System secure.")

if __name__ == "__main__":
    main()
