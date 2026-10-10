import socket
import os

def main():
    # Determine host IP based on operating system
    host = socket.gethostbyname(socket.gethostname())
    
    print("=" * 50)
    print("CodeAlpha Cybersecurity Internship - Basic Network Sniffer")
    print(f"Binding to Host: {host}")
    print("Starting packet capture... (Press Ctrl+C to stop)")
    print("=" * 50)

    # Create a raw socket and bind it to the public interface
    # Note: Requires Administrator / Root privileges to run
    if os.name == 'nt':
        # Windows specific socket configuration for raw packets
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((host, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        # Linux / Mac socket configuration
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    try:
        while True:
            # Capture packet data (65535 bytes buffer)
            raw_data, addr = s.recvfrom(65535)
            
            # Extract basic IP header fields from raw bytes
            # IP header starts at byte 0, Source IP at index 12-16, Dest IP at 16-20
            ip_header = raw_data[0:20]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            protocol = ip_header[9]

            print(f"\n[+] Packet Captured:")
            print(f"    Source IP      : {src_ip}")
            print(f"    Destination IP : {dst_ip}")
            print(f"    Protocol ID    : {protocol}")

    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")
        if os.name == 'nt':
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()