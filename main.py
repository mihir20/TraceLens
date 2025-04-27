from scapy.all import *
import argparse

# Global set to store unique domains
unique_domains = set()


def process_http_packet(packet):
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            tcp = packet[TCP]
            if tcp.dport == 80:  # HTTP
                payload = bytes(tcp.payload).decode('utf-8', errors='ignore')
                if 'GET ' in payload:
                    headers = payload.split('\r\n')
                    host = ''
                    path = ''
                    for header in headers:
                        if header.startswith('GET '):
                            path = header.split(' ')[1]
                        elif header.startswith('Host: '):
                            host = header.split(' ')[1].strip()
                    if host and path:
                        url = f'http://{host}{path}'
                        print(f'[HTTP URL] {url}')
                        # Add HTTP host to unique domains
                        unique_domains.add(host)
    except Exception as e:
        pass


def process_https_packet(packet):
    try:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == 443 and len(tcp.payload) > 0:
                data = bytes(tcp.payload)
                if data[0] == 0x16:  # TLS Handshake
                    if len(data) < 5:
                        return
                    handshake_type = data[5]
                    if handshake_type == 0x01:  # ClientHello
                        offset = 5 + 1 + 3 + 2 + 32
                        if len(data) < offset + 1:
                            return
                        session_id_length = data[offset]
                        offset += 1 + session_id_length
                        if len(data) < offset + 2:
                            return
                        cipher_suites_length = int.from_bytes(data[offset:offset + 2], 'big')
                        offset += 2 + cipher_suites_length
                        if len(data) < offset + 1:
                            return
                        compression_length = data[offset]
                        offset += 1 + compression_length
                        if len(data) < offset + 2:
                            return
                        extensions_length = int.from_bytes(data[offset:offset + 2], 'big')
                        offset += 2
                        extensions_end = offset + extensions_length
                        while offset < extensions_end:
                            if len(data) < offset + 4:
                                break
                            ext_type = int.from_bytes(data[offset:offset + 2], 'big')
                            ext_len = int.from_bytes(data[offset + 2:offset + 4], 'big')
                            if ext_type == 0x00:  # SNI extension
                                sni_data = data[offset + 4: offset + 4 + ext_len]
                                list_len = int.from_bytes(sni_data[:2], 'big')
                                sni_offset = 2
                                while sni_offset < list_len + 2:
                                    if len(sni_data) < sni_offset + 3:
                                        break
                                    name_type = sni_data[sni_offset]
                                    name_len = int.from_bytes(sni_data[sni_offset + 1:sni_offset + 3], 'big')
                                    if name_type == 0x00:
                                        host = sni_data[sni_offset + 3:sni_offset + 3 + name_len].decode('utf-8')
                                        print(f'[HTTPS Domain] {host}')
                                        # Add HTTPS domain to unique set
                                        unique_domains.add(host)
                                        break
                                    sni_offset += 3 + name_len
                                break
                            offset += 4 + ext_len
    except Exception as e:
        pass


def packet_handler(packet):
    process_http_packet(packet)
    process_https_packet(packet)


def main():
    # interfaces = get_if_list()
    interfaces = ['en0']
    print(f"Starting capture on ALL interfaces: {', '.join(interfaces)}...")

    try:
        sniff(iface=interfaces, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user")

    # Print unique domains when exiting
    print("\n=== Unique Domains Accessed ===")
    for domain in sorted(unique_domains):
        print(domain)
    print(f"Total: {len(unique_domains)} domains")


if __name__ == '__main__':
    main()