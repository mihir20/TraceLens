from scapy.all import *
from scapy.layers.inet import TCP
import openai

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

def generate_report():
    prompt = f"""
Create a comprehensive Markdown report analyzing the following list of accessed domains: {unique_domains}. 
The report should include:

1. **Header Section**
   - Title: "Domain Access Report"

2. **Summary Section**
   - Total unique domains accessed
   - Total requests made (if available)
   - Most frequently accessed domains (top 5)

3. **Category Analysis**
   - Group domains into logical categories (e.g., Social Media, News, Cloud Services, E-commerce)
   - Include category-specific counts and percentages
   - List example domains for each category

4. **Domain Details**
   - Table of all domains with columns:
     1. Domain
     2. Category
     3. Access Count (if available)

5. **Security/Privacy Highlights**
   - Flag any suspicious domains (e.g., known trackers, malware domains)
   - Highlight privacy-focused domains (HTTPS, privacy-first services)

6. **Pattern Analysis**
   - Notable access patterns (e.g., repeated access to specific domains)

7. **Footer**
   - Data source information
   - Disclaimer about report limitations

Format the report using proper Markdown syntax with headers, tables, and bullet points. Include visual elements like horizontal rules between sections.
"""

    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system",
                 "content": "You are a cyber security analyst and report generator"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=1000
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"OpenAI API error: {str(e)}")
        exit(1)


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
    # Generate and print the report
    openai.api_key = os.getenv("OPENAI_API_KEY")
    if not openai.api_key:
        print("ERROR: OPENAI_API_KEY environment variable not found")
        return
    report = generate_report()
    print("\n=== Generated Report ===")
    print(report)


if __name__ == '__main__':
    main()