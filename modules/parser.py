import scapy.all as scapy
from scapy.layers import http
from typing import Dict, Any

def parse_packet(packet: scapy.Packet, verbose: bool = False) -> Dict[str, Any]:
    """Paketi təhlükəsiz şəkildə analiz edib normalizasiya olunmuş lüğət qaytarır."""
    result: Dict[str, Any] = {
        "proto": "Unknown",
        "src": "N/A",
        "dst": "N/A",
        "info": "",
        "verbose_details": {}
    }

    try:
        # ARP Protokolu
        if packet.haslayer(scapy.ARP):
            arp = packet[scapy.ARP]
            result["proto"] = "ARP"
            result["src"] = arp.psrc
            result["dst"] = arp.pdst
            if arp.op == 1:
                result["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:
                result["info"] = f"{arp.psrc} is at {arp.hwsrc}"
            return result

        # IPv4 Protokolu
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = getattr(ip, "ttl", "N/A")
            length = len(packet)

            # ICMP Protokolu
            if packet.haslayer(scapy.ICMP):
                icmp = packet[scapy.ICMP]
                result["proto"] = "ICMP"
                result["src"] = src_ip
                result["dst"] = dst_ip
                result["info"] = f"Type: {icmp.type} Code: {icmp.code}"
                result["verbose_details"] = {"TTL": ttl, "Length": length}
                return result

            # TCP Protokolu
            elif packet.haslayer(scapy.TCP):
                tcp = packet[scapy.TCP]
                result["proto"] = "TCP"
                result["src"] = f"{src_ip}:{tcp.sport}"
                result["dst"] = f"{dst_ip}:{tcp.dport}"
                
                flags = tcp.flags
                result["info"] = f"Flags: {flags}"
                result["verbose_details"] = {
                    "TTL": ttl,
                    "SEQ": getattr(tcp, "seq", "N/A"),
                    "ACK": getattr(tcp, "ack", "N/A"),
                    "Window": getattr(tcp, "window", "N/A"),
                    "Length": length
                }

                # HTTPS / TLS Yoxlaması (Port 443 və ya TLS qatı)
                if tcp.dport == 443 or tcp.sport == 443 or packet.haslayer(scapy.TLS):
                    result["proto"] = "HTTPS/TLS"
                    result["info"] = "Encrypted TLS Traffic"
                    return result

                # HTTP Yoxlaması (Qat əsaslı və ya portdan asılı olmayaraq)
                if packet.haslayer(http.HTTPRequest):
                    result["proto"] = "HTTP"
                    try:
                        req = packet[http.HTTPRequest]
                        method = req.Method.decode('utf-8', errors='ignore') if req.Method else "UNKNOWN"
                        host = req.Host.decode('utf-8', errors='ignore') if req.Host else ""
                        path = req.Path.decode('utf-8', errors='ignore') if req.Path else ""
                        result["info"] = f"HTTP {method} {host}{path}"
                    except Exception:
                        result["info"] = "HTTP Request (Malformed)"
                elif packet.haslayer(http.HTTPResponse):
                    result["proto"] = "HTTP"
                    try:
                        res = packet[http.HTTPResponse]
                        status = res.Status.decode('utf-8', errors='ignore') if res.Status else ""
                        reason = res.Reason.decode('utf-8', errors='ignore') if res.Reason else ""
                        result["info"] = f"HTTP Response {status} {reason}"
                    except Exception:
                        result["info"] = "HTTP Response (Malformed)"

                return result

            # UDP Protokolu
            elif packet.haslayer(scapy.UDP):
                udp = packet[scapy.UDP]
                result["proto"] = "UDP"
                result["src"] = f"{src_ip}:{udp.sport}"
                result["dst"] = f"{dst_ip}:{udp.dport}"
                result["info"] = f"Length: {length}"
                result["verbose_details"] = {"TTL": ttl, "Length": length}

                # DNS Yoxlaması
                if packet.haslayer(scapy.DNS):
                    dns = packet[scapy.DNS]
                    # DNS Query (qr == 0)
                    if dns.qr == 0 and dns.qd:
                        result["proto"] = "DNS"
                        try:
                            if dns.qd.qname:
                                qname = dns.qd.qname.decode('utf-8', errors='ignore')
                                result["info"] = f"DNS Query: {qname}"
                        except Exception:
                            result["info"] = "DNS Query (Malformed)"
                    # DNS Response (qr == 1)
                    elif dns.qr == 1:
                        result["proto"] = "DNS"
                        result["info"] = "DNS Response"

                return result

    except Exception:
        result["proto"] = "Unknown"
        result["info"] = "Malformed Packet"

    return result
