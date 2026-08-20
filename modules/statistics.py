class TrafficStatistics:
    """Trafik növlərini izləmək üçün sayğac sinfi."""
    def __init__(self):
        self.total = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.dns = 0
        self.http = 0
        self.arp = 0
        self.tls = 0

    def update(self, proto: str):
        self.total += 1
        if proto == "TCP":
            self.tcp += 1
        elif proto == "UDP":
            self.udp += 1
        elif proto == "ICMP":
            self.icmp += 1
        elif proto == "DNS":
            self.dns += 1
        elif proto == "HTTP":
            self.http += 1
        elif proto == "ARP":
            self.arp += 1
        elif proto == "HTTPS/TLS":
            self.tls += 1

    def get_summary(self) -> dict:
        return {
            "Total": self.total,
            "TCP": self.tcp,
            "UDP": self.udp,
            "ICMP": self.icmp,
            "DNS": self.dns,
            "HTTP": self.http,
            "ARP": self.arp,
            "HTTPS/TLS": self.tls
        }
