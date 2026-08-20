import time
from collections import defaultdict, deque

class PortScanDetector:
    """Yalnız TCP SYN paketlərinə əsaslanan vaxt pəncərəli port-skan detektoru."""
    def __init__(self, threshold: int = 10, time_window: int = 5):
        self.threshold = threshold
        self.time_window = time_window
        # { src_ip: { dst_ip: deque([(port, timestamp), ...]) } }
        self.activity = defaultdict(lambda: defaultdict(deque))
        self.alerted_pairs = set()

    def check(self, packet, src_ip: str, dst_ip: str) -> str | None:
        if not packet.haslayer("TCP") or not src_ip or not dst_ip:
            return None

        tcp = packet["TCP"]
        flags = tcp.flags
        
        # Yalnız saf SYN paketlərini yoxlayırıq (SYN açıqdır, ACK yoxdur -> flags == 'S' və ya 0x02)
        if flags != "S" and flags != 2:
            return None

        dst_port = tcp.dport
        current_time = time.time()
        
        port_queue = self.activity[src_ip][dst_ip]
        
        # Köhnəlmiş (time_window xaricində olan) qeydləri təmizləyirik
        while port_queue and (current_time - port_queue[0][1] > self.time_window):
            port_queue.popleft()

        # Yeni portu əlavə edirik (əgər həmin port bu pəncərədə hələ əlavə edilməyibsə)
        existing_ports = [p for p, t in port_queue]
        if dst_port not in existing_ports:
            port_queue.append((dst_port, current_time))

        # Unikal portların sayını yoxlayırıq
        unique_ports = {p for p, t in port_queue}
        pair_key = (src_ip, dst_ip)

        if len(unique_ports) >= self.threshold:
            if pair_key not in self.alerted_pairs:
                self.alerted_pairs.add(pair_key)
                ports_list = sorted(list(unique_ports))
                ports_str = ",".join(map(str, ports_list[:10]))
                if len(ports_list) > 10:
                    ports_str += ",..."
                return f"[!] Possible TCP Port Scan\nSource: {src_ip}\nTarget: {dst_ip}\nPorts: {ports_str}"
        else:
            # Pəncərə daxilində limitin altına düşərsə, xəbərdarlıq kilidini açırıq
            if pair_key in self.alerted_pairs:
                self.alerted_pairs.remove(pair_key)

        return None
