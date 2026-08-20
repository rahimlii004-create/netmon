import scapy.all as scapy
from modules.parser import parse_packet
from modules.statistics import TrafficStatistics
from modules.detection import PortScanDetector

def start_capture(interface: str, bpf_filter: str, verbose: bool, scan_threshold: int, scan_window: int, output_file: str, callback_ui):
    stats = TrafficStatistics()
    detector = PortScanDetector(threshold=scan_threshold, time_window=scan_window)
    
    # Əgər output faylı göstərilibsə, faylı açırıq
    f_out = None
    if output_file:
        try:
            f_out = open(output_file, "a", encoding="utf-8")
        except Exception as e:
            print(f"[-] Fayl açılarkən xəta baş verdi: {e}")

    def packet_handler(packet):
        parsed = parse_packet(packet, verbose=verbose)
        proto = parsed["proto"]
        stats.update(proto)

        alert = None
        if proto == "TCP" and ":" in parsed["src"] and ":" in parsed["dst"]:
            try:
                src_ip = parsed["src"].rsplit(":", 1)[0]
                dst_ip = parsed["dst"].rsplit(":", 1)[0]
                alert = detector.check(packet, src_ip, dst_ip)
            except Exception:
                pass

        # Əgər fayl yazılması aktivdirsə, paketi fayla yazırıq
        if f_out:
            import time
            current_time = time.strftime("%Y-%m-%d %H:%M:%S")
            log_line = f"[{current_time}] PROTOCOL: {proto} | SRC: {parsed['src']} | DST: {parsed['dst']} | INFO: {parsed['info']}\n"
            f_out.write(log_line)
            f_out.flush() # Dərhal fayla yazılmasını təmin edir

        callback_ui(parsed, stats.get_summary(), alert)

    try:
        scapy.sniff(
            iface=interface,
            filter=bpf_filter,
            prn=packet_handler,
            store=False
        )
    except PermissionError:
        raise PermissionError("Error: Root / Administrator privileges required to capture packets.")
    except Exception as e:
        error_msg = str(e).lower()
        if "network is down" in error_msg or "no such device" in error_msg:
            raise ValueError(f"Invalid network interface: '{interface}'")
        elif "syntax error" in error_msg or "expression" in error_msg:
            raise ValueError(f"Invalid BPF filter expression: '{bpf_filter}'")
        else:
            raise RuntimeError(f"Capture error: {str(e)}")
    finally:
        if f_out:
            f_out.close()
