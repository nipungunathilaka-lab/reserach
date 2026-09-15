import threading
import time
import os
import collections
from datetime import datetime
from scapy.all import sniff, TCP, IP, conf
from scapy.packet import Packet

# Configuration (simulating env variables)
NETWORK_MONITORING_ENABLED = os.getenv("NETWORK_MONITORING_ENABLED", "true").lower() == "true"
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "auto")
NETWORK_FLOW_TIMEOUT_SECONDS = int(os.getenv("NETWORK_FLOW_TIMEOUT_SECONDS", "120"))
NETWORK_MAX_TRACKED_FLOWS = int(os.getenv("NETWORK_MAX_TRACKED_FLOWS", "1000"))
NETWORK_PACKET_SEQUENCE_LIMIT = int(os.getenv("NETWORK_PACKET_SEQUENCE_LIMIT", "256"))
NETWORK_PCAP_ENABLED = os.getenv("NETWORK_PCAP_ENABLED", "true").lower() == "true"
NETWORK_PCAP_DIRECTORY = os.getenv("NETWORK_PCAP_DIRECTORY", "data/pcaps")

class FlowStats:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        
        self.start_time = time.time()
        self.last_seen = time.time()
        
        self.packet_count = 0
        self.total_bytes = 0
        self.incoming_packets = 0
        self.outgoing_packets = 0
        self.incoming_bytes = 0
        self.outgoing_bytes = 0
        
        self.packet_sizes = []
        self.packet_size_sequence = []
        
        # Timing
        self.interarrival_times = []
        
        # TCP Flags
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.ack_count = 0
        self.psh_count = 0
        
        # TCP Sequence tracking
        self.retransmission_count = 0
        self.out_of_order_count = 0
        self.sequence_gap_count = 0
        self.duplicate_ack_count = 0
        
        # We track expected sequences for each direction
        # direction 0: src->dst, direction 1: dst->src
        self.expected_seq = {0: 0, 1: 0}
        self.last_ack = {0: 0, 1: 0}
        self.dup_acks = {0: 0, 1: 0}
        
    def add_packet(self, pkt, is_incoming: bool, timestamp: float):
        self.packet_count += 1
        pkt_len = len(pkt)
        self.total_bytes += pkt_len
        
        if self.last_seen > 0 and self.packet_count > 1:
            self.interarrival_times.append(timestamp - self.last_seen)
        self.last_seen = timestamp
        
        self.packet_sizes.append(pkt_len)
        direction_sign = -1 if is_incoming else 1
        if len(self.packet_size_sequence) < NETWORK_PACKET_SEQUENCE_LIMIT:
            self.packet_size_sequence.append(direction_sign * pkt_len)
            
        if is_incoming:
            self.incoming_packets += 1
            self.incoming_bytes += pkt_len
            direction = 1
        else:
            self.outgoing_packets += 1
            self.outgoing_bytes += pkt_len
            direction = 0

        if TCP in pkt:
            tcp = pkt[TCP]
            flags = tcp.flags
            if 'S' in flags: self.syn_count += 1
            if 'F' in flags: self.fin_count += 1
            if 'R' in flags: self.rst_count += 1
            if 'A' in flags: self.ack_count += 1
            if 'P' in flags: self.psh_count += 1

            seq = tcp.seq
            ack = tcp.ack
            payload_len = len(tcp.payload)

            if payload_len > 0 or 'S' in flags or 'F' in flags:
                expected = self.expected_seq[direction]
                if expected != 0:
                    if seq < expected:
                        self.retransmission_count += 1
                    elif seq > expected:
                        self.sequence_gap_count += 1
                        self.out_of_order_count += 1
                
                # Advance expected seq
                new_expected = seq + payload_len
                if 'S' in flags or 'F' in flags:
                    new_expected += 1
                
                if new_expected > self.expected_seq[direction]:
                    self.expected_seq[direction] = new_expected

            if 'A' in flags:
                if ack == self.last_ack[direction] and payload_len == 0:
                    self.dup_acks[direction] += 1
                    if self.dup_acks[direction] >= 3:
                        self.duplicate_ack_count += 1
                else:
                    self.last_ack[direction] = ack
                    self.dup_acks[direction] = 0

    def get_summary(self):
        duration = self.last_seen - self.start_time
        import statistics
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "duration_ms": int(duration * 1000) if duration > 0 else 0,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "incoming_packets": self.incoming_packets,
            "outgoing_packets": self.outgoing_packets,
            "incoming_bytes": self.incoming_bytes,
            "outgoing_bytes": self.outgoing_bytes,
            "average_packet_size": statistics.mean(self.packet_sizes) if self.packet_sizes else 0,
            "minimum_packet_size": min(self.packet_sizes) if self.packet_sizes else 0,
            "maximum_packet_size": max(self.packet_sizes) if self.packet_sizes else 0,
            "packet_size_std_dev": statistics.stdev(self.packet_sizes) if len(self.packet_sizes) > 1 else 0,
            "packet_rate": self.packet_count / duration if duration > 0 else 0,
            "byte_rate": self.total_bytes / duration if duration > 0 else 0,
            "mean_interarrival_time": statistics.mean(self.interarrival_times) if self.interarrival_times else 0,
            "retransmissions": self.retransmission_count,
            "out_of_order": self.out_of_order_count,
            "sequence_gaps": self.sequence_gap_count,
            "duplicate_acks": self.duplicate_ack_count,
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "packet_size_sequence": self.packet_size_sequence
        }

class NetworkMonitorService:
    _thread = None
    _stop_event = threading.Event()
    _flows = {}
    _lock = threading.Lock()
    _status = "DISABLED"
    _interface = None
    _total_packets_processed = 0
    
    # Store packets for PCAP writing. Flow ID -> list of packets
    _pcap_buffers = collections.defaultdict(list)

    @classmethod
    def start(cls):
        if not NETWORK_MONITORING_ENABLED:
            cls._status = "DISABLED"
            return
            
        try:
            # Check libpcap availability (scapy loads it)
            if conf.use_pcap is False and not os.name == 'nt':
                print("WARNING: libpcap not fully available, falling back to raw sockets.")
            
            cls._interface = NETWORK_INTERFACE if NETWORK_INTERFACE != "auto" else conf.iface
            cls._status = "ACTIVE"
            
            cls._stop_event.clear()
            cls._thread = threading.Thread(target=cls._sniff_loop, daemon=True)
            cls._thread.start()
            print(f"NetworkMonitorService started on interface {cls._interface}")
            
            if NETWORK_PCAP_ENABLED:
                os.makedirs(NETWORK_PCAP_DIRECTORY, exist_ok=True)
                
        except PermissionError:
            cls._status = "PERMISSION_DENIED"
            print("ERROR: Permission denied starting packet capture. Need NET_RAW capabilities.")
        except Exception as e:
            cls._status = f"ERROR: {str(e)}"
            print(f"ERROR: Failed to start packet capture: {e}")

    @classmethod
    def stop(cls):
        cls._stop_event.set()
        if cls._thread:
            cls._thread.join(timeout=2)
        cls._status = "DISABLED"

    @classmethod
    def _sniff_loop(cls):
        def packet_handler(pkt):
            if cls._stop_event.is_set():
                return
            if IP in pkt and TCP in pkt:
                cls._process_packet(pkt)
                
        while not cls._stop_event.is_set():
            try:
                # Use a small timeout so we can check stop_event
                sniff(iface=cls._interface if cls._interface != "auto" else None,
                      prn=packet_handler, 
                      store=False, 
                      timeout=2,
                      filter="tcp")
                cls._cleanup_expired_flows()
            except Exception as e:
                print(f"Packet capture error: {e}")
                time.sleep(5)

    @classmethod
    def _get_flow_key(cls, ip1, port1, ip2, port2):
        if ip1 < ip2:
            return f"{ip1}:{port1}-{ip2}:{port2}"
        elif ip1 > ip2:
            return f"{ip2}:{port2}-{ip1}:{port1}"
        else:
            if port1 < port2:
                return f"{ip1}:{port1}-{ip2}:{port2}"
            else:
                return f"{ip2}:{port2}-{ip1}:{port1}"

    @classmethod
    def _process_packet(cls, pkt):
        ip = pkt[IP]
        tcp = pkt[TCP]
        
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport
        
        flow_key = cls._get_flow_key(src_ip, src_port, dst_ip, dst_port)
        timestamp = float(pkt.time)
        
        with cls._lock:
            cls._total_packets_processed += 1
            if flow_key not in cls._flows:
                if len(cls._flows) >= NETWORK_MAX_TRACKED_FLOWS:
                    # Don't track new flows if we're at the limit
                    return
                # Determine "client" based on common ports (assume server is port 8000 if FastAPI)
                # If neither is 8000, just use src_ip as "src"
                # Let's standardize: the initiator is the one sending SYN.
                # If we don't catch SYN, we just pick the first seen src as initiator.
                cls._flows[flow_key] = FlowStats(src_ip, dst_ip, src_port, dst_port)
                
            flow = cls._flows[flow_key]
            # Is incoming? True if the packet's destination is our server port (e.g. 8000)
            is_incoming = (dst_port == 8000)
            flow.add_packet(pkt, is_incoming, timestamp)
            
            if NETWORK_PCAP_ENABLED:
                cls._pcap_buffers[flow_key].append(pkt)
                # Bounded PCAP buffer
                if len(cls._pcap_buffers[flow_key]) > 5000:
                    cls._pcap_buffers[flow_key].pop(0)

    @classmethod
    def _cleanup_expired_flows(cls):
        now = time.time()
        with cls._lock:
            expired = [k for k, v in cls._flows.items() if now - v.last_seen > NETWORK_FLOW_TIMEOUT_SECONDS]
            for k in expired:
                del cls._flows[k]
                if k in cls._pcap_buffers:
                    del cls._pcap_buffers[k]

    @classmethod
    def get_flow_stats_by_client(cls, client_ip, client_port):
        with cls._lock:
            # Find the flow that matches the client IP and port
            for k, flow in cls._flows.items():
                if (flow.src_ip == client_ip and flow.src_port == client_port) or \
                   (flow.dst_ip == client_ip and flow.dst_port == client_port):
                    return flow.get_summary(), k
            return None, None

    @classmethod
    def save_pcap(cls, flow_key, transfer_id):
        if not NETWORK_PCAP_ENABLED or flow_key not in cls._pcap_buffers:
            return None
        from scapy.utils import wrpcap
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"network_capture_{transfer_id}_{timestamp}.pcap"
        filepath = os.path.join(NETWORK_PCAP_DIRECTORY, filename)
        with cls._lock:
            pkts = cls._pcap_buffers[flow_key]
            if pkts:
                wrpcap(filepath, pkts)
                return filepath
        return None

    @classmethod
    def get_status(cls):
        with cls._lock:
            return {
                "enabled": NETWORK_MONITORING_ENABLED,
                "capture_active": cls._status == "ACTIVE",
                "interface": str(cls._interface) if cls._interface else "unknown",
                "capture_engine": "libpcap",
                "monitoring_status": cls._status,
                "packet_count": cls._total_packets_processed,
                "active_flows": len(cls._flows)
            }
