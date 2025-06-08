from bcc import BPF
import socket
import time
from struct import pack
import json
from helper.kafka import KafkaHelper

class NetLogger:
    def __init__(self, stop_event, hostname):
        self.bpf = BPF(src_file="bpf_programs/net_logger.c")
        self.kafka = KafkaHelper()
        self.topic = "log-network"
        self.stop_event = stop_event
        self.IPPROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
        self.hostname = hostname

    def inet_ntoa(self, addr):
        return socket.inet_ntoa(pack("I", addr))

    def print_event(self, cpu, data, size):
        event = self.bpf["conn_events"].event(data)
        payload = {
            "hostname":self.hostname,
            "type": "network",
            "timestamp": int(time.time()),
            "data": {
                "pid": event.pid_tgid >> 32,
                "comm": event.comm.decode('utf-8', errors='replace'),
                "protocol": self.IPPROTO_MAP.get(event.proto, str(event.proto)),
                "saddr": self.inet_ntoa(event.saddr),
                "daddr": self.inet_ntoa(event.daddr),
                "sport": str(event.sport) if event.sport > 0 else "-",
                "dport": str(event.dport) if event.dport > 0 else "-",
                "length": str(event.len) if event.len > 0 else "-"
            }
        }
        # self.kafka.send(self.topic, payload)

    def start(self):
        self.bpf["conn_events"].open_perf_buffer(self.print_event)
        print("NetLogger started...")

        while not self.stop_event.is_set():
            self.bpf.perf_buffer_poll()

        print("NetLogger stopped.")
