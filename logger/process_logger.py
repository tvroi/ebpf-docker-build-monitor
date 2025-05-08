from bcc import BPF
import ctypes as ct
import time
import json
from helper.kafka import KafkaHelper

class ProcessLogger:
    class Data(ct.Structure):
        _fields_ = [
            ("pid", ct.c_uint),
            ("ppid", ct.c_uint),
            ("comm", ct.c_char * 16),
            ("event", ct.c_char * 32)
        ]

    def __init__(self, stop_event, hostname):
        self.bpf = BPF(src_file="bpf_programs/process_logger.c")
        self.kafka = KafkaHelper()
        self.topic = "log-process"
        self.stop_event = stop_event
        self.hostname = hostname

    def print_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(self.Data)).contents
        payload = {
            "hostname":self.hostname,
            "type": "process",
            "timestamp": int(time.time()),
            "data": {
                "pid": event.pid,
                "ppid": event.ppid,
                "comm": event.comm.decode('utf-8', 'replace'),
                "event": event.event.decode('utf-8', 'replace')
            }
        }
        self.kafka.send(self.topic, payload)

    def start(self):
        print("Process started...")
        self.bpf["events"].open_perf_buffer(self.print_event)
        
        while not self.stop_event.is_set():
            self.bpf.perf_buffer_poll()
