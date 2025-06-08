import threading
import signal
import os
from bcc import BPF
import json
import time
from helper.kafka import KafkaHelper

class FileLogger:
    def __init__(self, stop_event, hostname):
        self.bpf = BPF(src_file="bpf_programs/file_logger.c")
        self.kafka = KafkaHelper()
        self.topic = "log-file-operation"
        self.stop_event = stop_event
        self.hostname = hostname
        
    def lost_event_callback(self, lost):
        print(f"Lost {lost} events")
        
    def print_file_event(self, cpu, data, size):
        event = self.bpf["file_events"].event(data)
        payload = {
            "hostname":self.hostname,
            "type": "file",
            "timestamp": int(time.time()),
            "data": {
                "pid": event.pid,
                "comm": event.comm.decode('utf-8', 'replace'),
                "operations": event.operation.decode('utf-8', 'replace'),
                "path": event.fname.decode('utf-8', 'replace')
            }
        }
        self.kafka.send(self.topic, payload)

    def start(self):
        self.bpf["file_events"].open_perf_buffer(self.print_file_event, lost_cb=self.lost_event_callback, page_cnt=2048)
        print("FileLogger started...")

        while not self.stop_event.is_set():
            self.bpf.perf_buffer_poll()  # Tunggu event, bisa dihentikan

        self.bpf.cleanup()
        print("FileLogger stopped.")
