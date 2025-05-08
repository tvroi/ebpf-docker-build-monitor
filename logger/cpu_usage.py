from bcc import BPF
import time
import psutil
import json
from helper.kafka import KafkaHelper

class CPULogger:
    def __init__(self, stop_event, hostname):
        self.bpf = BPF(src_file="bpf_programs/cpu_usage.c")
        self.cpu_count = psutil.cpu_count()
        self.prev_task_time = {}
        self.kafka = KafkaHelper()
        self.topic = "log-cpu-usage"
        self.stop_event = stop_event
        self.hostname = hostname

    def start(self):
        print("CPULogger started...")
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
                current_task_time = {}
                processes = {}

                for k, v in self.bpf["task_info"].items():
                    pid = k.value
                    cpu_ns = v.time_ns
                    comm = v.comm.decode('utf-8', 'replace')
                    current_task_time[pid] = (comm, cpu_ns)
                    
                process_count = 0
                for pid, (comm, cpu_ns) in current_task_time.items():
                    delta_ns = cpu_ns - self.prev_task_time.get(pid, (comm, 0))[1]
                    self.prev_task_time[pid] = (comm, cpu_ns)

                    cpu_percent = (delta_ns / (1e9 * self.cpu_count)) * 100
                    if cpu_percent > 0.1:
                        processes[process_count] = {"pid": pid, "comm": comm, "cpu_usage": round(cpu_percent, 2)}
                        process_count += 1

                if processes:
                    payload = {"hostname":self.hostname, 
                               "type": "cpu_usage", 
                               "timestamp": int(time.time()), 
                               "data": processes}
                    self.kafka.send(self.topic, payload)

        except KeyboardInterrupt:
            pass

        print("CPULogger stopped.")
