import threading
import signal
from logger.cpu_usage import CPULogger
from logger.file_logger import FileLogger
from logger.net_logger import NetLogger
from logger.process_logger import ProcessLogger

HOSTNAME = "pc-1"

stop_event = threading.Event()

def handle_signal(sig, frame):
    print("\nReceived SIGINT, stopping all loggers...")
    stop_event.set()

signal.signal(signal.SIGINT, handle_signal)

loggers = [
    CPULogger(stop_event, HOSTNAME),
    FileLogger(stop_event, HOSTNAME),
    NetLogger(stop_event, HOSTNAME),
    ProcessLogger(stop_event, HOSTNAME),
]

threads = []

for logger in loggers:
    thread = threading.Thread(target=logger.start)
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()

print("All loggers stopped.")