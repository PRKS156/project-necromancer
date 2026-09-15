import collections
import json
import os
import threading
from datetime import datetime

class NetworkBuffer:
    def __init__(self, max_items=5000):
        """
        Initializes the in-memory circular queues using thread-safe collections.deque.
        max_items limits how many recent records are held in memory before older ones roll off.
        """
        self.packet_buffer = collections.deque(maxlen=max_items)
        self.metric_buffer = collections.deque(maxlen=max_items)
        self._lock = threading.Lock()

    def log_packet(self, packet_summary):
        """Appends a new packet snapshot into the volatile RAM queue with a millisecond timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        packet_summary["timestamp"] = timestamp
        with self._lock:
            self.packet_buffer.append(packet_summary)

    def log_metric(self, metrics):
        """Appends local host performance metrics into the volatile RAM queue."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        metrics["timestamp"] = timestamp
        with self._lock:
            self.metric_buffer.append(metrics)

    def get_recent_packets(self, count):
        """Thread-safe snapshot of the most recent packets."""
        with self._lock:
            return list(self.packet_buffer)[-count:]

    def get_recent_metrics(self, count):
        """Thread-safe snapshot of the most recent metrics."""
        with self._lock:
            return list(self.metric_buffer)[-count:]

    def freeze_and_flush(self, output_dir="data"):
        """
        Triggered exclusively on network crash events. 
        Instantly freezes the live arrays and dumps the precise memory timeline into a physical JSON file.
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"crash_dump_{timestamp_str}.json")
        
        with self._lock:
            crash_data = {
                "metadata": {
                    "crash_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total_packets_captured": len(self.packet_buffer),
                    "total_metrics_captured": len(self.metric_buffer)
                },
                "packet_history": list(self.packet_buffer),
                "system_metrics_history": list(self.metric_buffer)
            }
        
        with open(filepath, "w") as f:
            json.dump(crash_data, f, indent=4)
            
        return filepath
