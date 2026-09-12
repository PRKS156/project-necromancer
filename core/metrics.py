import threading
import time
import psutil

class MetricsCollector(threading.Thread):
    def __init__(self, buffer_manager, interval=1):
        """
        Initializes the background environment telemetry sampler thread.
        interval defines how many seconds to wait between metric captures.
        """
        super().__init__()
        self.buffer_manager = buffer_manager
        self.interval = interval
        self.daemon = True # Closes the thread cleanly when the main script stops
        self.running = False

    def run(self):
        """Main execution engine tracking hardware and interface performance loops."""
        self.running = True
        # Initialize network I/O counters as a starting baseline
        old_io = psutil.net_io_counters()
        
        while self.running:
            time.sleep(self.interval)
            new_io = psutil.net_io_counters()
            
            # Compute raw data delta variations into accurate megabytes per second (MB/s)
            bytes_sent = (new_io.bytes_sent - old_io.bytes_sent) / (1024 * 1024)
            bytes_recv = (new_io.bytes_recv - old_io.bytes_recv) / (1024 * 1024)
            old_io = new_io
            
            # Pack current telemetry vectors
            metrics = {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "mb_sent_per_sec": round(bytes_sent, 2),
                "mb_recv_per_sec": round(bytes_recv, 2)
            }
            # Commit attributes straight to our volatile RAM array
            self.buffer_manager.log_metric(metrics)

    def stop(self):
        """Signals the telemetry interval sampler to stop cleanly."""
        self.running = False
