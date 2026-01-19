import socket
import threading
from datetime import datetime

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1000, max_threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    with self.lock:
                        self.open_ports.append(port)
                    print(f"✅ Port {port} ouvert")
        except Exception as e:
            pass
    
    def run_scan(self):
        print(f"🔍 Scan des ports {self.start_port}-{self.end_port} sur {self.target}")
        threads = []
        
        for port in range(self.start_port, self.end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limiter le nombre de threads simultanés
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()
                threads = []
        
        # Attendre les threads restants
        for t in threads:
            t.join()
        
        return sorted(self.open_ports)

# Test
if __name__ == "__main__":
    scanner = PortScanner("localhost", 1, 100)
    open_ports = scanner.run_scan()
    print(f"📊 Ports ouverts: {open_ports}")