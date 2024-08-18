import socket
from typing import List
from tabulate import tabulate
import requests
import ssl
import concurrent.futures
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext


class PortScanner:
    def __init__(self, target_ip: str, start_port: int, end_port: int):
        self.target_ip = target_ip
        self.start_port = min(start_port, end_port)
        self.end_port = max(start_port, end_port)

    def scan_ports(self) -> List[int]:
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.is_port_open, port) for port in range(self.start_port, self.end_port + 1)]
            open_ports = [future.result() for future in concurrent.futures.as_completed(futures) if future.result()]
        return open_ports

    def is_port_open(self, port: int) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((self.target_ip, port))
            return port if result == 0 else 0


class ServiceDetector:
    def __init__(self, target_ip: str, open_ports: List[int]):
        self.target_ip = target_ip
        self.open_ports = open_ports

    def detect_services(self) -> dict:
        services = {}
        for port in self.open_ports:
            service_info = self.get_service_info(port)
            services[port] = service_info
        return services

    def get_service_info(self, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((self.target_ip, port))
                banner = s.recv(1024).decode('utf-8').strip()
                return banner
        except socket.error:
            return "Unable to retrieve service information"
        except UnicodeDecodeError:
            return "Unable to decode service information"


class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Enumeration Tool")

        # Main Frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Menu Bar
        menubar = tk.Menu(root)
        root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.exit_application)

        # Input Frame
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding="10")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))

        # Entry for user input (IP address or URL)
        self.input_label = ttk.Label(input_frame, text="Enter an IP address or URL:")
        self.input_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.input_entry = ttk.Entry(input_frame, width=30)
        self.input_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Entry for starting port
        self.start_port_label = ttk.Label(input_frame, text="Enter the starting port:")
        self.start_port_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.start_port_entry = ttk.Entry(input_frame, width=10)
        self.start_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Entry for ending port
        self.end_port_label = ttk.Label(input_frame, text="Enter the ending port:")
        self.end_port_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.end_port_entry = ttk.Entry(input_frame, width=10)
        self.end_port_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        # Button to start scanning
        self.scan_button = ttk.Button(input_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Result Frame
        result_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        result_frame.grid(row=1, column=0, pady=10, sticky=(tk.W, tk.E))

        # Text area to display results
        self.result_text = scrolledtext.ScrolledText(result_frame, width=80, height=20)
        self.result_text.grid(row=0, column=0, padx=5, pady=5)

    def exit_application(self):
        self.root.quit()

    def start_scan(self):
        ip_or_url = self.input_entry.get()
        start_port = int(self.start_port_entry.get())
        end_port = int(self.end_port_entry.get())

        self.result_text.insert(tk.END, f"Scanning {ip_or_url} from port {start_port} to {end_port}...\n")

        port_scanner = PortScanner(ip_or_url, start_port, end_port)
        open_ports = port_scanner.scan_ports()
        self.result_text.insert(tk.END, f"Open ports: {open_ports}\n")

        service_detector = ServiceDetector(ip_or_url, open_ports)
        services = service_detector.detect_services()
        self.result_text.insert(tk.END, f"Services: {services}\n")

        # Clear entries
        self.input_entry.delete(0, tk.END)
        self.start_port_entry.delete(0, tk.END)
        self.end_port_entry.delete(0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
