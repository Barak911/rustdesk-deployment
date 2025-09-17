#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
import json
import subprocess

PORT = 8080  # Default port, can be modified as needed
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def do_GET(self):
        global os
        print(f"Request: {self.path}")

        # Test endpoint
        if self.path == '/test':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Web server is working"}).encode())
            return

        # Historical metrics endpoint
        if self.path == '/historical-metrics':
            try:
                import csv
                import os
                from datetime import datetime, timedelta

                # Read today's metrics file
                metrics_file = f"/opt/rustdesk/logs/metrics-{datetime.now().strftime('%Y%m%d')}.csv"
                historical_data = []

                if os.path.exists(metrics_file):
                    with open(metrics_file, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            try:
                                historical_data.append({
                                    'timestamp': int(row['timestamp']),
                                    'cpu_usage': float(row['cpu_usage']),
                                    'memory_usage': float(row['memory_usage']),
                                    'disk_usage': float(row['disk_usage']),
                                    'active_connections': int(row['active_connections']),
                                    'connectivity_score': float(row['connectivity_score']),
                                    'error_count': int(row['error_count'])
                                })
                            except (ValueError, KeyError):
                                continue

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(historical_data[-50:]).encode())  # Last 50 points
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

        # Refresh endpoint - triggers monitoring script
        if self.path == '/refresh':
            try:
                # Run the monitoring script to update status.json
                result = subprocess.run(['/opt/rustdesk/monitoring/monitor.sh'],
                                      capture_output=True, text=True, timeout=30)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Status refreshed", "success": True}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": str(e), "success": False}).encode())
            return

        if self.path == '/status.json':
            status_file = os.path.join(DIRECTORY, 'status.json')
            if os.path.exists(status_file):
                print(f"Status file exists: {status_file}")
                with open(status_file, 'r') as f:
                    content = f.read()
                    print(f"Status file content: {content[:200]}...")
            else:
                print(f"Status file not found: {status_file}")
                # Create a test status.json if it doesn't exist
                test_status = {
                    "timestamp": "2025-07-20T10:50:09Z",
                    "cpu_usage": 0.0,
                    "memory_usage": 0.0,
                    "disk_usage": 0,
                    "rustdesk_status": "UNKNOWN",
                    "cpu_threshold": 80,
                    "memory_threshold": 85,
                    "disk_threshold": 90,
                    "overall_status": "UNKNOWN",
                    "backup_status": "IDLE",
                    "service_health": "UNKNOWN"
                }
                with open(status_file, 'w') as f:
                    json.dump(test_status, f)
                print(f"Created test status file: {status_file}")
        super().do_GET()

if __name__ == "__main__":
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
        print(f"Server running at http://localhost:{PORT}")
        httpd.serve_forever()