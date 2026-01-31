#!/usr/bin/env python3
import os
import socket
from http.server import SimpleHTTPRequestHandler, HTTPServer

FOLDER_NAME = 'dist'
PORT = 8000

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def run_server():
    if not os.path.exists(FOLDER_NAME):
        print(f"Lỗi: Không tìm thấy thư mục '{FOLDER_NAME}'")
        return

    os.chdir(FOLDER_NAME)
    
    ip_address = get_local_ip()
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)

    print(f"Server đang chạy: http://{ip_address}:{PORT}/")
    print(f"Lệnh tải: wget http://{ip_address}:{PORT}/<ten_file>")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    run_server()
