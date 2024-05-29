import os
import json
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading

from rtspBrute import RtspBrute
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


if __name__ == '__main__':
    # Iniciar un hilo para actualizar los datos cada 10 segundos
    threading.Thread(target=actualizar_datos, daemon=True).start()

    # Iniciar el servidor HTTP en un hilo separado
    server_thread = threading.Thread(target=start_http_server)
    server_thread.start()

    # Cargar datos desde el archivo JSON
    with open('datos.json', 'r') as file:
        data = json.load(file)

    # Filtrar las entradas para obtener solo las que usan el puerto 554
    targets = [(entry['IP'], 554) for entry in data if entry['Puerto'] == 554]

    # Iniciar RtspBrute con las direcciones IP y puertos cargados desde el archivo JSON
    brute = RtspBrute(targets=targets, dictionary_file="diccionario.txt")
    brute.run()
