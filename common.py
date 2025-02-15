import os
import time
import json
import threading
from PIL import Image
import pytesseract
import re



def extraer_texto_desde_imagen(ruta_imagen):
    try:
        return pytesseract.image_to_string(Image.open(ruta_imagen))
    except Exception as e:
        pass

def actualizar_datos():
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    ruta_capturas = "screenshot/"
    datos_filtrados = reparar_json_por_campos("datos.json")
    if not datos_filtrados:
        print("No se pudieron reparar los datos del archivo JSON. Operación abortada.")
        return

    archivos = os.listdir(ruta_capturas)
    for archivo in archivos:
        if archivo.endswith(".png"):
            try:
                ip, puerto = archivo.split('-')
                puerto = puerto.split('.')[0]

                for dato in datos_filtrados:
                    if dato["IP"] == ip and str(dato["Puerto"]) == puerto:
                        banner = dato.get("Banner", "")
                        servicio = dato.get("Servicio", "")
                        camara = buscar_palabra(banner, servicio)
                        dato["Camara"] = camara

                        if banner == "\u001b[31munknown\u001b[0m":
                            ruta_imagen = os.path.join(ruta_capturas, archivo)
                            if os.path.exists(ruta_imagen):
                                texto = extraer_texto_desde_imagen(ruta_imagen)
                                if texto:
                                    print(f"El banner para {dato['IP']}:{dato['Puerto']} fue reemplazado.")
                                    dato["Banner"] = texto
                            else:
                                print(f"La imagen {ruta_imagen} no existe.")
            except ValueError:
                print(f"El archivo {archivo} no tiene el formato esperado (IP-Puerto.png).")

    try:
        guardar_datos(datos_filtrados)
        print("Datos actualizados y guardados exitosamente.")
    except Exception as e:
        print(f"Error al guardar datos: {e}")


def cargar_datos():
    while True:
        try:
            with open("datos.json", "r", encoding="utf-8") as file:
                return json.load(file)
        except FileNotFoundError:
            return []
        except json.decoder.JSONDecodeError as e:
            print(f"Error al cargar datos: {e}. Reintentando en 2 segundos...")
            time.sleep(2)

def guardar_datos(datos):
    try:
        with open('datos.json', 'w') as file:
            json.dump(datos, file, indent=2)
        print("Datos guardados correctamente.")
        threading.Timer(1, actualizar_datos).start()
    except Exception as e:
        print(f"Error al guardar datos: {e}")

def restaurar_respaldo(file_path, backup_path="respaldo.json"):
    if os.path.exists(backup_path):
        try:
            with open(backup_path, 'r', encoding='utf-8') as respaldo:
                data = respaldo.read()
            with open(file_path, 'w', encoding='utf-8') as destino:
                destino.write(data)
            print(f"Respaldo restaurado desde {backup_path} a {file_path}.")
        except Exception as e:
            print(f"Error al restaurar el respaldo: {e}")
    else:
        print(f"Archivo de respaldo no encontrado: {backup_path}")

def reparar_json_por_campos(file_path):
    """Repara un archivo JSON asegurando que cada combinación de IP y Puerto sea única."""
    try:
        if not os.path.exists(file_path):
            print(f"El archivo {file_path} no existe.")
            restaurar_respaldo(file_path)
        
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        content = re.sub(r'[\x00-\x1F\x7F]', '', content).strip()

        try:
            datos_existentes = json.loads(content)
        except json.JSONDecodeError:
            print("Error al decodificar el JSON. Restaurando respaldo.")
            restaurar_respaldo(file_path)
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            try:
                datos_existentes = json.loads(content)
            except json.JSONDecodeError:
                print("Error persistente tras restaurar respaldo. Se usará lista vacía.")
                datos_existentes = []

        if not isinstance(datos_existentes, list):
            print("El contenido no es una lista. Restaurando respaldo.")
            restaurar_respaldo(file_path)
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            try:
                datos_existentes = json.loads(content)
            except json.JSONDecodeError:
                print("Error persistente tras restaurar respaldo. Se usará lista vacía.")
                datos_existentes = []
            if not isinstance(datos_existentes, list):
                datos_existentes = []

        objetos_validos = []
        for obj in datos_existentes:
            if isinstance(obj, dict) and all(k in obj for k in ["IP", "Puerto", "Servicio"]):
                objetos_validos.append(obj)

        combinaciones = {}
        for obj in objetos_validos:
            clave = (obj["IP"], obj["Puerto"])
            if clave not in combinaciones:
                combinaciones[clave] = obj
        objetos_finales = list(combinaciones.values())

        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(objetos_finales, file, ensure_ascii=False, indent=2)
        print(f"Archivo reparado en {file_path}. Total objetos válidos: {len(objetos_finales)}.")

    except Exception as e:
        print(f"Error al reparar el archivo JSON: {e}")

def buscar_palabra(banner, servicio):
    banner_lower = banner.lower()
    servicios = servicio.lower().split()
    
    palabras_no_camara_found = ["Apache2", "apache", "ubuntu", "microsoft-iis", "routeros", "unix"]
    
    for palabra in palabras_no_camara_found:
        if palabra in banner_lower:
            return "NULL"
    
    for palabra in banner_lower.split():
        if not any(sv in palabra for sv in servicios):
            if any(keyword in palabra for keyword in ["camera", "model:", "etag:", "webs x-frame-options:", "iemobile", "homepa", "nvr", "hikvision"]):
                if "www-authenticate: basic realm=\"index.html\"" in banner_lower or "./doc/page/login.asp?_" in banner_lower or  "dnvrs-webs" in banner_lower or "web x-frame-options: sameorigin etag" in banner_lower or "iemobile" in banner_lower or "homepa" in banner_lower or "nvr" in banner_lower:
                    return "Camara-Hikvision/DVR"
                elif "ipcam" in banner_lower:
                    return "Camara-IPCAM"
                else:
                    return "Camara-Found"
            elif 'www-authenticate: basic realm="index.html"' in banner_lower:
                return "Camara-Authentication-401"
    
    return "NULL"
