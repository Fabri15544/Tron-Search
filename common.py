import os
import time
import json
import subprocess
import threading
from PIL import Image
import pytesseract



def extraer_texto_desde_imagen(ruta_imagen):
    try:
        return pytesseract.image_to_string(Image.open(ruta_imagen))
    except Exception as e:
        pass

def actualizar_datos():
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    ruta_capturas = "screenshot/"
    datos_filtrados = eliminar_duplicados(cargar_datos())

    archivos = os.listdir(ruta_capturas)
    for archivo in archivos:
        if archivo.endswith(".png"):
            ip, puerto = archivo.split('-')
            puerto = puerto.split('.')[0]  # Eliminar la extensión .png

            # Buscar la entrada correspondiente en los datos filtrados
            for dato in datos_filtrados:
                banner = dato["Banner"]
                servicio = dato["Servicio"]  # Obtener la lista de servicios (de donde sea que la obtengas)
                camara = buscar_palabra(banner,servicio)  # Llamada a la función buscar_palabra
                dato["Camara"] = camara  # Asignación del resultado a la clave "Camara"
                if (dato["IP"] == ip and str(dato["Puerto"]) == puerto) and dato["Banner"] == "\u001b[31munknown\u001b[0m":
                    ruta_imagen = os.path.join(ruta_capturas, archivo)
                    if os.path.exists(ruta_imagen):
                        texto = extraer_texto_desde_imagen(ruta_imagen)
                        if texto:
                            print(f"El banner para {dato['IP']}:{dato['Puerto']} fue reemplazado.")
                            dato["Banner"] = texto
                        else:
                            pass
                    else:
                        print(f"No se pudo extraer texto de la imagen {ruta_imagen}")
    try:
        guardar_datos(datos_filtrados)
    except Exception as e:
        print(f"Error al guardar datos: {e}")

def validar_json(filepath):
    try:
        # Validar el archivo usando json.tool
        subprocess.run(['python', '-m', 'json.tool', filepath], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error al validar '{filepath}' con json.tool: {e}")
        return False

def reparar_json(archivo):
    """Intenta reparar un archivo JSON con errores comunes de formato."""
    with open(archivo, 'r') as file:
        contenido = file.read()

    # Eliminar comas al final de los objetos y arrays
    contenido = re.sub(r',\s*}', '}', contenido)  # Comas antes de '}'
    contenido = re.sub(r',\s*\]', ']', contenido)  # Comas antes de ']'

    # Intentar cargar el contenido reparado
    try:
        return json.loads(contenido)
    except json.decoder.JSONDecodeError as e:
        print(f"Error al intentar reparar el JSON: {e}")
        return None

def cargar_datos(max_intentos=3):
    intentos = 0
    while intentos < max_intentos:
        if not os.path.exists('datos.json'):
            print("Archivo 'datos.json' no encontrado. Intentando cargar 'respaldo.json'...")
            if os.path.exists('respaldo.json') and validar_json('respaldo.json'):
                with open('respaldo.json', 'r') as respaldo:
                    return json.load(respaldo)
            print("Archivo 'respaldo.json' no encontrado o inválido.")
            break

        # Validar y cargar 'datos.json'
        if validar_json('datos.json'):
            try:
                with open('datos.json', 'r') as file:
                    return json.load(file)
            except json.decoder.JSONDecodeError as e:
                print(f"Error al cargar 'datos.json': {e}. Intentando reparar el archivo...")
                # Intentar reparar el archivo
                datos_reparados = reparar_json('datos.json')
                if datos_reparados:
                    print("Archivo reparado correctamente.")
                    with open('datos.json', 'w') as file:
                        json.dump(datos_reparados, file)
                    return datos_reparados
                else:
                    print("No se pudo reparar el archivo 'datos.json'. Reintentando en 2 segundos...")
                    intentos += 1
                    time.sleep(2)
            except Exception as e:
                print(f"Error inesperado al cargar 'datos.json': {e}")
                break
        else:
            print("Archivo 'datos.json' no válido. Intentando cargar 'respaldo.json'...")
            if os.path.exists('respaldo.json') and validar_json('respaldo.json'):
                with open('respaldo.json', 'r') as respaldo:
                    return json.load(respaldo)
            print("Archivo 'respaldo.json' no encontrado o inválido.")
            break

    print("No se pudo cargar 'datos.json' ni 'respaldo.json' después de varios intentos.")
    return None


def guardar_datos(datos):
    try:
        with open('datos.json', 'w') as file:
            json.dump(datos, file, indent=2)
        print("Datos guardados correctamente.")
        # Asegúrate de que actualizar_datos no interfiera con la escritura
        threading.Timer(1, actualizar_datos).start()
    except PermissionError:
        print("Error de permisos al guardar datos en 'datos.json'.")
    except FileNotFoundError:
        print("El archivo 'datos.json' no fue encontrado.")
    except json.JSONDecodeError:
        print("Error al decodificar el contenido del archivo JSON.")
    except Exception as e:
        print(f"Error al guardar datos: {e}")

def eliminar_duplicados(datos):
    datos_filtrados = []
    diccionario_combinaciones = {}

    for dato in datos:
        combinacion = (dato["IP"], dato["Puerto"])
        diccionario_combinaciones[combinacion] = dato

    datos_filtrados = list(diccionario_combinaciones.values())

    return datos_filtrados

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
