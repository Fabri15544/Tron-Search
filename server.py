import pytesseract
from PIL import Image
import os
import json
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading

class NoCacheHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            super().do_GET()
        except ConnectionAbortedError:
            print("Se ha producido una conexión abortada por el cliente.")

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        super().end_headers()

def cargar_datos():
    try:
        with open('datos.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

def guardar_datos(datos):
    try:
        with open('datos.json', 'w') as file:
            json.dump(datos, file, indent=2)
        print("Datos guardados correctamente.")
        threading.Timer(10, actualizar_datos).start()
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
            if any(keyword in palabra for keyword in ["camera", "model:", "etag:", "webs x-frame-options:", "iemobile", "homepa", "nvr"]):
                if "www-authenticate: basic realm=\"index.html\"" in banner_lower or "./doc/page/login.asp?_" in banner_lower or "dnvrs-webs" in banner_lower or "web x-frame-options: sameorigin etag" in banner_lower or "iemobile" in banner_lower or "homepa" in banner_lower or "nvr" in banner_lower:
                    return "Camara-Hikvision/DVR"
                elif "ipcam" in banner_lower:
                    return "Camara-IPCAM"
                else:
                    return "Camara-Found"
            elif 'www-authenticate: basic realm="index.html"' in banner_lower:
                return "Camara-Authentication-401"
    
    return "NULL"

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

if __name__ == '__main__':
    # Iniciar un hilo para actualizar los datos cada 10 segundos
    threading.Thread(target=actualizar_datos, daemon=True).start()

    # Iniciar el servidor HTTP
    port = 8080
    server_address = ('', port)
    httpd = HTTPServer(server_address, NoCacheHandler)
    print(f'Servidor iniciado en http://127.0.0.1:{port}')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Servidor detenido.")
        httpd.server_close()
