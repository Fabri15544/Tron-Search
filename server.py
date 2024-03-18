from http.server import SimpleHTTPRequestHandler, HTTPServer
import json
import time

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
    
    # Palabras que hacen que la función devuelva "NULL"
    palabras_no_camara_found = ["Apache2","apache","Ubuntu","microsoft-iis","routeros","unix"]
    
    
    for palabra in palabras_no_camara_found:
        if palabra in banner_lower:
            return "NULL"
    
    for palabra in banner_lower.split():
        if not any(sv in palabra for sv in servicios):
            if any(keyword in palabra for keyword in ["camera:", "model:", "etag:"]):
                if "www-authenticate: basic realm=\"index.html\"" in banner_lower or "/doc/page/login.asp?_" in banner_lower:
                    return "Camara-Hikvision/DVR"
                elif "ipcam" in banner_lower:
                    return "Camara-IPCAM"
                else:
                    return "Camara-Found"
            elif 'www-authenticate: basic realm="index.html"' in banner_lower:
                return "Camara-Authentication-401"
    
    return "NULL"

def actualizar_datos():
    while True:
        datos_previos = cargar_datos()
        datos_filtrados = eliminar_duplicados(datos_previos)

        for dato in datos_filtrados:
            banner = dato["Banner"]
            servicio = dato["Servicio"]  # Obtener la lista de servicios (de donde sea que la obtengas)
            camara = buscar_palabra(banner,servicio)  # Llamada a la función buscar_palabra
            dato["Camara"] = camara  # Asignación del resultado a la clave "Camara"

        try:
            with open('datos.json', 'w') as file:
                json.dump(datos_filtrados, file, indent=2)
            with open('respaldo.json', 'w') as file:
                json.dump(datos_filtrados, file, indent=2)

            print("Datos actualizados.")
        except Exception as e:
            print(f"Error: {e}")
            continue
        time.sleep(10)  # Pausa la ejecución durante 10 segundos



if __name__ == '__main__':
    # Iniciar un hilo para actualizar los datos cada 10 segundos
    import threading
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
