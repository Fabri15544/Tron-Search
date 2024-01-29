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
    combinaciones_unicas = set()
    datos_filtrados = []

    for dato in datos:
        combinacion = (dato["IP"], dato["Puerto"])
        if combinacion not in combinaciones_unicas:
            combinaciones_unicas.add(combinacion)
            datos_filtrados.append(dato)

    return datos_filtrados

def actualizar_datos():
    while True:
        datos_previos = cargar_datos()
        datos_filtrados = eliminar_duplicados(datos_previos)

        for dato in datos_filtrados:
            banner = dato["Banner"]
            
            if "Webs" in banner and "ETag:" in banner:
                dato["Camara"] = "Camara-Hikvision/DVR"
            elif "IPCAM" in banner:
                dato["Camara"] = "Camara-IPCAM"
            elif 'WWW-Authenticate: Basic realm="index.html"' in banner:
                dato["Camara"] = "Camara-Auntenticacion-401"
            elif "Camera:" in banner or "camera:" in banner or "Model:" in banner:
                dato["Camara"] = "Camara-Found"
            elif "HTTP/1.0 302 Found" in banner:
                dato["Camara"] = "Camara[?]"
            elif "WWW-Authenticate: Basic realm=\"index.html\"" in banner or "/doc/page/login.asp?_" in banner:
                dato["Camara"] = "Camara-Hikvision/DVR"
            elif "WWW-Authenticate: Basic realm=\"streaming_server\"" in banner:
                dato["Camara"] = "Camara-Auntenticacion-401"
            elif "Server: Hipcam RealServer/V1.0" in banner:
                dato["Camara"] = "Camara-Hipcam"
            elif "Network Camera with Pan/Tilt" in banner or "Boa/0.94.14rc21" in banner or "Plugin:" in banner or "Expires:" in banner:
                dato["Camara"] = "Camara-Found"
            elif "unknown" in banner:
                dato["Camara"] = "unknown"

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
