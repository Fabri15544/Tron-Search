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
