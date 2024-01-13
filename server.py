from http.server import SimpleHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta, timezone

class AlwaysFreshHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            # Llamar al método original do_GET() para manejar la solicitud GET
            super().do_GET()

            # Obtener la fecha y hora actual
            current_time = datetime.now(timezone.utc)

            # Agregar encabezados para indicar que el recurso siempre está actualizado
            self.send_response(200)
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.send_header('Last-Modified', current_time.strftime('%a, %d %b %Y %H:%M:%S GMT'))
            self.end_headers()

        except ConnectionAbortedError:
            # Manejar la excepción de conexión abortada
            print("Se ha producido una conexión abortada por el cliente.")

if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, AlwaysFreshHandler)
    print('Servidor iniciado en el puerto 8080...')
    httpd.serve_forever()
