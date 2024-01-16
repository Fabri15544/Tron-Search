from http.server import SimpleHTTPRequestHandler, HTTPServer

class NoCacheHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            # Llamar al método original do_GET() para manejar la solicitud GET
            super().do_GET()
        except ConnectionAbortedError:
            # Manejar la excepción de conexión abortada
            print("Se ha producido una conexión abortada por el cliente.")

    def end_headers(self):
        # Desactivar la memoria caché añadiendo encabezados específicos
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        super().end_headers()

if __name__ == '__main__':
    port = 8080
    server_address = ('', port)
    httpd = HTTPServer(server_address, NoCacheHandler)
    print(f'Servidor iniciado en http://127.0.0.1:{port}')
    httpd.serve_forever()

