import argparse

parser = argparse.ArgumentParser(description='Escaneo de puertos en direcciones IP')

parser.add_argument('--search', required=True, help='Patrón de direcciones IP a escanear con el * como comodín (ejemplo: 192.168.*.*). Consulta avanzada: https://www.exploit-db.com/google-hacking-database')
parser.add_argument('--port', nargs='+', type=str, help='Puerto o puertos a escanear. Presiona Enter para usar los puertos predeterminados o "all" para escanear todos los puertos.')
parser.add_argument('--region', help='Filtrar por región, ej: US, AR, MX')
parser.add_argument('--ciudad', help='Filtrar por ciudad')
parser.add_argument('--w', help='Ruta del archivo de texto con el wordlist (usuarios y contraseñas)')
parser.add_argument('--s', default=0.5, type=float, help='Tiempo de espera entre conexiones [SOCKET] (valor predeterminado: 0.5 segundos)')
parser.add_argument('--bn', default=2, type=float, help='Tiempo de espera [BANNER] (valor predeterminado: 2 segundos)')
parser.add_argument('--has_screenshot', choices=['all', 'cam'], default=None, help='Captura de pantalla [--has_screenshot all (todas las URLs)] [--has_screenshot cam (cámaras reconocidas)]')
parser.add_argument('--reanudar', help='IP a partir de la cual se reanudará el escaneo. Ej: --search 144.88.*.* --reanudar 144.88.92.63')
parser.add_argument('--fast', default=0, type=int, const=50, nargs='?', help='Salto de IPs para búsqueda rápida')
parser.add_argument('--time', default=30, type=int, help='Valor de tiempo para la opción --fast')

# Analizar los argumentos proporcionados al script
args = parser.parse_args()

# Acceder a los argumentos en el código
ip_pattern = args.search
FiltroRegion = args.region
FiltroCiudad = args.ciudad
reanudar_ip = args.reanudar
salto = args.fast
TiempoSalto = args.time
