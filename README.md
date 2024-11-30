
# Escáner de Puertos en Direcciones IP

Este script en Python te permite escanear puertos en un rango de direcciones IP utilizando hilos de ejecución para mejorar la velocidad del escaneo. Además, proporciona opciones para filtrar por región y ciudad, y te permite personalizar los puertos a escanear.

## Uso

1. **Instalación de dependencias:**
   Antes de ejecutar el script, asegúrate de tener instaladas las dependencias necesarias. Puedes instalarlas ejecutando el siguiente comando:

   ```bash
   pip install -r requirements.txt

   !!![REQUIERE DE CHROME INSTALADO https://www.google.com/intl/es-419/chrome/]!!!
   !!![REQUIERE DE WINCAP INSTALADO https://www.winpcap.org/install/]!!!
   !!![REQUIERE DE TESSERACT OCR INSTALADO https://github.com/UB-Mannheim/tesseract/wiki]!!! TRANSFORMA IMAGENES A TEXTO PARA EL BANNER, EN CASO DE NO OBTENERSE POR EL SOCK.

   python tron.py --search <patrón de direcciones IP> [--region <código de región>] [--ciudad <nombre de la ciudad>] [--port 80 443 21] [--port 80] [--w diccionario.txt]
   python tron.py --search <Nombre a buscar ej : google> [--region <código de región>] [--ciudad <nombre de la ciudad>] [--w diccionario.txt]

   options:
   -h, --help            show this help message and exit
   --search SEARCH       Patrón de direcciones IP a escanear con el * como comodín (ejemplo: 192.168.*.*) busqueda
                        avanzada con google:https://www.exploit-db.com/google-hacking-database
   --port PORT [PORT ...]
                        Puerto o puertos a escanear. Presiona Enter para usar los puertos predeterminados o "all" para
                        escanear todos los puertos.
   --region REGION       Filtrar por región ej US,AR,MX
   --ciudad CIUDAD       Filtrar por ciudad
   --w W                 Ruta del archivo de texto con el wordlist (usuarios y contraseñas)
   --s S                 Tiempo de espera entre conexiones[SOCKET] (valor predeterminado: 0.5 segundos)
   --bn BN               Tiempo de espera [BANNER] (valor predeterminado: 2 segundos)
   --has_screenshot      Captura de pantalla [--has_screenshot all (todas las urls)] [--has_screenshot cam (todas las que se reconocen como camaras)]
   --reanudar REANUDAR   IP a partir de la cual se reanudará el escaneo EJ: --search 144.88.*.* --reanudar 144.88.92.63
   --fast [FAST]         Salto de IPS para búsqueda rápida
   --time TIME           Valor de tiempo para la opción --fast, esta opcion controla el tiempo de espera entre saltos.
   


<a href="https://www.buymeacoffee.com/fabriciolou" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

## Web-UI

2. **USO DEL LOCALHOST:**
   
   Puede filtrar por puertos,servicios, busqueda avanzada filtro por baner y todo el html
   
   Cuenta con un mapa donde vera todos los datos recopilados en un numero total a la region escaneada
   
   Cuenta con modo Oscuro.

   
4. **CONSOLA:**
   
   Cuenta con barra de progreso al buscar un rango de ip.
   
   Cuenta con chequeo de Vulnerabilidades de camaras.
   
   Cuenta con un bypass 401 unauthorized (detecta si es una camara) solo funciona para camaras.

   Cuenta Metodo Reanudar Escaneo.

   Cuenta con salto automatico entre ips/ hasta encontrar 1 ip valida, con tiempo espera maximo antes de acelerar la carga. Argumento --fast

   Chequeo de IP para no repetir las que ya estan.

   obtencion del banner por medio de imagen, si el banner no esta pero tiene una captura la imagen se transforma a texto para completar el banner

   Camara-Check en localhost para saber que camara es.[Agregar Icon de la camara correspondientes automatico]

   Capturas Webs.
   
   https://github.com/ezelf/CVE-2018-9995_dvr_credentials. Una de ellas
  
   Iré agregando más a la lista próximamente.

   Detección del sistema operativo (SO) en el Puerto [3389] en desarrollo.

   Agregue detección de sistema Operativo SMB en el Puerto[445]: https://github.com/nopfor/ntlm_challenger/tree/master

   Modificar js/ para no mostrar datos nulos. //LISTO.

   Agregado volcado de ips:ports especificos para pasar a Metasploit. //INTEGRACION-WEB
  
4. **PUNTOS A MEJORAR:**

   Rtsp no es optimo es muy lento. tengo que agregar un nuevo valor al json para indicar que ya a sido scaneado para no volver a scanear el mismo.

   agregar actualizacion de ips escaneadas para refrescar informacion.

   Agregar combinación de archivos json. 
   
   Agregar conexion proxy.

   Hacer funcionar los botones[Unir todo en un solo boton de (Buscar), indicar busqueda sino existe la informacion]

   Mostrar capturas de camaras vulnerables a Wordlist/Link.

   Agrega detección de sistema Operativo Linux/Unix [Agregar-Argumento]

   Agregar WebTechnologies check.

   Agregar Smap para buscar, y en paralelo usar escaneo en tiempo real.(Probando)
   https://github.com/s0md3v/Smap
