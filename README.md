[![Imagen1](https://i.postimg.cc/jL3ZjGcL/Captura-de-pantalla-10.png)](https://postimg.cc/jL3ZjGc)
[![Imagen1](https://i.postimg.cc/KR80xZn6/Captura-de-pantalla-11.png)](https://postimg.cc/KR80xZn6)
[![Imagen1](https://i.postimg.cc/06Dfcrsw/Captura-de-pantalla-12.png)](https://postimg.cc/06Dfcrsw)
[![Imagen1](https://i.postimg.cc/dhz62rzF/Captura-de-pantalla-13.png)](https://postimg.cc/dhz62rzF)
[![Imagen1](https://i.postimg.cc/9w27mRqm/Captura-de-pantalla-13.png)](https://postimg.cc/9w27mRqm)
[![Imagen2](https://i.postimg.cc/w7NggfQk/Nombre-de-la-imagen.png)](https://postimg.cc/w7NggfQk)
[![Captura de pantalla 14](https://i.postimg.cc/xJQP7YfF/Captura-de-pantalla-14.png)](https://postimg.cc/xJQP7YfF)
[![Captura de pantalla 15](https://i.postimg.cc/G4BzTqgz/Captura-de-pantalla-15.png)](https://postimg.cc/G4BzTqgz)
[![Captura de pantalla 8](https://i.postimg.cc/DmFCpQmy/Captura-de-pantalla-8.png)](https://postimg.cc/DmFCpQmy)
[![Captura de pantalla 9](https://i.postimg.cc/pyZsw9nQ/Captura-de-pantalla-9.png)](https://postimg.cc/pyZsw9nQ)


# Escáner de Puertos en Direcciones IP

Este script en Python te permite escanear puertos en un rango de direcciones IP utilizando hilos de ejecución para mejorar la velocidad del escaneo. Además, proporciona opciones para filtrar por región y ciudad, y te permite personalizar los puertos a escanear.

## Uso

1. **Instalación de dependencias:**
   Antes de ejecutar el script, asegúrate de tener instaladas las dependencias necesarias. Puedes instalarlas ejecutando el siguiente comando:

   ```bash
   pip install -r requirements.txt

   python tron.py --search <patrón de direcciones IP> [--region <código de región>] [--ciudad <nombre de la ciudad>] [--port 80 443 21] [--port 80]
   python tron.py --search <Nombre a buscar ej : google> [--region <código de región>] [--ciudad <nombre de la ciudad>]

## Web-UI

1. **USO DEL LOCALHOST:**
   Puede filtrar por puertos,servicios, busqueda avanzada filtro por baner y todo el html
   Cuenta con un mapa donde vera todos los datos recopilados en un numero total a la region escaneada
   Cuenta con modo Oscuro.
2. **USO DE CONSOLA:**
   Cuenta con barra de progreso al buscar un rango de ip.
   Cuenta con chequeo de Vulnerabilidades de camaras.
   Cuenta con un bypass 401 unauthorized (detecta si es una camara) solo funciona para camaras.
  https://github.com/ezelf/CVE-2018-9995_dvr_credentials. Una de ellas
  Iré agregando más a la lista próximamente.
2. **PUNTOS A MEJORAR:**
   agregar argumento wordlist.
   agregar argumento time para controlar la conexiones(SOCKETS).
   agregar un chequeo de ip/host scaneados para reanudar desde el punto de interrupcion del script.

