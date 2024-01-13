# Escáner de Puertos en Direcciones IP

Este script en Python te permite escanear puertos en un rango de direcciones IP utilizando hilos de ejecución para mejorar la velocidad del escaneo. Además, proporciona opciones para filtrar por región y ciudad, y te permite personalizar los puertos a escanear.

## Uso

1. **Instalación de dependencias:**
   Antes de ejecutar el script, asegúrate de tener instaladas las dependencias necesarias. Puedes instalarlas ejecutando el siguiente comando:

   ```bash
   pip install -r requirements.txt

   python tron.py --search <patrón de direcciones IP> [--region <código de región>] [--ciudad <nombre de la ciudad>]
   python tron.py --search <Nombre a buscar ej : google> [--region <código de región>] [--ciudad <nombre de la ciudad>]
