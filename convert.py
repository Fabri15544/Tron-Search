import subprocess
import queue

# Pregunta al usuario si quiere eliminar un número de la última fila o reemplazarla con asteriscos
choice = input("¿Quieres eliminar un número de la última fila (E) o reemplazarla con asteriscos (A)? (E/A): ")

# Validación de la opción elegida y obtención de la cantidad correspondiente
if choice.upper() == 'E':
    try:
        num_digits = int(input("¿Cuántos números quieres eliminar de la última fila de la IP? "))
        num_asterisks = 0
    except ValueError:
        print("Por favor, ingresa un número válido.")
        exit()
elif choice.upper() == 'A':
    try:
        num_asterisks = int(input("¿Cuántos asteriscos quieres para los rangos de IP? "))
        num_digits = 0
    except ValueError:
        print("Por favor, ingresa un número válido.")
        exit()
else:
    print("Opción no válida. Debe seleccionar 'E' para eliminar un número o 'A' para reemplazar con asteriscos.")
    exit()

# Pregunta al usuario si tiene otro comando para tron.py
extra_command = input("¿Tienes otro comando para tron.py? (déjalo en blanco si no): ")

# Lee las IPs del archivo
try:
    with open('ips.txt', 'r') as file:
        ips = file.readlines()
except FileNotFoundError:
    print("El archivo 'ips.txt' no se encontró.")
    exit()

# Modifica las IPs según la opción elegida por el usuario
modified_ips = []
for ip in ips:
    ip_parts = ip.strip().split('.')
    if choice.upper() == 'E':
        ip_parts[-1] = ip_parts[-1][:-num_digits]
    elif choice.upper() == 'A':
        ip_parts = ip_parts[:-num_asterisks] + ['*'] * num_asterisks
    modified_ips.append('.'.join(ip_parts))

# Crear una cola para las IPs
ip_queue = queue.Queue()

# Llenar la cola con las IPs modificadas
for ip in modified_ips:
    ip_queue.put(ip)

# Procesar las IPs
while not ip_queue.empty():
    ip = ip_queue.get()
    command = f'python tron.py --search {ip} {extra_command}'
    try:
        proc = subprocess.Popen(command, shell=True)
        proc.wait(timeout=30)  # Establece un timeout de 2 segundos
    except subprocess.TimeoutExpired:
        proc.kill()
        print(f"El proceso para la IP {ip} ha sido cerrado automáticamente después de 2 segundos.")
    finally:
        ip_queue.task_done()

print("Todos los procesos han finalizado.")
