import subprocess
from multiprocessing import Pool

# Pregunta al usuario si quiere eliminar un número de la última fila o reemplazarla con asteriscos
choice = input("¿Quieres eliminar un número de la última fila (E) o reemplazarla con asteriscos (A)? (E/A): ")

# Si la opción es eliminar un número, pregunta cuántos números quiere eliminar
if choice.upper() == 'E':
    num_digits = int(input("¿Cuántos números quieres eliminar de la última fila de la IP? "))
    num_asterisks = 0  # Se establece en 0 ya que no se utilizará en este caso
# Si la opción es reemplazar con asteriscos, pregunta cuántos asteriscos quiere para los rangos de IP
elif choice.upper() == 'A':
    num_asterisks = int(input("¿Cuántos asteriscos quieres para los rangos de IP? "))
    num_digits = 0  # Se establece en 0 ya que no se utilizará en este caso
else:
    print("Opción no válida. Debe seleccionar 'E' para eliminar un número o 'A' para reemplazar con asteriscos.")
    exit()

# Pregunta al usuario si tiene otro comando para tron.py
extra_command = input("¿Tienes otro comando para tron.py? (déjalo en blanco si no) ")

# Lee las IPs del archivo
with open('ips.txt', 'r') as file:
    ips = file.readlines()

# Modifica las IPs según la opción elegida por el usuario
modified_ips = []
for ip in ips:
    ip_parts = ip.strip().split('.')
    if choice.upper() == 'E':
        ip_parts[-1] = ip_parts[-1][:-num_digits] + '*' * num_asterisks
    elif choice.upper() == 'A':
        ip_parts[-1] = '*' * num_asterisks
    modified_ips.append('.'.join(ip_parts))

def process_ip(ip):
    command = 'python tron.py --search ' + ip + ' ' + extra_command
    try:
        subprocess.run(command, shell=True, timeout=2)  # Establece un timeout de 2 segundos
    except subprocess.TimeoutExpired:
        print("El proceso para la IP", ip, "ha sido cerrado automáticamente después de 2 segundos.")

if __name__ == '__main__':
    # Procesar IPs en paralelo con un pool de procesos
    with Pool(processes=5) as pool:  # Puedes ajustar el número de procesos según tus necesidades
        pool.map(process_ip, modified_ips)
