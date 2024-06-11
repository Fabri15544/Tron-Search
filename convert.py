import subprocess
from multiprocessing import Pool

def get_user_input():
    while True:
        choice = input("¿Quieres eliminar un número de la última fila (E) o reemplazarla con asteriscos (A)? (E/A): ").strip().upper()
        if choice in ['E', 'A']:
            break
        else:
            print("Opción no válida. Debe seleccionar 'E' para eliminar un número o 'A' para reemplazar con asteriscos.")
    
    if choice == 'E':
        num_digits = int(input("¿Cuántos números quieres eliminar de la última fila de la IP? ").strip())
        num_asterisks = 0
    else:
        num_asterisks = int(input("¿Cuántos asteriscos quieres para los rangos de IP? ").strip())
        num_digits = 0
    
    extra_command = input("¿Tienes otro comando para tron.py? (déjalo en blanco si no) ").strip()
    return choice, num_digits, num_asterisks, extra_command

def modify_ips(ips, choice, num_digits, num_asterisks):
    modified_ips = []
    for ip in ips:
        ip_parts = ip.strip().split('.')
        if choice == 'E':
            ip_parts[-1] = ip_parts[-1][:-num_digits]
        else:
            ip_parts[-num_asterisks:] = ['*'] * num_asterisks
        modified_ips.append('.'.join(ip_parts))
    return modified_ips

def process_ip(ip, extra_command):
    command = f'python tron.py --search {ip} {extra_command}'
    try:
        subprocess.run(command, shell=True, timeout=2)
    except subprocess.TimeoutExpired:
        print(f"El proceso para la IP {ip} ha sido cerrado automáticamente después de 2 segundos.")
    except Exception as e:
        print(f"Error al procesar la IP {ip}: {e}")

def main():
    choice, num_digits, num_asterisks, extra_command = get_user_input()

    with open('ips.txt', 'r') as file:
        ips = file.readlines()

    modified_ips = modify_ips(ips, choice, num_digits, num_asterisks)

    if choice == 'A':
        for ip in modified_ips:
            process_ip(ip, extra_command)
    else:
        with Pool(processes=1) as pool:
            pool.starmap(process_ip, [(ip, extra_command) for ip in modified_ips])

if __name__ == '__main__':
    main()
