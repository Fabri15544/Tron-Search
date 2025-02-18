import subprocess
from multiprocessing import Pool
import json

def get_user_input():
    while True:
        choice = input("¿Quieres eliminar un número de la última fila (E), reemplazarla con asteriscos (A) o procesar desde JSON (J)? (E/A/J): ").strip().upper()
        if choice in ['E', 'A', 'J']:
            break
        else:
            print("Opción no válida. Debe seleccionar 'E' para eliminar un número, 'A' para reemplazar con asteriscos o 'J' para procesar desde JSON.")
    
    if choice == 'E':
        num_digits = int(input("¿Cuántos números quieres eliminar de la última fila de la IP? ").strip())
        num_asterisks = 0
    elif choice == 'A':
        num_asterisks = int(input("¿Cuántos asteriscos quieres para los rangos de IP? ").strip())
        num_digits = 0
    elif choice == 'J':
        option = input("¿Quieres eliminar un número de la última fila (E) o reemplazarla con asteriscos (A)? (E/A): ").strip().upper()
        if option == 'E':
            num_digits = int(input("¿Cuántos números quieres eliminar de la última fila de la IP? ").strip())
            num_asterisks = 0
        elif option == 'A':
            num_asterisks = int(input("¿Cuántos asteriscos quieres para los rangos de IP? ").strip())
            num_digits = 0
        else:
            num_digits = 0
            num_asterisks = 0
    else:
        num_digits = 0
        num_asterisks = 0

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
        subprocess.run(command, shell=True, timeout=10)
    except subprocess.TimeoutExpired:
        print(f"El proceso para la IP {ip} ha sido cerrado automáticamente después de 2 segundos.")
    except Exception as e:
        print(f"Error al procesar la IP {ip}: {e}")

def main():
    choice, num_digits, num_asterisks, extra_command = get_user_input()

    if choice == 'J':
        with open('ips.json', 'r') as file:
            data = json.load(file)
            ips = [bucket['key'] for bucket in data['buckets']]
    else:
        with open('ips.txt', 'r') as file:
            ips = file.readlines()

    if choice in ['E', 'A']:
        modified_ips = modify_ips(ips, choice, num_digits, num_asterisks)
    else:
        modified_ips = ips

    if choice == 'A' or choice == 'J':
        for ip in modified_ips:
            process_ip(ip, extra_command)
    else:
        with Pool(processes=1) as pool:
            pool.starmap(process_ip, [(ip, extra_command) for ip in modified_ips])

if __name__ == '__main__':
    main()
