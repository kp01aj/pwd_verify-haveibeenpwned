#!/usr/bin/env python
# Author = KernelPanicRD
# Contact = https://www.instagram.com/seguridad_lol
# Verify by Have I been Pwdned

import requests
import hashlib
import argparse

def verificar_contraseña(password):
    # Calcular el hash SHA-1 de la contraseña
    hash_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix_hash, suffix_hash = hash_password[:5], hash_password[5:]

    # Realizar una solicitud a la API de haveibeenpwned
    url = f"https://api.pwnedpasswords.com/range/{prefix_hash}"
    response = requests.get(url)

    # Verificar si el hash de la contraseña se encuentra en la respuesta
    hashes_comprometidos = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes_comprometidos:
        if h == suffix_hash:
            return int(count)
    return 0

def evaluar_fortaleza_contraseña(password):
    # Evaluar la longitud y complejidad de la contraseña
    longitud = len(password)
    complejidad = "Débil" if longitud < 8 else "Fuerte"

    # Verificar si la contraseña ha sido comprometida
    frecuencia_ocurrencia = verificar_contraseña(password)
    comprometida = frecuencia_ocurrencia > 0

    return longitud, complejidad, comprometida, frecuencia_ocurrencia

def main():
    parser = argparse.ArgumentParser(description="Verificar la seguridad de una contraseña.")
    parser.add_argument("contraseña", help="Contraseña a verificar")
    args = parser.parse_args()

    contraseña = args.contraseña

    # Evaluar la fortaleza de la contraseña
    longitud, complejidad, comprometida, frecuencia_ocurrencia = evaluar_fortaleza_contraseña(contraseña)

    print(f"Longitud de la contraseña: {longitud}")
    print(f"Complejidad de la contraseña: {complejidad}")

    if comprometida:
        print(f"La contraseña ha sido comprometida.")
        print(f"Frecuencia de ocurrencia en la base de datos de contraseñas comprometidas: {frecuencia_ocurrencia}")
        # Obtener la fecha de la última ocurrencia conocida
        # Obtener información sobre la fuente de la violación
    else:
        print("La contraseña no ha sido comprometida.")

if __name__ == "__main__":
    main()
