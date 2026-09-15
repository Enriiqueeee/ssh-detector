print ("SSH Brute Force Detector")

log = open("auth.log", "r")

log_failed = log.read()

linea = log_failed.splitlines()

fallos_contador = 0

umbral_fuerza_bruta = 6
umbral_fuerza_bruta_ip = 10

registro_ataque = {}
registro_ataque_ip = {}

for failed in linea:
    if "Failed password" in failed and "sshd-session" in failed:
        fallos_contador += 1

        partes = failed.split()

        ip = partes[8]

        usuario = partes[6]

        if (ip, usuario) in registro_ataque:
            registro_ataque[(ip, usuario)] += 1
        else:
            registro_ataque[(ip, usuario)] = 1

        if ip in registro_ataque_ip:
            registro_ataque_ip[ip] += 1
        else:
            registro_ataque_ip[ip] = 1


        print(failed)
        print("IP atacante:", ip)

print("\n" + "="*30)
print(f"{'IP atacante':<18} {'Usuario':<12} {'Intentos'}")
print("-" * 30)

for (ip, usuario), intentos in registro_ataque.items():
    print(f"{ip:<18} {usuario:<12} {intentos}")
    if intentos >= umbral_fuerza_bruta:
        print(f"Alerta: La IP {ip} ha realizado {intentos}. Posible ataque de fuerza bruta al usuario {usuario}")

for ip, intentos in registro_ataque_ip.items():
    if intentos >= umbral_fuerza_bruta_ip:
        print(f"Alerta: La IP {ip} ha realizado {intentos}. Posible ataque de fuerza bruta")

print("-" * 30)


def leer_log():
    log = open("auth.log", "r")
    log_failed = log.read()

    linea = log_failed.splitlines()

    fallos_contador = 0

    