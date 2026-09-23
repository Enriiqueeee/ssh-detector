# Librerias
from datetime import datetime
import getpass
import paramiko

# Configuración del servidor
COMANDO = "cat /var/log/auth.log"

#Variables fijas
UMBRAL_USUARIO = 6
UMBRAL_IP = 10
VENTANA_TIEMPO = 60


print("SSH Brute Force Detector")


def pedir_datos():
    ip = input("Introduce la IP del servidor: ")
    port = int(input("Introduce el puerto SSH (por defecto 22): ") or 22)
    username = input("Introduce el nombre de usuario: ")
    password = getpass.getpass("Introduce la contraseña: ")

    return ip, port, username, password


def conexion_ssh(ip, port, username, password):
    #Crear cliente
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    #Conectar al servidor
    ssh.connect(ip, port, username, password)
    
    #Ejecutar comando
    stdin, stdout, stderr = ssh.exec_command(COMANDO)
    ruta = stdout.read().decode()
    error = stderr.read().decode()

    ruta = ruta.splitlines()

    #Cerrar conexion
    ssh.close()

    if error:
        print(f"Error al ejecutar el comando: {error}")
        return None
    else:
        return ruta


# Analizar las líneas del log
def analizar_log(linea):
    registro_ataque = {}
    registro_ataque_ip = {}

    for failed in linea:

        partes = failed.split()

        if (
            len(partes) >= 9
            and partes[2].startswith("sshd-session[")
            and partes[3] == "Failed"
            and partes[4] == "password"
            and partes[5] == "for"
            and partes[7] == "from"
        ):

            ip = partes[8]
            usuario = partes[6]
            fecha = partes[0]
            fecha = datetime.fromisoformat(fecha)

            # Crear registro para IP + usuario
            if (ip, usuario) not in registro_ataque:
                registro_ataque[(ip, usuario)] = {
                    "intentos": 0,
                    "fechas": []
                }

            # Contar intentos
            registro_ataque[(ip, usuario)]["intentos"] += 1

            # Guardar fecha
            registro_ataque[(ip, usuario)]["fechas"].append(fecha)

            # Contar intentos totales por IP
            if ip not in registro_ataque_ip:
               registro_ataque_ip[ip] = {
                   "intentos": 0,
                     "fechas": []
               }
            registro_ataque_ip[ip]["intentos"] += 1
            registro_ataque_ip[ip]["fechas"].append(fecha)

    return registro_ataque, registro_ataque_ip


# Detectar posibles ataques de fuerza bruta
def detectar_fuerza_bruta(registro_ataque, registro_ataque_ip):

    alertas = []

    # Comprobar IP + usuario
    for (ip, usuario), datos in registro_ataque.items():

        intentos = datos["intentos"]
        fechas = datos["fechas"]

        if intentos >= UMBRAL_USUARIO:

            for i in range(UMBRAL_USUARIO - 1, len(fechas)):

                inicio = fechas[i - UMBRAL_USUARIO + 1]
                fin = fechas[i]

                duracion = fin - inicio

                if duracion.total_seconds() <= VENTANA_TIEMPO:

                    alerta = {
                        "tipo": "usuario",
                        "ip": ip,
                        "usuario": usuario,
                        "intentos": UMBRAL_USUARIO,
                        "primer_intento": inicio,
                        "ultimo_intento": fin
                    }

                    alertas.append(alerta)
                    break

    # Comprobar IP total
    for ip, datos_ip in registro_ataque_ip.items():

        intentos = datos_ip["intentos"]
        fechas = datos_ip["fechas"]

        if intentos >= UMBRAL_IP:

            for i in range(UMBRAL_IP - 1, len(fechas)):

                inicio = fechas[i - UMBRAL_IP + 1]
                fin = fechas[i]

                duracion = fin - inicio

                if duracion.total_seconds() <= VENTANA_TIEMPO:

                    alerta = {
                        "tipo": "IP",
                        "ip": ip,
                        "intentos": UMBRAL_IP,
                        "primer_intento": inicio,
                        "ultimo_intento": fin
                    }

                    alertas.append(alerta)
                    break

    return alertas


# Mostrar las alertas
def mostrar_alertas(alertas):

    for alerta in alertas:

        # Alerta contra un usuario concreto
        if alerta["tipo"] == "usuario":

            print(
                f"Alerta: La IP {alerta['ip']} ha realizado "
                f"{alerta['intentos']} intentos. "
                f"Posible ataque de fuerza bruta al usuario "
                f"{alerta['usuario']}"
            )

            print(f"Primer intento: {alerta['primer_intento']}")
            print(f"Último intento: {alerta['ultimo_intento']}")
            print("-" * 30)

        # Alerta contra múltiples usuarios desde una misma IP
        elif alerta["tipo"] == "IP":

            print(
                f"Alerta: La IP {alerta['ip']} ha realizado "
                f"{alerta['intentos']} intentos. "
                f"Posible ataque de fuerza bruta contra múltiples usuarios."
            )
            print(f"Primer intento: {alerta['primer_intento']}")
            print(f"Último intento: {alerta['ultimo_intento']}")
            print("-" * 30)


# Programa principal
ip, port, username, password = pedir_datos()

ruta = conexion_ssh(ip, port, username, password)

if ruta is None:
    print("No se pudo obtener el log del servidor. Saliendo del programa.")
    exit(1)

registro_ataque, registro_ataque_ip = analizar_log(ruta)

alertas = detectar_fuerza_bruta(
    registro_ataque,
    registro_ataque_ip
)

mostrar_alertas(alertas)