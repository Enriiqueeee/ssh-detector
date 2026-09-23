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

        if "Failed password" in failed and "sshd-session" in failed:

            partes = failed.split()

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
        primera_fecha = fechas[0]
        ultima_fecha = fechas[-1]

        duracion = ultima_fecha - primera_fecha

        if intentos >= UMBRAL_USUARIO and duracion.total_seconds() <= VENTANA_TIEMPO:

            alerta = {
                "tipo": "usuario",
                "ip": ip,
                "usuario": usuario,
                "intentos": intentos,
                "primer_intento": primera_fecha,
                "ultimo_intento": ultima_fecha
            }

            alertas.append(alerta)

    # Comprobar IP total
    for ip, datos_ip in registro_ataque_ip.items():
        intentos = datos_ip["intentos"]
        fechas = datos_ip["fechas"]
        primera_fecha = fechas[0]
        ultima_fecha = fechas[-1]

        duracion = ultima_fecha - primera_fecha

        if intentos >= UMBRAL_IP and duracion.total_seconds() <= VENTANA_TIEMPO:
            alerta = {
                "tipo": "IP",
                "ip": ip,
                "intentos": intentos,
                "primer_intento": primera_fecha,
                "ultimo_intento": ultima_fecha
            }

            alertas.append(alerta)

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