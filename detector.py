print ("SSH Brute Force Detector")

log = open("auth.log", "r")

log_failed = log.read()

linea = log_failed.splitlines()

fallos_contador = 0


for failed in linea:
    if "Failed password" in failed and "sshd-session" in failed:
        fallos_contador += 1

        partes = failed.split()

        ip = partes[8]

        print(failed)
        print("IP atacante:", ip)

print("Total de fallos intentados:" ,fallos_contador)
