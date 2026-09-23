# SSH Brute Force Detector

Herramienta desarrollada en Python para detectar posibles ataques de fuerza bruta contra SSH a partir de los registros de autenticación de un servidor Linux.

El detector se conecta remotamente al servidor mediante **SSH usando Paramiko**, obtiene `/var/log/auth.log`, analiza los intentos fallidos de autenticación y genera alertas cuando se supera un determinado número de intentos dentro de una ventana temporal.

## Características

* Conexión remota mediante SSH.
* Lectura de `/var/log/auth.log`.
* Detección de intentos fallidos de autenticación SSH.
* Identificación de IP de origen y usuario objetivo.
* Conteo de intentos por combinación IP + usuario.
* Conteo de intentos totales por IP.
* Detección mediante una ventana temporal deslizante.
* Generación de alertas cuando se superan los umbrales configurados.
* Filtrado de líneas que no corresponden realmente a eventos SSH para reducir falsos positivos.

## Arquitectura

```text
┌──────────────────────┐
│    Windows / PC      │
│                      │
│  SSH Brute Force     │
│      Detector        │
└──────────┬───────────┘
           │
           │ SSH / Paramiko
           ▼
┌──────────────────────┐
│    Ubuntu Server     │
│                      │
│   /var/log/auth.log  │
└──────────┬───────────┘
           │
           │
           ▼
┌──────────────────────┐
│    Análisis Python   │
│                      │
│  IP + usuario        │
│  IP total            │
│  Ventana temporal    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│       Alertas        │
└──────────────────────┘
```

## Detección

El proyecto utiliza dos reglas principales.

### 1. Fuerza bruta contra un usuario

Se genera una alerta cuando una misma combinación de:

```text
IP + usuario
```

alcanza al menos **6 intentos fallidos dentro de 60 segundos**.

Configuración actual:

```python
UMBRAL_USUARIO = 6
VENTANA_TIEMPO = 60
```

### 2. Fuerza bruta por IP

También se comprueba el número total de intentos procedentes de una misma IP.

Configuración actual:

```python
UMBRAL_IP = 10
VENTANA_TIEMPO = 60
```

La detección utiliza una **ventana deslizante**, por lo que no compara simplemente el primer y último evento de todo el historial del log.

Por ejemplo, si existen estos eventos:

```text
22:47:15
22:47:19
22:47:23
22:47:29
22:47:32
22:47:37
```

los seis intentos ocurren en 22 segundos y cumplen la regla de detección.

## Requisitos

* Python 3
* Paramiko
* Un servidor Linux con SSH habilitado
* Acceso al archivo `/var/log/auth.log`

## Instalación

Clona el repositorio:

```bash
git clone https://github.com/TU-USUARIO/ssh-detector.git
cd ssh-detector
```

Instala la dependencia:

```bash
pip install paramiko
```

También puedes instalar las dependencias desde `requirements.txt`:


## Uso

Ejecuta:

```bash
python detector.py
```

El programa solicitará:

```text
Introduce la IP del servidor:
Introduce el puerto SSH (por defecto 22):
Introduce el nombre de usuario:
Introduce la contraseña:
```

Después se conectará al servidor, ejecutará:

```bash
cat /var/log/auth.log
```

y analizará los registros obtenidos.

### Ejemplo

Una detección puede producir:

```text
Alerta: La IP 192.168.x.x ha realizado 6 intentos.
Posible ataque de fuerza bruta al usuario enrique
Primer intento: 2026-09-23 22:47:15.037535+00:00
Último intento: 2026-09-23 22:47:37.543742+00:00
------------------------------
```

## Estructura del proyecto

```text
ssh-detector/
│
├── detector.py
├── requirements.txt
└── README.md
```

## Tecnologías utilizadas

* **Python**
* **Paramiko**
* **SSH**
* **Linux**
* **Logs de autenticación**
* **Detección basada en reglas**
* **Análisis temporal de eventos**

## Lo que he aprendido desarrollando este proyecto

Durante el desarrollo he trabajado con:

* Lectura y análisis de logs reales.
* Parsing de líneas mediante `split()`.
* Uso de diccionarios para agrupar eventos.
* Trabajo con tuplas como claves de diccionario.
* Manejo de fechas y timestamps con `datetime`.
* Diseño de ventanas temporales para detección.
* Comunicación SSH desde Python mediante Paramiko.
* Separación de funcionalidades mediante funciones.
* Identificación y corrección de falsos positivos.

Uno de los problemas encontrados durante las pruebas fue que una línea de `sudo` que contenía el texto `sshd-session` y `Failed password` podía ser interpretada como un intento SSH. Para solucionarlo, el parser pasó a comprobar la estructura real de las líneas del servicio `sshd-session`.

## Limitaciones actuales

Este proyecto está pensado como una herramienta de **laboratorio y portfolio**, no como un sistema de detección listo para producción.

Actualmente quedan pendientes, entre otras, mejoras como:

* Manejo más completo de errores de conexión SSH.
* Validación estricta de claves de host SSH.
* Parser más robusto para diferentes formatos de logs.
* Persistencia de las alertas.
* Evitar alertas duplicadas.
* Monitorización continua.
* Configuración externa de umbrales.
* Exportación de resultados.

## Próximas mejoras

La evolución prevista del proyecto incluye:

```text
Versión actual
    ↓
Persistencia de alertas
    ↓
Monitorización continua
    ↓
Control de eventos ya procesados
    ↓
Exportación de resultados
    ↓
Mejoras de seguridad SSH
    ↓
Dashboard / visualización
```

## Disclaimer

Este proyecto ha sido desarrollado con fines educativos y de laboratorio para practicar Python, Linux, SSH y conceptos básicos de detección de amenazas.

No debe utilizarse como sustituto de una solución profesional de monitorización o SIEM.
