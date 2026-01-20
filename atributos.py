import wmi
import json
import hashlib
import platform
import os
import winreg

# Módulo de normalización y canonicalización
from normalizacion import (
    normalizar_atributos,
    canonicar,
    calcular_his
)


# =========================================
# FUNCIONES PARA OBTENER ATRIBUTOS DEL PC
# =========================================

# Esta función obtiene el ID único del procesador
def get_id_procesador():
    try:
        # Conexión con Windows Management Instrumentation (WMI)
        conexion_wmi = wmi.WMI()
        # Buscamos el primer objeto de procesador
        for procesador in conexion_wmi.Win32_Processor():
            # Devuelve el ID del procesador
            return procesador.ProcessorId.strip()
    except Exception:
        return "ID_CPU_NO_ENCONTRADO"


# Esta función obtiene el número de serie de la BIOS
def get_serie_bios():
    try:
        conexion_wmi = wmi.WMI()
        # Buscamos el objeto de la BIOS
        for info_bios in conexion_wmi.Win32_BIOS():
            # Se devuelve el número de serie
            return info_bios.SerialNumber.strip()
    except Exception:
        return "NUMERO_SERIE_NO_ENCONTRADA"


# Esta función busca la primera dirección MAC de un adaptador físico
def get_mac_principal():
    mac_predeterminada = "MAC_DESCONOCIDA"
    try:
        conexion_wmi = wmi.WMI()
        # Se itera sobre los adaptadores de red
        for tarjeta_red in conexion_wmi.Win32_NetworkAdapter():
            # Se comprueba que sea un adaptador físico y que tenga MAC
            if tarjeta_red.PhysicalAdapter and tarjeta_red.MACAddress:
                return tarjeta_red.MACAddress.strip()
    except Exception:
        pass # Se devuelve el valor por defecto

    return mac_predeterminada


# Esta función crea un hash del firmware
def crear_hash_firmware():
    try:
        conexion_wmi = wmi.WMI()
        # Diccionario para guardar los datos
        datos_hardware = {}

        # Info de la BIOS
        for bios in conexion_wmi.Win32_BIOS():
            datos_hardware["ver_bios"] = bios.SMBIOSBIOSVersion
            datos_hardware["fecha_bios"] = bios.ReleaseDate

        # Info de la envoltura del sistema
        for envoltura in conexion_wmi.Win32_SystemEnclosure():
            datos_hardware["fabricante_envoltura"] = envoltura.Manufacturer
            datos_hardware["ver_envoltura"] = envoltura.Version
            datos_hardware["serie_envoltura"] = envoltura.SerialNumber

        # Se convierte el diccionario en un json ordenado
        datos_crudos = json.dumps(datos_hardware, sort_keys=True)
        # Hash SHA256
        return hashlib.sha256(datos_crudos.encode()).hexdigest()
    except Exception:
        return "HASH_FW_NO_CALCULADO"


# Devuelve la versión del sistema operativo
def get_sistema_operativo():
    try:
        return platform.platform()
    except Exception:
        return "OS_NO_DETECTADO"


# Lee y hashea la clave pública (almacenada en el archivo 'ArchivoClaves')
def huella_clave_publica():
    # Ruta donde Windows guarda la clave de dispositivo
    RUTA_CLAVE_PUB = os.path.join(os.environ["USERPROFILE"], "ArchivoClaves", "mi_clave_publica.pub")
    
    # Comprobamos si el archivo existe primero
    if not os.path.exists(RUTA_CLAVE_PUB):
        return "CLAVE_PUBLICA_NO_EXISTE"

    try:
        # Abrimos la clave pública en modo lectura binaria
        with open(RUTA_CLAVE_PUB, "rb") as archivo_clave:
            contenido_clave = archivo_clave.read()
            # Devolvemos el hash SHA256 del contenido
            return hashlib.sha256(contenido_clave).hexdigest()
    except Exception:
        return "ERROR_AL_LEER_CLAVE"


# Esta función crea un hash del software instalado (por programas)
def crear_hash_software_instalado(debug=False):
    hashes_programas = []

    # Se definen las rutas del Registro de Windows donde se lista el software instalado
    rutas = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    try:
        for root, path in rutas:
            try:
                # Se abre la clave de registro principal para lectura
                with winreg.OpenKey(root, path) as key:
                    # Se itera sobre todas las subclaves que representan un programa
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            # Se obtiene el nombre de la subclave
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                # Se extrae el nombre y la versión del programa
                                nombre = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                # Se limpia de espacios en blanco y se manejan posibles valores nulos
                                nombre = (nombre or "").strip()
                                version = (version or "").strip()

                                # Si no hay nombre, el registro no es útil para identificar software
                                if not nombre:
                                    continue
                                # Se formatea la entrada para que el hash sea consistente
                                entrada = f"{nombre}:{version}"

                                if debug:
                                    print(f"[SOFTWARE] '{entrada}'")

                                # Se crea un hash SHA256 individual para cada programa detectado
                                h = hashlib.sha256(entrada.encode("utf-8")).hexdigest()
                                hashes_programas.append(h)

                        except FileNotFoundError:
                            # Si una subclave no tiene los valores buscados o no se puede leer, se salta
                            continue
                        except OSError:
                            continue
            except FileNotFoundError:
                continue

        # Se ordenan los hashes para que el resultado final sea el mismo
        hashes_programas.sort()
        # Se unen todos los hashes individuales con un separador y se genera el hash final del inventario
        inventario = "|".join(hashes_programas)
        return hashlib.sha256(inventario.encode("utf-8")).hexdigest()
    except Exception:
        return "HASH_SOFTWARE_NO_CALCULADO"

# ==================================
# EJECUCIÓN PRINCIPAL DEL PROGRAMA
# ==================================

if __name__ == "__main__":
    
    print("\n--- ATRIBUTOS DEL ORDENADOR EN CRUDO ---\n")
    
    raw_attrs = {
        "cpu_id": get_id_procesador(),           # ID del procesador
        "serial_number": get_serie_bios(),       # Número de serie de la BIOS
        "mac_original": get_mac_principal(),     # Dirección MAC
        "firmware_hash": crear_hash_firmware(),  # Hash del firmware
        "os_version": get_sistema_operativo(),   # Versión del SO
        "public_key_fingerprint": huella_clave_publica(), # Huella de la clave pública
        "software_inventory_hash": crear_hash_software_instalado() # Hash del software instalado
    }

    # Muestra los datos "en crudo"
    for k, v in raw_attrs.items():
        print(f"{k}: {v}")

    
    print("\n--- NORMALIZACIÓN (Etapa 2) ---\n")
    
    # Llamamos a la función que usa todas las reglas de limpieza definidas
    normalized = normalizar_atributos(raw_attrs)
    
    # Muestra el resultado normalizado.
    for k, v in normalized.items():
        print(f"{k}: {v}")
    
    print("\n--- CANONICALIZACIÓN (Etapa 3) ---\n")
    
    # Convertimos el diccionario limpio en una cadena única y ordenada.
    canonical = canonicar(normalized) 
    
    print("Cadena canónica generada:")
    print("--------------------------------------------------")
    print(canonical)
    print("--------------------------------------------------")
    
    print("\n--- GENERACIÓN DEL HIS ---\n")
    
    # Calculamos el hash SHA256 de la cadena canónica.
    his = calcular_his(canonical)
    
    print("El HIS es:", his) 

    print("\n--- FIN ---\n")


