import hashlib
from copy import deepcopy
from normalizacion import normalizar_atributos, canonicar, calcular_his

# -----------------------------
# Función auxiliar para software (case-sensitive input)
# -----------------------------
def generar_his_software(programas):
    hashes = []

    for app in programas:
        nombre = app["Name"].strip()       # case-sensitive
        version = app["Version"].strip()   # case-sensitive

        entrada = f"{nombre}:{version}"
        h = hashlib.sha256(entrada.encode("utf-8")).hexdigest()
        hashes.append(h)

    hashes.sort()
    inventario_str = "|".join(hashes)

    return hashlib.sha256(inventario_str.encode("utf-8")).hexdigest().upper()

# -----------------------------
# Diccionario base de atributos del dispositivo
# -----------------------------
apps_base = [
    {"Name": "app", "Version": "1.0"},
    {"Name": "prueba", "Version": "2.3"}
]

raw_base = {
    "cpu_id": "BFEBFBFF000806C1",
    "serial_number": "NXA0MEB00A1160D9C73400",
    "mac_original": "0A:00:27:00:00:0E",
    "firmware_hash": "663c81b7cfed5112d0fc382ab439ad1a62ecbd64db6518f6f8ae6f79591d34d6",
    "os_version": "Windows-11-10.0.26200-SP0",
    "public_key_fingerprint": "286d3173f934d9b531ca05f6fe900044e57694bb00a719020f6d5d6bd623bd9a",
    "software_inventory_hash": generar_his_software(apps_base)
}

# -----------------------------
# HIS base
# -----------------------------
norm_base = normalizar_atributos(raw_base)
canon_base = canonicar(norm_base)
his_base = calcular_his(canon_base)
print("HIS original (sin cambios):", his_base)

# -----------------------------
# Cambios a probar en software_inventory
# -----------------------------
cambios_software = {
    "Cambio nombre app": [
        {"Name": "APP", "Version": "1.0"},
        {"Name": "PRUEBA", "Version": "2.3"}
    ],
    "Cambio versión app": [
        {"Name": "app", "Version": "1.1"},
        {"Name": "prueba", "Version": "2.5"}
    ]
}

# -----------------------------
# Probar cambios y mostrar HIS
# -----------------------------
for desc, apps_mod in cambios_software.items():
    raw_mod = deepcopy(raw_base)
    raw_mod["software_inventory_hash"] = generar_his_software(apps_mod)
    
    norm_mod = normalizar_atributos(raw_mod)
    canon_mod = canonicar(norm_mod)
    his_mod = calcular_his(canon_mod)
    
    print("\n-------------------------------")
    print(f"Cambio probado: {desc}")
    print("HIS original:  ", his_base)
    print("HIS modificado:", his_mod)
    print("Cambio detectado?", his_base != his_mod)
