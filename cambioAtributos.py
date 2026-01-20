import hashlib
from copy import deepcopy
from normalizacion import normalizar_atributos, canonicar, calcular_his

# -----------------------------
# Diccionario base de atributos del dispositivo
# -----------------------------
raw_base = {
    "cpu_id": "BFEBFBFF000806C1",
    "serial_number": "NXA0MEB00A1160D9C73400",
    "mac_original": "0A:00:27:00:00:0E",
    "firmware_hash": "663c81b7cfed5112d0fc382ab439ad1a62ecbd64db6518f6f8ae6f79591d34d6",
    "os_version": "Windows-11-10.0.26200-SP0",
    "public_key_fingerprint": "286d3173f934d9b531ca05f6fe900044e57694bb00a719020f6d5d6bd623bd9a",
    "software_inventory_hash": "66d6431949b60908aba658a215a21ff81b73f21dccbd5d2d673592dc851f0116"
}

# -----------------------------
# HIS base
# -----------------------------
norm_base = normalizar_atributos(raw_base)
canon_base = canonicar(norm_base)
his_base = calcular_his(canon_base)
print("HIS original (sin cambios):", his_base)

# -----------------------------
# Cambios a probar
# -----------------------------
cambios = {
    "CPU case": lambda x: {"cpu_id": "bfebfbff000806c1"},
    "CPU alterado": lambda x: {"cpu_id": "BFEBFBFF000806C2"},
    "Serial case": lambda x: {"serial_number": "nxa0meb00a1160d9c73400"},
    "Serial alterado": lambda x: {"serial_number": "NXA0MEB00A1160D9C73401"},
    "MAC formato": lambda x: {"mac_original": "0a-00-27-00-00-0e"},
    "MAC case": lambda x: {"mac_original": "0b-00-27-00-00-0e"},
    "OS case": lambda x: {"os_version": "windows-11-10.0.26200-sp0"},
    "OS versión": lambda x: {"os_version": "Windows-11-10.0.26201-SP0"},
    "Software nombre app (simulado)": lambda x: {"software_inventory_hash": "66D6431949B60908ABA658A215A21FF81B73F21DCCBD5D2D673592DC851F0116"},
}

# -----------------------------
# Probar cambios y mostrar HIS
# -----------------------------
for desc, cambio_func in cambios.items():
    raw_mod = deepcopy(raw_base)
    raw_mod.update(cambio_func(raw_base))
    norm_mod = normalizar_atributos(raw_mod)
    canon_mod = canonicar(norm_mod)
    his_mod = calcular_his(canon_mod)
    
    print("\n-------------------------------")
    print(f"Cambio probado: {desc}")
    print("HIS original:  ", his_base)
    print("HIS modificado:", his_mod)
    print("Cambio detectado?", his_base != his_mod)
