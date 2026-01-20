import re
import hashlib
from enum import Enum, auto

# =============================
# POLÍTICA DE CASE
# =============================

class CasePolicy(Enum):
    SENSITIVE = auto()
    INSENSITIVE = auto()


ATTRIBUTE_POLICY = {
    "cpu_id": CasePolicy.SENSITIVE,
    "serial_number": CasePolicy.SENSITIVE,
    "os_version": CasePolicy.SENSITIVE,

    "mac_original": CasePolicy.INSENSITIVE,
    "firmware_hash": CasePolicy.INSENSITIVE,
    "public_key_fingerprint": CasePolicy.INSENSITIVE,

    # HASH case-insensitive, pero su input ya fue case-sensitive
    "software_inventory_hash": CasePolicy.INSENSITIVE,
}

HEX_CHARS_RE = re.compile(r'[^0-9A-F]', re.IGNORECASE)
VERSION_NUM_RE = re.compile(r"(\d+-\d+(?:\.\d+)*)")

# Elimina los espacios en blanco alrededor y convierte a cadena
def limpiar_basico(s):
    if s is None:
        return ""
    return str(s).strip()

# Establece el case según la política
def normalizar_case(val, policy: CasePolicy):
    s = limpiar_basico(val)
    if policy == CasePolicy.INSENSITIVE:
        return s.upper()
    return s


# =============================
# NORMALIZADORES ESPECÍFICOS
# =============================

# Elimina separadores, pasa a mayúsculas
def normalizar_mac(mac):
    s = limpiar_basico(mac)
    s = HEX_CHARS_RE.sub('', s)
    return s.upper()

# Elimina prefijo 0x, separadores, pasa a mayúsculas
def normalizar_hash_hex(h):
    s = limpiar_basico(h)
    if s.lower().startswith("0x"):
        s = s[2:]
    s = re.sub(r'[\s:-]', '', s)
    s = HEX_CHARS_RE.sub('', s)
    return s.upper()

# Extrae la parte numérica de la versión
def normalizar_version(v):
    s = limpiar_basico(v)
    m = VERSION_NUM_RE.search(s)
    return m.group(1) if m else ""


# =============================
# NORMALIZACIÓN PRINCIPAL
# =============================

# Normaliza todos los atributos según las reglas definidas
def normalizar_atributos(raw):
    # Se convierten todas las claves a minúsculas para acceso consistente
    rd = {k.lower(): v for k, v in raw.items()}
    
    # Diccionario donde se guardarán los valores normalizados
    norm = {}

    # Se recorre cada atributo y su política de case
    for attr, policy in ATTRIBUTE_POLICY.items():
        # Se obtiene el valor del atributo y si no existe usamos cadena vacía
        val = rd.get(attr, "")
    
        # Normalización específica según tipo de atributo

        if attr == "mac_original":
            # MACs son case-insensitive y deben limpiarse de separadores (:, -, .)
            # El resultado se convierte a mayúsculas para consistencia
            norm[attr] = normalizar_mac(val)

        elif attr in {
            "firmware_hash",
            "public_key_fingerprint",
            "software_inventory_hash"
        }:
            # Hashes hexadecimales son case-insensitive y deben limpiarse de caracteres extra
            norm[attr] = normalizar_hash_hex(val)

        elif attr == "os_version":
            # La versión del sistema operativo se extrae de la cadena completa
            # Se eliminan sufijos irrelevantes y se obtiene un formato determinista
            norm[attr] = normalizar_version(val)

        else:
            # Para todos los demás atributos sensibles al case (SENSITIVE),
            # se aplica la política definida:
            # - SENSITIVE: se conserva original
            # - INSENSITIVE: se convierte a mayúsculas
            norm[attr] = normalizar_case(val, policy)
    return norm


# =============================
# CANONICALIZACIÓN
# =============================

# Esta función convierte el diccionario normalizado en una cadena canonizada única y ordenada
def canonicar(normalized_dict, sep='|', kvsep='='):
    def limpiar_valor(v):
        return str(v).replace('\n', '').replace('\r', '').replace('\t', '').strip()

    parts = []
    for k in sorted(normalized_dict.keys()):
        parts.append(f"{k}{kvsep}{limpiar_valor(normalized_dict[k])}")

    return sep.join(parts)


# =============================
# HASH FINAL
# =============================

# Calcula el HIS a partir de la cadena canonizada
def calcular_his(cadena_canonizada):
    h = hashlib.sha256()
    h.update((cadena_canonizada or "").encode("utf-8"))
    return h.hexdigest().upper()
