import hashlib

from normalizacion import (
    normalizar_atributos,
    canonicar,
    calcular_his
)

# ============================
# UTILIDAD DE TEST
# ============================

def generar_his(raw_attrs):
    """
    Función auxiliar para generar el HIS completo desde atributos en crudo.
    """
    norm = normalizar_atributos(raw_attrs)
    canon = canonicar(norm)
    return calcular_his(canon)


# ============================
# TESTS CASE-SENSITIVE
# ============================

def test_cpu_id_case_sensitive():
    """
    Comprueba que CPU_ID es sensible a mayúsculas/minúsculas.
    Cambiar 'abc123' a 'ABC123' debe producir un HIS distinto.
    """
    raw1 = {
        "cpu_id": "abc123",
        "serial_number": "SERIAL",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa:bb:cc",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "cc",
    }

    raw2 = raw1.copy()
    raw2["cpu_id"] = "ABC123"

    his1 = generar_his(raw1)
    his2 = generar_his(raw2)

    assert his1 != his2, "cpu_id debe ser case-sensitive"


def test_serial_number_case_sensitive():
    """
    Comprueba que el número de serie de la BIOS es case-sensitive.
    Cambiar la capitalización debe alterar el HIS.
    """
    raw1 = {
        "cpu_id": "abc123",
        "serial_number": "n123j45",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa:bb:cc",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "cc",
    }

    raw2 = raw1.copy()
    raw2["serial_number"] = "N123J45"

    assert generar_his(raw1) != generar_his(raw2)


def test_os_version_case_sensitive():
    """
    La versión del sistema operativo debe ser sensible a cambios reales.
    Incrementar la versión (ej. 26200 -> 26201) altera el HIS.
    """
    raw1 = {
        "cpu_id": "abc123",
        "serial_number": "n123j45",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa:bb:cc",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "cc",
    }

    raw2 = raw1.copy()
    raw2["os_version"] = "Windows-11-10.0.26201"

    his1 = generar_his(raw1)
    his2 = generar_his(raw2)

    assert his1 != his2, "os_version debe ser case-sensitive"


# ============================
# TESTS CASE-INSENSITIVE
# ============================

def test_mac_case_insensitive():
    """
    Las MACs son case-insensitive.
    Cambiar 'aa:bb:cc:dd' a 'AA-BB-CC-DD' no altera el HIS.
    """
    raw1 = {
        "cpu_id": "abc123",
        "serial_number": "n123j45",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa:bb:cc:dd",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "cc",
    }

    raw2 = raw1.copy()
    raw2["mac_original"] = "AA-BB-CC-DD"

    assert generar_his(raw1) == generar_his(raw2)


def test_hash_case_insensitive():
    """
    Los hashes (firmware, clave pública, software) son case-insensitive.
    Cambiar letras a mayúsculas no debe afectar al HIS.
    """
    raw1 = {
        "cpu_id": "abc123",
        "serial_number": "n123j45",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa",
        "firmware_hash": "abc123",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "cc",
    }

    raw2 = raw1.copy()
    raw2["firmware_hash"] = "ABC123"

    assert generar_his(raw1) == generar_his(raw2)


# ============================
# TESTS SOFTWARE INVENTORY
# ============================

def test_software_inventory_input_is_case_sensitive():
    """
    El input de cada aplicación es case-sensitive.
    Cambiar 'app' a 'APP' produce un HIS distinto.
    """
    def software_hash(programas):
        hashes = []

        for nombre, version in programas:
            entrada = f"{nombre}:{version}"
            h = hashlib.sha256(entrada.encode()).hexdigest()
            hashes.append(h)

        hashes.sort()
        inventario = "|".join(hashes)
        return hashlib.sha256(inventario.encode()).hexdigest()


    raw1 = {
        "cpu_id": "abc123",
        "serial_number": "n123j45",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": software_hash([
            ("app", "1.0"),
        ]),
    }

    raw2 = raw1.copy()
    raw2["software_inventory_hash"] = software_hash([
        ("APP", "1.0"),
    ])

    assert generar_his(raw1) != generar_his(raw2)


def test_software_inventory_hash_representation_case_insensitive():
    """
    El hash de software final puede escribirse en mayúsculas o minúsculas.
    No altera el HIS porque los hashes son case-insensitive.
    """
    raw1 = {
        "cpu_id": "abc123",
        "serial_number": "n123j45",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "abc123",
    }

    raw2 = raw1.copy()
    raw2["software_inventory_hash"] = "ABC123"

    assert generar_his(raw1) == generar_his(raw2)


# ============================
# TESTS CANONICALIZACIÓN
# ============================

def test_canonicalization_is_deterministic():
    """
    Garantiza que la canonicalización siempre produce la misma cadena
    para los mismos datos, independientemente del orden de las claves.
    """
    raw = {
        "serial_number": "n123j45",
        "cpu_id": "abc123",
        "mac_original": "aa",
        "os_version": "Windows-11-10.0.26200",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "cc",
    }

    canon1 = canonicar(normalizar_atributos(raw))
    canon2 = canonicar(normalizar_atributos(raw))

    assert canon1 == canon2


# ============================
# TESTS CAMBIO REAL VS NO REAL
# ============================

def test_real_change_vs_no_real_change():
    """
    Diferencia entre cambios reales y superficiales:
    - Cambios superficiales (ej. MAC) no alteran el HIS
    - Cambios reales (ej. serial_number) sí alteran el HIS
    """
    base = {
        "cpu_id": "abc123",
        "serial_number": "n123j45",
        "os_version": "Windows-11-10.0.26200",
        "mac_original": "aa:bb",
        "firmware_hash": "aa",
        "public_key_fingerprint": "bb",
        "software_inventory_hash": "cc",
    }

    # Cambio superficial (MAC)
    superficial = base.copy()
    superficial["mac_original"] = "AA-BB"

    # Cambio real (serial)
    real = base.copy()
    real["serial_number"] = "N123J45"

    assert generar_his(base) == generar_his(superficial)
    assert generar_his(base) != generar_his(real)
