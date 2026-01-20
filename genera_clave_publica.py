from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os


# ==================================================
# FUNCIÓN PARA CREAR CLAVES ASIMÉTRICAS
# ==================================================

def crear_par_de_claves_seguras():
    """
    Esta función genera un par de claves RSA (Pública y Privada)
    y las guarda en la carpeta de usuario.
    """

    # Definimos la carpeta de trabajo, usando "MisArchivos" para que sea más claro
    CARPETA_BASE = os.path.join(os.environ["USERPROFILE"], "ArchivoClaves")

    # Si no existe carpeta se crea
    os.makedirs(CARPETA_BASE, exist_ok=True)

    # Nombres de archivos para las claves
    RUTA_CLAVE_PUBLICA = os.path.join(CARPETA_BASE, "mi_clave_publica.pub")
    RUTA_CLAVE_PRIVADA = os.path.join(CARPETA_BASE, "mi_clave_privada.pem")

    print("\n--- Iniciando generación de claves RSA ---")
    print(f"Los archivos se guardarán aquí: {CARPETA_BASE}\n")

    # ==============================
    # 1. GENERAR LAS CLAVES
    # ==============================
    # Tamaño de 2048 bits
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # La clave pública se saca directamente de la privada
    clave_publica = clave_privada.public_key()

    # ==============================
    # 2. GUARDAR clave PRIVADA (.pem)
    # ==============================
    datos_privados = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM, # Formato de codificación PEM
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # Sin contraseña para la prueba
    )

    # Escribimos los datos en el archivo binario
    with open(RUTA_CLAVE_PRIVADA, "wb") as archivo_privado:
        archivo_privado.write(datos_privados)

    # ==============================
    # 3. GUARDAR clave PÚBLICA (.pub)
    # ==============================
    datos_publicos = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Escribimos los datos en el archivo binario
    with open(RUTA_CLAVE_PUBLICA, "wb") as archivo_publico:
        archivo_publico.write(datos_publicos)

    # ==============================
    print(f" La clave privada está en:\n  {RUTA_CLAVE_PRIVADA}")
    print(f" La clave pública está en:\n  {RUTA_CLAVE_PUBLICA}")

    print("\n--- Proceso terminado ---\n")


if __name__ == "__main__":
    crear_par_de_claves_seguras()