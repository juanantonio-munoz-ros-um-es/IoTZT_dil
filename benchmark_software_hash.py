import time
import hashlib
import wmi
import winreg
import pandas as pd
import matplotlib.pyplot as plt

# --- Funciones de obtención de datos ---

# Usa WMI para obtener el inventario de software instalado
def crear1_hash_software_instalado():
    try:
        conexion_wmi = wmi.WMI()
        hashes_programas = []
        for app in conexion_wmi.Win32_Product():
            nombre = (app.Name or "").strip()
            version = (app.Version or "").strip()
            entrada = f"{nombre}:{version}"
            h = hashlib.sha256(entrada.encode("utf-8")).hexdigest()
            hashes_programas.append(h)
        hashes_programas.sort()
        inventario = "|".join(hashes_programas)
        return hashlib.sha256(inventario.encode("utf-8")).hexdigest()
    except Exception:
        return "HASH_SOFTWARE_NO_CALCULADO"

# Usa el Registro de Windows para obtener el inventario de software instalado
def crear_hash_software_instalado():
    hashes_programas = []
    rutas = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    try:
        for root, path in rutas:
            try:
                with winreg.OpenKey(root, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    nombre = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    entrada = f"{nombre.strip()}:{version.strip()}"
                                    hashes_programas.append(hashlib.sha256(entrada.encode("utf-8")).hexdigest())
                                except: continue
                        except: continue
            except: continue
        hashes_programas.sort()
        return hashlib.sha256("|".join(hashes_programas).encode("utf-8")).hexdigest()
    except Exception:
        return "HASH_SOFTWARE_NO_CALCULADO"


# Función para ejecutar el benchmark y comparar el rendimiento de dos métodos
def ejecutar_benchmark(iteraciones=20):
    resultados = []
    print(f"Iniciando benchmark: {iteraciones} iteraciones por método.")
    
    for i in range(1, iteraciones + 1):
        print(f"Ejecutando iteración {i}/{iteraciones}...", end="\r")
        
        # Medición del Método 1: WMI
        t0 = time.perf_counter()
        crear1_hash_software_instalado()
        t_wmi = time.perf_counter() - t0
        
        # Medición del Método 2: Registro de Windows
        t1 = time.perf_counter()
        crear_hash_software_instalado()
        t_reg = time.perf_counter() - t1
        
        # Almacenar los tiempos y calcular cuántas veces es más rápido el registro
        resultados.append({
            "Iteración": i,
            "WMI (s)": t_wmi,
            "Registro (s)": t_reg,
            "Diferencia (x)": t_wmi / t_reg if t_reg > 0 else 0
        })

    return pd.DataFrame(resultados)

if __name__ == "__main__":
    df_detalle = ejecutar_benchmark(iteraciones=20)

    # Calcular estadísticas
    resumen = df_detalle[["WMI (s)", "Registro (s)", "Diferencia (x)"]].agg(['mean', 'min', 'max', 'std'])
    resumen.index = ['Media', 'Mínimo', 'Máximo', 'Desv. Estándar']
    
    # Redondear a 3 decimales
    df_detalle = df_detalle.round(3)
    resumen = resumen.round(3)

    # Exportar a Excel 
    nombre_archivo = "Benchmark_Software_Inventory.xlsx"
    with pd.ExcelWriter(nombre_archivo) as writer:
        # Primera tabla
        df_detalle.to_excel(writer, sheet_name="Benchmark", index=False)
        
        # Calculamos la fila de inicio para la segunda tabla
        start_row = len(df_detalle) + 3
        
        # Segunda tabla
        resumen.to_excel(writer, sheet_name="Benchmark", startrow=start_row)
    
    print(f"\n[OK] Archivo '{nombre_archivo}' generado. Ambas tablas están en la pestaña 'Benchmark'.")

    # Gráfico
    plt.figure(figsize=(10, 6))
    plt.plot(df_detalle["Iteración"], df_detalle["WMI (s)"], label="WMI (Win32_Product)", color="red")
    plt.plot(df_detalle["Iteración"], df_detalle["Registro (s)"], label="Registro de Windows", color="green")
    plt.yscale("log")
    plt.xlabel("Número de Iteración")
    plt.ylabel("Tiempo (segundos) - Escala Log")
    plt.title("Estabilidad de rendimiento: WMI vs Registro")
    plt.legend()
    plt.grid(True, which="both", ls="-", alpha=0.5)
    plt.tight_layout()
    plt.show()