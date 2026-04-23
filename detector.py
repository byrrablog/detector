import re
import csv
import os

# Lista de IPs sospechosas
IPS_SOSPECHOSAS = ["192.168.1.100", "10.0.0.66"]


def resolver_ruta(ruta_usuario):
    """
    Permite usar:
    - nombre simple (sample_log.txt)
    - ruta completa
    - archivo en la misma carpeta del script
    """
    ruta_usuario = ruta_usuario.strip().replace('"', '').replace("'", "").replace("&", "")

    if os.path.exists(ruta_usuario):
        return ruta_usuario

    ruta_script = os.path.dirname(os.path.abspath(__file__))
    ruta_completa = os.path.join(ruta_script, ruta_usuario)

    if os.path.exists(ruta_completa):
        return ruta_completa

    return None


def analizar_log(ruta):
    amenazas = []

    with open(ruta, "r") as f:
        for linea in f:
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', linea)

            if ip_match:
                ip = ip_match.group()

                if ip in IPS_SOSPECHOSAS:
                    amenazas.append((ip, "IP sospechosa detectada"))

            if "error" in linea.lower():
                amenazas.append(("N/A", "Error detectado en log"))

    return amenazas


def exportar_csv(amenazas):
    ruta_salida = "threats.csv"

    with open(ruta_salida, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Descripcion"])

        for amenaza in amenazas:
            writer.writerow(amenaza)

    return ruta_salida


if __name__ == "__main__":
    print("=== LOG THREAT DETECTOR ===")

    archivo = input("Ruta del log: ")

    ruta_valida = resolver_ruta(archivo)

    if not ruta_valida:
        print(f"❌ Error: El archivo '{archivo}' no existe.")
    else:
        resultados = analizar_log(ruta_valida)

        if resultados:
            print("\n🚨 Amenazas detectadas:")
            for r in resultados:
                print(r)

            print(f"\n🔎 Total de eventos detectados: {len(resultados)}")

            archivo_csv = exportar_csv(resultados)
            print(f"\n📁 Reporte generado: {archivo_csv}")

        else:
            print("✅ No se detectaron amenazas")
