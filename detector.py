import re
import csv
import os

IPS_SOSPECHOSAS = ["192.168.1.100", "10.0.0.66"]


def resolver_ruta(ruta_usuario):
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

    try:
        with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
            contenido = f.read()

            # Detectar IPs
            ips_encontradas = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', contenido)

            for ip in ips_encontradas:
                if ip in IPS_SOSPECHOSAS:
                    amenazas.append((ip, "IP sospechosa detectada"))

            # Detectar eventos sospechosos
            lineas = contenido.splitlines()

            for linea in lineas:
                linea_lower = linea.lower()

                if (
                    "error" in linea_lower
                    or "failed" in linea_lower
                    or "unauthorized" in linea_lower
                    or "denied" in linea_lower
                    or "warning" in linea_lower
                ):
                    amenazas.append(("N/A", f"Evento sospechoso: {linea.strip()}"))

    except Exception as e:
        print(f"❌ Error leyendo el archivo: {e}")
        return []

    return amenazas


def exportar_csv(amenazas):
    ruta_salida = "threats.csv"

    try:
        with open(ruta_salida, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Descripcion"])

            for amenaza in amenazas:
                writer.writerow(amenaza)

        return ruta_salida

    except Exception as e:
        print(f"❌ Error exportando CSV: {e}")
        return None


if __name__ == "__main__":
    print("=== LOG THREAT DETECTOR ===")

    archivo = input("Ruta del log: ")

    ruta_valida = resolver_ruta(archivo)

    if not ruta_valida:
        print(f"❌ Error: El archivo '{archivo}' no existe.")
    else:
        print(f"\n📂 Analizando: {ruta_valida}")

        resultados = analizar_log(ruta_valida)

        if resultados:
            print("\n🚨 Amenazas detectadas:")
            for r in resultados:
                print(r)

            print(f"\n🔎 Total de eventos detectados: {len(resultados)}")

            archivo_csv = exportar_csv(resultados)

            if archivo_csv:
                print(f"\n📁 Reporte generado: {archivo_csv}")
        else:
            print("✅ No se detectaron amenazas")
