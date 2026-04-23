import re
import csv

# Lista de IPs sospechosas (puedes ampliarla)
IPS_SOSPECHOSAS = ["192.168.1.100", "10.0.0.66"]

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
    with open("threats.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Descripcion"])

        for amenaza in amenazas:
            writer.writerow(amenaza)


if __name__ == "__main__":
    archivo = input("Ruta del log: ")
    
    resultados = analizar_log(archivo)

    if resultados:
        print("\n🚨 Amenazas detectadas:")
        for r in resultados:
            print(r)
        
        exportar_csv(resultados)
        print("\n📁 Reporte generado: threats.csv")
    else:
        print("✅ No se detectaron amenazas")