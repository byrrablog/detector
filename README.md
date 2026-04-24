# 🛡️ Log Threat Detector

Python tool for analyzing logs and detecting suspicious activity, simulating SOC (Security Operations Center) workflows.

---

**Log Threat Detector** es un script diseñado para automatizar el análisis de logs y detectar comportamientos potencialmente maliciosos.

Este proyecto está orientado a:

- Estudiantes de ciberseguridad  
- Análisis básico de incidentes  
- Entornos pequeños o educativos  
- Introducción al procesamiento de logs  

---

## 🔍 ¿Qué detecta?

El sistema analiza:

### 🌐 IPs sospechosas
Compara direcciones IP encontradas en los logs contra una lista predefinida.

### ⚠️ Eventos críticos
Busca palabras clave asociadas a incidentes:

- `error`
- `failed`
- `unauthorized`
- `denied`
- `warning`

---

## ⚙️ Requisitos

- Python 3.x  
- Sistema operativo: Windows / Linux / macOS  
- Sin dependencias externas  

---

## 🚀 Instalación

Clona el repositorio:

```bash
git clone https://github.com/tuusuario/log-threat-detector.git
cd log-threat-detector ```
```
``` bash
python detector.py```
```
Input:

```text
sample_log.txt
```

---

## 📊 Example Output

```
🚨 Amenazas detectadas:
('192.168.1.100', 'IP sospechosa detectada')
('N/A', 'Error detectado en log')
```

---

## 👤 Author

Bayron Cares

