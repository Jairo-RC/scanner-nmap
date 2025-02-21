# 🚀 Scanner de Puertos con Nmap y VirusTotal

Escáner de puertos avanzado con detección de vulnerabilidades utilizando **Nmap**, integrado con **VirusTotal** para analizar direcciones IP sospechosas. 

---

## 📌 Características
✅ Escaneo de puertos con `nmap`
✅ Detección de vulnerabilidades en servicios
✅ Verificación de IPs en listas negras de **VirusTotal**
✅ **Historial de escaneos** almacenado en SQLite
✅ Exportación de reportes en **CSV y PDF**
✅ **Interfaz gráfica** con **Tkinter**
✅ Envío automático de reportes por correo electrónico

---

## 📥 Instalación y Uso

### 🔧 **Requisitos**
✔ Tener `Python 3.x` instalado
✔ Instalar **Nmap** en el sistema
✔ Obtener una API Key de **VirusTotal**
✔ Configurar el envío de correos para reportes

---

## 🖥 Instalación en **Windows**
1️⃣ **Descargar e instalar Nmap** desde [Nmap Download](https://nmap.org/download.html)
2️⃣ **Instalar dependencias** en PowerShell:
   ```powershell
   pip install requests python-nmap pandas reportlab tk
   ```
3️⃣ **Configurar la API de VirusTotal**:
   - Abre el archivo `scanner.py` y edita esta línea:
   ```python
   VIRUSTOTAL_API_KEY = "TU_API_KEY_AQUI"
   ```
4️⃣ **Ejecutar el escáner**:
   ```powershell
   python scanner.py
   ```

---

## 🐧 Instalación en **Linux (Kali, Ubuntu, Debian)**
Ejecuta estos comandos en la terminal:
```bash
sudo apt update && sudo apt install nmap python3-pip -y
pip install requests python-nmap pandas reportlab tk
```

### 🔑 **Configurar la API de VirusTotal**
Para verificar si una IP está en listas negras, es necesario obtener una API Key:
1. **Regístrate en VirusTotal** en [https://www.virustotal.com](https://www.virustotal.com)
2. Ve a tu perfil y copia tu API Key
3. Edita el archivo `scanner.py` y reemplaza la clave en esta línea:
   ```python
   VIRUSTOTAL_API_KEY = "TU_API_KEY_AQUI"
   ```

---

## 📧 Configurar el Envío de Correos (Opcional)
Para enviar reportes por correo electrónico, configura las variables de entorno con tu correo y contraseña:

### 🔹 **En Windows**
1. Abre **Ejecutar** (`Win + R`), escribe `sysdm.cpl` y presiona Enter.
2. Ve a la pestaña **Opciones avanzadas** → **Variables de entorno**.
3. Crea dos nuevas variables:
   - `EMAIL_SENDER`: Tu dirección de correo (`tucorreo@gmail.com`)
   - `EMAIL_PASSWORD`: Tu contraseña de correo
4. Guarda los cambios y **reinicia el sistema**.

### 🐧 **En Linux/Mac**
Ejecuta en la terminal:
```bash
echo 'export EMAIL_SENDER="tucorreo@gmail.com"' >> ~/.bashrc
echo 'export EMAIL_PASSWORD="tucontraseña"' >> ~/.bashrc
source ~/.bashrc
```
Para **Zsh** (Mac/Linux):
```bash
echo 'export EMAIL_SENDER="tucorreo@gmail.com"' >> ~/.zshrc
echo 'export EMAIL_PASSWORD="tucontraseña"' >> ~/.zshrc
source ~/.zshrc
```
Verifica que las variables se guardaron correctamente:
```bash
echo $EMAIL_SENDER
echo $EMAIL_PASSWORD
```

---

## 📜 Licencia
Este proyecto está bajo la **Licencia MIT**. Siéntete libre de modificar y mejorar el código.

¡Disfruta explorando redes de manera segura! 🚀🔍
