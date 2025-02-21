import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
import nmap
import pandas as pd
import datetime
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from threading import Thread
import os
import smtplib
import sqlite3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Configuración segura del correo
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# 🔹 CONFIGURACIÓN DE VIRUSTOTAL API 🔹
VIRUSTOTAL_API_KEY = "tu_api_aqui"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


if not EMAIL_PASSWORD or not EMAIL_SENDER:
    raise ValueError("⚠ ERROR: No se encontraron las credenciales en variables de entorno.")

# Conectar a la base de datos SQLite para el historial
conn = sqlite3.connect("historial.db")
cursor = conn.cursor()

# Crear la tabla para guardar el historial, si no existe
cursor.execute("""
    CREATE TABLE IF NOT EXISTS escaneos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT,
        ip TEXT,
        puertos TEXT,
        archivo TEXT,
        virustotal_result TEXT
    )
""")
conn.commit()


# 🔹 Función para escanear puertos 🔹
def escanear_puertos(host, puertos="1-65535"):
    scanner = nmap.PortScanner()
    print(f"🔍 Escaneando {host} en los puertos {puertos} con detección de vulnerabilidades...\n")
    scanner.scan(host, puertos, arguments="-sS -sV -O --script vuln")
    resultados = []

    fecha_hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for ip in scanner.all_hosts():
        os_info = scanner[ip]['osmatch'][0]['name'] if 'osmatch' in scanner[ip] and scanner[ip]['osmatch'] else "Desconocido"
        reporte_virustotal = verificar_ip_virustotal(ip)  # 🔹 Se agrega la verificación de VirusTotal

        if 'tcp' in scanner[ip]:
            for puerto in scanner[ip]['tcp']:
                estado = scanner[ip]['tcp'][puerto]['state']
                servicio = scanner[ip]['tcp'][puerto]['name']
                version = scanner[ip]['tcp'][puerto]['version']
                vulnerabilidades = scanner[ip]['tcp'][puerto].get('script', {})

                resultados.append({
                    "Fecha y Hora": fecha_hora,
                    "IP": ip,
                    "Puerto": puerto,
                    "Estado": estado,
                    "Servicio": servicio,
                    "Versión": version,
                    "Sistema Operativo": os_info,
                    "Vulnerabilidades": ", ".join(vulnerabilidades.keys()) if vulnerabilidades else "Ninguna detectada",
                    "VirusTotal": reporte_virustotal  # 🔹 Agregamos el resultado de VirusTotal
                })

    return resultados

# 🔹 Función para verificar IPs en VirusTotal 🔹
def verificar_ip_virustotal(ip):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(VIRUSTOTAL_URL + ip, headers=headers)

    if response.status_code == 200:
        data = response.json()
        try:
            detecciones = data["data"]["attributes"]["last_analysis_stats"]
            total_detecciones = detecciones["malicious"] + detecciones["suspicious"]
            if total_detecciones > 0:
                return f"⚠ {total_detecciones} reportes de actividad maliciosa en VirusTotal."
            else:
                return "✅ Sin reportes maliciosos en VirusTotal."
        except KeyError:
            return "❓ No hay información suficiente en VirusTotal."
    else:
        return "⚠ Error al conectar con VirusTotal."

# Función para guardar el reporte y añadir al historial
def guardar_reporte(datos, host, puertos):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    df = pd.DataFrame(datos)
    archivo_csv = f"reporte_nmap_{timestamp}.csv"
    df.to_csv(archivo_csv, index=False)

    # Crear una nueva conexión SQLite en el hilo actual
    with sqlite3.connect("historial.db") as conn_thread:
        cursor_thread = conn_thread.cursor()
        cursor_thread.execute("INSERT INTO escaneos (fecha, ip, puertos, archivo) VALUES (?, ?, ?, ?)",
                              (timestamp, host, puertos, archivo_csv))
        conn_thread.commit()

    print(f"✅ Reporte guardado en {archivo_csv}")
    return archivo_csv


# Función para enviar el reporte por correo
def enviar_reporte(archivo, correo_destinatario):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = correo_destinatario
        msg["Subject"] = "🔍 Reporte de Escaneo Nmap"
        msg.attach(MIMEText("Adjunto el reporte del escaneo realizado.", "plain"))

        with open(archivo, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={archivo}")
            msg.attach(part)

        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, correo_destinatario, msg.as_string())
        server.quit()
        print("📧 Correo enviado correctamente.")
    except Exception as e:
        print(f"⚠ Error al enviar correo: {e}")

# Función para exportar a PDF en tablas
def exportar_a_pdf():
    archivo_pdf = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if archivo_pdf:
        try:
            datos = cursor.execute("SELECT fecha, ip, puertos, archivo FROM escaneos ORDER BY id DESC").fetchall()
            doc = SimpleDocTemplate(archivo_pdf, pagesize=letter)
            elementos = []
            encabezados = ["Fecha", "IP", "Puertos", "Archivo"]
            tabla = [encabezados] + datos
            tabla_estilo = TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ])
            tabla_objeto = Table(tabla)
            tabla_objeto.setStyle(tabla_estilo)
            elementos.append(tabla_objeto)
            doc.build(elementos)
            messagebox.showinfo("Exportado", "Reporte guardado en PDF con formato tabular.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar el PDF: {e}")

# Función para mostrar el historial
def ver_historial():
    historial = tk.Toplevel(root)
    historial.title("Historial de Escaneos")
    historial.geometry("500x300")
    lista = tk.Listbox(historial, width=80, height=15)
    lista.pack(pady=10)
    for row in cursor.execute("SELECT fecha, ip, puertos, archivo FROM escaneos ORDER BY id DESC"):
        lista.insert(tk.END, f"{row[0]} - IP: {row[1]} - Puertos: {row[2]} - Archivo: {row[3]}")

# Función para ejecutar el escaneo con barra de progreso
def ejecutar_escaneo_con_progreso():
    progress_label["text"] = ""
    host = entry_ip.get()
    puertos = entry_puertos.get() or "1-65535"
    correo_destinatario = entry_correo.get()

    if not host or not correo_destinatario:
        messagebox.showerror("Error", "Debe ingresar una IP, puertos y un correo")
        return

    progress_bar["value"] = 0
    progress_bar["maximum"] = 100
    progress_label["text"] = "Escaneando, por favor espere..."

    def ejecutar_y_actualizar():
        for i in range(1, 101, 10):
            progress_bar["value"] = i
            time.sleep(0.1)

        resultados = escanear_puertos(host, puertos)
        if resultados:
            archivo = guardar_reporte(resultados, host, puertos)
            enviar_reporte(archivo, correo_destinatario)
            progress_label["text"] = f"Escaneo completado. Reporte enviado a {correo_destinatario}."
            messagebox.showinfo("Escaneo Completado", f"El escaneo ha finalizado.\nEl reporte fue enviado a {correo_destinatario}.")
        else:
            progress_label["text"] = "No se encontraron puertos abiertos."
            messagebox.showinfo("Escaneo Completado", "No se encontraron puertos abiertos.")

        entry_ip.delete(0, tk.END)
        entry_puertos.delete(0, tk.END)
        entry_correo.delete(0, tk.END)

    thread = Thread(target=ejecutar_y_actualizar)
    thread.start()
    
    

# Crear la ventana principal
root = tk.Tk()
root.title("Escáner de Puertos con Nmap - by JairoRC")
root.geometry("500x550")
root.resizable(False, False)

background_color = "#f0f0f0"
root.configure(bg=background_color)

style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background=background_color, foreground="black", font=("Arial", 12))
style.configure("TEntry", fieldbackground="white", foreground="black")
style.configure("TButton", background=background_color, foreground="black")

ttk.Label(root, text="🔒 Escáner Nmap", font=("Arial", 16, "bold")).pack(pady=10)
ttk.Label(root, text="IP o Rango de IPs:").pack(anchor="w", padx=20)
entry_ip = ttk.Entry(root, width=50)
entry_ip.pack(pady=5)
ttk.Label(root, text="Rango de Puertos:").pack(anchor="w", padx=20)
entry_puertos = ttk.Entry(root, width=50)
entry_puertos.pack(pady=5)
ttk.Label(root, text="Correo Destinatario:").pack(anchor="w", padx=20)
entry_correo = ttk.Entry(root, width=50)
entry_correo.pack(pady=5)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)
progress_label = ttk.Label(root, text="", font=("Arial", 10), background=background_color)
progress_label.pack()

button_frame = ttk.Frame(root)
button_frame.pack(pady=20)
iniciar_btn = ttk.Button(button_frame, text="Iniciar Escaneo", width=20, command=ejecutar_escaneo_con_progreso)
iniciar_btn.grid(row=0, column=0, padx=10, pady=5)
historial_btn = ttk.Button(button_frame, text="Ver Historial", width=20, command=ver_historial)
historial_btn.grid(row=0, column=1, padx=10, pady=5)
pdf_btn = ttk.Button(button_frame, text="Exportar a PDF", width=20, command=exportar_a_pdf)
pdf_btn.grid(row=1, column=0, padx=10, pady=5)

ttk.Label(root, text="by JairoRC", font=("Arial", 10, "italic"), foreground="gray").pack(side="bottom", pady=10)
root.mainloop()
