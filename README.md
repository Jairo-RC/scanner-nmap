# 🚀 Port Scanner with Nmap and VirusTotal

Advanced port scanner with **Nmap** vulnerability detection, integrated with **VirusTotal** to analyze suspicious IP addresses.

---

## 📌 Features
✅ Port scanning with `nmap`  
✅ Service vulnerability detection  
✅ IP verification in **VirusTotal** blacklists  
✅ **Scan history** stored in SQLite  
✅ Export reports in **CSV and PDF**  
✅ **Graphical interface** with **Tkinter**  
✅ Automatic email report sending  

---

## 📥 Installation and Usage

### 🔧 **Requirements**
✔ `Python 3.x` installed  
✔ **Nmap** installed on the system  
✔ Obtain a **VirusTotal API Key**  
✔ Configure email sending for reports  

---

## 🖥 Installation on **Windows**
1️⃣ **Download and install Nmap** from [Nmap Download](https://nmap.org/download.html)  
2️⃣ **Install dependencies** in PowerShell:
   ```powershell
   pip install requests python-nmap pandas reportlab tk
   ```
3️⃣ **Configure the VirusTotal API**:
   - Open the `scanner.py` file and edit this line:
   ```python
   VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
   ```
4️⃣ **Run the scanner**:
   ```powershell
   python scanner.py
   ```

---

## 🐧 Installation on **Linux (Kali, Ubuntu, Debian)**
Run these commands in the terminal:
```bash
sudo apt update && sudo apt install nmap python3-pip -y
pip install requests python-nmap pandas reportlab tk
```

### 🔑 **Configure the VirusTotal API**
To check if an IP is blacklisted, obtain an API Key:
1. **Sign up on VirusTotal** at [https://www.virustotal.com](https://www.virustotal.com)  
2. Go to your profile and copy your API Key  
3. Edit the `scanner.py` file and replace the key in this line:
   ```python
   VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
   ```

---

## 📧 Configure Email Sending (Optional)
To send reports via email, configure environment variables with your email and password:

### 🔹 **On Windows**
1. Open **Run** (`Win + R`), type `sysdm.cpl`, and press Enter.  
2. Go to the **Advanced options** tab → **Environment variables**.  
3. Create two new variables:
   - `EMAIL_SENDER`: Your email address (`youremail@gmail.com`)
   - `EMAIL_PASSWORD`: Your email password
4. Save the changes and **restart your system**.

### 🐧 **On Linux/Mac**
Run in the terminal:
```bash
echo 'export EMAIL_SENDER="youremail@gmail.com"' >> ~/.bashrc
echo 'export EMAIL_PASSWORD="yourpassword"' >> ~/.bashrc
source ~/.bashrc
```
For **Zsh** (Mac/Linux):
```bash
echo 'export EMAIL_SENDER="youremail@gmail.com"' >> ~/.zshrc
echo 'export EMAIL_PASSWORD="yourpassword"' >> ~/.zshrc
source ~/.zshrc
```
Verify that the variables are correctly saved:
```bash
echo $EMAIL_SENDER
echo $EMAIL_PASSWORD
```

---

## 📜 License
This project is under the **MIT License**. Feel free to modify and improve the code.

Enjoy exploring networks safely! 🚀🔍
