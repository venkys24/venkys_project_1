# 📌 venkys_project_1

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## 🚀 Overview
cybersecurity support tools for offensive attacks


## 🔧 Installation
```sh
git clone https://github.com/your-username/your-repo.git
cd your-repo
```


## 📜 License
This project is licensed under the **Apache 2.0 License**. See the [LICENSE](LICENSE) file for details.

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
   ...
   (Full license text here: https://www.apache.org/licenses/LICENSE-2.0)



## Overview
This repository contains various cybersecurity tools for penetration testing and security assessments. These tools are intended for ethical use only and should be employed responsibly.

---

## 1. MAC Address Changer
A MAC Address Changer allows users to modify the MAC address of their device.

### **Benefits**
- **Privacy & Anonymity:** Prevents tracking by ISPs, advertisers, and hackers.
- **Enhanced Security:** Helps bypass blacklisting and prevents MAC-based attacks.
- **Testing & Development:** Useful for testing network configurations.

### **Usage**
```bash
python3 mac.py -i eth0 -m 00:11:22:33:44:55
```
- `eth0` = Preferred interface for changing MAC
- `00:11:22:33:44:55` = New MAC address

---

## 2. ARP Spoofer
An ARP Spoofer manipulates the Address Resolution Protocol (ARP) to redirect network traffic.

### **Benefits**
- **Ethical Hacking:** Helps test network security vulnerabilities.
- **Packet Sniffing & Traffic Monitoring:** Used for network analysis.
- **Defensive Security Measures:** Helps train employees on ARP spoofing threats.
- **Bypassing Network Restrictions:** Can redirect personal traffic.

### **Usage**
```bash
python3 arp1.py -t 192.168.5.133 -g 192.168.5.2
```
- `-t` = Target IP address
- `-g` = Gateway address

---

## 3. Network Scanner
Scans a network for active devices, open ports, and vulnerabilities.

### **Benefits**
- **Network Security Testing**
- **Network Monitoring & Troubleshooting**
- **Asset Management**
- **Intrusion Detection**

### **Usage**
```bash
python3 netscan1.py
python3 netscan1.py 192.168.5.1/24
```

---

## 4. Login Finder / Brute Forcer
Automates login attempts using multiple username/password combinations.

### **Benefits**
- **Password Security Testing**
- **Identifying Weak Authentication Mechanisms**
- **Penetration Testing**
- **Cybersecurity Awareness**

### **Usage**
```bash
python3 login_finder.py
python3 login_finder.py http://vulnweb/login.php
```
**⚠ WARNING:** Modify the code to specify the path to `pwd.txt` before running.

---

## 5. Form Extractor
Extracts input fields from web forms for analysis.

### **Benefits**
- **Web Automation & Data Entry**
- **Security Auditing**
- **Competitive Intelligence**
- **Digital Document Processing**

### **Usage**
```bash
python3 vuln_aka-form_extract.py
```
**⚠ WARNING:** Edit the target URL in the code before running.

---

## 6. Port Scanner
Identifies open ports and services on a target device.

### **Benefits**
- **Network Security & Vulnerability Assessment**
- **System & Service Management**
- **Ethical Hacking**
- **Detecting Unauthorized Services**

### **Usage**
```bash
python3 port.py
python3 port.py 192.168.5.134
```

---

## 7. Link Finder
Extracts URLs from webpages and network traffic.

### **Benefits**
- **Web Scraping & Data Collection**
- **Security Testing**
- **SEO Optimization**
- **Identifying Hidden & Vulnerable Endpoints**

### **Usage**
```bash
python3 spy_aka_fill_link_find.py
```
**⚠ WARNING:** Edit the target URL in the code before running.

---

## 8. Packet Sniffer
Captures and analyzes network traffic.

### **Benefits**
- **Intrusion Detection**
- **Troubleshooting & Performance Optimization**
- **Protocol & Traffic Analysis**
- **Penetration Testing**

### **Usage**
```bash
python3 packetsniff1.py
```
**⚠ WARNING:** Edit the target interface in the code before running.
**⚠ WARNING:** Run the ARP Spoofer first on the target device for better results.

---

## 9. DNS Spoofer
Redirects a target’s DNS requests to a fake IP.

### **Benefits**
- **Cybersecurity & Penetration Testing**
- **Web Filtering & Parental Control**
- **Network Traffic Redirection**
- **Education & Research**

### **Usage**
```bash
python3 dns.py
```
**⚠ WARNING:** Edit the target interface before running.
**⚠ WARNING:** Run the ARP Spoofer first for better results.
**⚠ WARNING:** Modify the `blocked_domains.txt` file path in the code.

---

## 10. Caesar Cipher Maker
Encrypts and decrypts text using the Caesar cipher.

### **Benefits**
- **Cryptography Basics**
- **Secure Simple Messages**
- **Programming & Algorithm Development**
- **Puzzle Games & Escape Rooms**

### **Usage**
```bash
python3 caeser.py
```
**Alphabet Set:** `abcdefghijklmnopqrstuvwxyz0123456789`

---

## 11. Deauthentication Attack Detector
Detects and alerts users of Wi-Fi deauthentication attacks.

### **Benefits**
- **Detecting & Preventing Wi-Fi Attacks**
- **Securing Wireless Networks**
- **Incident Response**
- **Penetration Testing**

### **Usage**
```bash
python3 deauthentication.py
```

---

## 12. Web Crawler
Extracts and indexes data from websites.

### **Benefits**
- **Search Engine Indexing & SEO Optimization**
- **Data Extraction & Market Research**
- **Cybersecurity & Web Monitoring**
- **Automating Web Tasks**

### **Usage**
```bash
python3 craw.py
```
**⚠ WARNING:** Edit the target URL in the code before running.

---

## ⚠ Disclaimer
These tools are strictly for ethical hacking, penetration testing, and cybersecurity research. Unauthorized use against networks or systems without explicit permission is illegal and punishable by law. Use these tools responsibly.



