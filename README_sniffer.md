# Network Packet Analyzer (Educational Project)

This is a simple network packet sniffer built with Python using Scapy.  
It captures and prints basic information about network packets in real-time.

---

## ⚠️ Ethical Use Only
- Ensure you have permission to capture packets on the network.
- Unauthorized sniffing can violate privacy laws.
- This project is intended for **learning and research only**.

---

## 🛠 Requirements
- Python 3.x
- Install Scapy:
  ```bash
  pip install scapy
  ```

---

## ▶️ How to Run
```bash
sudo python packet_sniffer.py
```
> Run with `sudo` or as administrator to allow raw packet capture.

---

## 📋 Output
Sample output:
```
[+] TCP Packet: 192.168.1.5 -> 93.184.216.34
[+] UDP Packet: 192.168.1.5 -> 8.8.8.8
```

---

## 📌 Notes
- You can modify the script to filter specific protocols or ports.
- Works best on Unix-like systems with root access.

---

## 🛑 Disclaimer
The author assumes no responsibility for misuse of this tool.  
Always operate within legal and ethical boundaries.
