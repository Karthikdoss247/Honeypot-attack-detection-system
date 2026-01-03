# Honeypot Attack Detection System:

Overview:
This project implements a **low-interaction honeypot** using Python to simulate a fake SSH-like service.  
It is designed for **Blue Team / Defensive Security learning**, focusing on detecting brute-force attacks and analyzing attacker behavior.

The honeypot records:
- Attacker IP addresses
- Username & password attempts
- Number of attempts per IP
- Attack severity levels
- Incident reports
- Traffic visualization graphs

---

Objectives:
- Detect brute-force login attempts
- Log attacker activity for forensic analysis
- Assign severity based on attack intensity
- Generate incident reports automatically
- Visualize attack patterns

---

Technologies Used:
- Python
- Socket Programming
- Multithreading
- Matplotlib (Graphs)
- File-based logging
- Kali Linux (attack simulation)
- Windows Host (honeypot server)

---
