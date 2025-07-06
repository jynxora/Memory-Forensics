# Windows Memory Image Forensics — [Day 6]

This repository contains a step-by-step breakdown of my memory analysis workflow using **Volatility 2.6.1** on a Windows 7 64-bit memory image (`Challenge.raw`).  
This investigation was conducted as part of my ongoing **#700DaysOfSkill** series focusing on **DFIR (Digital Forensics and Incident Response)**, Cybersecurity, and Quantum Cryptography.

---

## 🔍 What This Repo Contains

- 📁 Memory image analysis using `vol.py` and 10+ core plugins  
- 📖 A professionally structured PDF report with findings from:
  - Process Discovery (`pslist`, `pstree`)
  - DLL & injected code detection (`malfind`, `dlllist`)
  - Network activity reconstruction (`netscan`)
  - Timeline reconstruction

---

## 🛠️ Tools Used

- 🐍 Volatility 2.6.1
- 🧠 Challenge.raw (1.6 GB memory dump)
- 📖 Kali Linux on VMware
- 📝 Notion + Markdown for documentation

---

## 📎 Files Included

- `investigatingMemoryImage.pdf` – Final Report [PDF]
- `investigatingMemoryImage.md` – Final Report [Mark Down]
- Download PDF Report: 
- CLI outputs + references

---

## 🔒 Scope & Legality

All steps are educational and follow responsible disclosure practices.  
Please use tools like Volatility only on legally acquired images or labs. This analysis is part of a simulated case study.

---

## 💡 Insights Learned

- How to distinguish between legitimate vs rogue `svchost.exe`
- Techniques to detect injected code, network anomalies, and loaded DLLs
- Real-world application of forensic scanning on memory dumps

---

A small step in a long road to mastery.

> **Note:** If you're learning DFIR and forensics, feel free to fork this repo, reuse the structure, and improve it further.
