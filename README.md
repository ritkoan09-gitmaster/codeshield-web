# 🛡️ CodeShield Enterprise (v2.5 Pro): Advanced Static Code Analysis Platform

CodeShield Enterprise is a production-ready, full-stack security auditing web application designed to scan project repositories locally for multi-vector threat patterns, including exposed cryptographic credentials, SQL injection vulnerabilities, insecure network protocols, and technical debt.

---

## 🚀 Core Architecture & Tech Stack
* **Frontend:** Responsive Single-Page Dashboard built with HTML5, Tailwind CSS, and Vanilla JavaScript (featuring live filtering, severity tabs, and dynamic security grading).
* **Backend Runtime:** Node.js & Express.js.
* **File Processing & Optimization:** Multer (multipart storage) & AdmZip (archive streaming), featuring automated noise reduction (`node_modules`, `.git`, binary files).
* **Analysis Engine:** Custom Multi-Vector Regular Expression (RegEx) matching engine with $O(1)$ line-by-line stream parsing.

---

## ⚙️ Advanced Features
1. **Multi-Vector Threat Detection:** Scans for AWS Access Keys, GitHub Tokens, Hardcoded Passwords, SQL Injection patterns, Insecure HTTP URLs, and `TODO` comments.
2. **Automated Security Health Scoring:** Dynamically computes a risk grade (`A+` to `F`) based on critical vulnerability density.
3. **Interactive UI Dashboard:** Drag-and-drop archive submission, real-time keyword search, and severity-based tab filtering (Critical, High, Low/Info).
4. **Audit Reporting:** One-click JSON report export for regulatory and team compliance reviews.

---

## 🛠️ How to Run Locally
1. Clone the repository and install dependencies:
   ```bash
   npm install