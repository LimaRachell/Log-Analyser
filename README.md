Hey! 👋
This project is a simple but powerful **log analyzer** that helps you understand what’s really happening inside system logs — and even spot suspicious activity using basic machine learning.


💡 Why I built this

While working with log files, I realized they’re:

 1.hard to read
 2.full of noise
 3.easy to ignore

So I built this tool to turn raw logs into something clear, visual, and actually useful.

## 🚀 What it does

* 📂 Upload any log dataset (CSV)
* 🔍 Identify suspicious IPs
* ⚠️ Detect possible attacks (brute force, unusual activity)
* 📊 Show alert levels (low / medium / high)
* 🖥️ Display logs in a clean dashboard format

---

## 🧠 Where ML comes in

The project uses basic machine learning to:

* detect anomalies
* flag unusual patterns
* improve threat detection beyond simple rules

---

## 🛠️ Tech used

* Python
* Pandas & NumPy
* Scikit-learn
* Streamlit (for dashboard)

---

## ▶️ How to run it

```bash
git clone https://github.com/LimaRachell/Log-Analyser.git
cd Log-Analyser
pip install -r requirements.txt
python app.py
```

---
📁 Dataset
Synthetic + real-world inspired logs
Includes multiple attack types:
Brute Force
DDoS
Unauthorized Access

📌 Use Cases
Cybersecurity monitoring
SOC analysis
Educational ML project
Log anomaly detection

## 📊 Example idea

Instead of reading messy logs like this:

```
Failed login from 192.168.1.1 at 12:01
```

You’ll see something like:

| IP          | Time  | Activity     | Risk |
| ----------- | ----- | ------------ | ---- |
| 192.168.1.1 | 12:01 | Failed Login | High |

---




Built by someone exploring **cybersecurity + machine learning** and trying to make logs less painful to deal with.
