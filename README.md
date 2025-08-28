# Real-time-PII-Defense-SOC-challenge  

## 📌 Challenge Background  
Flixkart’s SOC (Security Operations Center) identified a critical gap: sensitive **PII (Personally Identifiable Information)** could leak via unmonitored assets and logs.  

A past fraud case exposed customer details, proving that **traditional database security alone is not enough**.  
This challenge required building a **real-time defense system** that can detect, redact, and prevent PII leakage across pipelines.  

---

## 🎯 Solution Overview  

We built a **PII Detection & Redaction Engine** (`detector_full_candidate_name.py`) that:  
- Scans incoming CSV records for PII.  
- Applies **regex + contextual rules** to detect sensitive data.  
- **Redacts/masks** PII before storage or logging.  
- Tags each record with `is_pii=True/False`.  
- Outputs a sanitized dataset for safe use.  

This approach provides **real-time SOC defense** against PII exposure.  

---

## 🚀 How to Use  

### 1. Clone Repo  
```bash
git clone https://github.com/gowthamsai117/Real-time-PII-Defense-SOC-challenge
cd Real-time-PII-Defense-SOC-challenge
