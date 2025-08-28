#!/usr/bin/env python3
"""
detector_full_candidate_name.py
Usage:
  python3 detector_full_candidate_name.py iscp_pii_dataset.csv

Reads a CSV with columns: record_id, Data_json (stringified JSON).
Writes: redacted_output_candidate_full_name.csv with columns:
  record_id, redacted_data_json, is_pii

Rules implemented per challenge:
- Standalone PII (any one of these marks the record as PII and gets redacted):
  * Phone number (Indian 10-digit; prefer keys like phone/contact; regex-based).
  * Aadhaar number (12 digits, spaces allowed). Uses Verhoeff checksum to reduce FPs.
  * Passport number (Indian format: 1 letter + 7 digits).
  * UPI ID (local@handle).

- Combinatorial PII (needs >=2 in same record to mark as PII and redact):
  * Full name (first + last, or "name" containing both parts).
  * Email address.
  * Physical address (address that also has a 6-digit PIN present in record).
  * Device ID / IP address tied to user context (we consider ip_address or device_id).
  * City/State + Pin code + Address can combine.

- Non-PII (do NOT alone make record PII and should not be redacted on their own):
  * First name alone OR last name alone.
  * Email alone.
  * Standalone city/state/pin code.
  * Transaction/order/product identifiers, descriptions.
  * Any single attribute from the combinatorial list.

Implementation notes:
- We prioritize keys that are likely to contain PII to reduce false positives.
- For Aadhaar, Verhoeff checksum validation is used.
- Masking keeps limited context (prefix/suffix) for enrichment while protecting privacy.
- The script only redacts fields that qualify as PII under the above rules.
- The script is dependency-free (standard library only).

Author: candidate_full_candidate_name
"""
import sys, json, csv, re
from typing import Dict, Any, Tuple

# ---------- Utility: Verhoeff checksum for Aadhaar validation ----------
# Verhoeff tables
_d = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0]
]
_p = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8]
]
_inv = [0,4,3,2,1,5,6,7,8,9]

def verhoeff_validate(num: str) -> bool:
    c = 0
    num = re.sub(r'\s+', '', num)
    if not num.isdigit():
        return False
    for i, item in enumerate(reversed(num)):
        c = _d[c][_p[(i % 8)][int(item)]]
    return c == 0

# ---------- Regex patterns ----------
RE_PHONE = re.compile(r'(?<!\d)([6-9]\d{9})(?!\d)')  # Indian mobile
RE_AADHAAR = re.compile(r'(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)')
RE_PASSPORT_IN = re.compile(r'\b([A-PR-WY][0-9]{7})\b')  # avoid O/Q/X as starters
RE_UPI = re.compile(r'\b([a-zA-Z0-9.\-_]{2,})@([a-zA-Z][a-zA-Z0-9]{1,})\b')
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
RE_PIN = re.compile(r'(?<!\d)([1-9]\d{5})(?!\d)')
RE_IP = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

LIKELY_PII_KEYS = {
    'phone','contact','mobile','aadhar','aadhaar','passport','upi_id','upi','name',
    'first_name','last_name','email','address','ip','ip_address','device_id'
}

# ---------- Maskers ----------
def mask_phone(s: str) -> str:
    m = RE_PHONE.search(s)
    if not m: return s
    d = m.group(1)
    return s.replace(d, d[:2] + "XXXXXX" + d[-2:])

def normalize_aadhaar_digits(s: str) -> str:
    return re.sub(r'\s+', '', s)

def mask_aadhaar(s: str) -> str:
    # Keep first 4 and last 2, mask middle 6
    num = normalize_aadhaar_digits(s)
    if len(num) == 12 and num.isdigit():
        masked = f"{num[:4]}XXXXXX{num[-2:]}"
        return masked
    return s

def mask_passport(s: str) -> str:
    return RE_PASSPORT_IN.sub(lambda m: m.group(1)[0] + "XXXXXX" , s)

def mask_upi(s: str) -> str:
    def _m(m):
        local, handle = m.group(1), m.group(2)
        if len(local) <= 3:
            masked_local = local[0] + "X"*(len(local)-1)
        else:
            masked_local = local[:2] + "X"*(len(local)-3) + local[-1]
        return masked_local + "@" + handle
    return RE_UPI.sub(_m, s)

def mask_email(s: str) -> str:
    def _m(m):
        addr = m.group(0)
        local, domain = addr.split("@", 1)
        if len(local) <= 2:
            local_mask = local[0] + "X"*(len(local)-1)
        else:
            local_mask = local[0] + "X"*(len(local)-2) + local[-1]
        # mask domain label before TLD lightly
        parts = domain.split(".")
        if len(parts) >= 2:
            parts[0] = parts[0][0] + "X"*(len(parts[0])-1) if len(parts[0])>1 else parts[0]
        return local_mask + "@" + ".".join(parts)
    return RE_EMAIL.sub(_m, s)

def mask_name(fullname: str) -> str:
    parts = re.split(r'\s+', fullname.strip())
    out = []
    for p in parts:
        if not p: continue
        out.append(p[0] + "X"*(max(0, len(p)-1)))
    return " ".join(out)

def mask_ip(ip: str) -> str:
    # Hash last two octets to preserve /16 analytics but hide host identity
    try:
        octs = ip.split(".")
        if len(octs) == 4:
            prefix = ".".join(octs[:2])
            suffix = ".".join(octs[2:])
            import hashlib
            h = hashlib.sha256(suffix.encode()).hexdigest()[:4]
            return f"{prefix}.XX.XX-{h}"
    except Exception:
        pass
    return "X.X.X.X"

def mask_device(d: str) -> str:
    # Keep first 3 and last 3 chars
    if len(d) <= 6: return "X"*len(d)
    return d[:3] + "X"*(len(d)-6) + d[-3:]

# ---------- Detection helpers ----------
def has_full_name(d: Dict[str, Any]) -> Tuple[bool, str]:
    # Consider "name" with at least two parts OR both first_name and last_name present
    name = ""
    if isinstance(d.get("name"), str) and len(d["name"].split()) >= 2:
        name = d["name"]
        return True, name
    if isinstance(d.get("first_name"), str) and isinstance(d.get("last_name"), str):
        name = d.get("first_name","") + " " + d.get("last_name","")
        return True, name.strip()
    return False, ""

def has_email(d: Dict[str, Any]) -> Tuple[bool, str]:
    for k in ("email","username"):
        v = d.get(k)
        if isinstance(v, str) and RE_EMAIL.search(v):
            return True, v
    return False, ""

def has_address(d: Dict[str, Any]) -> Tuple[bool, str]:
    addr = d.get("address")
    pin_present = bool(RE_PIN.search(str(d.get("pin_code","")))) or (isinstance(addr, str) and RE_PIN.search(addr))
    if isinstance(addr, str) and addr.strip():
        return True, addr if pin_present else addr  # We'll combine with pin check below
    return False, ""

def has_device_or_ip(d: Dict[str, Any]) -> Tuple[bool, str, str]:
    ip = d.get("ip_address") or d.get("ip")
    dev = d.get("device_id")
    ip_s = ip if isinstance(ip, str) and RE_IP.search(ip or "") else ""
    dev_s = dev if isinstance(dev, str) and len(dev) >= 8 else ""
    ok = bool(ip_s or dev_s)
    return ok, ip_s, dev_s

def detect_standalone(d: Dict[str, Any]) -> Dict[str, str]:
    found = {}
    # Aadhaar
    for k in ("aadhar","aadhaar","address_proof"):
        v = d.get(k)
        if isinstance(v, str):
            m = RE_AADHAAR.search(v)
            if m and verhoeff_validate(m.group(1)):
                found["aadhaar"] = m.group(1)
                break
    # Phone
    for k in ("phone","contact","mobile"):
        v = d.get(k)
        if isinstance(v, str):
            m = RE_PHONE.search(v)
            if m:
                found["phone"] = m.group(1)
                break
    # Passport
    for k in ("passport",):
        v = d.get(k)
        if isinstance(v, str):
            m = RE_PASSPORT_IN.search(v)
            if m:
                found["passport"] = m.group(1)
                break
    # UPI
    for k in ("upi_id","upi"):
        v = d.get(k)
        if isinstance(v, str):
            m = RE_UPI.search(v)
            if m:
                found["upi"] = m.group(0)
                break
    return found

def detect_combinatorial(d: Dict[str, Any]) -> Dict[str, Any]:
    tags = {}
    has_name, name_val = has_full_name(d)
    if has_name: tags["name"] = name_val
    has_eml, email_val = has_email(d)
    if has_eml: tags["email"] = email_val
    has_addr, addr_val = has_address(d)
    if has_addr: tags["address"] = addr_val
    has_devip, ip_val, dev_val = has_device_or_ip(d)
    if has_devip:
        if ip_val: tags["ip_address"] = ip_val
        if dev_val: tags["device_id"] = dev_val

    # Count how many categories present
    count = len(tags)
    tags["_count"] = count
    # Stronger signal if address + pin code in record
    if "address" in tags:
        pin_any = False
        # consider pin_code field or pin-like in address string
        if isinstance(d.get("pin_code"), (int, str)) and RE_PIN.search(str(d.get("pin_code"))):
            pin_any = True
        elif isinstance(tags["address"], str) and RE_PIN.search(tags["address"]):
            pin_any = True
        tags["_has_pin_with_address"] = pin_any
    else:
        tags["_has_pin_with_address"] = False
    return tags

def redact_record(d: Dict[str, Any], standalone: Dict[str,str], combo: Dict[str,Any], is_pii: bool) -> Dict[str, Any]:
    if not is_pii:
        return d  # leave untouched

    out = dict(d)  # shallow copy

    # Apply standalone masks
    if "phone" in standalone:
        for k in ("phone","contact","mobile"):
            v = out.get(k)
            if isinstance(v, str):
                out[k] = mask_phone(v)
    if "aadhaar" in standalone:
        for k in ("aadhar","aadhaar","address_proof"):
            v = out.get(k)
            if isinstance(v, str):
                out[k] = mask_aadhaar(v)
    if "passport" in standalone:
        v = out.get("passport")
        if isinstance(v, str):
            out["passport"] = mask_passport(v)
    if "upi" in standalone:
        for k in ("upi_id","upi"):
            v = out.get(k)
            if isinstance(v, str):
                out[k] = mask_upi(v)

    # Apply combo masks
    if "name" in combo:
        if isinstance(out.get("name"), str):
            out["name"] = mask_name(out["name"])
        fn, ln = out.get("first_name"), out.get("last_name")
        if isinstance(fn, str) and isinstance(ln, str):
            out["first_name"] = mask_name(fn)
            out["last_name"] = mask_name(ln)
    if "email" in combo:
        if isinstance(out.get("email"), str):
            out["email"] = mask_email(out["email"])
        if isinstance(out.get("username"), str):
            out["username"] = mask_email(out["username"])
    if "address" in combo:
        if isinstance(out.get("address"), str):
            out["address"] = "[REDACTED_ADDRESS]"
        if "pin_code" in out:
            out["pin_code"] = "XXXXXX"
        # city/state often accompany address; mask lightly
        if isinstance(out.get("city"), str): out["city"] = out["city"][:2] + "XX"
        if isinstance(out.get("state"), str): out["state"] = out["state"][:2] + "XX"
    if "ip_address" in combo:
        if isinstance(out.get("ip_address"), str):
            out["ip_address"] = mask_ip(out["ip_address"])
        if isinstance(out.get("ip"), str):
            out["ip"] = mask_ip(out["ip"])
    if "device_id" in combo:
        if isinstance(out.get("device_id"), str):
            out["device_id"] = mask_device(out["device_id"])

    return out

def classify_and_redact(record_json: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    standalone = detect_standalone(record_json)
    combo = detect_combinatorial(record_json)

    is_combo_pii = combo.get("_count", 0) >= 2
    # Strengthen: if address present, require pin to count address as one pillar
    if "address" in combo and not combo.get("_has_pin_with_address", False):
        # discount the address when no PIN
        effective_combo_count = combo.get("_count",0) - 1
        is_combo_pii = effective_combo_count >= 2

    is_pii = bool(standalone) or is_combo_pii

    redacted = redact_record(record_json, standalone, combo, is_pii)
    return redacted, is_pii

def process_csv(input_csv: str, output_csv: str):
    with open(input_csv, newline='', encoding='utf-8') as f_in, \
         open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rid = row.get('record_id')
            data_json_str = row.get('Data_json') or row.get('data_json') or '{}'
            try:
                data = json.loads(data_json_str)
                if not isinstance(data, dict):
                    raise ValueError("Data_json must be an object")
            except Exception:
                # if invalid JSON, write as non-PII untouched but flagged False
                writer.writerow({'record_id': rid, 'redacted_data_json': data_json_str, 'is_pii': False})
                continue

            redacted, is_pii = classify_and_redact(data)
            writer.writerow({
                'record_id': rid,
                'redacted_data_json': json.dumps(redacted, ensure_ascii=False),
                'is_pii': str(bool(is_pii))
            })

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)
    input_csv = sys.argv[1]
    out_csv = "redacted_output_candidate_full_name.csv"
    process_csv(input_csv, out_csv)
    print(f"Wrote {out_csv}")
