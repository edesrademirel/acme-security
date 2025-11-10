# analyze_suspicious.py
# 4 log kaynağını birleştirir, yalnızca şüpheli olayları çıkarır (BOLA / SQLi / Phishing / Export / AttackerIP).
# İç ağdan (RFC1918) gelen EXPORT kayıtlarını timeline'a dahil ETMEZ.

import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import ipaddress

# ========== CONFIG ==========
# Test penceresi
TEST_START = datetime(2024, 10, 20)
TEST_END   = datetime(2024, 10, 25)

# Test IP’leri / CIDR
TEST_IPS = [
    "192.168.1.100",
    "10.0.0.0/24",
    "203.0.113.0/24",
]

# Test hesap aralığı
TEST_ACCOUNTS = list(range(5001, 5011))  # 5001–5010

# Vurgulamak istediğin saldırgan IP
ATTACKER_IP = "203.0.113.45"

# Basit örüntüler
SQLI_PATTERNS   = ["or 1=1", "union select", "drop table", "/*!50000", "sqli"]
PHISH_PATTERNS  = ["verify your account", "verify account", "urgent", "action required", "password reset"]
EXPORT_PATTERNS = ["/export", "export?", "format=csv", "download.csv", "export.csv"]

# Giriş dosyaları
LOG_FILES = {
    "api_logs":   "api_logs.csv",
    "web_logs":   "web_logs.csv",
    "waf_logs":   "waf_logs.csv",
    "email_logs": "email_logs.csv",
}

OUTPUT_XLSX = "timeline_suspicious.xlsx"


# ========== HELPERS ==========
def _find_col(df: pd.DataFrame, candidates):
    cmap = {c.lower().strip(): c for c in df.columns}
    # tam eşleşme
    for cand in candidates:
        if cand in cmap:
            return cmap[cand]
    # kısmi eşleşme
    for k in list(cmap.keys()):
        for cand in candidates:
            if cand in k:
                return cmap[k]
    return None

def _to_dt(s):
    return pd.to_datetime(s, errors="coerce")

def _safe_ip(ip_str: str):
    if not isinstance(ip_str, str) or not ip_str.strip():
        return None
    try:
        return ipaddress.ip_address(ip_str.strip())
    except Exception:
        return None

def _ip_in_tests(ip_str: str) -> bool:
    ip = _safe_ip(ip_str)
    if ip is None:
        return False
    for entry in TEST_IPS:
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except Exception:
            continue
    return False

def _is_internal_rfc1918(ip_str: str) -> bool:
    """RFC1918: 10/8, 172.16/12, 192.168/16"""
    ip = _safe_ip(ip_str)
    if ip is None:
        return False
    return (
        ip in ipaddress.ip_network("10.0.0.0/8") or
        ip in ipaddress.ip_network("172.16.0.0/12") or
        ip in ipaddress.ip_network("192.168.0.0/16")
    )

def _in_test_window(ts) -> bool:
    if pd.isna(ts):
        return False
    return (ts >= TEST_START) and (ts <= TEST_END)

def _contains_any(text, patterns) -> bool:
    if not isinstance(text, str):
        return False
    t = str(text).lower()
    return any(p.lower() in t for p in patterns)

def _normalize_csv(path: Path, source_name: str) -> pd.DataFrame:
    df = pd.read_csv(path)

    # Kolon adayları
    ts   = _find_col(df, ["timestamp", "time", "date_time", "datetime"])
    ip   = _find_col(df, ["ip", "source_ip", "ip_address", "client_ip"])
    act  = _find_col(df, ["action", "endpoint", "uri", "path", "request", "request_uri"])
    stat = _find_col(df, ["status", "response_code", "code", "http_status", "result"])
    subj = _find_col(df, ["subject"])
    qry  = _find_col(df, ["query", "query_params", "params"])
    ua   = _find_col(df, ["user_agent"])
    uid  = _find_col(df, ["user", "user_id"])
    acc  = _find_col(df, ["account", "account_id"])
    tok  = _find_col(df, ["token", "jwt", "auth_token"])
    sig  = _find_col(df, ["signature", "rule"])

    out = pd.DataFrame()
    out["timestamp"] = _to_dt(df[ts]) if ts else pd.NaT
    out["ip"]        = df[ip] if ip else ""

    # action: önce endpoint/uri; yoksa WAF signature veya email subject
    if act:
        out["action"] = df[act].astype(str)
    elif sig:
        out["action"] = df[sig].astype(str)
    elif subj:
        out["action"] = df[subj].astype(str)
    else:
        out["action"] = ""

    # SQLi analizine yardımcı: action + query birleştir
    if qry:
        out["action"] = (out["action"].astype(str) + " " + df[qry].astype(str))

    out["status"]  = df[stat] if stat else ""
    out["subject"] = df[subj] if subj else ""
    out["query"]   = df[qry] if qry else ""
    out["user_id"] = pd.to_numeric(df[uid], errors="coerce") if uid else np.nan
    out["account_id"] = pd.to_numeric(df[acc], errors="coerce") if acc else np.nan
    out["token"]   = df[tok] if tok else ""
    out["user_agent"] = df[ua] if ua else ""
    out["source"]  = source_name

    out = out.dropna(subset=["timestamp"])
    return out


# ========== ANALYSIS ==========
def main():
    frames = []
    for name, f in LOG_FILES.items():
        p = Path(f)
        if not p.exists():
            print(f"⚠️ Missing file, skipped: {f}")
            continue
        try:
            part = _normalize_csv(p, name)
            frames.append(part)
            print(f"✓ Loaded: {f}  ({len(part)} rows)")
        except Exception as e:
            print(f"⚠️ Read/normalize error ({f}): {e}")

    if not frames:
        print("No logs read. Exiting.")
        return

    df = pd.concat(frames, ignore_index=True).sort_values("timestamp")

    # Planlı test / iç ağ bayrakları
    df["is_test_ip"]       = df["ip"].apply(_ip_in_tests)
    df["is_internal_ip"]   = df["ip"].apply(_is_internal_rfc1918)
    df["is_test_window"]   = df["timestamp"].apply(_in_test_window)
    df["is_test_account"]  = df["account_id"].isin(TEST_ACCOUNTS) | df["user_id"].isin(TEST_ACCOUNTS)

    # BOLA: user_id != account_id ve HTTP 200
    df["is_bola"] = (
        df["user_id"].notna()
        & df["account_id"].notna()
        & (df["user_id"] != df["account_id"])
        & df["status"].astype(str).str.contains(r"^200$", na=False)
    )

    # Örüntüler
    df["is_sqli"]   = df["action"].apply(lambda x: _contains_any(x, SQLI_PATTERNS))
    df["is_phish"]  = df["subject"].apply(lambda x: _contains_any(x, PHISH_PATTERNS)) | \
                      df["action"].apply (lambda x: _contains_any(x, PHISH_PATTERNS))
    df["is_export"] = df["action"].apply(lambda x: _contains_any(x, EXPORT_PATTERNS))

    # Saldırgan IP vurgusu
    df["is_attacker_ip"] = df["ip"].astype(str).str.contains(ATTACKER_IP, na=False)

    # Planlı mı değil mi
    df["not_planned"] = (~(df["is_test_ip"] & df["is_test_window"])) & (~(df["is_test_account"] & df["is_test_window"]))

    # Şüpheli: planlı değil + (BOLA/SQLi/Phish/Export/AttackerIP’ten biri)
    df["is_suspicious"] = df["not_planned"] & df[["is_bola","is_sqli","is_phish","is_export","is_attacker_ip"]].any(axis=1)

    # Etiket (reason)
    df["reason"] = df.apply(lambda r: ", ".join([k for k,v in {
        "BOLA":r["is_bola"], "SQLi":r["is_sqli"], "Phishing":r["is_phish"],
        "Export":r["is_export"], "AttackerIP":r["is_attacker_ip"]
    }.items() if v]), axis=1)

    # Sınıflandırma (EN)
    df["classification"] = np.where(
        ((df["is_test_ip"] | df["is_test_account"]) & df["is_test_window"]),
        "Planned Test",
        "Real Incident"
    )

    # Severity (EN) – sade kural seti
    def _severity(r):
        if r["is_bola"] or r["is_sqli"] or r["is_export"]:
            return "High"
        if r["is_phish"]:
            return "High"
        if r["is_attacker_ip"]:
            return "Medium"
        return "Low"
    df["severity"] = df.apply(_severity, axis=1)

    # === IMPORTANT ===
    # İç IP'den gelen EXPORT kayıtlarını tamamen hariç tut
    sus = df[
        df["is_suspicious"] & ~(df["is_export"] & df["is_internal_ip"])
    ].copy()

    # Çıktı kolonları
    cols = [
        "timestamp","source","ip","user_id","account_id","action","status",
        "subject","reason","classification","severity"
    ]
    cols = [c for c in cols if c in sus.columns]

    with pd.ExcelWriter(OUTPUT_XLSX) as writer:
        sus[cols].to_excel(writer, index=False, sheet_name="Suspicious Timeline")

        # Gün-özet
        (sus.assign(date=sus["timestamp"].dt.date)
            .groupby(["date","reason","classification","severity"], dropna=False)
            .size().reset_index(name="count")
            .sort_values(["date","severity","reason"])
            .to_excel(writer, index=False, sheet_name="Summary"))

    print("\n--- SUMMARY ---")
    print(f"Total rows: {len(df)}")
    print(f"Suspicious rows (internal exports excluded): {len(sus)}")
    print(f"Output: {OUTPUT_XLSX}")


if __name__ == "__main__":
    main()
