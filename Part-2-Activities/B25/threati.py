import requests
import time
import json
import os
import re
from datetime import datetime, timedelta


VIRUSTOTAL_API_KEY = "PUT_YOUR_VIRUSTOTAL_API_KEY_HERE"
ABUSEIPDB_API_KEY = "PUT_YOUR_ABUSEIPDB_API_KEY_HERE"

CACHE_FILE = "ioc_cache.json"
CACHE_HOURS = 24


def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}

    with open(CACHE_FILE, "r") as file:
        return json.load(file)


def save_cache(cache):
    with open(CACHE_FILE, "w") as file:
        json.dump(cache, file, indent=4)


def is_cache_valid(timestamp):
    saved_time = datetime.fromisoformat(timestamp)
    return datetime.now() - saved_time < timedelta(hours=CACHE_HOURS)


def detect_ioc_type(ioc):
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if re.match(ip_pattern, ioc):
        return "ip"
    elif re.match(md5_pattern, ioc):
        return "hash"
    elif re.match(sha256_pattern, ioc):
        return "hash"
    elif re.match(domain_pattern, ioc):
        return "domain"
    else:
        return "unknown"


def check_virustotal_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": f"API error: {response.status_code}"
        }

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if malicious > 3:
        verdict = "malicious"
    elif malicious > 0 or suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "source": "VirusTotal",
        "type": "file_hash",
        "verdict": verdict,
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,
        "total_engines": total
    }


def check_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return {
            "source": "VirusTotal",
            "status": "error",
            "message": f"API error: {response.status_code}"
        }

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if malicious > 3:
        verdict = "malicious"
    elif malicious > 0 or suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "source": "VirusTotal",
        "type": "domain",
        "verdict": verdict,
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,
        "total_engines": total
    }


def check_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        return {
            "source": "AbuseIPDB",
            "status": "error",
            "message": f"API error: {response.status_code}"
        }

    data = response.json()["data"]

    abuse_score = data.get("abuseConfidenceScore", 0)
    country = data.get("countryCode", "Unknown")
    total_reports = data.get("totalReports", 0)

    if abuse_score > 50:
        verdict = "malicious"
    elif abuse_score > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "source": "AbuseIPDB",
        "type": "ip_address",
        "verdict": verdict,
        "abuse_confidence_score": abuse_score,
        "country": country,
        "total_reports": total_reports
    }


def check_ioc(ioc):
    cache = load_cache()

    if ioc in cache and is_cache_valid(cache[ioc]["timestamp"]):
        print("\nResult loaded from cache.")
        return cache[ioc]["result"]

    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "hash":
        result = check_virustotal_hash(ioc)
    elif ioc_type == "domain":
        result = check_virustotal_domain(ioc)
    elif ioc_type == "ip":
        result = check_abuseipdb(ioc)
    else:
        result = {
            "source": "Local Validator",
            "type": "unknown",
            "verdict": "invalid",
            "message": "Input is not a valid IP address, domain, MD5 hash, or SHA256 hash."
        }

    cache[ioc] = {
        "timestamp": datetime.now().isoformat(),
        "result": result
    }

    save_cache(cache)
    time.sleep(2)

    return result


def print_report(ioc, result):
    print("\n==============================")
    print(" IoC THREAT INTELLIGENCE REPORT")
    print("==============================")
    print(f"Indicator: {ioc}")
    print(f"Source: {result.get('source')}")
    print(f"Type: {result.get('type')}")
    print(f"Verdict: {result.get('verdict')}")

    print("\nDetails:")

    for key, value in result.items():
        if key not in ["source", "type", "verdict"]:
            print(f"- {key}: {value}")

    print("==============================")


def main():
    print("Basic IoC Threat Intelligence Checker")
    print("Supported inputs: IPv4 address, domain name, MD5 hash, SHA256 hash")

    while True:
        ioc = input("\nEnter an IoC to check or type 'exit': ").strip()

        if ioc.lower() == "exit":
            print("Exiting IoC checker.")
            break

        result = check_ioc(ioc)
        print_report(ioc, result)


if __name__ == "__main__":
    main()