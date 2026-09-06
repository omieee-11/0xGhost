import json
import sys

# Get the target domain passed from GitHub Actions (default to example.com if empty)
target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

print(f"[*] Starting OSINT scan for: {target}")

# --- YOUR CUSTOM SCAN CODE & TOOLS GO HERE LATER ---
# For now, we simulate finding open ports and basic info:
results = {
    "target": target,
    "status": "COMPLETED",
    "ip": "192.168.1.1",
    "subdomains": [f"api.{target}", f"dev.{target}", f"mail.{target}"],
    "ports": [
        {"port": "80", "service": "http", "state": "open"},
        {"port": "443", "service": "https", "state": "open"},
    ],
    "vulnerabilities": [
        {
            "title": "Missing Security Headers",
            "severity": "MEDIUM",
            "desc": "HSTS header not enforced on server.",
        }
    ],
}

# Save results file that index.html will read
output_filename = f"results_{target}.json"
with open(output_filename, "w") as f:
  json.dump(results, f, indent=4)

print(f"[+] Scan finished! Saved results to {output_filename}")
