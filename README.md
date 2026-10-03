# 🛡️ GeoShield.js (Defender)

> **Zero-dependency, multi-vector client-side engine for detecting VPNs, commercial hosting proxies, and geographic evasion.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-success.svg)]()
[![Platform: Browser / Node](https://img.shields.io/badge/Platform-Browser%20%2F%20Node-informational.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

---

## ⚡ The Problem: Why Traditional Geo-Blocking Fails

Most geo-compliance and anti-fraud filters rely purely on **IP-to-country lookups**. This approach is trivially bypassed:

1. **Unindexed VPN / VPS Ranges:** Free and budget IP reputation databases often fail to flag smaller, regional, or offshore bulletproof hosters (e.g., *Nekobyte, IT-Garage, Aeza, Timeweb*).
2. **Tunneling Obfuscation:** The web server only sees the tunnel's exit node; it has no network-layer visibility into the originating client IP.

```
TRADITIONAL DEFENSE:
Client (RU) ──[VPN Tunnel]──▶ German IP (Nekobyte/Hetzner) ──▶ Server: "Looks like Germany! Allowed." ❌

GEOSHIELD DEFENSE:
Client (RU) ──[VPN Tunnel]──▶ German IP (Nekobyte/Hetzner) ──▶ GeoShield Heuristics:
                                                                 ├── ASN Signature: Hosting Network (FLAGGED)
                                                                 ├── Edge Latency: 92ms to EU Edge (FLAGGED)
                                                                 ├── Device Timezone: Europe/Moscow (FLAGGED)
                                                                 └── Browser Locale: ru-RU (FLAGGED)
                                                                 └── Result: Risk Score 95/100 -> BLOCKED 🛡️
```

---

## 🔍 Detection Vectors

GeoShield correlates multiple independent layers into a **configurable weighted risk score**:

| Vector | Mechanism | Why It Works |
| :--- | :--- | :--- |
| **Data Center / ASN Signatures** | Scans ASNs, ISPs, and organization fields against an extensive dictionary of cloud hosts and regional VPS providers. | Real human traffic originates from residential/telecom ISPs, never data centers. |
| **Speed-of-Light (RTT) Latency** | Measures physical round-trip packet flight time to a high-availability CDN edge. | If an IP claims to be in Frankfurt/London but RTT is >65ms, physical distance proves the traffic is being routed from afar. |
| **System Timezone Cross-Check** | Inspects `Intl.DateTimeFormat` hardware time against the timezone expected for the IP. | Users often forget to spoof their underlying operating system's timezone. |
| **Browser Locale Fingerprinting** | Evaluates `navigator.languages` hierarchy. | Catches discrepancies between destination IP regions and installed language packs. |

---

## 🚀 Quickstart

### 1. Direct Script Include

Add `defender.js` to your frontend bundle or HTML:

```html
<script src="defender.js"></script>
<script>
  document.addEventListener("DOMContentLoaded", async () => {
    const shield = new GeoShield({
      riskThreshold: 40,            // Score (0-100) required to trigger action
      blockedCountries: ["RU"],     // Countries blocked on sight
      rttThresholdMs: 65            // Latency threshold for tunnel detection
    });

    const assessment = await shield.evaluate();

    if (assessment.isBlocked) {
      console.warn("Access denied. Risk score:", assessment.riskScore);
      window.location.href = "/restricted";
    } else {
      console.log("Session verified:", assessment);
    }
  });
</script>
```

---

## 📊 Result Payload Schema

Calling `await shield.evaluate()` resolves to a structured telemetry object:

```json
{
  "isBlocked": true,
  "riskScore": 90,
  "signals": [
    {
      "id": "LOCALE",
      "name": "Browser Language",
      "value": "ru-RU, ru, en-US",
      "flagged": true,
      "note": "Target language profile detected"
    },
    {
      "id": "TIMEZONE",
      "name": "System Timezone",
      "value": "Europe/Moscow",
      "flagged": true,
      "note": "Target timezone detected"
    },
    {
      "id": "HOSTING",
      "name": "Network Infrastructure",
      "value": "NEKOBYTE INTERNATIONAL LIMITED",
      "flagged": true,
      "note": "Identified as VPS/VPN provider (nekobyte)"
    },
    {
      "id": "LATENCY",
      "name": "Edge Round-Trip Time",
      "value": "89 ms",
      "flagged": true,
      "note": "High latency for an IP in NL (Tunnel indicator)"
    }
  ],
  "raw": {
    "ip": "185.x.x.x",
    "country": "Netherlands",
    "country_code": "NL",
    "rtt_ms": 89
  }
}
```

---

## ⚙️ Configuration Reference

Pass options into `new GeoShield(options)`:

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `riskThreshold` | `number` | `40` | Minimum score needed to set `isBlocked: true`. |
| `blockedCountries` | `string[]` | `["RU"]` | ISO 3166-1 alpha-2 country codes to block immediately. |
| `rttThresholdMs` | `number` | `65` | Maximum acceptable latency (ms) for close-proximity connections. |

---

## 🧪 Local Testing & Demo

The repository includes a live diagnostic dashboard (`index.html`).

Run the local server:
```bash
python3 -m http.server 3400
```
Open **`http://localhost:3400`** in your browser to view your live score breakdown.

---

## ⚖️ Defense-in-Depth Note

> **Client-Side vs. Edge Enforcement:**  
> This library provides intelligent front-line heuristics for anti-fraud, analytics, and progressive enforcement. However, any client-side JavaScript can theoretically be bypassed if an adversary disables JavaScript or modifies runtime execution. For high-security environments, combine GeoShield with server-side / WAF edge blocking (e.g., Cloudflare WAF, Nginx GeoIP2).

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more details.
