# GeoShield.js 🛡️

A lightweight, zero-dependency client-side anti-evasion and VPN detection engine.

Most basic geo-blocking mechanisms simply check the IP address. Commercial VPNs and regional hosting proxies easily bypass these checks. **GeoShield** implements defense-in-depth by correlating multiple browser and network characteristics to detect geographic masking and proxies.

---

## Detection Vectors

1. **Hosting & Offshore VPS Detection:** Detects data center providers, cloud infrastructure, and regional bulletproof/VPN hosters (e.g., Nekobyte, IT-Garage, Aeza, Hetzner, DigitalOcean) that often go unflagged on free IP registries.
2. **Speed-of-Light (RTT) Latency Checks:** Pings high-availability CDN edge nodes to measure physical packet travel time. If an IP claims to be in London or Amsterdam but has an 80ms+ round-trip latency, the physical distance mismatch flags the tunnel.
3. **Hardware & System Timezone Alignment:** Detects mismatches between the operating system's system clock/timezone and the timezone associated with the incoming IP.
4. **Browser Locale Fingerprinting:** Inspects `navigator.languages` for language traces inconsistent with the destination region.
5. **Weighted Risk Scoring:** Rather than a binary pass/fail, anomalies accumulate points toward a configurable risk threshold.

---

## Quickstart

### Include directly in HTML:
```html
<script src="defender.js"></script>
<script>
  async function checkAccess() {
    const shield = new GeoShield({
      riskThreshold: 40,
      blockedCountries: ["RU"]
    });

    const result = await shield.evaluate();

    if (result.isBlocked) {
      alert("Access restricted: VPN or blocked region detected.");
      window.location.href = "/blocked.html";
    }
  }
  checkAccess();
</script>
```

---

## Configuration Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `riskThreshold` | `number` | `40` | Total risk score required to trigger a block. |
| `blockedCountries` | `Array` | `["RU"]` | Country codes to block directly on sight. |
| `rttThresholdMs` | `number` | `65` | Max allowed RTT before flagging European IPs as tunnels. |

---

## Live Demo Test

Run a local server:
```bash
python3 -m http.server 3400
```
Open `http://localhost:3400` in your browser.

---

## License
MIT License.
