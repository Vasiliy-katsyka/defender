/**
 * GeoShield.js - Multi-Vector Client-Side VPN & Geo-Evasion Detection
 * Zero-dependency heuristic engine for anti-fraud and compliance.
 */
class GeoShield {
  constructor(config = {}) {
    this.blockedCountries = config.blockedCountries || ["RU"];
    this.riskThreshold = config.riskThreshold || 40;
    this.rttThresholdMs = config.rttThresholdMs || 65;
    this.euCountryCodes = ["NL", "DE", "GB", "FR", "BE", "SE", "CH", "AT", "IE"];

    this.hostingIdentifiers = [
      "nekobyte", "it-garage", "aeza", "firstvds", "justhost", "timeweb", "vdsina",
      "hosting", "datacenter", "data center", "cloud", "server", "vps", "dedicated",
      "digitalocean", "hetzner", "ovh", "linode", "vultr", "leaseweb", "m247",
      "choopa", "constant", "cogent", "fastly", "amazon", "aws", "google", "microsoft",
      "azure", "oracle", "datagroup", "ipvolume", "datacamp", "packethub", "selectel",
      "scaleway", "contabo", "kamatera", "melbicom", "redstation", "clouvider"
    ];

    this.targetTimezones = [
      "Europe/Moscow", "Asia/Yekaterinburg", "Asia/Novosibirsk", "Asia/Krasnoyarsk",
      "Asia/Irkutsk", "Asia/Yakutsk", "Asia/Vladivostok", "Asia/Magadan",
      "Asia/Sakhalin", "Asia/Kamchatka", "Asia/Anadyr", "Europe/Kaliningrad", "Europe/Samara"
    ];
  }

  async measureRTT() {
    const start = performance.now();
    try {
      await fetch("https://1.1.1.1/cdn-cgi/trace", { mode: "no-cors", cache: "no-store" });
      return Math.round(performance.now() - start);
    } catch {
      return null;
    }
  }

  async evaluate() {
    let riskScore = 0;
    const signals = [];

    // Signal 1: Browser Language Profile
    const langs = (navigator.languages || [navigator.language || ""]).join(", ");
    const hasTargetLang = (navigator.languages || [navigator.language]).some(l => l.toLowerCase().startsWith("ru"));
    if (hasTargetLang) {
      riskScore += 30;
      signals.push({ id: "LOCALE", name: "Browser Language", value: langs, flagged: true, note: "Target language profile detected" });
    } else {
      signals.push({ id: "LOCALE", name: "Browser Language", value: langs, flagged: false, note: "Standard locale" });
    }

    // Signal 2: Hardware / System Timezone
    const sysTZ = Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown";
    const isTargetTZ = this.targetTimezones.includes(sysTZ);
    if (isTargetTZ) {
      riskScore += 40;
      signals.push({ id: "TIMEZONE", name: "System Timezone", value: sysTZ, flagged: true, note: "Target timezone detected" });
    } else {
      signals.push({ id: "TIMEZONE", name: "System Timezone", value: sysTZ, flagged: false, note: "Normal timezone" });
    }

    // Signal 3: Network & Latency Telemetry
    try {
      const [ipData, rtt] = await Promise.all([
        fetch("https://ipwho.is/?security=1").then(r => r.json()),
        this.measureRTT()
      ]);

      // 3a. Direct IP Match
      if (this.blockedCountries.includes(ipData.country_code)) {
        riskScore += 100;
        signals.push({ id: "COUNTRY", name: "Direct IP Location", value: `${ipData.country} (${ipData.ip})`, flagged: true, note: "Origin country matched blocklist" });
      } else {
        signals.push({ id: "COUNTRY", name: "Direct IP Location", value: `${ipData.country} (${ipData.ip})`, flagged: false, note: `Routed via ${ipData.country_code}` });
      }

      // 3b. Hosting & VPN ASN Fingerprint
      const orgRaw = `${ipData.connection?.isp || ""} ${ipData.connection?.org || ""} ${ipData.connection?.asn || ""}`.toLowerCase();
      const matchedHoster = this.hostingIdentifiers.find(h => orgRaw.includes(h));

      if (matchedHoster || ipData.security?.hosting || ipData.security?.vpn || ipData.security?.proxy) {
        riskScore += 50;
        signals.push({ id: "HOSTING", name: "Network Infrastructure", value: ipData.connection?.isp || "Data Center", flagged: true, note: `Identified as VPS/VPN provider (${matchedHoster || "Hosting Subnet"})` });
      } else {
        signals.push({ id: "HOSTING", name: "Network Infrastructure", value: ipData.connection?.isp || "Residential", flagged: false, note: "Residential ISP profile" });
      }

      // 3c. Speed-of-Light (RTT) Discrepancy
      if (rtt !== null) {
        const isEuIP = this.euCountryCodes.includes(ipData.country_code);
        const isHighLatency = rtt > this.rttThresholdMs;

        if (isEuIP && isHighLatency) {
          riskScore += 30;
          signals.push({ id: "LATENCY", name: "Edge Round-Trip Time", value: `${rtt} ms`, flagged: true, note: `High latency for an IP in ${ipData.country_code} (Tunnel indicator)` });
        } else {
          signals.push({ id: "LATENCY", name: "Edge Round-Trip Time", value: `${rtt} ms`, flagged: false, note: "RTT consistent with physical geography" });
        }
      }

      return {
        isBlocked: riskScore >= this.riskThreshold,
        riskScore,
        signals,
        raw: { ...ipData, rtt_ms: rtt }
      };

    } catch (err) {
      return {
        isBlocked: false,
        error: err.message,
        signals
      };
    }
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = GeoShield;
} else {
  window.GeoShield = GeoShield;
}
