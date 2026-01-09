<div align="center">
<h1> SCAikido - Software Composition Analysis Tool </h1>

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Shell](https://img.shields.io/badge/shell-bash-yellow.svg)

**Automated vulnerability scanner using Syft SBOM and Aikido Intel database**

</div>

---

## 🚨 IMPORTANT DISCLAIMER

> **⚠️ LIMITED VULNERABILITY DATABASE COVERAGE**
> 
> 
> This tool uses the [Aikido Intel](https://github.com/AikidoSec/intel) vulnerability database, which tracks **5 million open-source packages** and exposes vulnerabilities **before they get CVE numbers** (many never do).
>
> ### Why Use Multiple Tools?
>
> While Aikido Intel provides **early detection** of vulnerabilities that may not have official CVEs yet, different security databases have different coverage:
>
> - 🔹 **Aikido Intel**: Early detection, curated high-impact vulnerabilities
> - 🔹 **npm audit / NVD**: Official CVEs and GitHub Security Advisories
> - 🔹 **Snyk / Trivy**: Commercial databases with extensive coverage
>
> This doesn't mean one is better than the other - they complement each other:
> - npm audit may catch older, well-documented CVEs
> - SCAikido may catch newer vulnerabilities without CVE numbers yet
>
> ### ✅ Best Practice:
>
> ### Known Limitations:
> 
> - ❌ **Older packages** may not be covered
>
> ### ✅ Recommendation:
>
> **DO NOT use this as your only security scanner!** Always complement with:
> 
> - 🔹 `npm audit` / `yarn audit` (Node.js)
> - 🔹 `pip-audit` (Python)
> - 🔹 among others / and similar tools
>
> **Use SCAikido as a complementary tool** alongside comprehensive scanners.

---

## 📋 How It Works

1. Generate SBOM (Syft) ↓
2. Download Aikido Intel Database ↓
3. Match Dependencies with Vulnerabilities ↓
4. Generate JSON Report


---

## 📦 Prerequisites

```bash
# Syft - SBOM generator
brew install syft  # macOS
# or: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# jq - JSON processor
brew install jq  # macOS
# or: sudo apt-get install jq

# Node.js - Version comparison
brew install node  # macOS
# or: sudo apt-get install nodejs

# Git - Clone Aikido Intel
# Usually pre-installed
```

---
## 🚀 Installation

```bash
git clone https://github.com/yourusername/scaikido.git
cd scaikido
chmod +x SCAikido.sh
```

---

## 💻 Usage

```bash
# Silent mode
./SCAikido.sh

# Verbose mode
./SCAikido.sh -v

# Debug mode
./SCAikido.sh -d

# Custom output
./SCAikido.sh -v -o my_report.json
```

---
## 📄 Output Example
```json
{
  "scan_date": "2026-01-09T12:59:45Z",
  "total_packages": 47,
  "vulnerable_packages": 1,
  "vulnerabilities": [
    {
      "package": "axios",
      "version": "0.18.0",
      "vulnerability_id": "AIKIDO-2023-10001",
      "title": "Several security vulnerabilities were quietly patched in `axios` version 1.6.4 and version 0.29.0. Notably, a prototype pollution flaw impacted the `formDataToJSON` function, posing a significant risk. Additionally, a Regular Expression Denial of Service (ReDoS) vulnerability was identified and fixed in the `combineURLs` function.",
      "severity": "HIGH",
      "aikido_score": 77,
      "cve": "",
      "cwe": [
        "CWE-1321"
      ],
      "affected_versions": [
        [
          "0.1.0",
          "0.28.1"
        ],
        [
          "1.0.0",
          "1.6.3"
        ]
      ],
      "patched_versions": [
        "0.29.0",
        "1.6.4"
      ],
      "description": "Several security vulnerabilities were quietly patched in `axios` version 1.6.4 and version 0.29.0. Notably, a prototype pollution flaw impacted the `formDataToJSON` function, posing a significant risk. Additionally, a Regular Expression Denial of Service (ReDoS) vulnerability was identified and fixed in the `combineURLs` function.",
      "how_to_fix": "To fix, either freeze the prototype or upgrade to axios 1.6.4 or above.",
      "does_this_affect_me": "You are affected by this flaw if you use the formDataToJSON function. This is more likely to happen in a front-end than in a backend.",
      "vulnerable_to": "Prototype Pollution",
      "changelog": "https://github.com/axios/axios/releases/tag/v1.6.4",
      "published": "2024-02-01"
    }
],
  "statistics": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}

```

---
## 🤝 Contributing
Contributions welcome! Please open an issue or submit a pull request.

---
## 🙏 Acknowledgments
- [Aikido Security](https://github.com/AikidoSec/intel) - Vulnerability database
- [Anchore Syft](https://github.com/anchore/syft) - SBOM generation

---
<div align="center">

Made with ❤️ by [TryckMaster](https://github.com/DaniloSilvaDeOliveira)

</div>
