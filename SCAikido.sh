#!/bin/bash

# Vulnerability Analysis Script using Syft SBOM and Aikido Intel
# Author: TryckMaster
# Optimized Version - Universal Package Matching with Language Validation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SBOM_FILE=""
AIKIDO_INTEL_DIR="aikido-intel"
AIKIDO_INTEL_REPO="https://github.com/AikidoSec/intel.git"
RESULTS_FILE="vulnerability_report.json"
VERBOSE=false
DEBUG=false

# Logging function
log() {
    if [ "$VERBOSE" = true ]; then
        echo -e "$@"
    fi
}

debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $@"
    fi
}

# Cleanup function
cleanup() {
    if [ -d "$AIKIDO_INTEL_DIR" ]; then
        log "${YELLOW}[*] Cleaning up Aikido Intel directory...${NC}"
        rm -rf "$AIKIDO_INTEL_DIR"
        log "${GREEN}[+] Cleanup completed${NC}"
    fi
    rm -f /tmp/check_version.js /tmp/build_index.js /tmp/vuln_index.json /tmp/packages.json /tmp/vulnerabilities.json /tmp/lang_map.json
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Show usage
show_usage() {
    echo "Usage: $0 [options] <sbom.json>"
    echo ""
    echo "Arguments:"
    echo "  sbom.json           Path to SBOM file (JSON format from Syft)"
    echo ""
    echo "Options:"
    echo "  -v, --verbose       Verbose mode (shows detailed logs)"
    echo "  -d, --debug         Debug mode (shows version comparison details)"
    echo "  -o, --output FILE   Specify output file (default: vulnerability_report.json)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Supported Ecosystems (Aikido Intel):"
    echo "  NPM, PyPi, PHP, Ruby, NuGet, Maven, Rust, Go, C++, Dart, Elixir, Swift"
    echo ""
    echo "Examples:"
    echo "  $0 sbom.json"
    echo "  $0 -v sbom.json"
    echo "  $0 -o my_report.json sbom.json"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            VERBOSE=true
            shift
            ;;
        -o|--output)
            RESULTS_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            echo -e "${RED}[!] Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
        *)
            SBOM_FILE="$1"
            shift
            ;;
    esac
done

# Validate inputs
if [ -z "$SBOM_FILE" ]; then
    echo -e "${RED}[!] Error: SBOM file not provided${NC}" >&2
    echo ""
    show_usage
    exit 1
fi

if [ ! -f "$SBOM_FILE" ]; then
    echo -e "${RED}[!] Error: SBOM file not found: $SBOM_FILE${NC}" >&2
    exit 1
fi

# Check dependencies
for cmd in jq node git; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}[!] Error: $cmd not found. Please install $cmd before running this script.${NC}" >&2
        exit 1
    fi
done

log "${GREEN}[+] Starting vulnerability analysis...${NC}"
log "${BLUE}[i] SBOM file: $SBOM_FILE${NC}"

# Validate SBOM format
log "${YELLOW}[*] Validating SBOM format...${NC}"
if ! jq -e '.artifacts' "$SBOM_FILE" >/dev/null 2>&1; then
    echo -e "${RED}[!] Error: Invalid SBOM format. Expected Syft JSON format with 'artifacts' field.${NC}" >&2
    exit 1
fi
log "${GREEN}[+] SBOM format validated${NC}"

# Clone Aikido Intel
log "${YELLOW}[*] Cloning Aikido Intel repository...${NC}"
if [ -d "$AIKIDO_INTEL_DIR" ]; then
    log "${YELLOW}[*] Removing existing directory to ensure fresh data...${NC}"
    rm -rf "$AIKIDO_INTEL_DIR"
fi

if [ "$VERBOSE" = true ]; then
    git clone --depth 1 "$AIKIDO_INTEL_REPO" "$AIKIDO_INTEL_DIR"
else
    git clone --depth 1 "$AIKIDO_INTEL_REPO" "$AIKIDO_INTEL_DIR" >/dev/null 2>&1
fi
log "${GREEN}[+] Aikido Intel downloaded${NC}"

# Create refined language mapping based on Aikido ecosystems
cat > /tmp/lang_map.json <<'LANGMAP'
{
  "npm": ["js"],
  "yarn": ["js"],
  "pnpm": ["js"],
  "node": ["js"],
  "javascript": ["js"],
  "python": ["python"],
  "pip": ["python"],
  "pipenv": ["python"],
  "poetry": ["python"],
  "pypi": ["python"],
  "gem": ["ruby"],
  "bundler": ["ruby"],
  "ruby": ["ruby"],
  "php-composer": ["php"],
  "composer": ["php"],
  "php": ["php"],
  "dotnet": ["dotnet"],
  "nuget": ["dotnet"],
  "csharp": ["dotnet"],
  "java-archive": ["java"],
  "maven": ["java"],
  "gradle": ["java"],
  "jar": ["java"],
  "java": ["java"],
  "rust": ["rust"],
  "cargo": ["rust"],
  "crate": ["rust"],
  "go-module": ["go"],
  "go": ["go"],
  "golang": ["go"],
  "dart-pub": ["dart"],
  "pub": ["dart"],
  "flutter": ["dart"],
  "dart": ["dart"],
  "hex": ["elixir"],
  "mix": ["elixir"],
  "elixir": ["elixir"],
  "swift": ["swift"],
  "cocoapods": ["swift"],
  "carthage": ["swift"],
  "cpp": ["c++"],
  "conan": ["c++"],
  "c": ["c++"],
  "cxx": ["c++"],
  "c++": ["c++"],
  "alpm": ["c++"],
  "apk": ["c++"],
  "deb": ["c++"],
  "rpm": ["c++"]
}
LANGMAP

# Create optimized index builder (Node.js)
log "${YELLOW}[*] Building vulnerability index...${NC}"

cat > /tmp/build_index.js <<'INDEXSCRIPT'
const fs = require('fs');
const path = require('path');

// Aikido supported languages
const AIKIDO_LANGUAGES = [
    'js', 'python', 'php', 'ruby', 'dotnet', 
    'java', 'rust', 'go', 'c++', 'dart', 
    'elixir', 'swift'
];

// Normalize package name for matching
function normalizePackageName(name) {
    return name.toLowerCase().replace(/[^a-z0-9]/g, '-');
}

// Normalize language name
function normalizeLanguage(lang) {
    const normalized = lang.toLowerCase().trim();
    
    // Map common variations to Aikido standard
    const langMap = {
        'javascript': 'js',
        'node': 'js',
        'nodejs': 'js',
        'py': 'python',
        'csharp': 'dotnet',
        'c#': 'dotnet',
        '.net': 'dotnet',
        'golang': 'go',
        'cpp': 'c++',
        'cxx': 'c++',
        'c': 'c++'
    };
    
    return langMap[normalized] || normalized;
}

// Build comprehensive index
function buildIndex(vulnDir) {
    const index = {
        exact: {},      // Original name -> [{lang, data}, ...]
        lower: {},      // Lowercase -> [{lang, data}, ...]
        normalized: {}, // Alphanumeric + hyphens -> [{lang, data}, ...]
        all: []         // All vulnerabilities for substring search
    };
    
    const files = fs.readdirSync(vulnDir)
        .filter(f => f.endsWith('.json'));
    
    let processed = 0;
    let skipped = 0;
    const languageStats = {};
    
    for (const file of files) {
        const filePath = path.join(vulnDir, file);
        try {
            const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            const pkgName = content.package_name;
            const rawLanguage = content.language || 'unknown';
            const language = normalizeLanguage(rawLanguage);
            
            if (!pkgName) {
                skipped++;
                continue;
            }
            
            // Track language statistics
            languageStats[language] = (languageStats[language] || 0) + 1;
            
            const vulnData = {
                file: filePath,
                package: pkgName,
                language: language,
                ranges: content.vulnerable_ranges || [],
                patches: content.patch_versions || []
            };
            
            // Index by exact name
            if (!index.exact[pkgName]) {
                index.exact[pkgName] = [];
            }
            index.exact[pkgName].push(vulnData);
            
            // Index by lowercase
            const lowerName = pkgName.toLowerCase();
            if (!index.lower[lowerName]) {
                index.lower[lowerName] = [];
            }
            index.lower[lowerName].push(vulnData);
            
            // Index by normalized name
            const normName = normalizePackageName(pkgName);
            if (!index.normalized[normName]) {
                index.normalized[normName] = [];
            }
            index.normalized[normName].push(vulnData);
            
            // Add to full list for substring search
            index.all.push(vulnData);
            
            processed++;
            
        } catch (err) {
            skipped++;
        }
    }
    
    return { index, processed, skipped, languageStats };
}

// Main execution
const vulnDir = process.argv[2];
const outputFile = process.argv[3];

const startTime = Date.now();
const { index, processed, skipped, languageStats } = buildIndex(vulnDir);
const elapsed = Date.now() - startTime;

fs.writeFileSync(outputFile, JSON.stringify(index, null, 2));

console.error(`Indexed ${processed} vulnerabilities in ${elapsed}ms`);
console.error(`Skipped: ${skipped} invalid files`);
console.error(`Unique packages: ${Object.keys(index.exact).length}`);
console.error(`\nLanguage distribution:`);
Object.entries(languageStats)
    .sort((a, b) => b[1] - a[1])
    .forEach(([lang, count]) => {
        console.error(`  ${lang}: ${count}`);
    });
INDEXSCRIPT

# Build index
start_time=$(date +%s%3N)
if [ "$VERBOSE" = true ]; then
    node /tmp/build_index.js "$AIKIDO_INTEL_DIR/vulnerabilities" /tmp/vuln_index.json
else
    node /tmp/build_index.js "$AIKIDO_INTEL_DIR/vulnerabilities" /tmp/vuln_index.json 2>/dev/null
fi
end_time=$(date +%s%3N)
index_time=$((end_time - start_time))
log "${GREEN}[+] Index built in ${index_time}ms${NC}"

# Extract packages from SBOM with language detection
log "${YELLOW}[*] Extracting packages from SBOM...${NC}"
jq '[.artifacts[] | {name: .name, version: .version, type: .type, purl: .purl}]' "$SBOM_FILE" > /tmp/packages.json

total_packages=$(jq 'length' /tmp/packages.json)
log "${GREEN}[+] Found $total_packages packages to analyze${NC}"

if [ "$total_packages" -eq 0 ]; then
    echo -e "${YELLOW}[!] Warning: No packages found in SBOM${NC}"
    exit 0
fi

# Show package type distribution
if [ "$VERBOSE" = true ]; then
    log "${BLUE}[i] Package type distribution:${NC}"
    jq -r '.[].type' /tmp/packages.json | sort | uniq -c | while read count type; do
        log "${BLUE}    $count x $type${NC}"
    done
fi

# Create version comparison script
cat > /tmp/check_version.js <<'VERSIONSCRIPT'
function parseVersion(v) {
    const cleanVersion = v.split('-')[0].split('+')[0];
    return cleanVersion.split('.').map(x => parseInt(x) || 0);
}

function compareVersions(v1, v2) {
    const parts1 = parseVersion(v1);
    const parts2 = parseVersion(v2);
    
    const maxLen = Math.max(parts1.length, parts2.length);
    for (let i = 0; i < maxLen; i++) {
        const p1 = parts1[i] || 0;
        const p2 = parts2[i] || 0;
        if (p1 > p2) return 1;
        if (p1 < p2) return -1;
    }
    return 0;
}

function isInRange(version, minVersion, maxVersion) {
    const cmpMin = compareVersions(version, minVersion);
    const cmpMax = compareVersions(version, maxVersion);
    return cmpMin >= 0 && cmpMax <= 0;
}

const args = process.argv.slice(2);
console.log(isInRange(args[0], args[1], args[2]));
VERSIONSCRIPT

# Create vulnerability scanner with language validation
cat > /tmp/scan_vulnerabilities.js <<'SCANSCRIPT'
const fs = require('fs');
const { execSync } = require('child_process');

// Load language mapping
const langMap = JSON.parse(fs.readFileSync('/tmp/lang_map.json', 'utf8'));

// Aikido supported languages
const AIKIDO_LANGUAGES = [
    'js', 'python', 'php', 'ruby', 'dotnet', 
    'java', 'rust', 'go', 'c++', 'dart', 
    'elixir', 'swift'
];

function normalizePackageName(name) {
    return name.toLowerCase().replace(/[^a-z0-9]/g, '-');
}

function checkVersion(version, minVersion, maxVersion) {
    try {
        const result = execSync(
            `node /tmp/check_version.js "${version}" "${minVersion}" "${maxVersion}"`,
            { encoding: 'utf8' }
        ).trim();
        return result === 'true';
    } catch {
        return false;
    }
}

// Map SBOM package type to Aikido languages
function getCompatibleLanguages(packageType, purl) {
    const type = packageType.toLowerCase();
    
    // Try purl first (more reliable)
    if (purl) {
        const purlType = purl.split(':')[1]?.split('/')[0] || '';
        if (langMap[purlType]) {
            return langMap[purlType];
        }
    }
    
    // Direct mapping from type
    if (langMap[type]) {
        return langMap[type];
    }
    
    // Fuzzy matching on type
    for (const [key, langs] of Object.entries(langMap)) {
        if (type.includes(key) || key.includes(type)) {
            return langs;
        }
    }
    
    return [];
}

// Check if vulnerability language matches package type
function isLanguageCompatible(vulnLang, compatibleLangs) {
    if (compatibleLangs.length === 0) return true; // No filter = accept all
    
    const normalized = vulnLang.toLowerCase().trim();
    return compatibleLangs.some(lang => 
        lang.toLowerCase() === normalized
    );
}

function findVulnerabilities(pkg, index, verbose) {
    const packageName = pkg.name;
    const packageVersion = pkg.version;
    const packageType = pkg.type;
    const purl = pkg.purl || '';
    
    // Get compatible languages for this package type
    const compatibleLangs = getCompatibleLanguages(packageType, purl);
    
    if (verbose) {
        if (compatibleLangs.length > 0) {
            console.error(`  [i] Compatible languages: ${compatibleLangs.join(', ')}`);
        } else {
            console.error(`  [!] Warning: Could not determine language for type '${packageType}'`);
        }
    }
    
    const candidateVulns = [];
    
    // Strategy 1: Exact match
    if (index.exact[packageName]) {
        if (verbose) console.error(`  [✓] Exact match found`);
        candidateVulns.push(...index.exact[packageName]);
    }
    
    // Strategy 2: Lowercase match
    if (candidateVulns.length === 0) {
        const lowerName = packageName.toLowerCase();
        if (index.lower[lowerName]) {
            if (verbose) console.error(`  [✓] Lowercase match found`);
            candidateVulns.push(...index.lower[lowerName]);
        }
    }
    
    // Strategy 3: Normalized match
    if (candidateVulns.length === 0) {
        const normName = normalizePackageName(packageName);
        if (index.normalized[normName]) {
            if (verbose) console.error(`  [✓] Normalized match found`);
            candidateVulns.push(...index.normalized[normName]);
        }
    }
    
    // Strategy 4: Substring match (only with language filter)
    if (candidateVulns.length === 0 && compatibleLangs.length > 0) {
        const lowerPkg = packageName.toLowerCase();
        const matches = index.all.filter(v => {
            const nameMatch = v.package.toLowerCase().includes(lowerPkg) ||
                            lowerPkg.includes(v.package.toLowerCase());
            const langMatch = isLanguageCompatible(v.language, compatibleLangs);
            return nameMatch && langMatch;
        });
        
        if (matches.length > 0) {
            if (verbose) console.error(`  [✓] Substring match found (${matches.length} candidates)`);
            candidateVulns.push(...matches);
        }
    }
    
    // Filter by language compatibility
    let filteredVulns = candidateVulns;
    if (compatibleLangs.length > 0) {
        const beforeCount = candidateVulns.length;
        filteredVulns = candidateVulns.filter(v => 
            isLanguageCompatible(v.language, compatibleLangs)
        );
        
        if (verbose && filteredVulns.length < beforeCount) {
            const rejected = beforeCount - filteredVulns.length;
            console.error(`  [i] Filtered ${rejected} vulnerability(ies) due to language mismatch`);
            
            // Show rejected vulnerabilities
            const rejectedVulns = candidateVulns.filter(v => !filteredVulns.includes(v));
            rejectedVulns.forEach(v => {
                console.error(`      - ${v.package} (${v.language}) ≠ [${compatibleLangs.join(', ')}]`);
            });
        }
    }
    
    if (filteredVulns.length === 0) {
        if (verbose) console.error(`  [✓] No vulnerabilities found`);
        return [];
    }
    
    // Check version ranges
    const vulnerabilities = [];
    for (const vuln of filteredVulns) {
        for (const range of vuln.ranges) {
            if (range.length === 2) {
                const [minVer, maxVer] = range;
                if (checkVersion(packageVersion, minVer, maxVer)) {
                    const vulnFile = JSON.parse(fs.readFileSync(vuln.file, 'utf8'));
                    const vulnId = vuln.file.split('/').pop().replace('.json', '');
                    
                    if (verbose) {
                        console.error(`  [!] VULNERABLE: ${vulnId} [${vuln.language}]`);
                    }
                    
                    vulnerabilities.push({
                        package: packageName,
                        version: packageVersion,
                        package_type: packageType,
                        language: vuln.language,
                        vulnerability_id: vulnId,
                        title: vulnFile.tldr,
                        severity: vulnFile.severity_class,
                        aikido_score: vulnFile.aikido_score,
                        cve: vulnFile.related_cve_id,
                        cwe: vulnFile.cwe,
                        affected_versions: vulnFile.vulnerable_ranges,
                        patched_versions: vulnFile.patch_versions,
                        description: vulnFile.tldr,
                        how_to_fix: vulnFile.how_to_fix,
                        does_this_affect_me: vulnFile.doest_this_affect_me,
                        vulnerable_to: vulnFile.vulnerable_to,
                        changelog: vulnFile.changelog,
                        published: vulnFile.published
                    });
                    break; // One vulnerability per package
                }
            }
        }
    }
    
    return vulnerabilities;
}

// Main execution
const packagesFile = process.argv[2];
const indexFile = process.argv[3];
const outputFile = process.argv[4];
const verbose = process.argv[5] === 'true';

const packages = JSON.parse(fs.readFileSync(packagesFile, 'utf8'));
const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));

const allVulnerabilities = [];
let checkedCount = 0;

for (const pkg of packages) {
    checkedCount++;
    if (verbose) {
        console.error(`\n[${checkedCount}/${packages.length}] ${pkg.name}@${pkg.version} (${pkg.type})`);
    }
    
    const vulns = findVulnerabilities(pkg, index, verbose);
    allVulnerabilities.push(...vulns);
}

fs.writeFileSync(outputFile, JSON.stringify(allVulnerabilities, null, 2));

if (verbose) {
    console.error(`\n${'='.repeat(50)}`);
}
console.error(`Scan completed: ${allVulnerabilities.length} vulnerabilities in ${checkedCount} packages`);
SCANSCRIPT

# Run vulnerability scan
log "${YELLOW}[*] Scanning for vulnerabilities...${NC}"
scan_start=$(date +%s%3N)

if [ "$VERBOSE" = true ]; then
    node /tmp/scan_vulnerabilities.js /tmp/packages.json /tmp/vuln_index.json /tmp/vulnerabilities.json true
else
    node /tmp/scan_vulnerabilities.js /tmp/packages.json /tmp/vuln_index.json /tmp/vulnerabilities.json false 2>/dev/null
fi

scan_end=$(date +%s%3N)
scan_time=$((scan_end - scan_start))
log "${GREEN}[+] Scan completed in ${scan_time}ms${NC}"

# Build final report
log "${YELLOW}[*] Building final report...${NC}"

vulnerable_count=$(jq 'length' /tmp/vulnerabilities.json)

jq -n \
   --arg date "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
   --arg sbom "$SBOM_FILE" \
   --argjson total "$total_packages" \
   --argjson vulnerable "$vulnerable_count" \
   --slurpfile vulns /tmp/vulnerabilities.json \
   '{
        scan_date: $date,
        sbom_file: $sbom,
        total_packages: $total,
        vulnerable_packages: $vulnerable,
        vulnerabilities: $vulns[0],
        statistics: {
            critical: ([$vulns[0][] | select(.severity == "CRITICAL")] | length),
            high: ([$vulns[0][] | select(.severity == "HIGH")] | length),
            medium: ([$vulns[0][] | select(.severity == "MEDIUM")] | length),
            low: ([$vulns[0][] | select(.severity == "LOW")] | length)
        },
        by_language: (
            $vulns[0] | group_by(.language) | 
            map({
                language: .[0].language,
                count: length,
                packages: map(.package) | unique
            })
        )
    }' > "$RESULTS_FILE"

# Final summary
echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  ANALYSIS COMPLETED${NC}"
echo -e "${GREEN}================================${NC}"
echo -e "SBOM file: ${BLUE}$SBOM_FILE${NC}"
echo -e "Total packages: ${YELLOW}$total_packages${NC}"
echo -e "Vulnerable packages: ${RED}$vulnerable_count${NC}"
echo -e "Index build time: ${BLUE}${index_time}ms${NC}"
echo -e "Scan time: ${BLUE}${scan_time}ms${NC}"
echo ""
echo -e "Report saved to: ${GREEN}$RESULTS_FILE${NC}"
echo ""

if [ "$vulnerable_count" -gt 0 ]; then
    echo -e "${RED}[!] VULNERABILITIES FOUND:${NC}"
    jq -r '.vulnerabilities[] | "  - \(.package)@\(.version) [\(.package_type)] → \(.language): \(.vulnerability_id) - \(.title) [\(.severity)]"' "$RESULTS_FILE"
    echo ""
    
    # Statistics
    critical=$(jq '.statistics.critical' "$RESULTS_FILE")
    high=$(jq '.statistics.high' "$RESULTS_FILE")
    medium=$(jq '.statistics.medium' "$RESULTS_FILE")
    low=$(jq '.statistics.low' "$RESULTS_FILE")
    
    echo -e "${YELLOW}Severity Distribution:${NC}"
    [ "$critical" -gt 0 ] && echo -e "  ${RED}Critical: $critical${NC}"
    [ "$high" -gt 0 ] && echo -e "  ${RED}High: $high${NC}"
    [ "$medium" -gt 0 ] && echo -e "  ${YELLOW}Medium: $medium${NC}"
    [ "$low" -gt 0 ] && echo -e "  ${GREEN}Low: $low${NC}"
    
    echo ""
    echo -e "${YELLOW}By Language:${NC}"
    jq -r '.by_language[] | "  \(.language): \(.count) vulnerabilities in \(.packages | length) package(s)"' "$RESULTS_FILE"
    
    exit 1
else
    echo -e "${GREEN}[✓] No vulnerabilities found!${NC}"
    exit 0
fi
