#!/usr/bin/env bash
# =============================================================================
# Unpack and organize FirmAE dataset into vendor directories
# Expected input: aiedge-inputs/FirmAE_dataset.zip (11.9GB)
# Output:         aiedge-inputs/firmae-benchmark/<vendor>/<firmware files>
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ZIP_FILE="${1:-${REPO_ROOT}/aiedge-inputs/FirmAE_dataset.zip}"
BENCHMARK_DIR="${REPO_ROOT}/aiedge-inputs/firmae-benchmark"
TEMP_DIR="${REPO_ROOT}/aiedge-inputs/.firmae-unpack-tmp"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
log()  { echo -e "${BLUE}[UNPACK]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }

# --- Validate ---
[[ -f "$ZIP_FILE" ]] || fail "ZIP not found: $ZIP_FILE"
log "Source: $ZIP_FILE ($(du -h "$ZIP_FILE" | awk '{print $1}'))"

# --- Unzip to temp ---
log "Extracting to temp directory..."
mkdir -p "$TEMP_DIR"
unzip -q -o "$ZIP_FILE" -d "$TEMP_DIR"
ok "Extraction complete"

# --- Vendor classification ---
# FirmAE dataset naming conventions:
#   D-Link:   DIR-*, DCS-*, DAP-*, DSL-*, DWR-*
#   TP-Link:  TL-*, Archer*, TD-*, RE*, Deco*
#   NETGEAR:  R[0-9]*, WNDR*, WNR*, DGN*, D[0-9]*, EX*, XR*
#   TRENDnet: TEW-*, TV-IP*, TW100-*
#   ASUS:     RT-*, DSL-*, GT-*, ZenWiFi*
#   Belkin:   F[0-9]*, N[0-9]*
#   Linksys:  WRT*, EA*, E[0-9]*, MR*, MX*
#   Zyxel:    NBG-*, VMG-*, WAP-*, LTE*

classify_vendor() {
    local filename="$1"
    local upper
    upper=$(echo "$filename" | tr '[:lower:]' '[:upper:]')

    # Check directory path hints first
    case "$filename" in
        *[Dd]-[Ll]ink*|*[Dd]link*)  echo "dlink"; return ;;
        *[Tt][Pp]-[Ll]ink*|*tplink*) echo "tplink"; return ;;
        *[Nn]etgear*|*NETGEAR*)     echo "netgear"; return ;;
        *[Tt][Rr][Ee][Nn][Dd]net*)  echo "trendnet"; return ;;
        *[Aa][Ss][Uu][Ss]*)         echo "asus"; return ;;
        *[Bb]elkin*)                echo "belkin"; return ;;
        *[Ll]inksys*)               echo "linksys"; return ;;
        *[Zz]yxel*|*[Zz]y[Xx][Ee][Ll]*) echo "zyxel"; return ;;
    esac

    # Check filename patterns
    case "$upper" in
        DIR-*|DCS-*|DAP-*|DSL-*|DWR-*|DHP-*|DNR-*|DGL-*)
            echo "dlink" ;;
        TL-*|ARCHER*|TD-*|RE[0-9]*|DECO*|TX-*)
            echo "tplink" ;;
        R[0-9]*|WNDR*|WNR*|DGN*|D[0-9][0-9][0-9][0-9]*|EX[0-9]*|XR[0-9]*|NIGHTHAWK*|ORBI*|RAX*|RBK*|RBS*)
            echo "netgear" ;;
        TEW-*|TV-IP*|TW100-*)
            echo "trendnet" ;;
        RT-*|GT-*|ZENWIFI*|ROG*|TUF-*)
            echo "asus" ;;
        F[0-9][A-Z]*|N[0-9][0-9][0-9]*)
            echo "belkin" ;;
        WRT*|EA[0-9]*|E[0-9][0-9][0-9][0-9]*|MR[0-9]*|MX[0-9]*)
            echo "linksys" ;;
        NBG-*|VMG-*|WAP-*|LTE[0-9]*|USG*)
            echo "zyxel" ;;
        *)
            echo "unknown" ;;
    esac
}

# --- Organize files ---
log "Classifying firmware by vendor..."
mkdir -p "$BENCHMARK_DIR"/{dlink,tplink,netgear,trendnet,asus,belkin,linksys,zyxel,ipcam,unknown}

declare -A COUNT
TOTAL_FILES=0

find "$TEMP_DIR" -type f | while read -r filepath; do
    filename=$(basename "$filepath")

    # Skip non-firmware files
    case "$filename" in
        *.txt|*.md|*.csv|*.json|*.html|*.py|*.sh|*.log)
            continue ;;
    esac

    vendor=$(classify_vendor "$filepath")
    target_dir="$BENCHMARK_DIR/$vendor"
    mkdir -p "$target_dir"

    # Avoid overwriting — add hash suffix if exists
    if [[ -f "$target_dir/$filename" ]]; then
        hash=$(sha256sum "$filepath" | cut -c1-8)
        ext="${filename##*.}"
        base="${filename%.*}"
        filename="${base}_${hash}.${ext}"
    fi

    cp "$filepath" "$target_dir/$filename"
    echo "  $vendor <- $filename"
done

# --- Summary ---
log "Classification complete. Summary:"
for vendor_dir in "$BENCHMARK_DIR"/*/; do
    vendor=$(basename "$vendor_dir")
    count=$(find "$vendor_dir" -type f | wc -l)
    if [[ $count -gt 0 ]]; then
        ok "  ${vendor}: ${count} images"
    fi
done

TOTAL=$(find "$BENCHMARK_DIR" -type f | wc -l)
ok "Total: ${TOTAL} firmware images organized"

# --- Cleanup ---
log "Cleaning up temp directory..."
rm -rf "$TEMP_DIR"
ok "Done! Dataset ready at: ${BENCHMARK_DIR}"
echo ""
echo "Next steps:"
echo "  # Dry run (list files):"
echo "  ./scripts/benchmark_firmae.sh --dry-run"
echo ""
echo "  # Quick test (10 images, 2 min each):"
echo "  ./scripts/benchmark_firmae.sh --max-images 10 --time-budget 120"
echo ""
echo "  # Full benchmark:"
echo "  ./scripts/benchmark_firmae.sh --parallel 8"
