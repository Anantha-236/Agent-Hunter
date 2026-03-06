#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Agent-Hunter Live Test Runner
#  Run this from the root of the test-suite folder:
#    chmod +x scripts/run_tests.sh
#    ./scripts/run_tests.sh
# ─────────────────────────────────────────────────────────────

set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

# ── STEP 1: Start containers ──────────────────────────────────
echo ""
echo -e "${CYAN}════════════════════════════════════════════${NC}"
echo -e "${CYAN}   Agent-Hunter Test Suite — Live Runner    ${NC}"
echo -e "${CYAN}════════════════════════════════════════════${NC}"
echo ""

log "Starting all vulnerable target containers..."
docker compose up -d

log "Waiting 30 seconds for containers to initialize..."
sleep 30

# ── STEP 2: Health checks ─────────────────────────────────────
log "Checking targets are live..."

check_url() {
  local name=$1 url=$2
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
  if [[ "$code" == "200" || "$code" == "302" || "$code" == "301" ]]; then
    ok "$name is UP ($url) → HTTP $code"
  else
    warn "$name may not be ready ($url) → HTTP $code — try waiting a few more seconds"
  fi
}

check_url "DVWA"         "http://localhost:8010"
check_url "Juice Shop"   "http://localhost:8011"
check_url "WebGoat"      "http://localhost:8012/WebGoat"
check_url "Manifests"    "http://localhost:8030/package.json"
check_url "SAST files"   "http://localhost:8040/vuln_app.py"

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  All targets ready. Now run Agent-Hunter!  ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── STEP 3: Prompt user to run agent + collect output ─────────
TARGETS=(
  "web|DVWA|http://localhost:8010"
  "web|Juice Shop|http://localhost:8011"
  "web|WebGoat|http://localhost:8012/WebGoat"
  "network|Metasploitable|172.30.0.20"
  "dependency|NPM manifest|http://localhost:8030/package.json"
  "dependency|Python manifest|http://localhost:8030/requirements.txt"
  "sast|Python code|http://localhost:8040/vuln_app.py"
  "sast|JS code|http://localhost:8040/vuln_app.js"
)

ALL_RESULTS="$RESULTS_DIR/all_results.json"
echo "[" > "$ALL_RESULTS"
FIRST=true

for entry in "${TARGETS[@]}"; do
  IFS='|' read -r category name url <<< "$entry"

  echo ""
  echo -e "${CYAN}────────────────────────────────────────────${NC}"
  echo -e "  Target   : ${GREEN}$name${NC}"
  echo -e "  Category : $category"
  echo -e "  URL      : $url"
  echo -e "${CYAN}────────────────────────────────────────────${NC}"
  echo ""

  OUT_FILE="$RESULTS_DIR/result_$(echo "$name" | tr ' ' '_' | tr '[:upper:]' '[:lower:]').json"

  echo -e "${YELLOW}Run Agent-Hunter against this target and save output to:${NC}"
  echo -e "  ${GREEN}$OUT_FILE${NC}"
  echo ""
  echo "  Example (adjust to your agent's CLI):"
  echo -e "  ${CYAN}agent-hunter scan --url \"$url\" --output \"$OUT_FILE\"${NC}"
  echo ""
  read -rp "  Press ENTER once the scan is complete (or type 'skip' to skip): " resp

  if [[ "$resp" == "skip" ]]; then
    warn "Skipping $name"
    continue
  fi

  if [[ ! -f "$OUT_FILE" ]]; then
    warn "No output file found at $OUT_FILE — skipping validation for $name"
    continue
  fi

  ok "Output found: $OUT_FILE"

  # Merge into combined results
  if [ "$FIRST" = true ]; then
    FIRST=false
  else
    echo "," >> "$ALL_RESULTS"
  fi

  # Add category field to each finding if missing, then append
  python3 -c "
import json, sys
with open('$OUT_FILE') as f:
    findings = json.load(f)
for item in findings:
    item.setdefault('category', '$category')
print(json.dumps(findings)[1:-1], end='')
" >> "$ALL_RESULTS" 2>/dev/null || warn "Could not parse $OUT_FILE as JSON"

done

echo "]" >> "$ALL_RESULTS"

# ── STEP 4: Validate ──────────────────────────────────────────
echo ""
echo -e "${CYAN}════════════════════════════════════════════${NC}"
echo -e "${CYAN}   Running Validation Scorecard...          ${NC}"
echo -e "${CYAN}════════════════════════════════════════════${NC}"

if python3 scripts/validate_results.py --agent-output "$ALL_RESULTS"; then
  ok "Validation complete. Full combined results saved to: $ALL_RESULTS"
else
  err "Validation failed — check that $ALL_RESULTS is valid JSON."
fi

# ── STEP 5: Teardown prompt ───────────────────────────────────
echo ""
read -rp "Tear down all containers now? (y/N): " teardown
if [[ "$teardown" =~ ^[Yy]$ ]]; then
  docker compose down
  ok "All containers stopped."
else
  warn "Containers still running. Stop them later with: docker compose down"
fi

echo ""
ok "Done! Review your results in the '$RESULTS_DIR/' folder."
echo ""
