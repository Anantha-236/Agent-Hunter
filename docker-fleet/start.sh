#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  Agent-Hunter Docker Scanner Fleet — Quick Start
# ═══════════════════════════════════════════════════════════
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}   Agent-Hunter · Docker Scanner Fleet    ${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

# ── 1. Build + start everything ───────────────────────────
log "Building orchestrator image..."
docker compose build orchestrator

log "Starting all scanner containers..."
docker compose up -d

log "Waiting for services to initialize (45s)..."
sleep 45

# ── 2. Health check orchestrator ──────────────────────────
log "Checking orchestrator health..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/ 2>/dev/null || echo "000")
if [ "$STATUS" = "200" ]; then
  ok "Orchestrator API is live at http://localhost:8888"
else
  warn "Orchestrator not responding yet (HTTP $STATUS). Give it a few more seconds."
fi

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Ready! How to trigger scans:           ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "  1. From Agent-Hunter backend (Python):"
echo -e "     ${CYAN}import httpx"
echo -e "     r = httpx.post('http://localhost:8888/scan', json={"
echo -e "         'url': 'https://testphp.vulnweb.com',"
echo -e "         'modules': ['web', 'network', 'dependency', 'sast'],"
echo -e "         'depth': 'medium'"
echo -e "     })"
echo -e "     scan_id = r.json()['scan_id']${NC}"
echo ""
echo "  2. Poll for results:"
echo -e "     ${CYAN}GET http://localhost:8888/scan/{scan_id}${NC}"
echo ""
echo "  3. Live log stream (SSE):"
echo -e "     ${CYAN}GET http://localhost:8888/scan/{scan_id}/stream${NC}"
echo ""
echo "  4. Quick CLI test:"
echo -e "     ${CYAN}curl -X POST http://localhost:8888/scan \\"
echo -e "       -H 'Content-Type: application/json' \\"
echo -e "       -d '{\"url\":\"https://testphp.vulnweb.com\",\"modules\":[\"web\"]}'"
echo -e "     ${NC}"
echo ""
warn "WebGoat needs authentication! Add your session cookie:"
echo -e "     ${CYAN}-d '{\"url\":\"https://webgoat.org\", \"auth_cookie\": \"JSESSIONID=abc123\"}'"
echo -e "     ${NC}"
echo ""
echo -e "  Stop everything: ${CYAN}docker compose down${NC}"
echo ""
