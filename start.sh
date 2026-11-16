#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker info >/dev/null || { echo 'Docker unavailable. Enable Docker Desktop integration for this WSL distribution.' >&2; exit 1; }
for port in 8000 5173; do
  if ss -H -ltn "sport = :$port" | grep -q .; then echo "Port $port is already in use" >&2; exit 1; fi
done
.venv/bin/python - <<'PY'
import ipaddress,json,subprocess,sys
wanted=ipaddress.ip_network('10.199.0.0/16')
ids=subprocess.check_output(['docker','network','ls','-q'],text=True).split()
for ident in ids:
    network=json.loads(subprocess.check_output(['docker','network','inspect',ident],text=True))[0]
    if network['Name']=='bgpguard-v2_lab': continue
    for conf in network.get('IPAM',{}).get('Config') or []:
        subnet=conf.get('Subnet')
        if subnet and ipaddress.ip_network(subnet).version==4 and wanted.overlaps(ipaddress.ip_network(subnet)):
            sys.exit(f'Subnet conflict with {network["Name"]}: {subnet}')
PY
export PATH="$PWD/.tools/node-v22.17.0-linux-x64/bin:$PATH"
command -v node >/dev/null || { echo 'Node.js is required' >&2; exit 1; }
docker compose up -d
.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000 & backend=$!
(cd frontend && npm run dev) & frontend=$!
trap 'kill "$backend" "$frontend" 2>/dev/null || true' EXIT INT TERM
echo 'Open http://127.0.0.1:5173'
wait -n "$backend" "$frontend"
