#!/usr/bin/env bash
# scripts/teardown-vms.sh - Automated clean-slate state purge across all testbed VMs
set -euo pipefail

VMS_NET_A=("192.168.122.101" "192.168.122.102" "192.168.122.103")

TEARDOWN_PAYLOAD=$(cat << 'PAYLOAD'
sudo systemctl stop fabric-server fabric-thread fabric-dns fabric 2>/dev/null || true
sudo systemctl disable fabric-server fabric-thread fabric-dns fabric 2>/dev/null || true
sudo pkill -9 -f "fabric" 2>/dev/null || true
sudo rm -f /etc/systemd/system/fabric*.service
sudo systemctl daemon-reload
sudo ip link delete wg-fabric 2>/dev/null || true
sudo ip link delete fabric0 2>/dev/null || true
sudo rm -rf /etc/fabric /var/lib/fabric /var/log/fabric /tmp/fabric* ~/.fabric /root/.fabric
sudo sed -i '/\.fabric\.mesh/d' /etc/hosts 2>/dev/null || true
sudo sed -i '/# Fabric Mesh Hosts/d' /etc/hosts 2>/dev/null || true
echo "Teardown complete for $(hostname)"
PAYLOAD
)

for ip in "${VMS_NET_A[@]}"; do
  echo "==> Purging state on $ip..."
  ssh -o BatchMode=yes -o ConnectTimeout=5 "debian@$ip" "$TEARDOWN_PAYLOAD"
done

echo "==> Purging state on VM 4 (127.0.0.1:2224 / 10.0.3.15)..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2224 debian@127.0.0.1 "$TEARDOWN_PAYLOAD"

echo "==> All testbed VMs successfully reset to pristine clean-slate state."
