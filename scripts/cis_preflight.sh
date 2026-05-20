#!/bin/bash
# Pre-flight check: verify everything is in place before running UBUNTU24-CIS
# on your K8s cluster. Run from WSL.

set -e

echo "=== CIS K8s Pre-Flight Check (UBUNTU24-CIS) ==="
echo ""

# 1. Verify ansible collections are installed
echo "[1/6] Checking Ansible collections..."
MISSING_COLS=()
for col in community.general community.crypto ansible.posix; do
  if ! ansible-galaxy collection list 2>/dev/null | grep -q "$col"; then
    MISSING_COLS+=("$col")
  fi
done

if [ ${#MISSING_COLS[@]} -gt 0 ]; then
  echo "    MISSING collections: ${MISSING_COLS[*]}"
  echo "    Install with: ansible-galaxy collection install -r /tmp/UBUNTU24-CIS/collections/requirements.yml"
  exit 1
else
  echo "    OK - all required collections present"
fi

# 2. Verify UBUNTU24-CIS role is present
echo "[2/6] Checking /tmp/UBUNTU24-CIS role exists..."
if [ ! -f /tmp/UBUNTU24-CIS/tasks/main.yml ]; then
  echo "    MISSING - clone it: git clone --branch devel https://github.com/ansible-lockdown/UBUNTU24-CIS.git /tmp/UBUNTU24-CIS"
  exit 1
else
  echo "    OK"
fi

# 3. Verify UBUNTU22-CIS is NOT being used by mistake
echo "[3/6] Checking playbook points to UBUNTU24-CIS..."
if grep -q 'UBUNTU22-CIS' ~/k8s-cluster/playbooks/20_cis_hardening.yml 2>/dev/null; then
  echo "    WARNING: playbook still references UBUNTU22-CIS!"
  echo "    Fix: sed -i 's/UBUNTU22-CIS/UBUNTU24-CIS/g' ~/k8s-cluster/playbooks/20_cis_hardening.yml"
fi

# 4. Verify connectivity
echo "[4/6] Checking SSH connectivity to cluster nodes..."
cd ~/k8s-cluster
for host in $(ansible-inventory -i inventory.ini --list 2>/dev/null | jq -r '.k8s_cluster.hosts[] // empty'); do
  ip=$(ansible-inventory -i inventory.ini --host "$host" 2>/dev/null | jq -r '.ansible_host // empty')
  if [ -z "$ip" ]; then continue; fi
  if sshpass -p ansible ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ansible@$ip "echo OK" 2>/dev/null | grep -q OK; then
    echo "    OK  $host ($ip)"
  else
    echo "    FAIL $host ($ip)"
  fi
done

# 5. Verify K8s is healthy
echo "[5/6] Checking K8s cluster health (via master1)..."
ip=$(ansible-inventory -i inventory.ini --host master1 2>/dev/null | jq -r '.ansible_host')
if sshpass -p ansible ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ansible@$ip "kubectl get nodes" 2>/dev/null | grep -q 'Ready'; then
  echo "    OK - cluster responding"
else
  echo "    WARNING - cluster may not be fully healthy (or kubectl not available)"
fi

# 6. Verify swap is already off
echo "[6/6] Checking swap state on nodes..."
for host in $(ansible-inventory -i inventory.ini --list 2>/dev/null | jq -r '.k8s_cluster.hosts[] // empty'); do
  ip=$(ansible-inventory -i inventory.ini --host "$host" 2>/dev/null | jq -r '.ansible_host // empty')
  if [ -z "$ip" ]; then continue; fi
  swap=$(sshpass -p ansible ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ansible@$ip "swapon --show=NAME --noheadings 2>/dev/null || echo NONE")
  if [ "$swap" = "NONE" ] || [ -z "$swap" ]; then
    echo "    OK  $host - swap disabled"
  else
    echo "    WARN $host - swap ENABLED ($swap)"
  fi
done

echo ""
echo "=== Pre-flight complete ==="
echo "To run CIS hardening:"
echo "  cd ~/k8s-cluster && ansible-playbook -i inventory.ini playbooks/20_cis_hardening.yml"
echo ""
echo "To do a dry run first:"
echo "  cd ~/k8s-cluster && ansible-playbook -i inventory.ini playbooks/20_cis_hardening.yml --check --diff"
