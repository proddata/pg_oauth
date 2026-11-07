#!/bin/sh
# Linux/KVM host entry point. The guest has its own enforcing SELinux kernel.
set -eu
test -r /dev/kvm && test -w /dev/kvm
work=$(mktemp -d)
vm_pid=
cleanup() {
	if test -n "$vm_pid"; then kill "$vm_pid" 2>/dev/null || true; wait "$vm_pid" 2>/dev/null || true; vm_pid=; fi
	rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
image=Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
# The image is pinned by SHA-256, so any source is safe. Prefer the fixed primary
# host: the download.fedoraproject.org redirector picks an arbitrary mirror per
# request, and one mirror with an expired certificate failed the whole job.
sh "$(dirname "$0")/fetch-pinned-image.sh" \
	28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f "$work/base.qcow2" \
	"https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/$image" \
	"https://archives.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/$image" \
	"https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/$image"
qemu-img create -f qcow2 -F qcow2 -b "$work/base.qcow2" "$work/guest.qcow2" 24G
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: ci
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$work/key.pub")
ssh_pwauth: false
disable_root: true
preserve_hostname: true
EOF
printf 'instance-id: pg-oauth-selinux\n' >"$work/meta-data"
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp 2 -nographic \
	-drive "file=$work/guest.qcow2,if=virtio,format=qcow2" \
	-drive "file=$work/seed.img,if=virtio,format=raw" \
	-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
	-device virtio-net-pci,netdev=net0 >"$work/console.log" 2>&1 &
vm_pid=$!
# This generated identity and host-key file are scoped to the disposable guest.
ssh_guest() {
	ssh -i "$work/key" -p 2222 -o BatchMode=yes -o ConnectTimeout=5 \
		-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$work/known_hosts" ci@127.0.0.1 "$@"
}
ready=false
for attempt in $(seq 1 90); do
	kill -0 "$vm_pid" || { cat "$work/console.log"; exit 1; }
	if ssh_guest true 2>/dev/null; then ready=true; break; fi
	sleep 2
done
if test "$ready" != true; then cat "$work/console.log"; exit 1; fi
ssh_guest 'sudo cloud-init status --wait --long && sudo mkdir /opt/pg-oauth-validator && sudo chown ci /opt/pg-oauth-validator'
# Checkout disables persisted credentials. Include Git metadata for the existing
# exact-commit source preparation; omit local build outputs.
git archive --format=tar HEAD >"$work/source.tar"
tar --append --file="$work/source.tar" .git
gzip "$work/source.tar"
ssh_guest 'tar -xzf - -C /opt/pg-oauth-validator' <"$work/source.tar.gz"
ssh_guest 'sudo /bin/sh /opt/pg-oauth-validator/scripts/ci/test-selinux-guest.sh'
