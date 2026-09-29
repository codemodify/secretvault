#!/bin/sh
# Builds secretvault from this checkout and installs it for the current
# user: the programs into ~/.local/bin (or --prefix), the helper names git,
# docker and age look for, and secretvaultd as a service that starts at
# login. Vaults and settings are never touched, installing or not.
#
#   scripts/install.sh [--prefix DIR] [--no-service]
#   scripts/install.sh --uninstall [--prefix DIR]
set -eu

prefix="${HOME}/.local/bin"
service=yes
action=install
while [ $# -gt 0 ]; do
	case "$1" in
	--prefix) prefix="$2"; shift 2 ;;
	--prefix=*) prefix="${1#--prefix=}"; shift ;;
	--no-service) service=no; shift ;;
	--uninstall) action=uninstall; shift ;;
	-h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "install.sh: unknown option $1" >&2; exit 2 ;;
	esac
done

programs="secretvault secretvaultd secretvault-tui secretvault-tui-prompt secretvault-server"
gui_programs="secretvault-gui secretvault-gui-prompt"
helpers="git-credential-secretvault docker-credential-secretvault age-plugin-secretvault"
exe=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) exe=".exe" ;; esac

if [ "$action" = uninstall ]; then
	if [ -x "$prefix/secretvaultd$exe" ]; then
		"$prefix/secretvaultd$exe" uninstall || true
	fi
	for p in $programs $gui_programs; do rm -f "$prefix/$p$exe"; done
	for h in $helpers; do
		if [ -L "$prefix/$h" ]; then rm -f "$prefix/$h"; fi
	done
	echo "Removed secretvault from $prefix. Your vaults and settings are where they were."
	exit 0
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
if ! command -v go >/dev/null 2>&1; then
	echo "install.sh: Go 1.26 or newer is needed to build (https://go.dev/dl/)" >&2
	exit 1
fi
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
echo "Building in $root ..."
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$build/" \
	./cmd/secretvault ./cmd/secretvaultd ./cmd/secretvault-tui \
	./cmd/secretvault-tui-prompt ./cmd/secretvault-server)

# The desktop programs are a module of their own (gui/), built with cgo
# against a uitoolkit release, which go fetches like any other module;
# without cgo, the rest works.
if (cd "$root/gui" && CGO_ENABLED=1 go build -trimpath -o "$build/" ./cmd/...) 2>"$build/gui.log"; then
	programs="$programs $gui_programs"
else
	echo "Skipped the desktop programs ($gui_programs): they need cgo, which needs a C compiler. The build said:"
	tail -n 5 "$build/gui.log" | sed 's/^/  /'
fi

mkdir -p "$prefix"
for p in $programs; do
	# A new file, not an overwrite: a running daemon keeps its own copy.
	install -m 0755 "$build/$p$exe" "$prefix/$p$exe"
done
for h in $helpers; do
	if [ -e "$prefix/$h" ] && [ ! -L "$prefix/$h" ]; then
		echo "Left $prefix/$h alone: it is not our link."
		continue
	fi
	ln -sf "secretvault$exe" "$prefix/$h"
done
echo "Installed $programs into $prefix."

case ":$PATH:" in
*":$prefix:"*) ;;
*) echo "Note: $prefix is not on your PATH; add it, or git, docker and age will not find the helpers." ;;
esac

if [ "$service" = yes ]; then
	"$prefix/secretvaultd$exe" install
	# An update: the running daemon is still the old program. Restarting
	# locks every vault.
	if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet secretvaultd.service 2>/dev/null; then
		systemctl --user restart secretvaultd.service
		echo "Restarted secretvaultd with the new version; every vault is locked."
	fi
fi

cat <<EOF

Next:
  secretvault init --recovery          create your first vault
  secretvault-tui                      the full-screen manager
  secretvault keyring takeover --dry-run   what becoming the desktop keyring would change
EOF
