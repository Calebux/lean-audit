#!/bin/bash
# Run project code for a local proof without letting it reach the network, your credentials or
# the rest of the disk.
#
#   isolate.sh <scratch-dir> <wall-seconds> -- <command...>
#
# - no network (macOS: sandbox-exec deny network*; Linux: unshare -rn, else docker --network none)
# - empty environment: PATH, HOME/TMPDIR inside the scratch dir, NODE_ENV=test, CI=1
# - writes only inside <scratch-dir>; ~/.ssh, ~/.aws, ~/.config, ~/.gnupg, ~/.netrc, ~/.npmrc,
#   ~/.docker and ~/.kube unreadable (macOS)
# - limits: CPU 120 s, files 100 MB, Node heap 1 GB, wall clock <wall-seconds>
set -euo pipefail
[ $# -ge 4 ] && [ "$3" = "--" ] || { echo "usage: isolate.sh <scratch-dir> <wall-seconds> -- <command...>" >&2; exit 2; }
mkdir -p "$1"; SCRATCH=$(cd "$1" && pwd -P); WALL=$2; shift 3
mkdir -p "$SCRATCH/home" "$SCRATCH/tmp"
ENVV=(PATH="$(dirname "$(command -v node 2>/dev/null || echo /usr/bin/node)"):/usr/local/bin:/usr/bin:/bin" HOME="$SCRATCH/home" TMPDIR="$SCRATCH/tmp" \
  XDG_CACHE_HOME="$SCRATCH/tmp" LANG=C NODE_ENV=test CI=1 NODE_OPTIONS=--max-old-space-size=1024 PYTHONDONTWRITEBYTECODE=1)
LIMITS='ulimit -t 120; ulimit -f 204800'
TIMER=(perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$WALL")
cd "$SCRATCH"

if [ "$(uname)" = Darwin ]; then
  PROFILE="$SCRATCH/tmp/isolate.sb"
  {
    echo '(version 1)(allow default)(deny network*)(deny file-write*)'
    echo "(allow file-write* (subpath \"$SCRATCH\") (literal \"/dev/null\") (literal \"/dev/tty\") (regex #\"^/dev/fd/\"))"
    for d in .ssh .aws .config .gnupg .netrc .npmrc .docker .kube; do echo "(deny file-read* (subpath \"$HOME/$d\"))"; done
  } > "$PROFILE"
  exec /usr/bin/env -i "${ENVV[@]}" /bin/bash -c "$LIMITS; exec \"\$@\"" _ "${TIMER[@]}" /usr/bin/sandbox-exec -f "$PROFILE" "$@"
elif unshare -rn true 2>/dev/null; then
  exec /usr/bin/env -i "${ENVV[@]}" /bin/bash -c "$LIMITS; exec \"\$@\"" _ "${TIMER[@]}" unshare -rn "$@"
elif command -v docker >/dev/null; then
  echo "isolate.sh: no unshare; using docker --network none with the repo mounted read-only (set ISOLATE_IMAGE)" >&2
  exec docker run --rm --network none --memory 1g --cpus 1 -v "$PWD:/scratch" -v "${ISOLATE_REPO:-$PWD}:/repo:ro" -w /scratch \
    -e NODE_ENV=test -e CI=1 "${ISOLATE_IMAGE:-node:22-alpine}" timeout "$WALL" "$@"
else
  echo "isolate.sh: no way to cut the network here (sandbox-exec, unshare or docker). Not running project code." >&2
  exit 3
fi
