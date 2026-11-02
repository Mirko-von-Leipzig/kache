#!/usr/bin/env bash
set -euo pipefail

# Exercises automatic bundle publication and warmup around a real Cargo build.
#
# Two fresh local stores share a filesystem remote, so a successful warmup
# proves that the existing daemon-start and manifest-save lifecycle is enough.
kache_bin="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
trial_dir="$(mktemp -d "${TMPDIR:-/tmp}/kache-bundle-trial.XXXXXX")"
export KACHE_HOST_CONFIG="" KACHE_CONFIG="${trial_dir}/kache.toml"
export KACHE_CACHE_DIR="${trial_dir}/cache-first" KACHE_RUNTIME_DIR="${trial_dir}/run"
export KACHE_CI_BUNDLES=true KACHE_MANIFEST_KEY=bundle-smoke
export KACHE_MIN_COMPILE_MS=0 CARGO_INCREMENTAL=0 RUSTC_WRAPPER="${kache_bin}"
cleanup() {
    "${kache_bin}" daemon stop || true
    rm -rf "${trial_dir}"
}
trap cleanup EXIT
# Isolates the disposable filesystem fixture from the hosting CI's branch policy.
#
# This test must publish locally even when its workflow runs on a read-only
# branch. It never configures an external remote or changes production policy.
unset GITHUB_ACTIONS GITLAB_CI
mkdir -p "${trial_dir}/project/src" "${trial_dir}/remote"
cat > "${KACHE_CONFIG}" <<TOML
[cache]
remote_key_listing = false
prefetch_enabled = false
[cache.remote]
type = "filesystem"
path = "${trial_dir}/remote"
prefix = "artifacts"
TOML
cat > "${trial_dir}/project/Cargo.toml" <<'TOML'
[package]
name = "bundle-smoke"
version = "0.1.0"
edition = "2024"
[workspace]
TOML
printf 'pub fn answer() -> u32 { 42 }\n' > "${trial_dir}/project/src/lib.rs"
cd "${trial_dir}/project"
"${kache_bin}" daemon start
cargo build --offline
"${kache_bin}" save-manifest --manifest-key "${KACHE_MANIFEST_KEY}"
python3 - "${trial_dir}/remote/artifacts" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
assert list(root.glob('_manifests/bundles/*.json.zst')), 'automatic publication did not save a bundle'
assert list(root.glob('v4/prefetch/packs/*/*.kpack')), 'artifact bundle is missing'
PY
cargo clean
export KACHE_CACHE_DIR="${trial_dir}/cache-second"
"${kache_bin}" daemon start 2>&1 | tee "${trial_dir}/restore.log"
python3 - "${trial_dir}/restore.log" <<'PY'
from pathlib import Path
import re
import sys
log = Path(sys.argv[1]).read_text()
assert re.search(r'CI bundle: [1-9][0-9]* packs, [1-9][0-9]* entries, [1-9][0-9]* predictions', log), log
PY
cargo build --offline
"${kache_bin}" stats --full --format json --output "${trial_dir}/stats.json"
python3 - "${trial_dir}/stats.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as stream:
    report = json.load(stream)
assert report['summary']['local_hits'] > 0, report
print('Automatic bundle lifecycle restored artifacts and predictions; the second build hit locally.')
PY
