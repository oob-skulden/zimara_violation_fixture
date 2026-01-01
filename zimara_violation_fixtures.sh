#!/usr/bin/env bash
# zimara-test-fixtures.sh
#
# Creates a test workspace with ONE folder per Zimara check (01..53),
# each crafted to trigger a finding (or at least a non-pass INFO for the
# handful of checks that do not generate findings by design).
#
# Usage:
#   ./zimara-test-fixtures.sh [OUTPUT_ROOT]
#
# Example:
#   ./zimara-test-fixtures.sh ./zimara-violations
#   ./zimara_v0.51.0.sh ./zimara-violations/check_04
#
# Notes:
# - Checks 11, 15, 21, 22, 26, 27, 28, 30, 32, 33 are INFO/PASS oriented in v0.51.0.
#   This script still sets them up to produce a meaningful run state, but they may not
#   emit "findings" (that’s a Zimara behavior, not a test gap).
# - Checks 12 (gitleaks), 13 (detect-secrets), 14 (npm audit) require those tools (and
#   for npm audit, typically network access). We lay down content that *should* trip them.
#
set -euo pipefail

ROOT="${1:-./zimara-violations}"
rm -rf "$ROOT"
mkdir -p "$ROOT"

# ---------- helpers ----------
init_git_min() {
  local dir="$1"
  ( cd "$dir"
    git init -q
    git config user.email "zimara-test@example.com"
    git config user.name "Zimara Test"
  )
}

git_commit_all() {
  local dir="$1"
  local msg="${2:-commit}"
  ( cd "$dir"
    git add -A
    git commit -q -m "$msg" || true
  )
}

dd_supports_status_none() {
  # GNU dd supports status=none; BusyBox usually doesn't.
  # We probe once and return 0/1.
  dd --help 2>&1 | grep -q "status=" && return 0
  return 1
}

make_large_file_21mb() {
  local path="$1"
  mkdir -p "$(dirname "$path")"

  # Portable dd: use 1M (NOT 1m), because BusyBox dd rejects "1m"
  if dd_supports_status_none; then
    dd if=/dev/zero of="$path" bs=1M count=21 status=none
  else
    dd if=/dev/zero of="$path" bs=1M count=21 >/dev/null 2>&1
  fi
}

# ---------- CHECK 01 ----------
# Violation: no .git directory
mkdir -p "$ROOT/check_01"
cat > "$ROOT/check_01/README.txt" <<'EOF'
CHECK_01: No .git directory -> should flag "No .git directory found"
EOF

# ---------- CHECK 02 ----------
# Violation: missing .gitignore
mkdir -p "$ROOT/check_02"
init_git_min "$ROOT/check_02"
cat > "$ROOT/check_02/README.txt" <<'EOF'
CHECK_02: Missing .gitignore -> should flag "Missing .gitignore"
EOF
git_commit_all "$ROOT/check_02" "init"

# ---------- CHECK 03 ----------
# Violation: private key block in a file
mkdir -p "$ROOT/check_03"
init_git_min "$ROOT/check_03"
cat > "$ROOT/check_03/leaked.key" <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALlN0tOTallyNotARealKeyButItTriggersThePattern==
-----END RSA PRIVATE KEY-----
EOF
git_commit_all "$ROOT/check_03" "add private key fixture"

# ---------- CHECK 04 ----------
# Violation: secrets pattern (AWS access key style)
mkdir -p "$ROOT/check_04"
init_git_min "$ROOT/check_04"
cat > "$ROOT/check_04/app.py" <<'EOF'
# Fake but pattern-matching AWS key
AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"
EOF
git_commit_all "$ROOT/check_04" "add secret pattern fixture"

# ---------- CHECK 05 ----------
# Violation: *.bak / temp artifacts
mkdir -p "$ROOT/check_05"
init_git_min "$ROOT/check_05"
echo "backup junk" > "$ROOT/check_05/notes.bak"
git_commit_all "$ROOT/check_05" "add backup artifact"

# ---------- CHECK 06 ----------
# Violation: .env present
mkdir -p "$ROOT/check_06"
init_git_min "$ROOT/check_06"
cat > "$ROOT/check_06/.env" <<'EOF'
DB_PASSWORD=super_secret_password
EOF
git_commit_all "$ROOT/check_06" "add dotenv"

# ---------- CHECK 07 ----------
# Violation: output dir contains .git
mkdir -p "$ROOT/check_07/public/.git"
init_git_min "$ROOT/check_07"
echo "ref: refs/heads/main" > "$ROOT/check_07/public/.git/HEAD"
git_commit_all "$ROOT/check_07" "add output/.git"

# ---------- CHECK 08 ----------
# Violation: mixed content in output
mkdir -p "$ROOT/check_08/public"
init_git_min "$ROOT/check_08"
cat > "$ROOT/check_08/public/index.html" <<'EOF'
<html>
  <head></head>
  <body>
    <img src="http://example.com/insecure.png">
  </body>
</html>
EOF
git_commit_all "$ROOT/check_08" "add mixed content"

# ---------- CHECK 09 ----------
# INFO/PASS only. We make it PASS.
mkdir -p "$ROOT/check_09"
init_git_min "$ROOT/check_09"
cat > "$ROOT/check_09/netlify.toml" <<'EOF'
# minimal netlify config to make CHECK_09 pass
EOF
git_commit_all "$ROOT/check_09" "add netlify.toml"

# ---------- CHECK 10 ----------
# Violation: netlify.toml missing HSTS and X-Content-Type-Options
mkdir -p "$ROOT/check_10"
init_git_min "$ROOT/check_10"
cat > "$ROOT/check_10/netlify.toml" <<'EOF'
[[headers]]
  for = "/*"
  [headers.values]
    # Intentionally missing:
    # Strict-Transport-Security
    # X-Content-Type-Options
    X-Frame-Options = "DENY"
EOF
git_commit_all "$ROOT/check_10" "netlify headers missing"

# ---------- CHECK 11 ----------
# INFO/PASS only. We make it PASS by creating .github/
mkdir -p "$ROOT/check_11/.github"
init_git_min "$ROOT/check_11"
echo "placeholder" > "$ROOT/check_11/.github/README.txt"
git_commit_all "$ROOT/check_11" "add .github directory"

# ---------- CHECK 12 ----------
# Needs gitleaks installed + git repo. We provide secret content.
mkdir -p "$ROOT/check_12"
init_git_min "$ROOT/check_12"
cat > "$ROOT/check_12/secret.txt" <<'EOF'
ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD
EOF
git_commit_all "$ROOT/check_12" "add gitleaks-target secret"

# ---------- CHECK 13 ----------
# Needs detect-secrets installed. We provide obvious secret content.
mkdir -p "$ROOT/check_13"
init_git_min "$ROOT/check_13"
cat > "$ROOT/check_13/config.yml" <<'EOF'
api_token: "sk-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghiJKLMN"
EOF
git_commit_all "$ROOT/check_13" "add detect-secrets-target secret"

# ---------- CHECK 14 ----------
# Needs npm installed and usually network. We provide package.json with known-risky old dep version.
mkdir -p "$ROOT/check_14"
init_git_min "$ROOT/check_14"
cat > "$ROOT/check_14/package.json" <<'EOF'
{
  "name": "zimara-npm-audit-fixture",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.20"
  }
}
EOF
git_commit_all "$ROOT/check_14" "add package.json for npm audit"

# ---------- CHECK 15 ----------
# INFO-only ("Uncommitted changes detected"). We set up a dirty worktree.
mkdir -p "$ROOT/check_15"
init_git_min "$ROOT/check_15"
echo "clean" > "$ROOT/check_15/file.txt"
git_commit_all "$ROOT/check_15" "clean commit"
echo "dirty change" >> "$ROOT/check_15/file.txt"

# ---------- CHECK 16 ----------
# Violation: risky debug artifact in output (e.g., debug.log)
mkdir -p "$ROOT/check_16/public"
init_git_min "$ROOT/check_16"
echo "debug stuff" > "$ROOT/check_16/public/debug.log"
git_commit_all "$ROOT/check_16" "add debug.log in output"

# ---------- CHECK 17 ----------
# Violation: sensitive extension in git history (.env committed at least once)
mkdir -p "$ROOT/check_17"
init_git_min "$ROOT/check_17"
cat > "$ROOT/check_17/.env" <<'EOF'
HISTORY_SECRET=committed_once
EOF
git_commit_all "$ROOT/check_17" "commit dotenv to history"
rm -f "$ROOT/check_17/.env"
echo "env removed in working tree" > "$ROOT/check_17/README.txt"
git_commit_all "$ROOT/check_17" "remove dotenv from working tree"

# ---------- CHECK 18 ----------
# Violation: git remote uses http://
mkdir -p "$ROOT/check_18"
init_git_min "$ROOT/check_18"
( cd "$ROOT/check_18"
  git remote add origin "http://example.com/not-secure/repo.git"
)
echo "remote set" > "$ROOT/check_18/README.txt"
git_commit_all "$ROOT/check_18" "add http remote"

# ---------- CHECK 19 ----------
# Violation: known sensitive filename (id_rsa)
mkdir -p "$ROOT/check_19"
init_git_min "$ROOT/check_19"
echo "not a real key but named like one" > "$ROOT/check_19/id_rsa"
git_commit_all "$ROOT/check_19" "add id_rsa"

# ---------- CHECK 20 ----------
# Violation: API key-ish pattern in output JS bundle
mkdir -p "$ROOT/check_20/public"
init_git_min "$ROOT/check_20"
cat > "$ROOT/check_20/public/app.js" <<'EOF'
// Fake but pattern-matching Google API key format
const key = "AIzaSyA0123456789abcdefghijklmnopqrstuvwxYZ";
EOF
git_commit_all "$ROOT/check_20" "add key in output bundle"

# ---------- CHECK 21 ----------
# INFO/PASS only (looks for redirect rules in netlify.toml). We'll produce INFO by having netlify.toml without redirects.
mkdir -p "$ROOT/check_21"
init_git_min "$ROOT/check_21"
cat > "$ROOT/check_21/netlify.toml" <<'EOF'
# no redirect rules included
EOF
git_commit_all "$ROOT/check_21" "netlify.toml without redirects"

# ---------- CHECK 22 ----------
# INFO/PASS only (CNAME present or not). We'll produce PASS by adding CNAME.
mkdir -p "$ROOT/check_22"
init_git_min "$ROOT/check_22"
echo "example.com" > "$ROOT/check_22/CNAME"
git_commit_all "$ROOT/check_22" "add CNAME"

# ---------- CHECK 23 ----------
# Violation: .htaccess present
mkdir -p "$ROOT/check_23"
init_git_min "$ROOT/check_23"
echo "Options +Indexes" > "$ROOT/check_23/.htaccess"
git_commit_all "$ROOT/check_23" "add htaccess"

# ---------- CHECK 24 ----------
# Violation: sensitive config/key artifacts inside output directory
mkdir -p "$ROOT/check_24/public"
init_git_min "$ROOT/check_24"
echo "SHOULD_NOT_SHIP=1" > "$ROOT/check_24/public/.env"
git_commit_all "$ROOT/check_24" "add output dotenv"

# ---------- CHECK 25 ----------
# Violation: secret-looking var in netlify.toml
mkdir -p "$ROOT/check_25"
init_git_min "$ROOT/check_25"
cat > "$ROOT/check_25/netlify.toml" <<'EOF'
[build.environment]
API_KEY = "AKIAABCDEFGHIJKLMNOP"
EOF
git_commit_all "$ROOT/check_25" "add netlify env secret"

# ---------- CHECK 26 ----------
# INFO/PASS only (Hugo modules). We set up Hugo detection + missing go.mod -> INFO.
mkdir -p "$ROOT/check_26"
init_git_min "$ROOT/check_26"
cat > "$ROOT/check_26/config.toml" <<'EOF'
baseURL = "https://example.com"
languageCode = "en-us"
title = "Hugo Fixture"
EOF
git_commit_all "$ROOT/check_26" "hugo config without go.mod"

# ---------- CHECK 27 ----------
# INFO/PASS only (Jekyll plugins hint). We set up Jekyll detection.
mkdir -p "$ROOT/check_27"
init_git_min "$ROOT/check_27"
cat > "$ROOT/check_27/_config.yml" <<'EOF'
title: "Jekyll Fixture"
plugins:
  - jekyll-seo-tag
EOF
git_commit_all "$ROOT/check_27" "jekyll config"

# ---------- CHECK 28 ----------
# INFO/PASS only (Astro integrations hint). We set up Astro detection.
mkdir -p "$ROOT/check_28"
init_git_min "$ROOT/check_28"
cat > "$ROOT/check_28/astro.config.mjs" <<'EOF'
export default {};
EOF
git_commit_all "$ROOT/check_28" "astro config"

# ---------- CHECK 29 ----------
# Violation: Eleventy + eval()/Function() usage
mkdir -p "$ROOT/check_29"
init_git_min "$ROOT/check_29"
cat > "$ROOT/check_29/.eleventy.js" <<'EOF'
module.exports = function (eleventyConfig) {
  // Heuristic trigger
  eval("console.log('nope')");
  return {};
};
EOF
git_commit_all "$ROOT/check_29" "eleventy eval"

# ---------- CHECK 30 ----------
# INFO/PASS only (Next.js export output presence). We set up Next detection without out/ -> INFO.
mkdir -p "$ROOT/check_30"
init_git_min "$ROOT/check_30"
cat > "$ROOT/check_30/next.config.js" <<'EOF'
module.exports = {};
EOF
git_commit_all "$ROOT/check_30" "next config without out/"

# ---------- CHECK 31 ----------
# Violation: >20MB file
mkdir -p "$ROOT/check_31"
init_git_min "$ROOT/check_31"
make_large_file_21mb "$ROOT/check_31/big.bin"
git_commit_all "$ROOT/check_31" "add large file"

# ---------- CHECK 32 ----------
# INFO/PASS only (pre-commit hook presence). We'll create it to make PASS.
mkdir -p "$ROOT/check_32/.git/hooks"
init_git_min "$ROOT/check_32"
cat > "$ROOT/check_32/.git/hooks/pre-commit" <<'EOF'
#!/usr/bin/env bash
echo "pre-commit placeholder"
EOF
chmod +x "$ROOT/check_32/.git/hooks/pre-commit"
git_commit_all "$ROOT/check_32" "add pre-commit hook"

# ---------- CHECK 33 ----------
# INFO-only (README presence). We'll omit README to produce INFO.
mkdir -p "$ROOT/check_33"
init_git_min "$ROOT/check_33"
echo "no readme here" > "$ROOT/check_33/file.txt"
git_commit_all "$ROOT/check_33" "no readme"

# ---------- CHECK 34 ----------
# Violation: workflow foot-guns (pull_request_target, curl|bash, set -x, secrets.)
mkdir -p "$ROOT/check_34/.github/workflows"
init_git_min "$ROOT/check_34"
cat > "$ROOT/check_34/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: bad idea
        run: |
          set -x
          curl -sSL https://example.com/install.sh | bash
          echo "${{ secrets.SUPER_SECRET }}"
EOF
git_commit_all "$ROOT/check_34" "add foot-gun workflow"

# ---------- CHECK 35 ----------
# Violation: unpinned actions, permissions write-all, and/or missing explicit permissions block
mkdir -p "$ROOT/check_35/.github/workflows"
init_git_min "$ROOT/check_35"
cat > "$ROOT/check_35/.github/workflows/build.yml" <<'EOF'
name: build
on: [push]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
EOF
git_commit_all "$ROOT/check_35" "add pinning/permissions issues"

# ---------- CHECK 36 ----------
# Violation: package.json present but no lockfile
mkdir -p "$ROOT/check_36"
init_git_min "$ROOT/check_36"
cat > "$ROOT/check_36/package.json" <<'EOF'
{ "name": "lockfile-missing", "version": "1.0.0", "dependencies": { "left-pad": "1.3.0" } }
EOF
git_commit_all "$ROOT/check_36" "add package.json without lockfile"

# ---------- CHECK 37 ----------
# Violation: missing security.txt (no file anywhere)
mkdir -p "$ROOT/check_37"
init_git_min "$ROOT/check_37"
echo "nothing" > "$ROOT/check_37/file.txt"
git_commit_all "$ROOT/check_37" "no security.txt"

# ---------- CHECK 38 ----------
# Violation: CSP missing OR unsafe-* present. We include unsafe-inline.
mkdir -p "$ROOT/check_38"
init_git_min "$ROOT/check_38"
cat > "$ROOT/check_38/netlify.toml" <<'EOF'
[[headers]]
  for = "/*"
  [headers.values]
    Content-Security-Policy = "default-src 'self'; script-src 'self' 'unsafe-inline'"
EOF
git_commit_all "$ROOT/check_38" "add CSP with unsafe-inline"

# ---------- CHECK 39 ----------
# Violation: missing RP/PP/COOP/COEP
mkdir -p "$ROOT/check_39"
init_git_min "$ROOT/check_39"
cat > "$ROOT/check_39/netlify.toml" <<'EOF'
[[headers]]
  for = "/*"
  [headers.values]
    Strict-Transport-Security = "max-age=63072000; includeSubDomains; preload"
EOF
git_commit_all "$ROOT/check_39" "missing hardening headers"

# ---------- CHECK 40 ----------
# Violation: output missing robots.txt
mkdir -p "$ROOT/check_40/public"
init_git_min "$ROOT/check_40"
echo "<html/>" > "$ROOT/check_40/public/index.html"
git_commit_all "$ROOT/check_40" "output without robots.txt"

# ---------- CHECK 41 ----------
# Violation: cloud storage endpoint reference in output
mkdir -p "$ROOT/check_41/public"
init_git_min "$ROOT/check_41"
cat > "$ROOT/check_41/public/index.html" <<'EOF'
<a href="https://mybucket.s3.amazonaws.com/public/file.txt">download</a>
EOF
git_commit_all "$ROOT/check_41" "add storage endpoint"

# ---------- CHECK 42 ----------
# Violation: recon breadcrumbs in output (/admin)
mkdir -p "$ROOT/check_42/public"
init_git_min "$ROOT/check_42"
cat > "$ROOT/check_42/public/index.html" <<'EOF'
<a href="/admin">admin</a>
EOF
git_commit_all "$ROOT/check_42" "add recon breadcrumb"

# ---------- CHECK 43 ----------
# Violation: exfil indicators in source (webhook.site)
mkdir -p "$ROOT/check_43"
init_git_min "$ROOT/check_43"
cat > "$ROOT/check_43/app.js" <<'EOF'
const exfil = "https://webhook.site/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
EOF
git_commit_all "$ROOT/check_43" "add exfil indicator"

# ---------- CHECK 44 ----------
# Violation: pre-commit hook world-writable perms
mkdir -p "$ROOT/check_44"
init_git_min "$ROOT/check_44"
mkdir -p "$ROOT/check_44/.git/hooks"
cat > "$ROOT/check_44/.git/hooks/pre-commit" <<'EOF'
#!/usr/bin/env bash
echo "hook"
EOF
chmod 777 "$ROOT/check_44/.git/hooks/pre-commit"
git_commit_all "$ROOT/check_44" "add bad hook perms"

# ---------- CHECK 45 ----------
# Violation: dependency manifests exist but no dependabot config
mkdir -p "$ROOT/check_45"
init_git_min "$ROOT/check_45"
cat > "$ROOT/check_45/package.json" <<'EOF'
{ "name": "needs-dependabot", "version": "1.0.0", "dependencies": { "lodash": "4.17.20" } }
EOF
git_commit_all "$ROOT/check_45" "deps without dependabot"

# ---------- CHECK 46 ----------
# Violation: IaC hardcoded secrets in .tf
mkdir -p "$ROOT/check_46"
init_git_min "$ROOT/check_46"
cat > "$ROOT/check_46/main.tf" <<'EOF'
# Hardcoded secret pattern
variable "aws_access_key" { default = "AKIAABCDEFGHIJKLMNOP" }
EOF
git_commit_all "$ROOT/check_46" "iac hardcoded secret"

# ---------- CHECK 47 ----------
# Violation: Dockerfile uses :latest and runs as root (no USER)
mkdir -p "$ROOT/check_47"
init_git_min "$ROOT/check_47"
cat > "$ROOT/check_47/Dockerfile" <<'EOF'
FROM ubuntu:latest
RUN echo "hello"
EOF
git_commit_all "$ROOT/check_47" "docker issues"

# ---------- CHECK 48 ----------
# Violation: overly permissive cidr_blocks 0.0.0.0/0
mkdir -p "$ROOT/check_48"
init_git_min "$ROOT/check_48"
cat > "$ROOT/check_48/network.tf" <<'EOF'
resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
EOF
git_commit_all "$ROOT/check_48" "overly permissive iac"

# ---------- CHECK 49 ----------
# Violation: terraform.tfstate present
mkdir -p "$ROOT/check_49"
init_git_min "$ROOT/check_49"
cat > "$ROOT/check_49/terraform.tfstate" <<'EOF'
{ "version": 4, "resources": [] }
EOF
git_commit_all "$ROOT/check_49" "state file committed"

# ---------- CHECK 50 ----------
# Violation: secrets used with pull_request_target and echoed
mkdir -p "$ROOT/check_50/.github/workflows"
init_git_min "$ROOT/check_50"
cat > "$ROOT/check_50/.github/workflows/ci.yml" <<'EOF'
name: ci
on:
  pull_request_target:
jobs:
  leak:
    runs-on: ubuntu-latest
    steps:
      - name: oops
        run: echo "${{ secrets.PROD_TOKEN }}"
EOF
git_commit_all "$ROOT/check_50" "pipeline secret injection risk"

# ---------- CHECK 51 ----------
# Violation: docker push without signing
mkdir -p "$ROOT/check_51/.github/workflows"
init_git_min "$ROOT/check_51"
cat > "$ROOT/check_51/.github/workflows/release.yml" <<'EOF'
name: release
on: [push]
jobs:
  push:
    runs-on: ubuntu-latest
    steps:
      - name: build and push unsigned
        run: |
          docker build -t myorg/myapp:latest .
          docker push myorg/myapp:latest
EOF
git_commit_all "$ROOT/check_51" "unsigned container push"

# ---------- CHECK 52 ----------
# Violation: download-artifact without integrity verification
mkdir -p "$ROOT/check_52/.github/workflows"
init_git_min "$ROOT/check_52"
cat > "$ROOT/check_52/.github/workflows/artifacts.yml" <<'EOF'
name: artifacts
on: [push]
jobs:
  fetch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-output
      - name: use artifact
        run: ls -la
EOF
git_commit_all "$ROOT/check_52" "artifact download no checksum"

# ---------- CHECK 53 ----------
# Violation: third-party action not pinned to SHA
mkdir -p "$ROOT/check_53/.github/workflows"
init_git_min "$ROOT/check_53"
cat > "$ROOT/check_53/.github/workflows/thirdparty.yml" <<'EOF'
name: thirdparty
on: [push]
jobs:
  use:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-rando/action@v1
EOF
git_commit_all "$ROOT/check_53" "unpinned/untrusted actions"

# ---------- summary ----------
cat <<EOF

Created Zimara test fixtures at:
  $(cd "$(dirname "$ROOT")" && pwd)/$(basename "$ROOT")

Run examples:
  ./zimara_v0.51.0.sh $ROOT/check_04
  ./zimara_v0.51.0.sh $ROOT/check_47

Batch run (bash):
  for d in $ROOT/check_*; do
    echo "=== \$d ==="
    ./zimara_v0.51.0.sh "\$d" || true
    echo
  done

Tool-dependent checks:
  - CHECK_12 requires: gitleaks
  - CHECK_13 requires: detect-secrets
  - CHECK_14 requires: npm (and typically network for audit data)

EOF