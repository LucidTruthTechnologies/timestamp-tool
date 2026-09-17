#!/usr/bin/env bash
#
# build.sh: assemble src/ into a single self-contained dist/index.html.
#
# The published artifact is ONE file with no external requests of any kind: no CDN,
# no web font, no analytics, no source map. That is not minimalism for its own sake.
# A tool that claims your document never leaves your computer has to be auditable by
# reading it, and a page that fetches code at run time cannot make that claim about
# code it has not seen yet.
#
# The bundling is a plain concatenation in dependency order, with `import` lines and
# the `export ` keyword stripped. This is why the DER helpers carry distinct names
# (derParse, derChildren, and so on) rather than generic ones: there is no module
# scope in the output, so the source has to be collision-free by construction. The
# cost is a naming convention; the benefit is that anyone can diff the bundle against
# the sources by eye, with no toolchain and no trust in a bundler.
#
# Usage: ./build.sh [version]

set -euo pipefail

cd "$(dirname "$0")"

VERSION="${1:-$(cat VERSION 2>/dev/null || echo 0.1.0)}"
RELAY_URL="${RELAY_URL:-https://relay.timestamp.lucidtruthtechnologies.com}"

SRC=src
OUT=dist
mkdir -p "$OUT"

# Dependency order. sha256 first (nothing depends on nothing), app.js last.
MODULES=(sha256.js asn1.js tsp.js verify.js zip.js report.js package.js app.js)

for m in "${MODULES[@]}"; do
  [ -f "$SRC/$m" ] || { echo "build: missing $SRC/$m" >&2; exit 1; }
done
[ -f "$SRC/index.html" ] || { echo "build: missing $SRC/index.html" >&2; exit 1; }
[ -f "$SRC/styles.css" ] || { echo "build: missing $SRC/styles.css" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- refuse to bundle colliding top-level names ----------------------------
#
# Concatenation removes module scope, so two files declaring the same top-level name
# produce a SyntaxError at best and a silently shadowed function at worst. This check
# exists because the first build hit exactly that: sha256.js and verify.js both
# declared `eq`. Node caught it that time; a `var` collision would not have been
# caught at all, it would just have won.
python3 - "$SRC" "${MODULES[@]}" <<'PY'
import re, sys, collections
src, mods = sys.argv[1], sys.argv[2:]
pat = re.compile(r'^(?:export\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)')
seen = collections.defaultdict(list)
for m in mods:
    with open(f'{src}/{m}', encoding='utf-8') as fh:
        for line in fh:
            hit = pat.match(line)
            if hit:
                seen[hit.group(1)].append(m)
dupes = {k: v for k, v in seen.items() if len(v) > 1}
if dupes:
    for name, files in sorted(dupes.items()):
        print(f"build: top-level name '{name}' declared in {', '.join(files)}", file=sys.stderr)
    print('build: the bundle has no module scope; these names must be unique', file=sys.stderr)
    raise SystemExit(1)
PY

# ---- JavaScript ------------------------------------------------------------
{
  echo "/* ${VERSION}. Built from src/ by build.sh."
  echo " * Module boundaries are removed; the sources are in the repository, one file"
  echo " * per section below, and each section is byte-identical to its source apart"
  echo " * from stripped import lines and the export keyword."
  echo " */"
  for m in "${MODULES[@]}"; do
    echo
    echo "/* ===== $m ================================================== */"
    # Strip:
    #   - single-line imports
    #   - multi-line imports (from "import {" through the line containing "} from")
    #   - the leading `export ` keyword
    #   - bare `export { ... };` re-export statements
    awk '
      /^import .*;[[:space:]]*$/ { next }
      /^import[[:space:]]*\{[[:space:]]*$/ { inimport=1; next }
      inimport && /\}[[:space:]]*from[[:space:]]*.*;[[:space:]]*$/ { inimport=0; next }
      inimport { next }
      /^export[[:space:]]*\{[^}]*\}[[:space:]]*;[[:space:]]*$/ { next }
      { sub(/^export[[:space:]]+/, ""); print }
    ' "$SRC/$m"

    # A namespace import (`import * as tsp from './tsp.js'`) has no meaning once
    # module scope is gone, so every `tsp.foo` call site becomes a ReferenceError.
    # Rather than banning the form or hand-maintaining a list, synthesise the
    # namespace object from the module's own exports, right after the module. The
    # list is derived from the source on every build, so adding an export cannot
    # leave the namespace stale. A real browser run caught this; a Node import of
    # the same sources never would, because there the imports are real.
    python3 - "$SRC" "$m" <<'NSPY'
import re, sys, os
src, mod = sys.argv[1], sys.argv[2]
wanted = set()
for other in os.listdir(src):
    if not other.endswith('.js'):
        continue
    text = open(os.path.join(src, other), encoding='utf-8').read()
    for ns in re.findall(r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+'\./%s'" % re.escape(mod), text):
        wanted.add(ns)
if not wanted:
    sys.exit(0)
body = open(os.path.join(src, mod), encoding='utf-8').read()
names = sorted(set(
    re.findall(r'^export\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)', body, re.M)
))
for extra in re.findall(r'^export\s*\{([^}]*)\}\s*;', body, re.M):
    names.extend(n.strip() for n in extra.split(',') if n.strip())
names = sorted(set(names))
if not names:
    print(f'build: {mod} is imported as a namespace but exports nothing', file=sys.stderr)
    sys.exit(1)
for ns in sorted(wanted):
    print(f'/* namespace object for `import * as {ns} from "./{mod}"`, generated by build.sh */')
    print(f'const {ns} = {{ {", ".join(names)} }};')
NSPY
  done
} > "$TMP/bundle.js"

# The entry point auto-runs on DOMContentLoaded; nothing further to call.
sed -i "s|__VERSION__|${VERSION}|g; s|__RELAY_URL__|${RELAY_URL}|g" "$TMP/bundle.js"

# ---- assemble --------------------------------------------------------------
python3 - "$SRC/index.html" "$SRC/styles.css" "$TMP/bundle.js" "$OUT/index.html" <<'PY'
import sys
html_path, css_path, js_path, out_path = sys.argv[1:5]
html = open(html_path, encoding='utf-8').read()
css  = open(css_path,  encoding='utf-8').read()
js   = open(js_path,   encoding='utf-8').read()

# A literal </script> inside the bundle would terminate the script element early.
# Nothing in src/ contains one today; splitting the token keeps that true if it ever
# does, and costs nothing.
js = js.replace('</script>', '<\\/script>')

for marker, payload in (('/*<!--INLINE:styles.css-->*/', css), ('/*<!--INLINE:js-->*/', js)):
    if marker not in html:
        raise SystemExit(f'build: marker not found in index.html: {marker}')
    html = html.replace(marker, payload)

open(out_path, 'w', encoding='utf-8').write(html)
PY

# ---- publish the digest of what we just built ------------------------------
#
# The report inside every archive names the tool version. Publishing the digest of
# that exact file is what lets someone confirm the page they used was the published
# one: a single HTML file is trivially editable, and "it said version 0.1.0" is not
# evidence that it WAS version 0.1.0.
DIGEST="$(sha256sum "$OUT/index.html" | cut -d' ' -f1)"
printf '%s  index.html\n' "$DIGEST" > "$OUT/index.html.sha256"

BYTES="$(wc -c < "$OUT/index.html")"
echo "built  $OUT/index.html"
echo "       version  $VERSION"
echo "       relay    $RELAY_URL"
echo "       size     $BYTES bytes"
echo "       sha256   $DIGEST"

# ---- guard rails on the claims the page makes ------------------------------
fail=0
note() { echo "       CHECK FAIL: $*" >&2; fail=1; }

grep -qiE '<script[^>]+src=|<link[^>]+href="https?:|@import[[:space:]]+url\(' "$OUT/index.html" \
  && note "the page references an external resource; it must be self-contained"

grep -qE '__VERSION__|__RELAY_URL__' "$OUT/index.html" \
  && note "a build placeholder was left unsubstituted"

grep -q 'INLINE:' "$OUT/index.html" \
  && note "an inline marker survived into the output"

[ "$fail" -eq 0 ] || { echo "build: refusing to publish" >&2; exit 1; }
echo "       checks   self-contained, no placeholders"
