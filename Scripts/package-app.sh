#!/bin/bash
# Human-run release step. No OAuth input, key creation, key export or installation.
set -euo pipefail
umask 077
usage() {
  printf '%s\n' 'Usage: Scripts/package-app.sh "Developer ID Application: Name (TEAMID)" TEAMID /path/profile.provisionprofile [output-directory]' >&2
  exit 2
}
[[ $# -ge 3 && $# -le 4 ]] || usage
identity=$1
team=$2
profile=$3
output=${4:-dist}
[[ $identity == "Developer ID Application: "* && $team =~ ^[A-Z0-9]{10}$ && -f $profile ]] || usage
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
[[ $output = /* ]] || output="$root/$output"
# Never overwrite a release bundle or accidentally merge untrusted files into it.
app="$output/Tailgate.app"
[[ ! -e $app ]] || { printf '%s\n' 'Output Tailgate.app already exists; choose a new empty output directory.' >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/tailgate-release.XXXXXX")
trap 'rm -rf "$work"' EXIT
/usr/bin/security cms -D -i "$profile" > "$work/profile.plist"
/usr/bin/plutil -lint "$work/profile.plist" >/dev/null
# The OS verifies profile authorization when launching the signed app. This additional
# preflight rejects wrong-team, wildcard-ID, expired, and development profiles early.
/usr/bin/python3 - "$work/profile.plist" "$team" <<'PY'
import datetime, plistlib, sys
with open(sys.argv[1], 'rb') as f:
    p = plistlib.load(f)
t = sys.argv[2]
e = p.get('Entitlements', {})
app = t + '.dev.tailgate.mac'
expiry = p.get('ExpirationDate')
assert isinstance(expiry, datetime.datetime) and expiry > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None), 'Profile expired'
assert t in p.get('TeamIdentifier', []), 'Wrong profile team'
assert e.get('com.apple.application-identifier') == app, 'Profile must authorize exact dev.tailgate.mac App ID'
assert e.get('com.apple.developer.team-identifier') == t, 'Wrong entitlement team'
assert e.get('get-task-allow', False) is False and e.get('com.apple.security.get-task-allow', False) is False, 'Development profile refused'
assert p.get('ProvisionsAllDevices') is True and not p.get('ProvisionedDevices'), 'Developer ID distribution profile required'
allowed = e.get('keychain-access-groups', [])
assert app in allowed or t + '.*' in allowed, 'Profile does not authorize the private keychain group'
PY
swift build -c release --product TailgateReview
binary_dir=$(swift build -c release --show-bin-path)
mkdir -p "$work/Tailgate.app/Contents/MacOS" "$work/Tailgate.app/Contents/Resources"
cp "$binary_dir/TailgateReview" "$work/Tailgate.app/Contents/MacOS/TailgateReview"
cp Release/Info.plist "$work/Tailgate.app/Contents/Info.plist"
cp "$profile" "$work/Tailgate.app/Contents/embedded.provisionprofile"
cp Release/Tailgate.entitlements "$work/entitlements.plist"
/usr/libexec/PlistBuddy -c "Set :TailgateTeamIdentifier $team" "$work/Tailgate.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :com.apple.application-identifier $team.dev.tailgate.mac" "$work/entitlements.plist"
/usr/libexec/PlistBuddy -c "Set :com.apple.developer.team-identifier $team" "$work/entitlements.plist"
/usr/libexec/PlistBuddy -c "Set :keychain-access-groups:0 $team.dev.tailgate.mac" "$work/entitlements.plist"
/usr/bin/python3 - "$work/entitlements.plist" "$team" <<'PY'
import plistlib, sys
with open(sys.argv[1], 'rb') as f:
    actual = plistlib.load(f)
t = sys.argv[2]
expected = {
    'com.apple.application-identifier': t + '.dev.tailgate.mac',
    'com.apple.developer.team-identifier': t,
    'keychain-access-groups': [t + '.dev.tailgate.mac'],
    'com.apple.security.app-sandbox': True,
    'com.apple.security.network.client': True,
    'com.apple.security.files.user-selected.read-only': True,
}
assert actual == expected, 'Release entitlements must match the exact reviewed allowlist'
PY
# Timestamping contacts Apple's service; run this step only with the human's consent.
/usr/bin/codesign --sign "$identity" --options runtime --timestamp --entitlements "$work/entitlements.plist" "$work/Tailgate.app"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$work/Tailgate.app"
mkdir -p "$output"
mv "$work/Tailgate.app" "$app"
printf '\nSigned app: %s\n' "$app"
printf '%s\n' 'Next: notarize and staple per Docs/signing.md, then have an administrator install a root-owned /Applications/Tailgate.app.'
printf '%s\n' 'This script has not installed, launched, provisioned OAuth, or touched a tailnet.'
