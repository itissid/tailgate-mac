#!/usr/bin/python3
"""Local dummy fixture driver. Safe preflight and offline checks need no Keychain.
Never generates/imports identities or creates/resets Keychains/search-list entries.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

MAX_OUTPUT = 512
IDENTIFIER = "dev.tailgate.local-keychain-probe"


def summary(status, *, stage, codes=None):
    value = {"version": 1, "status": status, "stage": stage,
             "signer_isolation_observed": status == "passed"}
    if codes is not None:
        value["osstatuses"] = codes
    return value


def classify_case(results):
    """Only A/A, B/B, B/A, A/B, A/A, B/B establishes the controls and denials."""
    return classify_reads(results, ["ok", "ok", "denied", "denied", "ok", "ok"])


def classify_update(results):
    """A1/A, A2/A, B/B, B/A, A1/B, A2/B, A1/A, A2/A, B/B."""
    return classify_reads(results, ["ok", "ok", "ok", "denied", "denied", "denied", "ok", "ok", "ok"])


def classify_reads(results, expected):
    if len(results) != len(expected):
        return "inconclusive"
    for result, status in zip(results, expected):
        if not isinstance(result, dict):
            return "inconclusive"
        actual = result.get("status")
        code = result.get("osstatus")
        if type(code) is not int or actual not in ("ok", "denied"):
            return "inconclusive"
        if actual == "ok" and code != 0:
            return "inconclusive"
        if actual == "denied" and code not in (-25293, -25308):
            return "inconclusive"
        if actual != status:
            return "failed" if actual == "ok" and status == "denied" else "inconclusive"
    return "passed"


def strict_result(raw):
    if not raw or len(raw) > MAX_OUTPUT:
        raise ValueError("result")
    def unique(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate")
            output[key] = value
        return output
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) - {"version", "status", "osstatus"} or value.get("version") != 1:
        raise ValueError("shape")
    if type(value["version"]) is not int or value.get("status") not in ("ok", "denied", "inconclusive"):
        raise ValueError("shape")
    if "osstatus" in value and (type(value["osstatus"]) is not int or abs(value["osstatus"]) > 2**31):
        raise ValueError("status")
    return value


def environment():
    # No caller-injected tool, dylib, locale hooks, credentials or defaults overrides.
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}


def command(args, *, timeout=60):
    # File-backed capture is bounded on read and lives in private temporary storage;
    # the helper emits <=512 bytes. No dynamic compiler/Security diagnostic is shown.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                                env=environment(), timeout=timeout, check=False)
        output.seek(0)
        raw = output.read(MAX_OUTPUT + 1)
        return result.returncode, raw


def compile_probe(directory):
    source = Path(__file__).with_name("Probe.swift")
    target = Path(directory) / "KeychainProbe"
    code, _ = command(["/usr/bin/swiftc", "-O", "-suppress-warnings", "-framework", "Security",
                       str(source), "-o", str(target)], timeout=90)
    if code != 0:
        raise ValueError("compiler")
    return target


def safe_root(path):
    root = Path(path)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError("fixture")
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("fixture")
    return root


def in_root(root, value):
    target = Path(value)
    if not target.is_absolute() or target.resolve() != target or root not in target.parents:
        raise ValueError("fixture")
    for element in [target] + list(target.parents):
        if element == root:
            break
        info = os.lstat(element)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("fixture")
    return target


def fixture_test(arguments, verifier):
    if len(arguments) != 4:
        return summary("inconclusive", stage="arguments")
    # The operator must explicitly attest a dedicated disposable account/VM. There
    # is no flag to relax signature validity, credential ACLs, or Keychain failures.
    if os.environ.get("TAILGATE_DISPOSABLE_LAB") != "1":
        return summary("blocked", stage="isolated-fixtures-required")
    root = safe_root(arguments[0])
    a, b, keychain = [in_root(root, value) for value in arguments[1:]]
    if a == b or a.name != "KeychainProbe.app" or b.name != a.name:
        return summary("inconclusive", stage="identities")
    binaries = [p / "Contents/MacOS/KeychainProbe" for p in (a, b)]
    for binary in binaries:
        in_root(root, binary)
    code, raw = command([str(verifier), "--verify-pair", str(root), str(a), str(b), str(keychain)])
    if code != 0 or strict_result(raw)["status"] != "ok":
        return summary("inconclusive", stage="signature-controls")
    code, raw = command([str(binaries[0]), "--seed", str(root), str(a), str(b), str(keychain)])
    if code != 0 or strict_result(raw)["status"] != "ok":
        return summary("inconclusive", stage="item-setup")
    results = []
    for binary, account in [(binaries[0], "a"), (binaries[1], "b"), (binaries[1], "a"),
                            (binaries[0], "b"), (binaries[0], "a"), (binaries[1], "b")]:
        code, raw = command([str(binary), "--read", str(root), str(keychain), account], timeout=10)
        result = strict_result(raw)
        if code != 0 and result["status"] != "inconclusive":
            return summary("inconclusive", stage="reader-process")
        results.append(result)
    return summary(classify_case(results), stage="identity-acl", codes=[r.get("osstatus") for r in results])


def update_test(arguments, verifier):
    """Consume explicitly supplied signed fixtures; never create an identity.

    Different private paths are mandatory. An A2 success must not be explainable
    solely by replacing A1 at a previously trusted pathname.
    """
    def result(status, stage, codes=None):
        value = summary(status, stage=stage, codes=codes)
        value["update_access_observed"] = status == "passed"
        return value
    if len(arguments) != 7:
        return result("inconclusive", "update-arguments")
    if os.environ.get("TAILGATE_DISPOSABLE_LAB") != "1":
        return result("blocked", "isolated-fixtures-required")
    try:
        root = safe_root(arguments[0])
        first, second, unrelated, keychain = [in_root(root, p) for p in arguments[1:5]]
        pin_a, pin_b = arguments[5:]
        if (any(len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin)
                for pin in (pin_a, pin_b)) or pin_a == pin_b or
                len({first, second, unrelated}) != 3 or
                any(app.name != "KeychainProbe.app" for app in (first, second, unrelated))):
            raise ValueError("identity")
        binaries = [app / "Contents/MacOS/KeychainProbe" for app in (first, second, unrelated)]
        for binary in binaries:
            in_root(root, str(binary))
        if len({(p.stat().st_dev, p.stat().st_ino) for p in binaries}) != 3:
            raise ValueError("identity")
    except FileNotFoundError:
        return result("blocked", "update-fixtures-missing")
    except (ValueError, OSError):
        return result("inconclusive", "update-fixtures-invalid")
    evidence = [str(root), str(first), str(second), str(unrelated), str(keychain), pin_a, pin_b]
    def control(binary, mode):
        code, raw = command([str(binary), mode] + evidence)
        return code == 0 and strict_result(raw)["status"] == "ok"
    try:
        if not control(verifier, "--verify-update"):
            return result("inconclusive", "update-signature-controls")
        if not control(binaries[0], "--seed-update"):
            return result("inconclusive", "update-item-setup")
        reads = []
        for binary, account in [(binaries[0], "a"), (binaries[1], "a"), (binaries[2], "b"),
                                (binaries[2], "a"), (binaries[0], "b"), (binaries[1], "b"),
                                (binaries[0], "a"), (binaries[1], "a"), (binaries[2], "b")]:
            code, raw = command([str(binary), "--read", str(root), str(keychain), account], timeout=10)
            observed = strict_result(raw)
            if code != 0 and observed["status"] != "inconclusive":
                return result("inconclusive", "update-reader-process")
            reads.append(observed)
        # Detect altered fixtures between preflight and actual reads, not merely
        # an unchanged filename. Never reuse an earlier successful control result.
        if not control(verifier, "--verify-update"):
            return result("inconclusive", "update-signature-controls")
        return result(classify_update(reads), "update-identity-acl", [r.get("osstatus") for r in reads])
    except (Exception, KeyboardInterrupt):
        return result("inconclusive", "update-process")


def main(args):
    if not args or args == ["--preflight"]:
        return summary("blocked", stage="codesign-may-consult-user-search-list")
    if sys.platform != "darwin":
        return summary("blocked", stage="macos-required")
    with tempfile.TemporaryDirectory(prefix="tailgate-local-keychain-") as temp:
        probe = compile_probe(temp)
        if args == ["--offline"]:
            code, raw = command([str(probe), "--self-test"])
            if code != 0 or strict_result(raw)["status"] != "ok":
                return summary("inconclusive", stage="classifier")
            return summary("offline-checks-passed", stage="compile-and-classifier")
        if args[:1] == ["--fixtures"]:
            return fixture_test(args[1:], probe)
        if args[:1] == ["--update-fixtures"]:
            return update_test(args[1:], probe)
        return summary("inconclusive", stage="arguments")


if __name__ == "__main__":
    try:
        value = main(sys.argv[1:])
    except (Exception, KeyboardInterrupt):
        value = summary("inconclusive", stage="setup-or-process")
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if value["status"] in ("passed", "offline-checks-passed") else 3)
