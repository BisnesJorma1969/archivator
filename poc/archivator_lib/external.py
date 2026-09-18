"""OpenSSL and PAR2 commands, with argument lists rather than shell strings."""

import shutil
import subprocess
from pathlib import Path

from .common import ArchiveError, IntegrityError, WORK_DIR


def executable(name):
    installed = shutil.which(name)
    if installed:
        return installed
    local = WORK_DIR / "tools" / "usr" / "bin" / name
    if local.is_file():
        return str(local)
    raise ArchiveError(f"Required executable not found: {name}; see poc/README.md")


def run(arguments, cwd=None):
    result = subprocess.run(arguments, cwd=cwd, capture_output=True, text=True, errors="replace")
    if result.returncode:
        message = (result.stderr or result.stdout).strip()
        raise ArchiveError(f"{Path(arguments[0]).name} failed ({result.returncode}): {message}")
    return result.stdout


def encrypt(source, target, certificate):
    run([executable("openssl"), "cms", "-encrypt", "-binary", "-aes-256-gcm",
         "-outform", "DER", "-in", str(source), "-out", str(target), str(certificate)])


def decrypt(source, target, key, certificate):
    arguments = [executable("openssl"), "cms", "-decrypt", "-binary", "-inform", "DER",
                 "-in", str(source), "-out", str(target), "-inkey", str(key),
                 "-passin", "pass:"]
    if certificate:
        arguments.extend(["-recip", str(certificate)])
    try:
        run(arguments)
    except ArchiveError as error:
        raise IntegrityError(f"CMS decryption/authentication failed: {error}") from error


def normalize_certificate(source, target):
    # x509 writes only the public certificate, even if the input PEM also has a key.
    run([executable("openssl"), "x509", "-in", str(source), "-out", str(target)])
    result = run([executable("openssl"), "x509", "-in", str(target), "-noout",
                  "-fingerprint", "-sha256"])
    return result.strip().split("=", 1)[1].replace(":", "").lower()


def create_parity(directory, prefix, members, slice_size, blocks):
    if blocks > 32768:
        raise ArchiveError("PAR2 recovery block limit exceeded; increase the internal slice size")
    run([executable("par2"), "create", "-q", "-t1", "-T1", f"-s{slice_size}",
         f"-c{blocks}", "-u", "-n4", "--", prefix + ".par2", *members], cwd=directory)
    files = sorted(directory.glob(prefix + "*.par2"))
    if len(files) != 5:
        raise ArchiveError("PAR2 did not produce one index and four recovery volumes")
    if check_parity(directory, prefix) != 0:
        raise IntegrityError("New PAR2 set failed verification")
    return files


def check_parity(directory, prefix, repair=False):
    files = sorted(directory.glob(prefix + "*.par2"))
    if not files:
        return 2
    index = directory / (prefix + ".par2")
    if not index.exists():
        index = files[0]
    operation = "repair" if repair else "verify"
    arguments = [executable("par2"), operation, "-q", "-t1", "-T1", "--", index.name]
    result = subprocess.run(arguments, cwd=directory, capture_output=True, text=True, errors="replace")
    # par2: 0 = intact, 1 = repair possible, 2 = insufficient recovery data,
    # 4 = insufficient critical PAR2 metadata. Other codes are operational errors.
    if result.returncode in (0, 1, 2, 4):
        return result.returncode
    if repair and result.returncode == 5:
        raise IntegrityError(f"PAR2 repair failed: {result.stdout.strip()}")
    raise ArchiveError(f"PAR2 failed ({result.returncode}): {(result.stderr or result.stdout).strip()}")
