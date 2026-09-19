"""Zstd, OpenSSL, and PAR2 commands with explicit subprocess lifetimes."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .common import ArchiveError, IntegrityError, WORK_DIR
from .progress import progress


def executable(name):
    installed = shutil.which(name)
    if installed:
        return installed
    local = WORK_DIR / "tools" / "usr" / "bin" / name
    if local.is_file():
        return str(local)
    raise ArchiveError(f"Required executable not found: {name}; see poc/README.md")


def run(arguments, cwd=None, activity=None):
    progress.update(activity or f"Running {Path(arguments[0]).name} {arguments[1] if len(arguments) > 1 else ''}")
    result = subprocess.run(arguments, cwd=cwd, capture_output=True, text=True, errors="replace")
    if result.returncode:
        message = (result.stderr or result.stdout).strip()
        raise ArchiveError(f"{Path(arguments[0]).name} failed ({result.returncode}): {message}")
    return result.stdout


class ZstdWriter:
    """Stream one independent frame to disk without buffering a whole chunk."""

    def __init__(self, target):
        self.process = None
        self.output = None
        self.errors = None
        try:
            # Compressed data is still plaintext until CMS encryption finishes.
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.output = os.fdopen(descriptor, "wb")
            # A file avoids a full stderr pipe blocking the compressor.
            self.errors = tempfile.TemporaryFile(dir=Path(target).parent)
            self.process = subprocess.Popen(
                [executable("zstd"), "-q", "-3", "--single-thread", "--check", "-c"],
                stdin=subprocess.PIPE, stdout=self.output, stderr=self.errors)
        except BaseException:
            self.close()
            raise

    def write(self, data):
        try:
            self.process.stdin.write(data)
        except BrokenPipeError as error:
            raise ArchiveError("Zstd compressor stopped while writing a chunk") from error

    def finish(self):
        progress.update("Finishing zstd frame; waiting for compressor")
        try:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass  # Read the compressor's exit status and diagnostic below.
            status = self.process.wait()
            if status:
                self.errors.seek(0)
                message = self.errors.read().decode("utf-8", errors="replace").strip()
                raise ArchiveError(f"Zstd compression failed ({status}): {message}")
        finally:
            self.close()

    def close(self):
        # Failed source reads must not leave a child process or publish a partial frame.
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
        if self.output is not None:
            self.output.close()
        if self.errors is not None:
            self.errors.close()


def encrypt(source, target, certificate):
    run([executable("openssl"), "cms", "-encrypt", "-binary", "-aes-256-gcm",
         "-outform", "DER", "-in", str(source), "-out", str(target),
         "-recip", str(certificate), "-keyopt", "rsa_padding_mode:oaep",
         "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"],
        activity="Encrypting chunk with OpenSSL CMS")


def decrypt(source, target, key, certificate):
    arguments = [executable("openssl"), "cms", "-decrypt", "-binary", "-inform", "DER",
                 "-in", str(source), "-out", str(target), "-inkey", str(key),
                 "-passin", "pass:"]
    if certificate:
        arguments.extend(["-recip", str(certificate)])
    # OpenSSL may write plaintext before it checks the authentication tag.
    # Restrict the output before starting it, including when reusing a scratch file.
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    try:
        run(arguments, activity="Decrypting and authenticating chunk with OpenSSL CMS")
    except ArchiveError as error:
        Path(target).unlink(missing_ok=True)
        raise IntegrityError(f"CMS decryption/authentication failed: {error}") from error


def normalize_certificate(source, target):
    # x509 writes only the public certificate, even if the input PEM also has a key.
    run([executable("openssl"), "x509", "-in", str(source), "-out", str(target)])
    details = run([executable("openssl"), "x509", "-in", str(target),
                   "-noout", "-text", "-certopt", "no_extensions", "-modulus"])
    lines = [line.strip() for line in details.splitlines()]
    # Check the subject key, not the certificate's signature algorithm.
    # RSA-PSS keys are signing-only and cannot transport the CMS content key.
    if "Public Key Algorithm: rsaEncryption" not in lines:
        raise ArchiveError("Encryption requires an RSA recipient key of at least 3072 bits")
    modulus = next((line.removeprefix("Modulus=") for line in lines
                    if line.startswith("Modulus=")), "")
    try:
        bits = int(modulus, 16).bit_length()
    except ValueError as error:
        raise ArchiveError("Cannot read the recipient certificate's RSA modulus") from error
    if bits < 3072:
        raise ArchiveError(f"Recipient RSA key is {bits} bits; at least 3072 bits are required")
    result = run([executable("openssl"), "x509", "-in", str(target), "-noout",
                  "-fingerprint", "-sha256"])
    return result.strip().split("=", 1)[1].replace(":", "").lower()


def create_parity(directory, prefix, members, slice_size, blocks, output_directory=None, volumes=1):
    if blocks > 32768:
        raise ArchiveError("PAR2 recovery block limit exceeded")
    output_directory = output_directory or directory
    index = output_directory.resolve() / (prefix + ".par2")
    # Explicit source base keeps stored member names relative to the archive,
    # even when the recovery files are generated in a separate staging directory.
    run([executable("par2"), "create", "-q", "-t1", "-T1", f"-s{slice_size}",
         f"-c{blocks}", "-u", f"-n{volumes}", f"-B{directory.resolve()}", "--", str(index), *members], cwd=directory,
        activity=f"PAR2: creating {blocks:,} recovery blocks of {slice_size:,} bytes for {len(members):,} files")
    files = sorted(output_directory.glob(prefix + "*.par2"))
    if len(files) != volumes + 1:
        raise ArchiveError("PAR2 did not produce the requested index and recovery volumes")
    if check_parity(output_directory, prefix, data_directory=directory) != 0:
        raise IntegrityError("New PAR2 set failed verification")
    return files


def check_parity(directory, prefix, repair=False, data_directory=None, parity_files=None):
    files = sorted(parity_files if parity_files is not None else directory.glob(prefix + "*.par2"))
    if not files:
        return 2
    index = next((path for path in files if path.name == prefix + ".par2"), files[0])
    operation = "repair" if repair else "verify"
    role = "metadata" if "_metadata" in prefix else "datagroup" if "_datagroup-" in prefix else "supergroup"
    progress.update(f"PAR2: {operation} {role} recovery set; waiting for par2cmdline")
    data_directory = data_directory or directory
    arguments = [executable("par2"), operation, "-q", "-t1", "-T1",
                 f"-B{data_directory.resolve()}", "--", str(index.resolve()),
                 *(str(path.resolve()) for path in files if path != index)]
    result = subprocess.run(arguments, cwd=directory, capture_output=True, text=True, errors="replace")
    # par2: 0 = intact, 1 = repair possible, 2 = insufficient recovery data,
    # 4 = insufficient critical PAR2 metadata. Other codes are operational errors.
    if result.returncode in (0, 1, 2, 4):
        return result.returncode
    if repair and result.returncode == 5:
        raise IntegrityError(f"PAR2 repair failed: {result.stdout.strip()}")
    raise ArchiveError(f"PAR2 failed ({result.returncode}): {(result.stderr or result.stdout).strip()}")
