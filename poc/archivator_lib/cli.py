"""The deliberately small command-line interfaces."""

import argparse
import sys
from pathlib import Path

from .common import ArchiveError, IntegrityError
from .progress import progress


def parser():
    result = argparse.ArgumentParser(prog="archivator", description="Local-filesystem archive PoC")
    commands = result.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("backup", help="Create a complete archive")
    backup.add_argument("source", type=Path)
    backup.add_argument("archive", type=Path)
    backup.add_argument("--compression", action=argparse.BooleanOptionalAction, default=True,
                        help="Use zstd for payload and metadata (default: enabled)")
    backup.add_argument("--par2", action=argparse.BooleanOptionalAction, default=True,
                        help="Protect data and metadata with PAR2 (default: enabled)")
    encryption = backup.add_mutually_exclusive_group()
    encryption.add_argument("--encrypt-cert", type=Path, help="Enable CMS encryption using this certificate")
    encryption.add_argument("--no-encryption", action="store_true", help="Explicitly disable encryption (the default)")
    backup.add_argument("--max-file-bytes", type=int, default=256 * 1024 * 1024 - 1,
                        help="Hard maximum for each stored file (default: 268435455)")
    backup.add_argument("--max-group-bytes", type=int, default=14 * 1024 * 1024 * 1024,
                        help="Hard total per group, including metadata/PAR2 (default: 15032385536)")
    backup.add_argument("--large-file-bytes", type=int,
                        help="Route files at or above this size to RAW; capped at the safe input limit")
    backup.add_argument("--waiting-groups", type=int, default=4,
                        help="Maximum waiting groups in addition to the active group (default: 4)")
    backup.add_argument("--group-close-percent", type=int, default=95,
                        help="Close a non-fitting group at this budget percentage (default: 95)")
    for name in ("verify", "repair", "restore"):
        command = commands.add_parser(name)
        command.add_argument("archive", type=Path)
        command.add_argument("--archive-id")
        if name == "restore":
            command.add_argument("target", type=Path)
            command.add_argument("--decrypt-key", type=Path)
            command.add_argument("--decrypt-cert", type=Path)
            command.add_argument("--scan-index", type=Path,
                                 help="Recover streams using a filename-only index instead of archive metadata")
    scan = commands.add_parser("scan", help="Build a recovery index from filenames without reading archive contents")
    scan.add_argument("archive", type=Path)
    scan.add_argument("index", type=Path, help="New recovery index ending in .json or .json.zst")
    scan.add_argument("--archive-id")
    compare = commands.add_parser("compare", help="Compare two filesystem trees")
    compare.add_argument("source", type=Path)
    compare.add_argument("target", type=Path)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    with progress.reporting(args.command):
        try:
            if args.command == "backup":
                from .backup import backup
                print(f"Backing up {args.source} to {args.archive}", flush=True)
                from .format import Settings
                settings = Settings(max_file_bytes=args.max_file_bytes, max_group_bytes=args.max_group_bytes,
                                    large_file_bytes=args.large_file_bytes, waiting_groups=args.waiting_groups,
                                    group_close_percent=args.group_close_percent,
                                    compression=args.compression, par2=args.par2)
                archive = backup(args.source, args.archive, args.encrypt_cert, settings)
                print(f"Backup complete: {args.archive} (archive {archive})")
                return 0
            if args.command == "verify":
                from .recovery import verify
                print(f"Verifying {args.archive}; archive files will not be modified.", flush=True)
                return verify(args.archive, args.archive_id)
            if args.command == "repair":
                from .recovery import repair
                print(f"Repairing {args.archive} in place.", flush=True)
                repair(args.archive, args.archive_id)
                return 0
            if args.command == "restore":
                from .restore import restore
                print(f"Restoring {args.archive} to {args.target}; recovery uses scratch copies.", flush=True)
                return restore(args.archive, args.target, args.archive_id, args.decrypt_key,
                               args.decrypt_cert, args.scan_index) or 0
            if args.command == "scan":
                from .scan import scan
                scan(args.archive, args.index, args.archive_id)
                return 0
            from .compare import compare
            print(f"Comparing {args.source} with {args.target}", flush=True)
            return compare(args.source, args.target)
        except IntegrityError as error:
            print(f"Integrity failure: {error}", file=sys.stderr)
            return 1
        except (ArchiveError, OSError) as error:
            print(f"Error: {error}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print("Interrupted; no unfinished backup is marked complete.", file=sys.stderr)
            return 2
