import argparse
import getpass
import os
import subprocess
import sys
from pathlib import Path

from .volume import Volume


def _passphrase(args, prompt: str = "Passphrase: ") -> str:
    if getattr(args, "password", None):
        return args.password
    env = os.environ.get("SECUREFS_PASS")
    if env:
        return env
    return getpass.getpass(prompt)


def _unlock(args) -> Volume:
    return Volume.unlock(args.root, _passphrase(args))


def cmd_init(args) -> int:
    passphrase = _passphrase(args, "New passphrase: ")
    confirm = _passphrase(args, "Confirm passphrase: ")
    if passphrase != confirm:
        print("passphrases do not match", file=sys.stderr)
        return 1
    Volume.create(args.root, passphrase)
    print(f"created volume: {args.root}")
    return 0


def cmd_mount(args) -> int:
    from .fuse_fs import mount

    volume = _unlock(args)
    mount(volume, args.mountpoint, foreground=not args.background)
    return 0


def cmd_unmount(args) -> int:
    commands = [
        ["fusermount", "-u", args.mountpoint],
        ["umount", args.mountpoint],
    ]
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                return 0
        except FileNotFoundError:
            continue
    print(f"cannot unmount {args.mountpoint}", file=sys.stderr)
    return 1


def cmd_ls(args) -> int:
    volume = _unlock(args)
    for name in volume.list():
        print(name)
    return 0


def cmd_put(args) -> int:
    volume = _unlock(args)
    source = Path(args.file)
    name = args.name or source.name
    volume.store(name, source.read_bytes())
    print(f"stored {name} ({source.stat().st_size} bytes)")
    return 0


def cmd_get(args) -> int:
    volume = _unlock(args)
    data = volume.read(args.name)
    Path(args.output).write_bytes(data)
    print(f"extracted {args.name} -> {args.output} ({len(data)} bytes)")
    return 0


def cmd_rm(args) -> int:
    volume = _unlock(args)
    if args.secure:
        volume.secure_delete(args.name)
    else:
        volume.delete(args.name)
    print(f"deleted {args.name}")
    return 0


def cmd_passwd(args) -> int:
    volume = _unlock(args)
    new_passphrase = _passphrase(args, "New passphrase: ")
    confirm = _passphrase(args, "Confirm passphrase: ")
    if new_passphrase != confirm:
        print("passphrases do not match", file=sys.stderr)
        return 1
    volume.change_passphrase(new_passphrase)
    print("passphrase updated")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securefs")
    parser.add_argument("--pass", dest="password", help="passphrase (or SECUREFS_PASS)")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("root")
    init.set_defaults(func=cmd_init)

    mount = sub.add_parser("mount")
    mount.add_argument("root")
    mount.add_argument("mountpoint")
    mount.add_argument("--background", action="store_true")
    mount.set_defaults(func=cmd_mount)

    unmount = sub.add_parser("unmount")
    unmount.add_argument("mountpoint")
    unmount.set_defaults(func=cmd_unmount)

    ls = sub.add_parser("ls")
    ls.add_argument("root")
    ls.set_defaults(func=cmd_ls)

    put = sub.add_parser("put")
    put.add_argument("root")
    put.add_argument("file")
    put.add_argument("name", nargs="?")
    put.set_defaults(func=cmd_put)

    get = sub.add_parser("get")
    get.add_argument("root")
    get.add_argument("name")
    get.add_argument("output")
    get.set_defaults(func=cmd_get)

    rm = sub.add_parser("rm")
    rm.add_argument("root")
    rm.add_argument("name")
    rm.add_argument("--secure", action="store_true")
    rm.set_defaults(func=cmd_rm)

    passwd = sub.add_parser("passwd")
    passwd.add_argument("root")
    passwd.set_defaults(func=cmd_passwd)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
