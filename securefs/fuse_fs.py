import errno
import os
import stat
import time
from pathlib import Path

from .volume import Volume

try:
    from fuse import FUSE, FuseOSError, Operations
except ImportError:  # pragma: no cover - only needed for mounting
    FUSE = None
    FuseOSError = RuntimeError
    Operations = object


class SecureFS(Operations):
    def __init__(self, volume: Volume) -> None:
        self.volume = volume
        self.handles: dict[int, dict] = {}
        self.next_handle = 1

    def _name(self, path: str) -> str:
        return Path(path).name

    def _handle(self, fh: int) -> dict:
        if fh not in self.handles:
            raise FuseOSError(errno.EBADF)
        return self.handles[fh]

    def getattr(self, path, fh=None):
        now = time.time()
        if path == "/":
            return {
                "st_mode": stat.S_IFDIR | 0o700,
                "st_nlink": 2,
                "st_size": 0,
                "st_ctime": now,
                "st_mtime": now,
                "st_atime": now,
            }

        name = self._name(path)
        try:
            size = self.volume.size(name)
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)
        return {
            "st_mode": stat.S_IFREG | 0o600,
            "st_nlink": 1,
            "st_size": size,
            "st_ctime": now,
            "st_mtime": now,
            "st_atime": now,
        }

    def readdir(self, path, fh):
        if path != "/":
            raise FuseOSError(errno.ENOENT)
        return [".", ".."] + self.volume.list()

    def create(self, path, mode, fi=None):
        name = self._name(path)
        self.volume.store(name, b"")
        fh = self.next_handle
        self.next_handle += 1
        self.handles[fh] = {"name": name, "data": bytearray()}
        return fh

    def open(self, path, flags):
        name = self._name(path)
        try:
            data = self.volume.read(name)
        except FileNotFoundError:
            if flags & os.O_CREAT:
                data = b""
                self.volume.store(name, data)
            else:
                raise FuseOSError(errno.ENOENT)

        fh = self.next_handle
        self.next_handle += 1
        self.handles[fh] = {"name": name, "data": bytearray(data)}
        return fh

    def read(self, path, size, offset, fh):
        data = self._handle(fh)["data"]
        return bytes(data[offset : offset + size])

    def write(self, path, data, offset, fh):
        handle = self._handle(fh)
        buffer = handle["data"]
        if offset > len(buffer):
            buffer.extend(b"\x00" * (offset - len(buffer)))
        buffer[offset : offset + len(data)] = data
        self.volume.store(handle["name"], bytes(buffer))
        return len(data)

    def truncate(self, path, length, fh=None):
        name = self._name(path)
        if fh is not None:
            buffer = self._handle(fh)["data"]
        else:
            buffer = bytearray(self.volume.read(name))

        if length < len(buffer):
            del buffer[length:]
        else:
            buffer.extend(b"\x00" * (length - len(buffer)))
        self.volume.store(name, bytes(buffer))

        if fh is not None:
            self._handle(fh)["data"] = buffer
        return 0

    def flush(self, path, fh):
        handle = self._handle(fh)
        self.volume.store(handle["name"], bytes(handle["data"]))
        return 0

    def release(self, path, fh):
        handle = self.handles.pop(fh, None)
        if handle is not None:
            self.volume.store(handle["name"], bytes(handle["data"]))
        return 0

    def unlink(self, path):
        try:
            self.volume.delete(self._name(path))
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)
        return 0

    def rename(self, old, new):
        old_name = self._name(old)
        new_name = self._name(new)
        data = self.volume.read(old_name)
        self.volume.store(new_name, data)
        self.volume.delete(old_name)
        return 0

    def mkdir(self, path, mode):
        raise FuseOSError(errno.EROFS)

    def rmdir(self, path):
        raise FuseOSError(errno.EROFS)

    def chmod(self, path, mode):
        return 0

    def utimens(self, path, times=None):
        return 0


def mount(volume: Volume, mountpoint: str, foreground: bool = True) -> None:
    if FUSE is None:
        raise RuntimeError("fusepy is not installed: pip install fusepy")
    Path(mountpoint).mkdir(parents=True, exist_ok=True)
    FUSE(
        SecureFS(volume),
        mountpoint,
        foreground=foreground,
        nothreads=True,
        ro=False,
    )
