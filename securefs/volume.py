import json
import os
from pathlib import Path

from .crypto import (
    KEY_LEN,
    SALT_LEN,
    b64d,
    b64e,
    decrypt,
    derive_key,
    encrypt,
    filename_token,
)

MAGIC = "SECUREFS1"
META = ".securefs.json"
DATA = "data"

DEFAULT_KDF = {"name": "scrypt", "n": 2**14, "r": 8, "p": 1}


class Volume:
    def __init__(self, root: Path, master_key: bytes, salt: bytes) -> None:
        self.root = Path(root)
        self.master_key = master_key
        self.salt = salt

    @property
    def data_dir(self) -> Path:
        return self.root / DATA

    @staticmethod
    def create(root: str | Path, passphrase: str) -> "Volume":
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        (root / DATA).mkdir(exist_ok=True)

        salt = os.urandom(SALT_LEN)
        kek = derive_key(
            passphrase,
            salt,
            n=DEFAULT_KDF["n"],
            r=DEFAULT_KDF["r"],
            p=DEFAULT_KDF["p"],
        )
        master_key = os.urandom(KEY_LEN)
        wrapped = encrypt(kek, master_key, b"master-key")

        meta = {
            "magic": MAGIC,
            "version": 1,
            "kdf": DEFAULT_KDF,
            "salt": b64e(salt),
            "wrapped_key": b64e(wrapped),
        }
        (root / META).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return Volume(root, master_key, salt)

    @staticmethod
    def unlock(root: str | Path, passphrase: str) -> "Volume":
        root = Path(root)
        meta_path = root / META
        if not meta_path.exists():
            raise ValueError(f"not a securefs volume: {root}")

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("magic") != MAGIC:
            raise ValueError("invalid volume magic")
        if meta.get("version") != 1:
            raise ValueError("unsupported volume version")

        kdf = meta.get("kdf", DEFAULT_KDF)
        salt = b64d(meta["salt"])
        kek = derive_key(
            passphrase,
            salt,
            n=int(kdf["n"]),
            r=int(kdf["r"]),
            p=int(kdf["p"]),
        )
        master_key = decrypt(kek, b64d(meta["wrapped_key"]), b"master-key")
        return Volume(root, master_key, salt)

    def _token(self, name: str) -> str:
        return filename_token(self.master_key, name)

    def _path(self, name: str) -> Path:
        return self.data_dir / self._token(name)

    def store(self, name: str, data: bytes) -> None:
        if "/" in name or "\\" in name or name in ("", ".", ".."):
            raise ValueError("invalid file name")
        token = self._token(name)
        payload = name.encode("utf-8") + b"\x00" + data
        blob = encrypt(self.master_key, payload, token.encode("ascii"))
        self._path(name).write_bytes(blob)

    def read(self, name: str) -> bytes:
        token = self._token(name)
        path = self._path(name)
        if not path.exists():
            raise FileNotFoundError(name)
        blob = path.read_bytes()
        payload = decrypt(self.master_key, blob, token.encode("ascii"))
        stored_name, sep, data = payload.partition(b"\x00")
        if not sep or stored_name.decode("utf-8") != name:
            raise ValueError("filename/content mismatch")
        return data

    def list(self) -> list[str]:
        names: list[str] = []
        if not self.data_dir.exists():
            return names
        for path in self.data_dir.iterdir():
            if not path.is_file():
                continue
            try:
                blob = path.read_bytes()
                payload = decrypt(self.master_key, blob, path.name.encode("ascii"))
                stored_name, sep, _ = payload.partition(b"\x00")
                if sep:
                    names.append(stored_name.decode("utf-8"))
            except Exception:
                continue
        return sorted(names)

    def exists(self, name: str) -> bool:
        return self._path(name).exists()

    def size(self, name: str) -> int:
        return len(self.read(name))

    def delete(self, name: str) -> None:
        path = self._path(name)
        if not path.exists():
            raise FileNotFoundError(name)
        path.unlink()

    def secure_delete(self, name: str) -> None:
        path = self._path(name)
        if not path.exists():
            raise FileNotFoundError(name)
        size = path.stat().st_size
        with path.open("r+b") as handle:
            handle.write(os.urandom(size))
            handle.flush()
            os.fsync(handle.fileno())
        path.unlink()

    def change_passphrase(self, new_passphrase: str) -> None:
        meta_path = self.root / META
        meta = json.loads(meta_path.read_text(encoding="utf-8"))

        salt = os.urandom(SALT_LEN)
        kek = derive_key(
            new_passphrase,
            salt,
            n=DEFAULT_KDF["n"],
            r=DEFAULT_KDF["r"],
            p=DEFAULT_KDF["p"],
        )
        wrapped = encrypt(kek, self.master_key, b"master-key")

        meta["salt"] = b64e(salt)
        meta["wrapped_key"] = b64e(wrapped)
        meta["kdf"] = DEFAULT_KDF
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.salt = salt
