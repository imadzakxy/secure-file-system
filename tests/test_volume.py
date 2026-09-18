import pytest

from securefs.volume import Volume


def test_volume_roundtrip(tmp_path):
    root = tmp_path / "vault"
    volume = Volume.create(root, "correct horse battery staple")

    volume.store("hello.txt", b"hello encrypted world")
    assert volume.read("hello.txt") == b"hello encrypted world"
    assert volume.list() == ["hello.txt"]
    assert volume.exists("hello.txt")
    assert volume.size("hello.txt") == len(b"hello encrypted world")

    volume.delete("hello.txt")
    assert not volume.exists("hello.txt")
    assert volume.list() == []


def test_wrong_passphrase_rejected(tmp_path):
    root = tmp_path / "vault"
    Volume.create(root, "right")
    with pytest.raises(Exception):
        Volume.unlock(root, "wrong")


def test_on_disk_is_unreadable(tmp_path):
    root = tmp_path / "vault"
    volume = Volume.create(root, "pass")
    volume.store("secret.txt", b"very secret content")

    raw = b"".join(path.read_bytes() for path in (root / "data").iterdir())
    assert b"very secret content" not in raw
    assert b"secret.txt" not in raw


def test_secure_delete(tmp_path):
    root = tmp_path / "vault"
    volume = Volume.create(root, "pass")
    volume.store("a.bin", b"A" * 4096)
    volume.secure_delete("a.bin")
    assert not volume.exists("a.bin")


def test_change_passphrase(tmp_path):
    root = tmp_path / "vault"
    volume = Volume.create(root, "old")
    volume.store("file", b"data")
    volume.change_passphrase("new")

    with pytest.raises(Exception):
        Volume.unlock(root, "old")

    reopened = Volume.unlock(root, "new")
    assert reopened.read("file") == b"data"
