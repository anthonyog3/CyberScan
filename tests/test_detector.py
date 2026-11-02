import os

from core.detector import static_checks


def make(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def fake_pe(body=b""):
    """Smallest header that looks like a Windows program: 'MZ', a pointer, 'PE'."""
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x40).to_bytes(4, "little")
    header[0x40:0x44] = b"PE\x00\x00"
    return bytes(header) + body


def has(reasons, word):
    return any(word in reason.lower() for reason in reasons)


def test_program_disguised_as_image(tmp_path):
    reasons = static_checks(make(tmp_path, "holiday.jpg", fake_pe()))
    assert has(reasons, "disguised")


def test_real_exe_is_not_called_disguised(tmp_path):
    reasons = static_checks(make(tmp_path, "setup.exe", fake_pe()))
    assert not has(reasons, "disguised")


def test_text_starting_with_mz_is_not_a_program(tmp_path):
    reasons = static_checks(make(tmp_path, "notes.txt", b"MZ are my initials"))
    assert not has(reasons, "disguised")


def test_real_jpeg_is_clean(tmp_path):
    reasons = static_checks(make(tmp_path, "photo.jpg", b"\xff\xd8\xff\xe0" + b"data" * 100))
    assert reasons == []


def test_high_entropy_program(tmp_path):
    reasons = static_checks(make(tmp_path, "packed.exe", fake_pe(os.urandom(100_000))))
    assert has(reasons, "entropy")


def test_low_entropy_program(tmp_path):
    reasons = static_checks(make(tmp_path, "plain.exe", fake_pe(b"A" * 100_000)))
    assert not has(reasons, "entropy")


def test_entropy_ignored_for_non_programs(tmp_path):
    reasons = static_checks(make(tmp_path, "archive.zip", os.urandom(100_000)))
    assert not has(reasons, "entropy")


def test_right_to_left_override(tmp_path):
    reasons = static_checks(make(tmp_path, "invoice\u202egpj.exe", b"x"))
    assert has(reasons, "right-to-left")