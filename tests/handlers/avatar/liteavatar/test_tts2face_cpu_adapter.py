import subprocess
from pathlib import Path
from zipfile import ZipFile

import pytest

from handlers.avatar.liteavatar.algo.tts2face_cpu_adapter import (
    Tts2faceCpuAdapter,
)


def test_existing_absolute_avatar_directory_is_used_without_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    avatar_data_dir = tmp_path / "preload"
    avatar_data_dir.mkdir()
    adapter = Tts2faceCpuAdapter()

    def unexpected_download(_avatar_name: str) -> str:
        raise AssertionError("local avatar data must not be sent to ModelScope")

    monkeypatch.setattr(adapter, "_download_from_modelscope", unexpected_download)

    assert adapter._get_avatar_data_dir(str(avatar_data_dir)) == str(avatar_data_dir)


def test_missing_absolute_avatar_directory_fails_without_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    avatar_data_dir = tmp_path / "missing"
    adapter = Tts2faceCpuAdapter()

    def unexpected_download(_avatar_name: str) -> str:
        raise AssertionError("local avatar data must not be sent to ModelScope")

    monkeypatch.setattr(adapter, "_download_from_modelscope", unexpected_download)

    with pytest.raises(
        FileNotFoundError,
        match="local avatar data directory does not exist",
    ):
        adapter._get_avatar_data_dir(str(avatar_data_dir))


def test_modelscope_downloader_rejects_absolute_avatar_name(tmp_path: Path) -> None:
    adapter = Tts2faceCpuAdapter()

    with pytest.raises(
        ValueError,
        match="ModelScope avatar names must be safe repository-relative paths",
    ):
        adapter._download_from_modelscope(str(tmp_path / "preload"))


@pytest.mark.parametrize(
    "avatar_name",
    (
        "",
        ".",
        "..",
        "../outside",
        "nested/../../outside",
        "nested//avatar",
        "nested/./avatar",
        "nested/avatar/",
        r"nested\avatar",
        ".zip",
    ),
)
def test_modelscope_downloader_rejects_unsafe_relative_avatar_names(
    avatar_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = Tts2faceCpuAdapter()

    def unexpected_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unsafe avatar names must not reach ModelScope")

    monkeypatch.setattr(
        "handlers.avatar.liteavatar.algo.tts2face_cpu_adapter.sp.run",
        unexpected_run,
    )

    with pytest.raises(
        ValueError,
        match="ModelScope avatar names must be safe repository-relative paths",
    ):
        adapter._download_from_modelscope(avatar_name)


def test_relative_avatar_name_remains_a_checked_modelscope_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = Tts2faceCpuAdapter()
    commands: list[tuple[list[str], bool]] = []

    monkeypatch.setattr(adapter, "get_avatar_dir", lambda: str(tmp_path))

    def record_run(command: list[str], *, check: bool) -> None:
        commands.append((command, check))

    monkeypatch.setattr(
        "handlers.avatar.liteavatar.algo.tts2face_cpu_adapter.sp.run",
        record_run,
    )

    result = adapter._download_from_modelscope("20250408/sample_data")

    assert result == str(tmp_path / "20250408" / "sample_data.zip")
    assert commands == [
        (
            [
                "modelscope",
                "download",
                "--model",
                "HumanAIGC-Engineering/LiteAvatarGallery",
                "20250408/sample_data.zip",
                "--local_dir",
                str(tmp_path),
            ],
            True,
        )
    ]


def test_modelscope_download_failure_is_propagated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = Tts2faceCpuAdapter()
    monkeypatch.setattr(adapter, "get_avatar_dir", lambda: str(tmp_path))

    def fail_run(command: list[str], *, check: bool) -> None:
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(
        "handlers.avatar.liteavatar.algo.tts2face_cpu_adapter.sp.run",
        fail_run,
    )

    with pytest.raises(subprocess.CalledProcessError):
        adapter._download_from_modelscope("20250408/sample_data")


def test_explicit_relative_zip_name_extracts_and_returns_data_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = Tts2faceCpuAdapter()
    avatar_archive = tmp_path / "20250408" / "sample_data.zip"
    avatar_archive.parent.mkdir()
    with ZipFile(avatar_archive, "w") as archive:
        archive.writestr("sample_data/marker.txt", "ready")

    monkeypatch.setattr(adapter, "get_avatar_dir", lambda: str(tmp_path))

    result = adapter._get_avatar_data_dir("20250408/sample_data.zip")

    assert result == str(tmp_path / "20250408" / "sample_data")
    assert (Path(result) / "marker.txt").read_text(encoding="utf-8") == "ready"
