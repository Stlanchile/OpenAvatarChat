from pathlib import Path

import pytest

from scripts import download_models


def _liteavatar_paths(root: Path) -> tuple[Path, Path, Path]:
    weights = (
        root
        / "src"
        / "handlers"
        / "avatar"
        / "liteavatar"
        / "algo"
        / "liteavatar"
        / "weights"
    )
    speech = (
        weights / "speech_paraformer-large_asr_nat-zh-cn-16k-common-vocab8404-pytorch"
    )
    return (
        weights / "model_1.onnx",
        speech / "model.pb",
        speech / "lm" / "lm.pb",
    )


def test_liteavatar_download_propagates_modelscope_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(download_models, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(download_models, "ensure_package", lambda _name: None)
    monkeypatch.setattr(download_models, "run_cmd", lambda *_args, **_kwargs: False)

    assert download_models.download_liteavatar("modelscope") is False


@pytest.mark.parametrize(
    "present_indexes",
    (
        (),
        (0,),
        (1,),
        (2,),
        (0, 1),
        (0, 2),
        (1, 2),
    ),
)
def test_liteavatar_download_rejects_every_partial_result(
    tmp_path: Path,
    monkeypatch,
    present_indexes: tuple[int, ...],
) -> None:
    monkeypatch.setattr(download_models, "PROJECT_ROOT", tmp_path)
    for index in present_indexes:
        path = _liteavatar_paths(tmp_path)[index]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"partial")
    monkeypatch.setattr(download_models, "ensure_package", lambda _name: None)
    monkeypatch.setattr(download_models, "run_cmd", lambda *_args, **_kwargs: True)

    assert download_models.download_liteavatar("modelscope") is False


def test_liteavatar_download_accepts_only_complete_existing_weights(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(download_models, "PROJECT_ROOT", tmp_path)
    for path in _liteavatar_paths(tmp_path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"ready")

    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("complete weights must not trigger a download")

    monkeypatch.setattr(download_models, "ensure_package", unexpected_run)
    monkeypatch.setattr(download_models, "run_cmd", unexpected_run)

    assert download_models.download_liteavatar("modelscope") is True
