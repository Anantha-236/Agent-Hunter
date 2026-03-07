from pathlib import Path

import startservers


def test_load_local_env_reads_env_files_without_overwriting(tmp_path, monkeypatch):
    (tmp_path / ".env.local").write_text("TELEGRAM_BOT_TOKEN=local-token\nAPI_HOST=127.0.0.1\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TELEGRAM_BOT_TOKEN=env-token\nUI_PORT=9000\n", encoding="utf-8")
    monkeypatch.setenv("API_HOST", "already-set")

    loaded = startservers.load_local_env(tmp_path)

    assert loaded["TELEGRAM_BOT_TOKEN"] == "local-token"
    assert loaded["API_HOST"] == "already-set"
    assert loaded["UI_PORT"] == "9000"


def test_build_service_specs_supports_telegram_and_custom_ports():
    args = startservers.parse_args(
        [
            "--with-telegram",
            "--api-port",
            "9001",
            "--ui-port",
            "6001",
            "--no-reload",
        ]
    )

    specs = startservers.build_service_specs(
        args,
        npm_cmd="npm",
        python_executable="python",
    )

    api = next(spec for spec in specs if spec.name == "api")
    ui = next(spec for spec in specs if spec.name == "dashboard")
    telegram = next(spec for spec in specs if spec.name == "telegram")

    assert api.health_url == "http://localhost:9001/api/settings"
    assert "--reload" not in api.cmd
    assert ui.health_url == "http://localhost:6001"
    assert ui.cmd[-2:] == ["--port", "6001"]
    assert telegram.cmd == ["python", "main.py", "--telegram-bot"]


def test_partition_service_specs_reuses_healthy_services():
    args = startservers.parse_args([])
    specs = startservers.build_service_specs(args, npm_cmd="npm", python_executable="python")

    reused, pending = startservers.partition_service_specs(
        specs,
        reuse_running=True,
        health_check=lambda url, timeout_sec=0: url.endswith(":8888/api/settings"),
    )

    assert [spec.name for spec in reused] == ["api"]
    assert [spec.name for spec in pending] == ["dashboard"]
