from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_external_wrapper_fleet_is_removed():
    assert not (ROOT / "docker-fleet").exists()


def test_gitignore_no_longer_mentions_removed_fleet():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "docker-fleet/.env" not in gitignore


def test_dashboard_blueprint_does_not_advertise_wrapped_external_scanners():
    blueprint = (ROOT / "dashboard" / "src" / "Blueprint.jsx").read_text(encoding="utf-8")
    assert "Nmap, Nuclei, SQLmap (wrapped)" not in blueprint
