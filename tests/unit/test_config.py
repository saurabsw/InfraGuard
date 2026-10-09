"""Unit tests for core configuration module."""

from __future__ import annotations

from app.core.config import Settings


class TestSettings:
    """Verify environment-based settings load correctly."""

    def test_defaults(self):
        """Settings should have sane defaults without any env vars."""
        s = Settings(
            _env_file=None,  # Don't read .env during tests
        )
        assert s.app_name == "InfraGuard"
        assert s.app_version == "1.0.0"
        assert s.debug is False
        assert s.database_url == "sqlite:///./infraguard.db"
        assert s.max_file_size_bytes == 5_242_880
        assert s.max_files_per_scan == 20
        assert s.host == "127.0.0.1"
        assert s.port == 8000
        assert s.policy_version == "1.0.0"
        assert s.scanner_version == "1.0.0"

    def test_custom_values(self, monkeypatch):
        """Settings should respect environment overrides."""
        monkeypatch.setenv("APP_NAME", "TestGuard")
        monkeypatch.setenv("DEBUG", "true")
        monkeypatch.setenv("MAX_FILE_SIZE_BYTES", "1000")
        s = Settings(
            _env_file=None,
        )
        assert s.app_name == "TestGuard"
        assert s.debug is True
        assert s.max_file_size_bytes == 1000
