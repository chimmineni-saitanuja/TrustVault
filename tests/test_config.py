"""Tests for deployment configuration validation."""

import unittest

from pydantic import ValidationError
from starlette.middleware.cors import CORSMiddleware

from app.config import Settings, settings
from app.main import app


class TestSettings(unittest.TestCase):
    def test_development_settings_keep_local_cors_defaults(self):
        config = Settings(_env_file=None)

        self.assertEqual(
            config.cors_origins,
            ["http://localhost:3000", "http://127.0.0.1:8000"],
        )

    def test_configured_cors_origins_are_split_and_trimmed(self):
        config = Settings(
            _env_file=None,
            CORS_ORIGINS="https://vault.example.com, https://admin.example.com",
        )

        self.assertEqual(
            config.cors_origins,
            ["https://vault.example.com", "https://admin.example.com"],
        )

    def test_cors_middleware_uses_configured_origins(self):
        cors_middleware = next(
            middleware
            for middleware in app.user_middleware
            if middleware.cls is CORSMiddleware
        )

        self.assertEqual(cors_middleware.kwargs["allow_origins"], settings.cors_origins)

    def test_production_requires_explicit_cors_origins(self):
        with self.assertRaises(ValidationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                SECRET_KEY="0123456789abcdef0123456789abcdef",
            )

    def test_production_rejects_localhost_only_cors_origins(self):
        with self.assertRaises(ValidationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                SECRET_KEY="0123456789abcdef0123456789abcdef",
                CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:8000",
            )

    def test_production_rejects_development_fallback_secret(self):
        with self.assertRaises(ValidationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                CORS_ORIGINS="https://vault.example.com",
            )

    def test_production_rejects_short_secret(self):
        with self.assertRaises(ValidationError):
            Settings(
                _env_file=None,
                APP_ENV="production",
                SECRET_KEY="too-short",
                CORS_ORIGINS="https://vault.example.com",
            )

    def test_production_accepts_configured_key_and_origins(self):
        config = Settings(
            _env_file=None,
            APP_ENV="production",
            SECRET_KEY="0123456789abcdef0123456789abcdef",
            CORS_ORIGINS="https://vault.example.com",
        )

        self.assertEqual(config.cors_origins, ["https://vault.example.com"])

    def test_cors_origins_reject_paths_and_non_http_schemes(self):
        for value in ("https://vault.example.com/app", "ftp://vault.example.com"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                Settings(_env_file=None, CORS_ORIGINS=value)
