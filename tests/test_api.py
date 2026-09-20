import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from src.api import create_app
from src.service_config import ServiceSettings


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        settings = ServiceSettings(
            database_path=root / "sentinel.db",
            artifact_dir=root / "models",
            secret_key="test-secret-key-with-at-least-32-characters",
            token_minutes=5,
            admin_username="admin",
            admin_password="correct-horse-battery-staple",
        )
        self.client_context = TestClient(create_app(settings))
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.temporary_directory.cleanup()

    def login(self, username="admin", password="correct-horse-battery-staple"):
        response = self.client.post(
            "/auth/token", data={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def test_health_and_authentication_boundary(self):
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")
        self.assertTrue(health.json()["production_secret_configured"])
        self.assertEqual(self.client.get("/incidents").status_code, 401)
        self.assertEqual(self.client.get("/auth/me", headers=self.login()).json()["role"], "admin")

    def test_admin_can_create_analyst_but_analyst_cannot_administer(self):
        admin_headers = self.login()
        created = self.client.post(
            "/users",
            headers=admin_headers,
            json={"username": "analyst", "password": "analyst-password", "role": "analyst"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        analyst_headers = self.login("analyst", "analyst-password")
        self.assertEqual(self.client.get("/system/metrics", headers=analyst_headers).status_code, 200)
        forbidden = self.client.post(
            "/suppressions",
            headers=analyst_headers,
            json={"source_dataset": "cert_style", "reason": "test"},
        )
        self.assertEqual(forbidden.status_code, 403)
        audit = self.client.get("/audit", headers=admin_headers)
        self.assertEqual(audit.status_code, 200)
        self.assertEqual(audit.json()[0]["action"], "create_user")

    def test_bad_credentials_are_rejected(self):
        response = self.client.post(
            "/auth/token", data={"username": "admin", "password": "not-the-password"}
        )
        self.assertEqual(response.status_code, 401)

    def test_secure_mode_rejects_placeholder_credentials(self):
        root = Path(self.temporary_directory.name)
        settings = ServiceSettings(
            database_path=root / "unsafe.db",
            artifact_dir=root / "unsafe-models",
            secret_key="replace-with-at-least-32-random-characters",
            admin_password="replace-with-a-strong-password",
            require_secure_config=True,
        )
        with self.assertRaisesRegex(RuntimeError, "Secure deployment requires"):
            with TestClient(create_app(settings)):
                pass


if __name__ == "__main__":
    unittest.main()
