import os

import pytest

import gen


@pytest.fixture(autouse=True)
def mock_installer_latest_complete_artifact(monkeypatch):
    monkeypatch.setattr(
        gen.build_deploy.bash,
        'installer_latest_complete_artifact',
        lambda _: {'bootstrap': os.getenv('BOOTSTRAP_ID', '12345'), 'packages': []},
    )
