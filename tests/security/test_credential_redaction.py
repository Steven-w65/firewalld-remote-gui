from __future__ import annotations

from tests.acceptance.harness import application_harness


def test_all_logs_errors_and_visible_widgets_exclude_credentials(
    application_harness, caplog
):
    app = application_harness.with_credentials(
        ssh="acceptance-ssh-credential-sentinel",
        sudo="acceptance-sudo-credential-sentinel",
    )
    app.simulate_auth_and_sudo_failures()
    combined = caplog.text + app.visible_text() + app.error_text()
    assert "acceptance-ssh-credential-sentinel" not in combined
    assert "acceptance-sudo-credential-sentinel" not in combined
