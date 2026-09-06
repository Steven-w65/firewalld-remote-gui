from __future__ import annotations

from tests.acceptance.harness import application_harness


def test_all_logs_errors_and_visible_widgets_exclude_credentials(
    application_harness,
):
    app = application_harness.with_credentials(
        ssh="acceptance-ssh-credential-sentinel",
        sudo="acceptance-sudo-credential-sentinel",
    )
    evidence = app.simulate_auth_and_sudo_failures()

    surfaces = {
        "application logs": evidence.logs,
        "error dialogs": evidence.errors,
        "clipboard": (evidence.clipboard,),
        "visible widgets": evidence.widgets,
        "table models": evidence.models,
        "safe session views": evidence.sessions,
        "public results": evidence.public_results,
    }
    for name, values in surfaces.items():
        assert any(value.strip() for value in values), f"{name} evidence is empty"
        combined = "\n".join(values)
        assert "acceptance-ssh-credential-sentinel" not in combined
        assert "acceptance-sudo-credential-sentinel" not in combined

    assert evidence.sudo_prompted
    assert evidence.sudo_reached_fake_service
    assert evidence.sudo_widget_cleared
    assert any("partially completed" in value.casefold() for value in evidence.widgets)
    assert any("9443" in value for value in evidence.models)
    assert any(
        "ssh authentication failed" in value.casefold() for value in evidence.errors
    )
    assert any("add_port" in value for value in evidence.public_results)

    later_error = app.simulate_later_sudo_authentication_failure()
    assert "Sudo Authentication Failed" in later_error
    assert "acceptance-ssh-credential-sentinel" not in later_error
    assert "acceptance-sudo-credential-sentinel" not in later_error
