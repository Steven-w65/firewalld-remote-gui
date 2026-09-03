from __future__ import annotations

import pytest
from PySide6.QtWidgets import QDialog

from app.gui.dialogs.add_port_dialog import AddPortDialog
from app.models.enums import ApplyTarget
from app.models.port import AddPortRequest


def test_add_dialog_defaults_to_current_zone_both_and_cancel(qtbot):
    dialog = AddPortDialog(("public", "internal"), "public")
    qtbot.addWidget(dialog)

    assert dialog.zone_combo.currentText() == "public"
    assert dialog.target() is ApplyTarget.BOTH
    assert dialog.defaultButton() is dialog.cancel_button
    assert not dialog.add_button.isEnabled()
    assert dialog.request() is None


def test_add_dialog_falls_back_to_first_snapshot_zone_and_rejects_empty_inventory(qtbot):
    dialog = AddPortDialog(("internal", "public"), "missing")
    qtbot.addWidget(dialog)
    assert dialog.zone_combo.currentText() == "internal"

    with pytest.raises(ValueError, match="zone"):
        AddPortDialog((), "public")


@pytest.mark.parametrize(
    "port",
    ("", "0", "65536", "8100-8000", "22; id", "22 23", "２２", "1-65536"),
)
def test_invalid_port_disables_add_and_shows_fixed_safe_reason(qtbot, port):
    dialog = AddPortDialog(("public",), "public")
    qtbot.addWidget(dialog)

    dialog.port_edit.setText(port)

    assert not dialog.add_button.isEnabled()
    assert dialog.validation_label.text() == AddPortDialog.INVALID_PORT_MESSAGE
    if port:
        assert port not in dialog.validation_label.text()


@pytest.mark.parametrize("port", ("1", "22", "65535", "8000-8100"))
def test_valid_single_ports_and_inclusive_ranges_enable_add(qtbot, port):
    dialog = AddPortDialog(("public",), "public")
    qtbot.addWidget(dialog)

    dialog.port_edit.setText(port)

    assert dialog.add_button.isEnabled()
    assert dialog.validation_label.text() == ""


def test_protocol_and_target_choices_are_bounded(qtbot):
    dialog = AddPortDialog(("public",), "public")
    qtbot.addWidget(dialog)

    assert tuple(
        dialog.protocol_combo.itemText(index)
        for index in range(dialog.protocol_combo.count())
    ) == ("TCP", "UDP")
    targets = []
    for index in range(dialog.target_combo.count()):
        dialog.target_combo.setCurrentIndex(index)
        targets.append(dialog.target())
    assert tuple(targets) == (
        ApplyTarget.RUNTIME,
        ApplyTarget.PERMANENT,
        ApplyTarget.BOTH,
    )


def test_accept_captures_validated_immutable_request_and_reject_clears_it(qtbot):
    dialog = AddPortDialog(("public", "internal"), "public")
    qtbot.addWidget(dialog)
    dialog.zone_combo.setCurrentText("internal")
    dialog.port_edit.setText("8080")
    dialog.protocol_combo.setCurrentText("UDP")
    dialog.target_combo.setCurrentIndex(0)

    dialog.add_button.click()

    assert dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.request() == AddPortRequest(
        "internal", "8080", "udp", ApplyTarget.RUNTIME
    )

    dialog.reject()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert dialog.request() is None


def test_close_and_escape_paths_never_return_raw_widget_state(qtbot):
    dialog = AddPortDialog(("public",), "public")
    qtbot.addWidget(dialog)
    dialog.port_edit.setText("22; id")

    dialog.close()

    assert dialog.result() == QDialog.DialogCode.Rejected
    assert dialog.request() is None


def test_add_port_request_is_validated_independently_of_widgets():
    request = AddPortRequest("public", "443", "TCP", ApplyTarget.BOTH)
    assert request == AddPortRequest("public", "443", "tcp", ApplyTarget.BOTH)

    with pytest.raises(TypeError, match="ApplyTarget"):
        AddPortRequest("public", "443", "tcp", "both")
