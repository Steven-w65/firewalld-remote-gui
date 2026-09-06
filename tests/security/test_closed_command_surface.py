from __future__ import annotations

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ServerController
from app.gui.main_window import MainWindow
from tests.acceptance.harness import application_harness


def test_gui_and_controllers_expose_no_arbitrary_command_entrypoint():
    def public_callable_names(*types):
        return {
            name
            for type_ in types
            for name in dir(type_)
            if not name.startswith("_") and callable(getattr(type_, name))
        }

    forbidden = {"run_command", "execute_shell", "terminal", "command_text"}
    assert forbidden.isdisjoint(
        public_callable_names(MainWindow, ServerController, FirewallController)
    )


def test_actionable_gui_surface_has_no_generic_command_or_file_path_input(
    application_harness,
):
    app = application_harness.with_servers("web01")
    actionable = "\n".join(app.actionable_texts()).casefold()
    editable = "\n".join(app.editable_field_descriptors()).casefold()
    forbidden = ("terminal", "shell", "command text", "raw rich", "file path")
    assert all(value not in actionable for value in forbidden)
    assert all(value not in editable for value in forbidden)
