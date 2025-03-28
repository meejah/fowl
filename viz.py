

from datetime import datetime

from textual.app import App, ComposeResult
from textual.widgets import Digits


class VizApp(App):
    CSS = """
    Screen { align: center middle; }
    Digits { width: auto; }
    """

    BINDINGS = [
        ('q', 'quit', 'Quit the app'),
    ]

    def compose(self) -> ComposeResult:
        yield Digits("")

    def on_ready(self) -> None:
        self.update_clock()
        self.set_interval(1, self.update_clock)

    def update_clock(self) -> None:
        clock = datetime.now().time()
        self.query_one(Digits).update(f"{clock:%T}")

    # XXX Fun! the infrastructure already overrides / implements action_quit

if __name__ == "__main__":
    app = VizApp()
    app.run()
