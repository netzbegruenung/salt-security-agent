"""Curses front end for `agent.chat`.

The LLM turn runs on a worker thread and reports through the `ChatObserver` methods;
those only push events onto a queue, so all drawing happens on the main thread. The
one exception is `request_approval`, which blocks the worker until the operator answers
the prompt in the footer — that is the whole point of the approval gate.
"""

from __future__ import annotations

import curses
import locale
import queue
import threading
from dataclasses import dataclass, field
from typing import Any

from agent.chat import ChatSession

MODE_INPUT = "input"
MODE_BUSY = "busy"
MODE_APPROVAL = "approval"

PREVIEW_LINES = 12
MAX_INPUT_HISTORY = 100

HELP_TEXT = (
    "Commands:\n"
    "  /help      show this help\n"
    "  /verbose   toggle between previewed and full tool output\n"
    "  /reset     forget the conversation (keeps the same minion)\n"
    "  /context   show how much of the context budget is in use\n"
    "  /quit      leave the chat\n"
    "Keys:\n"
    "  enter      send      pgup/pgdn  scroll      up/down  recall input\n"
    "  ctrl-c     cancel the running turn, or quit when the input is empty\n"
    "Approval:\n"
    "  read_file_minion and grep_file_minion ask before every call; y approves,\n"
    "  anything else denies."
)


@dataclass
class _Block:
    kind: str
    text: str
    prefix: str = ""


@dataclass
class _Approval:
    name: str
    arguments: dict[str, Any]
    event: threading.Event = field(default_factory=threading.Event)
    approved: bool = False


def _format_arguments(arguments: dict[str, Any]) -> str:
    parts = []
    for key, value in arguments.items():
        text = value if isinstance(value, str) else repr(value)
        if len(text) > 120:
            text = text[:117] + "..."
        parts.append(f"{key}={text}")
    return " ".join(parts)


def _sanitize(text: str) -> str:
    """Make arbitrary minion output safe to draw: no tabs, no control characters."""
    out = []
    for char in text.replace("\t", "    "):
        if char == "\n" or char >= " ":
            out.append(char)
        elif char != "\r":
            out.append("?")
    return "".join(out)


def _wrap(text: str, width: int) -> list[str]:
    """Wrap on explicit newlines first, then on word boundaries where reasonable."""
    if width < 8:
        width = 8
    lines: list[str] = []
    for raw in text.split("\n"):
        if not raw:
            lines.append("")
            continue
        while len(raw) > width:
            cut = raw.rfind(" ", 0, width + 1)
            if cut < width // 2:
                cut = width
            lines.append(raw[:cut].rstrip())
            raw = raw[cut:].lstrip(" ")
        lines.append(raw)
    return lines


class CursesChatUI:
    def __init__(self, session: ChatSession) -> None:
        self.session = session
        self._events: queue.Queue[tuple] = queue.Queue()
        self._blocks: list[_Block] = []
        self._version = 0
        self._cache: tuple[int, int, bool] | None = None
        self._cached_lines: list[tuple[str, str]] = []
        self._mode = MODE_INPUT
        self._status = "ready"
        self._input = ""
        self._cursor = 0
        self._history: list[str] = []
        self._history_index: int | None = None
        self._scroll = 0
        self._verbose = False
        self._pending: _Approval | None = None
        self._worker: threading.Thread | None = None
        self._quit = False
        self._streaming = False

    # -- ChatObserver (called from the worker thread) --------------------------

    def on_assistant_text(self, chunk: str) -> None:
        self._events.put(("text", chunk))

    def on_assistant_end(self) -> None:
        self._events.put(("end",))

    def on_tool_start(self, name: str, arguments: dict[str, Any]) -> None:
        self._events.put(("tool", name, _format_arguments(arguments)))

    def on_tool_end(self, name: str, result: str, *, failed: bool = False) -> None:
        self._events.put(("tool_result", name, result, failed))

    def on_notice(self, text: str) -> None:
        self._events.put(("notice", text))

    def request_approval(self, name: str, arguments: dict[str, Any]) -> bool:
        approval = _Approval(name=name, arguments=arguments)
        self._events.put(("approval", approval))
        approval.event.wait()
        return approval.approved

    # -- transcript ------------------------------------------------------------

    def _append(self, kind: str, text: str, prefix: str = "") -> None:
        self._blocks.append(_Block(kind=kind, text=text, prefix=prefix))
        self._version += 1

    def _touch(self) -> None:
        self._version += 1

    def _drain_events(self) -> None:
        while True:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                return

            kind = event[0]
            if kind != "text":
                self._streaming = False

            if kind == "text":
                if self._streaming and self._blocks and self._blocks[-1].kind == "assistant":
                    self._blocks[-1].text += event[1]
                    self._touch()
                else:
                    self._append("assistant", event[1], prefix="")
                    self._streaming = True
                self._status = "responding"
            elif kind == "tool":
                self._append("tool", f"{event[1]} {event[2]}".rstrip(), prefix="- ")
                self._status = f"running {event[1]}"
            elif kind == "tool_result":
                _, name, result, failed = event
                self._append(
                    "error" if failed else "result",
                    result,
                    prefix="  ",
                )
                self._status = "thinking"
            elif kind == "notice":
                self._append("notice", event[1], prefix="! ")
            elif kind == "approval":
                self._pending = event[1]
                self._mode = MODE_APPROVAL
                self._status = "approval required"
            elif kind == "end":
                self._mode = MODE_INPUT
                self._status = "ready"

    def _render_lines(self, width: int) -> list[tuple[str, str]]:
        key = (self._version, width, self._verbose)
        if self._cache == key:
            return self._cached_lines

        lines: list[tuple[str, str]] = []
        for block in self._blocks:
            text = _sanitize(block.text)
            if block.kind == "result" and not self._verbose:
                physical = text.split("\n")
                if len(physical) > PREVIEW_LINES:
                    hidden = len(physical) - PREVIEW_LINES
                    text = "\n".join(physical[:PREVIEW_LINES])
                    text += f"\n[{hidden} more line(s); /verbose to show]"
            prefix = block.prefix
            indent = " " * len(prefix)
            wrapped = _wrap(text, width - len(prefix))
            for index, line in enumerate(wrapped):
                lines.append((block.kind, (prefix if index == 0 else indent) + line))
            if block.kind in {"user", "assistant"}:
                lines.append((block.kind, ""))

        self._cache = key
        self._cached_lines = lines
        return lines

    # -- drawing ---------------------------------------------------------------

    def _colour(self, kind: str) -> int:
        if not curses.has_colors():
            return curses.A_BOLD if kind == "user" else curses.A_NORMAL
        return {
            "user": curses.color_pair(1) | curses.A_BOLD,
            "assistant": curses.color_pair(2),
            "tool": curses.color_pair(3),
            "result": curses.color_pair(4),
            "notice": curses.color_pair(5),
            "error": curses.color_pair(6),
        }.get(kind, curses.A_NORMAL)

    @staticmethod
    def _put(win, y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
        height, width = win.getmaxyx()
        if y < 0 or y >= height or x >= width:
            return
        text = text[: width - x - 1] if width - x - 1 > 0 else ""
        if not text:
            return
        try:
            win.addstr(y, x, text, attr)
        except curses.error:
            try:
                win.addstr(y, x, text.encode("ascii", "replace").decode(), attr)
            except curses.error:
                pass

    def _draw(self, stdscr) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if height < 5 or width < 24:
            self._put(stdscr, 0, 0, "terminal too small")
            stdscr.refresh()
            return

        header = f" minion: {self.session.minion} "
        right = f" {self._status} "
        header_attr = curses.color_pair(7) if curses.has_colors() else curses.A_REVERSE
        self._put(stdscr, 0, 0, " " * (width - 1), header_attr)
        self._put(stdscr, 0, 0, header, header_attr)
        self._put(stdscr, 0, max(len(header) + 1, width - len(right) - 1), right, header_attr)

        body_height = height - 2
        lines = self._render_lines(width - 1)
        max_scroll = max(0, len(lines) - body_height)
        self._scroll = min(self._scroll, max_scroll)
        start = max(0, len(lines) - body_height - self._scroll)
        visible = lines[start : start + body_height]
        for row, (kind, text) in enumerate(visible, start=1):
            self._put(stdscr, row, 0, text, self._colour(kind))

        if self._scroll > 0:
            self._put(
                stdscr,
                height - 2,
                max(0, width - 22),
                f" scrolled +{self._scroll} ",
                curses.A_REVERSE,
            )

        self._draw_footer(stdscr, height, width)
        stdscr.refresh()

    def _draw_footer(self, stdscr, height: int, width: int) -> None:
        row = height - 1
        if self._mode == MODE_APPROVAL and self._pending is not None:
            call = f"{self._pending.name} {_format_arguments(self._pending.arguments)}"
            prompt = f"approve {call}? [y/N] "
            attr = curses.color_pair(6) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
            self._put(stdscr, row, 0, prompt[: width - 1], attr)
            curses.curs_set(0)
            return

        if self._mode == MODE_BUSY:
            self._put(stdscr, row, 0, "working... (ctrl-c to cancel)", curses.A_DIM)
            curses.curs_set(0)
            return

        prompt = "> "
        space = max(1, width - len(prompt) - 1)
        offset = max(0, self._cursor - space + 1)
        self._put(stdscr, row, 0, prompt + self._input[offset : offset + space])
        curses.curs_set(1)
        try:
            stdscr.move(row, len(prompt) + self._cursor - offset)
        except curses.error:
            pass

    # -- input -----------------------------------------------------------------

    def _handle_key(self, key: int | str) -> None:
        # `get_wch` hands back a str for ordinary characters and an int for the
        # KEY_* constants, so both shapes have to be understood here.
        char = key if isinstance(key, str) and len(key) == 1 else None
        code = ord(char) if char is not None else None

        if key == curses.KEY_RESIZE:
            self._cache = None
            return
        if key == curses.KEY_PPAGE:
            self._scroll += 5
            return
        if key == curses.KEY_NPAGE:
            self._scroll = max(0, self._scroll - 5)
            return

        if self._mode == MODE_APPROVAL:
            self._resolve_approval(char is not None and char in "yY")
            return
        if self._mode == MODE_BUSY:
            return

        if key == curses.KEY_ENTER or code in (10, 13):
            self._submit()
        elif key == curses.KEY_BACKSPACE or code in (8, 127):
            if self._cursor > 0:
                self._input = self._input[: self._cursor - 1] + self._input[self._cursor :]
                self._cursor -= 1
        elif key == curses.KEY_DC:
            self._input = self._input[: self._cursor] + self._input[self._cursor + 1 :]
        elif key == curses.KEY_LEFT:
            self._cursor = max(0, self._cursor - 1)
        elif key == curses.KEY_RIGHT:
            self._cursor = min(len(self._input), self._cursor + 1)
        elif key == curses.KEY_HOME or code == 1:
            self._cursor = 0
        elif key == curses.KEY_END or code == 5:
            self._cursor = len(self._input)
        elif code == 21:  # ctrl-u
            self._input = self._input[self._cursor :]
            self._cursor = 0
        elif key == curses.KEY_UP:
            self._recall(-1)
        elif key == curses.KEY_DOWN:
            self._recall(1)
        elif char is not None and code is not None and code >= 32 and code != 127:
            self._input = self._input[: self._cursor] + char + self._input[self._cursor :]
            self._cursor += 1

    def _recall(self, direction: int) -> None:
        if not self._history:
            return
        if self._history_index is None:
            self._history_index = len(self._history)
        index = self._history_index + direction
        if index < 0:
            index = 0
        if index >= len(self._history):
            self._history_index = None
            self._input = ""
            self._cursor = 0
            return
        self._history_index = index
        self._input = self._history[index]
        self._cursor = len(self._input)

    def _resolve_approval(self, approved: bool) -> None:
        pending = self._pending
        self._pending = None
        self._mode = MODE_BUSY
        self._status = "thinking"
        if pending is not None:
            pending.approved = approved
            pending.event.set()

    def _submit(self) -> None:
        text = self._input.strip()
        self._input = ""
        self._cursor = 0
        self._history_index = None
        if not text:
            return
        self._history.append(text)
        del self._history[:-MAX_INPUT_HISTORY]
        self._scroll = 0

        if text.startswith("/"):
            self._command(text)
            return

        self._append("user", text, prefix="> ")
        self._mode = MODE_BUSY
        self._status = "thinking"
        self._worker = threading.Thread(
            target=self.session.send, args=(text, self), daemon=True
        )
        self._worker.start()

    def _command(self, text: str) -> None:
        command = text.split()[0].lower()
        if command in ("/quit", "/exit", "/q"):
            self._quit = True
        elif command == "/help":
            self._append("notice", HELP_TEXT, prefix="! ")
        elif command == "/verbose":
            self._verbose = not self._verbose
            self._append(
                "notice",
                f"tool output: {'full' if self._verbose else f'first {PREVIEW_LINES} lines'}",
                prefix="! ",
            )
        elif command == "/reset":
            self.session.reset()
            self._blocks = []
            self._append("notice", "conversation cleared", prefix="! ")
        elif command == "/context":
            budget = self.session.llm_cfg.context_char_budget
            used = self.session.context_chars
            self._append(
                "notice",
                f"context: {used} / {budget} chars ({used * 100 // max(budget, 1)}%)",
                prefix="! ",
            )
        else:
            self._append("notice", f"unknown command: {command} (try /help)", prefix="! ")

    # -- main loop -------------------------------------------------------------

    def _interrupt(self) -> None:
        if self._mode == MODE_APPROVAL:
            self._resolve_approval(False)
        elif self._mode == MODE_BUSY:
            self.session.cancel()
            self._status = "cancelling"
        elif self._input:
            self._input = ""
            self._cursor = 0
        else:
            self._quit = True

    def _main(self, stdscr) -> None:
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        if curses.has_colors():
            for index, colour in enumerate(
                (
                    curses.COLOR_CYAN,
                    curses.COLOR_WHITE,
                    curses.COLOR_YELLOW,
                    curses.COLOR_BLUE,
                    curses.COLOR_MAGENTA,
                    curses.COLOR_RED,
                ),
                start=1,
            ):
                curses.init_pair(index, colour, -1)
            curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)
        stdscr.keypad(True)
        stdscr.timeout(50)

        self._append(
            "notice",
            f"Investigating {self.session.minion}. Inspection tools run on their own; "
            "file reads and greps ask you first. /help for commands.",
            prefix="! ",
        )

        while not self._quit:
            self._drain_events()
            self._draw(stdscr)
            try:
                key = stdscr.get_wch()
            except curses.error:  # no input before the timeout expired
                continue
            except KeyboardInterrupt:
                self._interrupt()
                continue
            if key == "\x03":  # ctrl-c arriving as a key rather than a signal
                self._interrupt()
                continue
            self._handle_key(key)

    def run(self) -> None:
        locale.setlocale(locale.LC_ALL, "")
        try:
            curses.wrapper(self._main)
        finally:
            self.session.cancel()
            if self._pending is not None:
                self._pending.approved = False
                self._pending.event.set()
            if self._worker is not None:
                self._worker.join(timeout=2)
            self.session.close()


def run_chat_ui(session: ChatSession) -> None:
    CursesChatUI(session).run()
