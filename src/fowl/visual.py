from rich.columns import Columns
from rich.table import Table
from rich.live import Live
from rich.abc import RichRenderable
from rich.text import Text

import time
import json
import random
import functools

import humanize

from .status import FowlStatus
from fowl import chicken


def render_status(st: FowlStatus) -> Table:  # Panel? seomthing else
    """
    Render the given fowl status to a Rich thing
    """
    t = Table(show_header=False, show_lines=True) #title="Active Connections")
    t.add_column(justify="left", width=8)
    t.add_column(justify="left", width=40)
    t.add_column(justify="left", width=8)

    status_local = Text(chicken.default[0])
    status_remote = Text(chicken.default[0])
    message_text = Text("")
    t.add_row(status_local, message_text, status_remote)

    if st.url is None:
        status_local.stylize("rgb(100,255,0) on rgb(255,0,0)")
        status_remote.stylize("rgb(255,255,255) on rgb(255,0,0)")
        message_text.append("connecting...")
    else:
        message_text.append(st.url)
        message_text.stylize("green")
        message_text.append(f"\nwelcome={st.welcome}\n")
        status_local.plain = chicken.default[1]
        status_local.stylize("rgb(0,100,100) on rgb(255,255,100)")

    if st.code is not None:
        # only display code until we're connected
        if st.verifier is None:
            message_text.append(Text(f"code: {st.code}\n", "bold"))

    if st.verifier is not None:
        nice_verifier = " ".join(
            st.verifier[a:a+4]
            for a in range(0, len(st.verifier), 4)
        )
        message_text.append(nice_verifier)
        status_local.plain = chicken.default[2]
        status_local.stylize("rgb(0,100,0) on rgb(100,255,100)")
        status_remote.plain = chicken.default[2]
        status_remote.stylize("rgb(0,100,0) on rgb(100,255,100)")

    for id_, data in st.listeners.items():
        if data.remote:
            t.add_row(
                Text(""),
                Text("{} <--".format(data.connect.split(":")[2]), justify="right"),
                Text("{} 🧙".format(data.listen.split(":")[1])),
            )
        else:
            t.add_row(
                Text("🧙 {}".format(data.listen.split(":")[1])),
                Text("--> {}".format(data.connect.split(":")[2])),
                Text(""),
            )

    return t


def render_bw(sub):
    start = time.time()
    if not sub.i:
        return
    accum = 0
    idx = 0
    next_time = start - interval
    points = []
    for _ in range(20):
        while idx < len(sub.i) and sub.i[idx][1] > next_time:
            accum += sub.i[idx][0]
            idx += 1

        points.append(accum)
        accum = 0
        next_time = next_time - interval

    bw = ""
    for p in points:
        if p < 1:
            bw += "\u2581"
        elif p < 100:
            bw += "\u2582"
        elif p < 1000:
            bw += "\u2583"
        elif p < 10000:
            bw += "\u2584"
        elif p < 100000:
            bw += "\u2585"
        elif p < 10000000:
            bw += "\u2586"
        elif p < 10000000000:
            bw += "\u2587"
        else:
            bw += "\u2588"
    bw += "  " + humanize.naturalsize(sum(x[0] for x in sub.i))
    sub.bw.plain = ""
    sub.bw.append_text(Text(bw, style="blue"))
    sub.bw.append_text(Text("\n" + render_bw_out(sub), style="yellow"))


def render_bw_out(sub):
    start = time.time()
    if not sub.o:
        return
    accum = 0
    idx = 0
    next_time = start - interval
    points = []
    for _ in range(30):
        while idx < len(sub.o) and sub.o[idx][1] > next_time:
            accum += sub.o[idx][0]
            idx += 1

        points.append(accum)
        accum = 0
        next_time = next_time - interval

    bw = humanize.naturalsize(sum(x[0] for x in sub.o)) + "  "
    for p in reversed(points):
        if p < 1:
            bw += "\u2581"
        elif p < 100:
            bw += "\u2582"
        elif p < 1000:
            bw += "\u2583"
        elif p < 10_000:
            bw += "\u2584"
        elif p < 100_000:
            bw += "\u2585"
        elif p < 1_000_000:
            bw += "\u2586"
        elif p < 100_000_000:
            bw += "\u2587"
        else:
            bw += "\u2588"
    return bw
