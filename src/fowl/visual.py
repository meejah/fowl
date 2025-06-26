from rich.table import Table
from rich.text import Text

import time
import random

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
    status_remote = Text(chicken.peer[0])
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
        status_remote.plain = chicken.peer[2]
        status_remote.stylize("rgb(0,100,0) on rgb(100,255,100)")

    if st.is_connecting:
        status_local.stylize("rgb(0,100,100) on rgb(100,255,200)")

    if not st.peer_connected:
        status_remote.stylize("rgb(100,255,0) on rgb(255,0,0)")


    # turn purple if we / they are closing
    if st.peer_closing:
        status_remote.stylize("rgb(0,100,100) on rgb(255,100,255)")
    if st.we_closing:
        status_local.stylize("rgb(0,100,100) on rgb(255,100,255)")

    if random.choice("abcdefgh") == "a":
        status_local.plain = random.choice(chicken.default)

    for id_, data in st.listeners.items():
        t.add_row(
            Text("{} {}".format('🧙' if data.remote else ' ', data.local_port)),
            Text("--> {}".format(data.service_name)),
            Text("{}".format(' ' if data.remote else '🧙'), justify="center"),
        )

    for id_, data in st.subchannels.items():
        if data.service_name in st.listeners:
            if st.listeners[data.service_name].remote:
                remote = Text("ᯤ", justify="center")
                local = Text("")
            else:
                if st.listeners[data.service_name].remote_port:
                    remote = Text("connect\n" + str(st.listeners[data.service_name].remote_port))
                else:
                    remote = Text("connect")
                local = Text("ᯤ", justify="center")
        else:
            remote = local = Text("???", justify="center")
            local = Text("???", justify="center")
        bw = render_bw(data)
        t.add_row(local, bw, remote)

    return t


interval = 0.25


def render_bw(sub):
    start = time.time()  # FIXME time provuder
    if sub.i:
        accum = 0
        idx = 0
        next_time = start - interval
        points = []
        for _ in range(25):
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
    else:
        bw = ""
    rendered = Text(bw, style="blue", justify="center")
    rendered.append_text(Text("\n" + render_bw_out(sub), style="yellow"))
    return rendered


# XXX fixme, need to send in time here (or something) to fix --replay
def render_bw_out(sub):
    start = time.time()
    if not sub.o:
        return ""
    accum = 0
    idx = 0
    next_time = start - interval
    points = []
    for _ in range(25):
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
