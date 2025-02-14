from rich.columns import Columns
from rich.table import Table
from rich.live import Live
from rich.abc import RichRenderable
from rich.text import Text

import time
import json
import functools

import humanize

t = Table(show_header=False, show_lines=True) #title="Active Connections")
t.add_column(justify="right", width=10)
t.add_column(justify="center", width=40)
t.add_column(justify="left", width=10)
interval = 0.5


data = [
    json.loads(line)
    for line in open("ssh.json", "r").readlines()
]

where_are_we = 0.0

from fowl.messages import BytesIn, BytesOut, OutgoingConnection, OutgoingDone, OutgoingLost, Listening
from fowl._proto import parse_fowld_output


import attrs

@attrs.define
class Subchannel:
    endpoint: str
    i: list
    o: list
    src: RichRenderable
    bw: RichRenderable
    dest: RichRenderable


@attrs.define
class Listener:
    listen: str
    connect: str


subchannels = {}  # id -> Subchannel
listeners = {}

@functools.singledispatch
def message(msg):
    """
    Process an output message into the shared state
    """
    pass#print(msg)


@message.register(Listening)
def _(msg):
    listeners[msg.listener_id] = Listener(msg.listen, msg.connect)


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


@message.register(BytesIn)
def _(msg):
    global subchannels
    subchannels[msg.id].i.insert(0, (msg.bytes, time.time()))
    render_bw(subchannels[msg.id])


@message.register(BytesOut)
def _(msg):
    global subchannels
    subchannels[msg.id].o.insert(0, (msg.bytes, time.time()))
    render_bw(subchannels[msg.id])


@message.register(OutgoingConnection)
def _(msg):
    global subchannels
    src = Text("")
    bw = Text("<no packets>", justify="center")
    dst = Text("")
    widget = Columns([src, bw, dst], align="right")
    dst.plain = "connect\n" + str(msg.endpoint.split(":")[-1])
    src.plain = listeners[msg.listener_id].listen.split(":")[1] + "\nlisten"
    t.add_row(src, bw, dst)
    subchannels[msg.id] = Subchannel(msg.endpoint, [], [], src, bw, dst)


@message.register(OutgoingDone)
def _(msg):
    del subchannels[msg.id]


@message.register(OutgoingLost)
def _(msg):
    del subchannels[msg.id]


with Live(t):
    while data:
        d = data.pop(0)
        #FIXME indicates should have helper for json too?
        msg = parse_fowld_output(json.dumps(d))
        message(msg)

        delay = d["timestamp"] - where_are_we
        while delay > interval:
            time.sleep(interval)
            for _, sub in subchannels.items():
                render_bw(sub)
            delay -= interval
        time.sleep(delay)
