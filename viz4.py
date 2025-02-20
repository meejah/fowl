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


wizard1 = "  / \\   \n /___\\  \n( _ _ ) \n)  L  ("
wizard2 = "  / \\   \n /___\\  \n( . . ) \n)  L  ("
wizard3 = "  / \\   \n /___\\  \n( o o ) \n)  L  ("
wizard4 = "  / \\   \n /___\\  \n( - - ) \n)  L  ("
wizard5 = "  / \\   \n /___\\  \n( o < ) \n)  L  ("

wizard1 = r"""  ,.    
 (\(\)  
 ;  . > 
/  (_)  """
wizard2 = r"""  ,.    
 (\(\)  
 ;  o > 
/  (_)  """
wizard3 = r"""  ,.    
 (\(\)  
 ;  * > 
/  (_)  """
wizard4 = r"""  ,.    
 (\(\)  
 ;  - > 
/  (_)  """
wizard5 = r"""  ,.    
 (\(\)  
 ;  ^ > 
/  (_)  """


wizard1 = r""" MM      
<' \___/|
  \_  _/ 
    ][   """
wizard2 = r""" MM      
<` \___/|
  \_  _/ 
    ][   """
wizard3 = r""" MM      
>' \___/|
  \_  _/ 
    ][   """
wizard4 = r""" MM      
<" \___/|
  \_  _/ 
    ][   """
wizard5 = """ MM      
<\u203e \\___/|
  \\_  _/ 
    ][   """



wizard1 = r"""    \\  
    (-> 
 \\_//) 
  \_/_) """
wizard2 = r"""    \\  
    (o> 
 \\_//) 
  \_/_) """
wizard3 = r"""    \\  
    (o< 
 \\_//) 
  \_/_) """
wizard4 = r"""    \\  
    (-> 
 \\_//) 
  \_/_) """
wizard5 = r"""    ||  
    (o> 
 \\_//) 
  \_/_) """





interval = 0.25
t = Table(show_header=False, show_lines=True) #title="Active Connections")
t.add_column(justify="left", width=8)
t.add_column(justify="left", width=40)
t.add_column(justify="left", width=8)

status_local = Text(wizard1)
status_local.stylize("rgb(100,255,0) on rgb(255,0,0)")
status_remote = Text(wizard1)
status_remote.stylize("rgb(255,255,255) on rgb(255,0,0)")
message_text = Text("connecting...")
t.add_row(status_local, message_text, status_remote)


data = [
    json.loads(line)
    for line in open("ssh-orig.json", "r").readlines()
    ##for line in open("ssh.json", "r").readlines()
    ##for line in open("demo.json", "r").readlines()
]

where_are_we = 0.0

from fowl.messages import BytesIn, BytesOut, OutgoingConnection, OutgoingDone, OutgoingLost, Listening, Welcome, PeerConnected, LocalListener, RemoteListeningSucceeded, WormholeClosed, CodeAllocated, IncomingConnection, IncomingDone, IncomingLost
from fowl._proto import parse_fowld_output


import attrs


@attrs.define
class GlobalStatus:
    url: str
    welcome: dict
    code: str


the_status = GlobalStatus("", {}, "")


@attrs.define
class Subchannel:
    endpoint: str
    i: list
    o: list
    src: RichRenderable
    bw: RichRenderable
    dest: RichRenderable
    row: int


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


@message.register(Welcome)
def _(msg):
    the_status.url = msg.url
    the_status.welcome = msg.welcome
    message_text.plain = the_status.url
    message_text.stylize("green")
    message_text.append(f"\nwelcome={the_status.welcome}\n")
    status_local.plain = wizard2
    status_local.stylize("rgb(0,100,100) on rgb(255,255,100)")


@message.register(CodeAllocated)
def _(msg):
    message_text.plain = the_status.url
    message_text.stylize("green")
    message_text.append(f"\nwelcome={the_status.welcome}\n")
    message_text.append(Text(f"code: {msg.code}\n", "bold"))
    status_local.plain = wizard2
    status_local.stylize("rgb(0,100,100) on rgb(255,255,100)")


@message.register(PeerConnected)
def _(msg):
    import binascii
    v = binascii.hexlify(msg.verifier).decode("utf8")
    nice_verifier = " ".join(
        v[a:a+4]
        for a in range(0, len(v), 4)
    )
    status_local.plain = wizard3
    status_local.stylize("rgb(0,100,0) on rgb(100,255,100)")
    status_remote.plain = wizard3
    status_remote.stylize("rgb(0,100,0) on rgb(100,255,100)")

    message_text.plain = the_status.url
    message_text.stylize("green")
    message_text.append(f"\nwelcome={the_status.welcome}\n")
    message_text.append(nice_verifier)


@message.register(WormholeClosed)
def _(msg):
    status_local.plain = wizard1
    status_local.stylize("default on default")
    status_remote.plain = wizard1
    status_remote.stylize("default on default")
    # no better way to get rid of things?
    for c in range(len(t.columns)):
        while len(t.columns[c]._cells) > 1:
            del t.columns[c]._cells[1]
    t.columns[1].justify = "center"
    message_text.plain = "\n\ndone: {}".format(msg.result)


@message.register(Listening)
def _(msg):
    listeners[msg.listener_id] = Listener(msg.listen, msg.connect)
    t.add_row(
        Text("🧙 {}".format(msg.listen.split(":")[1])),
        Text("--> {}".format(msg.connect.split(":")[2])),
        Text(""),
    )


@message.register(RemoteListeningSucceeded)
def _(msg):
    listeners[msg.listener_id] = Listener(msg.listen, msg.connect)
    t.add_row(
        Text(""),
        Text("{} <--".format(msg.connect.split(":")[2]), justify="right"),
        Text("{} 🧙".format(msg.listen.split(":")[1])),
    )




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


@message.register(IncomingConnection)
def _(msg):
    global subchannels
    src = Text("")
    bw = Text("<no packets>", justify="center")
    dst = Text("")
    widget = Columns([src, bw, dst], align="right")
    dst.plain = "connect\n" + str(msg.endpoint.split(":")[-1])
    src.plain = listeners[msg.listener_id].listen.split(":")[1] + "\nlisten"
    t.add_row(src, bw, dst)
    subchannels[msg.id] = Subchannel(msg.endpoint, [], [], src, bw, dst, len(t.rows) - 1)


@message.register(IncomingDone)
def _(msg):
    out = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].o]))
    in_ = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].i]))
    print(f"{msg.id} closed: {out} out, {in_} in")
    del subchannels[msg.id]
    # delete from the table too


@message.register(IncomingLost)
def _(msg):
    del subchannels[msg.id]
    # delete from the table too


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
    subchannels[msg.id] = Subchannel(msg.endpoint, [], [], src, bw, dst, len(t.rows) - 1)


@message.register(OutgoingDone)
def _(msg):
    out = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].o]))
    in_ = humanize.naturalsize(sum([b for b, _ in subchannels[msg.id].i]))
    print(f"{msg.id} closed: {out} out, {in_} in")
    # better way to delete from the table?
    for c in range(len(t.columns)):
        del t.columns[c]._cells[subchannels[msg.id].row]
    del t.rows[subchannels[msg.id].row]
    # bye
    del subchannels[msg.id]


@message.register(OutgoingLost)
def _(msg):
    del subchannels[msg.id]
    # delete from the table too



local_blink = False
local_old_wizard = wizard1
remote_blink = False
remote_old_wizard = wizard1


def render_wormhole_state():
    return t

with Live(get_renderable=render_wormhole_state):
    while data:
        d = data.pop(0)
        #FIXME indicates should have helper for json too?

        delay = d["timestamp"] - where_are_we
        while delay > interval:
            time.sleep(interval)
            for _, sub in subchannels.items():
                render_bw(sub)
            delay -= interval
            if local_blink:
                local_old_wizard = status_local.plain
                status_local.plain = random.choice([wizard1, wizard5, wizard4])
                local_blink = False
            else:
                if status_local.plain in [wizard1, wizard5, wizard4]:
                    status_local.plain = local_old_wizard
            if remote_blink:
                remote_old_wizard = status_remote.plain
                status_remote.plain = random.choice([wizard1, wizard5, wizard4])
                remote_blink = False
            else:
                if status_remote.plain in [wizard1, wizard5, wizard4]:
                    status_remote.plain = remote_old_wizard
        time.sleep(delay)
        where_are_we = d["timestamp"]
        # blink every time we get a packet/message?
        local_blink = True
        remote_blink = True

        msg = parse_fowld_output(json.dumps(d))
        message(msg)
