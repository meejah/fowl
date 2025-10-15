from rich.table import Table
from rich.text import Text

import random

import humanize

from .status import FowlStatus
from fowl import chicken


littlebitspace_word_logo = r"""[0m                                           [1;34m,ssss.[0m   ,r.  l[1;33mM[0ml
                                         [1;34m,d²'[0m  [1;34m`[0m_,*?%;`  [1;34mbsd[0m
       [1;31mr ,s                   [37m_.,[0m        [1;34md?[0m   ,s=²²b?:   [1;34m?8P[0m
      [1;31m;8d8bs[0m                 [1m!8!'[0m        [1;34m8:[0m   [33m,[1;31m#"[0;33m,8,[37mb.   [1;34m`?;[0m
      [1;31m!8P²`'[0m [1m,ss.[0m  [1;33ms ,s. ,r  [37m88P         [34m8:[0m  [33m;[1;37m`[0;33md:[1;37m`[0;33m8db[37m"    [1;34m8:[0m
    [1;31m²sd88sP[0m [1md8888.[0m [1;33mYb`8L,8!  [37m88l         [34m8:[0m  [33m8[1m,@[0;33m:Y8sPb,[37m   [1;34m8:[0m
     [1;31m*'8l   [37m88888![0m [1;33m`8b8888;  [37mY8b_,r[0m      [1;34m8:[0m [33m;P[1;31mJ²P[0;33m,bsdP[1;37m,%.[0m [1;34mY:[0m
      [1;31md8b.  [37m!8888;[0m  [1;33m!8P`8P   [37m:@lbs*[0m      [1;34m8:[0m [33m!bsP?88sf[1;37m,d?%b[34m?:[0m
      [1;33m,8L    [37m`²²'[0m    [1;33m²  "     [37m`"²²s[0m     [1;34m,?;[0m [1ms.[0;33m²P"?8²[1;37m,d%??%[34m?:[0m
     [1;33m²'V`*[0m                              [1;34md8b[0m [1m?%bsdbs?88?%?'[34md:[0m
                                        [1;34mP²?[0m [1m`?%?8?%%?8?%'[34ms?'[0m
                                        ![1;33mM[0m!  [1m`²²?%%%²^'[34m²²'[0m"""


littlebitspace_big_logo = r"""[0m                      _       .[1;33m,,[0m.
      [1;34m.sd8888bs.[0m   ,s?%²s     l[1;33mWW[0ml
    [1;34ms8?²^'  `^²?[0m,s²?8%P `    [1;34m:[0ml88l[1;34m;[0m
   [1;34md?;[0m      ,*8²²²²b²%:      [1;34m`bssd'[0m
   [1;34m8%[0m      :l[1;31m,sd8P*[0m`b²:       [1;34m?88Y[0m
   [1;34m8%[0m      [33m,[1;31m`8P²'[0;33msds[37m`b.        [1;34m?%[0m
   [1;34m8%[0m     [33m;8bsd88²8Pb[37m"P        [1;34m8%[0m
   [1;34m8%[0m    [33m;8[37m [1m'[0;33m²²[37m [1m'[0;33m8fd88.[37m        [1;34m8%
[0m   [1;34m8%[0m    [33mi?'[1md8b[0;33m`88²88²db.[37m      [1;34m@%[0m
   [1;34m8%[0m    [33mld'[1;31m,d?b[0;33m`88bdY8?8s[1;37m.[0m    [1;34mL%[0m
   [1;34m8%[0m    [33m!8s[1;31m²^YF[0;33m,²88PJ8b[37m [1md%:.[0m  [1;34mB%[0m
   [1;34m8%[0m    [33md?8b8bsd8bs8²8'[1;37m,?8b%.[0m [1;34mS%[0m
   [1;34m??[0m    [33mPYsd8²888888P[1;37m,d%%?8%l[0m [1;34m8%[0m
  [1;34md88b  [37m,b,[0;33mY88r²88P²'[1;37m,d?%%%?%;[0m [1;34m8?[0m
 [1;34m,P²²?.[0m [1m!%%++sdbsssd88?%%%%?;[0m [1;34mJ?'[0m
 [1;34m:[0ml88l[1;34m;[0m [1m`?%%%?88?%%%?88???%'[34m,d?"[0m
  l[1;33mMM[0ml   [1m`Y%?88?%%%%%?8%²'[34m8P²'[0m
  `[1;33m""[0m'     [1m`"²Y?%%%%²"'[0m"""


def render_status(st: FowlStatus, time_now) -> Table:  # Panel? seomthing else
    """
    Render the given fowl status to a Rich thing
    """

    logo = Text.from_ansi(littlebitspace_word_logo)
#    logo = Text.from_ansi(littlebitspace_big_logo)
    top = Table.grid('one')
    top.add_row(logo)

    from rich import box
    t = Table(show_header=False, show_lines=True, box=box.HORIZONTALS) #title="Active Connections")
    t.add_column(justify="left", width=8)
    t.add_column(justify="left", width=40)
    t.add_column(justify="left", width=8)

    top.add_row(t)

    status_local = Text(chicken.default[0])
    status_remote = Text(chicken.peer[0])
    message_text = Text("")
    t.add_row(status_local, message_text, status_remote)

    color_connect = "rgb(25,25,25) on rgb(0,147,38)"
    color_no_peer = "rgb(0,0,0) on rgb(160,176,0)"
    color_nothing = "rgb(255,255,255) on rgb(176,0,0)"
    color_connecting = "rgb(0,0,0) on rgb(178,40,192)"
    color_closing = "rgb(0,100,100) on rgb(227,125,48)"

    if st.url is None:
        status_local.stylize(color_nothing)
        status_remote.stylize(color_nothing)
        message_text.append("connecting...")
    else:
        message_text.append(st.url)
        message_text.stylize("green")
        message_text.append(f"\nwelcome={st.welcome}\n")
        status_local.plain = chicken.default[1]
        status_local.stylize(color_no_peer)

    if st.code is not None:
        # only display code until we're connected
        if st.verifier is None:
            message_text.append(Text(f"code: {st.code} ", "bold"))

    if st.verifier is not None:
        nice_verifier = " ".join(
            st.verifier[a:a+4]
            for a in range(0, len(st.verifier), 4)
        )
        message_text.append(nice_verifier)
        status_local.plain = chicken.default[2]
        status_local.stylize(color_connect)
        status_remote.plain = chicken.peer[2]
        status_remote.stylize(color_connect)

    if st.is_connecting:
        status_local.stylize(color_connecting)

    if not st.peer_connected:
        # can/should we tell diff between "never connected" and
        # "reconnecting"?
        status_remote.stylize(color_connecting)
        t.add_row(Text("hints"), Text("\n".join(st.hints)), None)
    else:
        t.add_row(Text("hint"), Text("🐥 {}".format(st.peer_connected)), None)

    # turn purple if we / they are closing
    if st.peer_closing:
        status_remote.stylize(color_closing)
    if st.we_closing:
        status_local.stylize(color_closing)

    if random.choice("abcdefgh") == "a":
        status_local.plain = random.choice(chicken.default)

    for id_, data in st.listeners.items():
        t.add_row(
            Text("{} {}".format('🧙' if data.remote else ' ', data.local_port)),
            Text("{} {}".format("-->" if data.remote else "<--", data.service_name)),
            Text("{}".format(' ' if data.remote else '🧙'), justify="center"),
        )

    for id_, data in st.subchannels.items():
        if data.done_at is not None:
            if time_now - data.done_at > 10.0:
                # skip an ended Subchannel some time after it's finished
                continue
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
        bw = render_bw(data, time_now)
        if data.done_at is not None:
            from rich.style import Style
            if 0:
                # so, it would be cool to "fade out" the old streams,
                # but figuring out the background colour is like "a
                # whole blog post" (and rich doesn't support it)
                # .. leaving here for future-me
                # (move me to a function if this is good)
                # fade from "999999" towards "222222" based on 10s timeout
                elapsed = time_now - data.done_at
                if elapsed > 10.0: elapsed = 10.0
                diff = elapsed / 10.0  # normalize to [0, 1)
                # at "10.0" we want to equal 222222
                color_diff = 0xaa - 0x22
                color = 0x22 + int(diff * color_diff)
                s = Style(color=f"#{color:02x}{color:02x}{color:02x}", dim=True, bgcolor=None)
            else:
                s = Style(color=f"#676767", dim=True, bgcolor=None)
            local = Text("", s)
            remote = Text("✓", s, justify="center")
            bw.stylize(s)
        t.add_row(local, bw, remote)

    return top


interval = 0.25


def render_bw(sub, start):
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
    rendered.append_text(Text("\n" + render_bw_out(sub, start), style="yellow"))
    return rendered


def render_bw_out(sub, start):
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
