import json
from io import StringIO

from hypothesis.strategies import one_of, integers, lists, sampled_from, builds, text, just
from hypothesis import given


from fowl._proto import _TimestampedWriter, parse_fowld_command, fowld_command_to_json


def command_messages():
    from fowl import messages
    return [
        (cls, command_class_to_arg_generators(cls))
        for cls in [getattr(messages, nm) for nm in dir(messages)]
        if type(cls) is type and issubclass(cls, messages.FowlCommandMessage) and cls !=  messages.FowlCommandMessage
    ]


def command_class_to_arg_generators(cls):
    from fowl import messages
    return {
        messages.AllocateCode: {
            "length": integers(min_value=1, max_value=32),
        },
        messages.SetCode: {
            "code": text(),
        },
        messages.BytesIn: {
            "id": integers(),
            "bytes": integers(min_value=1),
        },
        messages.BytesOut: {
            "id": integers(),
            "bytes": integers(min_value=1),
        },
        messages.LocalListener: {
            "name": text(min_size=1),
            "local_listen_port": one_of([just(None), integers(min_value=1, max_value=65535)]),
            "remote_connect_port": one_of([just(None), integers(min_value=1, max_value=65535)]),
#            "bind_interface": ip_addresses(v=4),
        },
        messages.RemoteListener: {
            "name": text(min_size=1),
            "remote_listen_port": one_of([just(None), integers(min_value=1, max_value=65535)]),
            "local_connect_port": one_of([just(None), integers(min_value=1, max_value=65535)]),
#            "connect_address": ip_addresses(v=4),
        },
        messages.SessionClose: {
            "timeout": integers(min_value=1, max_value=30),
        },
        messages.Ping: {
            "ping_id": text(),  # should really be "base16-encoded 4-bytes of binary"
        },
    }[cls]


def ports():
    return integers(min_value=1, max_value=65535)


def port_lists():
    return lists(ports())


def local_server_endpoints():
    return sampled_from([
        "tcp:1234:interface=localhost",
    ])


def local_client_endpoints():
    return sampled_from([
        "tcp:localhost:1234",
    ])


all_commands = {
    k: kwargs
    for k, kwargs in command_messages()
}


def commands():
    return one_of([
        builds(k, **kwargs)
        for k, kwargs in all_commands.items()
    ])



@given(commands())
def test_roundtrip(og_cmd):
    """
    Let Hypothesis play with a bunch of round-trip tests for command
    serialization
    """
    parsed_cmd = parse_fowld_command(json.dumps(fowld_command_to_json(og_cmd)))
    assert parsed_cmd == og_cmd, "Command mismatch"


def test_timestamped_writer_prefixes_each_line():
    class Reactor:
        now = 123.0

        def seconds(self):
            return self.now

    reactor = Reactor()
    stream = StringIO()
    writer = _TimestampedWriter(reactor, stream, start_time=123.0)

    writer.write("first\nsecond")
    reactor.now = 124.25
    writer.write(" continued\n")
    writer.write("third\n")

    assert stream.getvalue() == (
        "0.000 first\n"
        "0.000 second continued\n"
        "1.250 third\n"
    )
