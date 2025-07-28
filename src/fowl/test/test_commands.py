import json

from hypothesis.strategies import one_of, integers, lists, sampled_from, builds, text, just
from hypothesis import given


from fowl._proto import parse_fowld_command, fowld_command_to_json


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
        messages.DangerDisablePermissionCheck: {
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
        messages.GrantPermission: {
            "listen": port_lists(),
            "connect": port_lists(),
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
