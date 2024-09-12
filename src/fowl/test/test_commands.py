import pytest
import ipaddress
import json
from io import StringIO

import attrs
from hypothesis.strategies import ip_addresses, one_of, integers, lists, sampled_from, just, builds, text
from hypothesis import given, assume, reproduce_failure, settings

from twisted.internet.endpoints import TCP4ServerEndpoint, TCP6ServerEndpoint

from fowl._proto import parse_fowld_command, _Config, fowld_command_to_json


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
            "listen": local_server_endpoints(),
            "connect": local_client_endpoints(),
        },
        messages.RemoteListener: {
            "listen": local_server_endpoints(),
            "connect": local_client_endpoints(),
        },
        messages.GrantPermission: {
            "listen": port_lists(),
            "connect": port_lists(),
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
