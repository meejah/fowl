import pytest
import ipaddress
import json
from io import StringIO

import attrs
from hypothesis.strategies import ip_addresses, one_of, integers, lists, sampled_from, just, builds
from hypothesis import given, assume, reproduce_failure, settings

from twisted.internet.endpoints import TCP4ServerEndpoint, TCP6ServerEndpoint

from fowl._proto import parse_fowld_command, _Config, fowld_command_to_json
from fowl.messages import GrantPermission


@pytest.fixture()
def config():
    def create_stdin(proto, reactor=None):
        cfg._fake_stdin = FakeStandardIO(proto, reactor, messages=[])
        return cfg._fake_stdin
    cfg = _Config(
        relay_url="invalid",
        use_tor=False,
        create_stdio=create_stdin,
        stdout=StringIO(),
    )
    return cfg


def ports():
    return integers(min_value=1, max_value=65535)


def port_lists():
    return lists(ports())


@given(
    port_lists(),
    port_lists(),
)
def test_roundtrip_grant_permission(listen, connect):
    from fowl.messages import GrantPermission
    og_cmd = GrantPermission(
        listen=listen,
        connect=connect,
    )
    parsed_cmd = parse_fowld_command(json.dumps(fowld_command_to_json(og_cmd)))
    assert parsed_cmd == og_cmd, "Command mismatch"


all_commands = {
    GrantPermission: {
        "listen": port_lists(),
        "connect": port_lists(),
    },
}


def commands():
    return one_of([
        builds(k, **kwargs)
        for k, kwargs in all_commands.items()
    ])



@given(commands())
def test_roundtrip(og_cmd):
    parsed_cmd = parse_fowld_command(json.dumps(fowld_command_to_json(og_cmd)))
    assert parsed_cmd == og_cmd, "Command mismatch"



def ___test_command_serialize(config):
    print(config)
    cmd = parse_fowld_command(json.dumps({
        "kind": "grant-permission",
        "listen": [1234],
        "connect": [4321],
    }))
    print(cmd)
