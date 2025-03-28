diff --git a/NEWS.rst b/NEWS.rst
index 3db334e..037a153 100644
--- a/NEWS.rst
+++ b/NEWS.rst
@@ -12,6 +12,10 @@ Unreleased
 ----------
 
 * (Put new changelog items here)
+* Allow for non-local addresses: for both listening interfaces and
+  connect endpoints, non-local addresses may be specified in a manner
+  similar to "ssh -L" or "ssh -R" arguments. See #37:
+  https://github.com/meejah/fowl/issues/37
 * Fix up some fallout from refactoring
 * Enable "remote" command in --interactive
 * Proper error-message rendering
diff --git a/src/fowl/cli.py b/src/fowl/cli.py
index 5f80074..19f9c13 100644
--- a/src/fowl/cli.py
+++ b/src/fowl/cli.py
@@ -20,7 +20,13 @@ from .messages import (
     LocalListener,
     RemoteListener,
 )
-from .policy import LocalhostTcpPortsListenPolicy, LocalhostTcpPortsConnectPolicy
+from .policy import (
+    LocalhostTcpPortsListenPolicy,
+    LocalhostTcpPortsConnectPolicy,
+    ArbitraryAddressTcpConnectPolicy,
+    ArbitraryInterfaceTcpPortsListenPolicy,
+    is_localhost,
+)
 
 
 @click.option(
@@ -88,26 +94,41 @@ def fowld(ctx, ip_privacy, mailbox, debug):
 @click.option(
     "--local", "-L",
     multiple=True,
-    help="Listen locally, connect remotely (accepted multiple times)",
-    metavar="listen-port[:connect-port]",
+    help=(
+        "Listen locally, connect remotely (accepted multiple times)."
+        "Unless otherwise specified, (local) bind and (remote) connect addresses are localhost."
+        'For example "127.0.0.1:1234:127.0.0.1:22" is the same as "1234:22" effectively.'
+    ),
+    metavar="[bind-address:]listen-port[:remote-address][:connect-port]",
 )
 @click.option(
     "--remote", "-R",
     multiple=True,
-    help="Listen remotely, connect locally (accepted multiple times)",
-    metavar="listen-port[:connect-port]",
+    help=(
+        "Listen remotely, connect locally (accepted multiple times)"
+        "Unless otherwise specified, the (remote) bind and (local) connect addresses are localhost."
+        'For example "127.0.0.1:1234:127.0.0.1:22" is the same as "1234:22" effectively.'
+        ),
+    metavar="[remote-bind-address:]listen-port[:local-connect-address][:local-connect-port]",
 )
 @click.option(
     "--allow-listen",
     multiple=True,
-    help="Accept a connection to this local port. Accepted multiple times. Note that local listeners added via --local are already allowed and do not need this option.",
-    metavar="listen-port",
+    help=(
+        "Accept a connection to this local port. Accepted multiple times."
+        "Note that local listeners added via --local are already allowed and do not need this option."
+        'If no interface is specified, "localhost" is assumed.'
+    ),
+    metavar="[interface:]listen-port",
 )
 @click.option(
     "--allow-connect",
     multiple=True,
-    help="Accept a connection to this local port. Accepted multiple times",
-    metavar="connect-port",
+    help=(
+        "Accept a connection to this local port. Accepted multiple times"
+        'If no address is specified, "localhost" is assumed.'
+    ),
+    metavar="[address:]connect-port",
 )
 @click.option(
     "--code-length",
@@ -144,38 +165,78 @@ def fowl(ip_privacy, mailbox, debug, allow_listen, allow_connect, local, remote,
         display_readme()
         return
 
-    def to_command(cls, cmd):
-        if ':' in cmd:
-            listen, connect = cmd.split(':')
-        else:
-            listen = connect = cmd
-        # XXX ipv6?
-        return cls(
-            f"tcp:{listen}:interface=localhost",
-            f"tcp:localhost:{connect}",
+    local_commands = [
+        _specifier_to_tuples(cmd)
+        for cmd in local
+    ]
+    remote_commands = [
+        _specifier_to_tuples(cmd)
+        for cmd in remote
+    ]
+
+    def to_local(local_interface, local_port, remote_address, remote_port):
+        return LocalListener(
+            f"tcp:{local_port}:interface={local_interface}",
+            f"tcp:{remote_address}:{remote_port}",
         )
 
-    def to_listener(cmd):
-        if ':' in cmd:
-            listen, _ = cmd.split(':')
-        else:
-            listen = cmd
-        return int(listen)
-
-    def to_connecter(cmd):
-        if ':' in cmd:
-            _, conn = cmd.split(':')
-        else:
-            conn = cmd
-        return int(conn)
-
-    def to_local_port(arg):
-        arg = int(arg)
-        if arg < 1 or arg >= 65536:
-            raise click.UsageError(
-                "Listen ports must be an integer from 1 to 65535"
-            )
-        return arg
+    def to_remote(local_interface, local_port, remote_address, remote_port):
+        return RemoteListener(
+            f"tcp:{local_port}:interface={local_interface}",
+            f"tcp:{remote_address}:{remote_port}",
+        )
+
+    def to_listen_policy(local_interface, local_port, remote_address, remote_port):
+        return local_port
+
+    def to_connect_policy(local_interface, local_port, remote_address, remote_port):
+        return remote_port
+
+    def to_iface_port(allowed):
+        if ':' in allowed:
+            iface, port = allowed.split(':', 1)
+            return iface, _to_port(port)
+        return "localhost", _to_port(allowed)
+
+    def to_local_port(allowed):
+        if ':' in allowed:
+            iface, port = allowed.split(':', 1)
+            if iface != "localhost":
+                raise ValueError(f"Non-local interface: {iface}")
+            return _to_port(port)
+        return _to_port(allowed)
+
+    def is_local(local_interface, local_port, remote_address, remote_port):
+        return is_localhost(local_interface)
+
+    def is_local_connect(local_interface, local_port, remote_address, remote_port):
+        return is_localhost(remote_address)
+
+    if any(not is_local(*cmd) for cmd in local_commands) or \
+       any(not is_localhost(to_iface_port(allowed)[0]) for allowed in allow_listen):
+        listen_policy = ArbitraryInterfaceTcpPortsListenPolicy(
+            [(iface, port) for iface, port, _, _ in local_commands] + \
+            [to_iface_port(allowed) for allowed in allow_listen]
+        )
+    else:
+        listen_policy = LocalhostTcpPortsListenPolicy(
+            [to_listen_policy(*cmd) for cmd in local_commands] +
+            [to_local_port(port) for port in allow_listen]
+        )
+
+    if any(not is_local_connect(*cmd) for cmd in remote_commands) or \
+       any(not is_localhost(to_iface_port(allowed)[0]) for allowed in allow_connect):
+        # yes, this says "to_iface_port()" below but they both look
+        # the same currently: "192.168.1.2:4321" for example
+        connect_policy = ArbitraryAddressTcpConnectPolicy(
+            [(addr, port) for _, _, addr, port in remote_commands] + \
+            [to_iface_port(allowed) for allowed in allow_connect]
+        )
+    else:
+        connect_policy = LocalhostTcpPortsConnectPolicy(
+            [to_connect_policy(*cmd) for cmd in remote_commands] +
+            [to_local_port(port) for port in allow_connect]
+        )
 
     cfg = _Config(
         relay_url=WELL_KNOWN_MAILBOXES.get(mailbox, mailbox),
@@ -184,20 +245,14 @@ def fowl(ip_privacy, mailbox, debug, allow_listen, allow_connect, local, remote,
         code=code,
         code_length=code_length,
         commands=[
-            to_command(LocalListener, cmd)
-            for cmd in local
+            to_local(*t)
+            for t in local_commands
         ] + [
-            to_command(RemoteListener, cmd)
-            for cmd in remote
+            to_remote(*t)
+            for t in remote_commands
         ],
-        listen_policy = LocalhostTcpPortsListenPolicy(
-            [to_listener(cmd) for cmd in local] +
-            [to_local_port(port) for port in allow_listen]
-        ),
-        connect_policy = LocalhostTcpPortsConnectPolicy(
-            [int(conn) for conn in allow_connect] +
-            [to_connecter(cmd) for cmd in remote]
-        ),
+        listen_policy=listen_policy,
+        connect_policy=connect_policy,
     )
 
     if interactive:
@@ -208,6 +263,90 @@ def fowl(ip_privacy, mailbox, debug, allow_listen, allow_connect, local, remote,
     return react(run)
 
 
+def _to_port(arg):
+    arg = int(arg)
+    if arg < 1 or arg >= 65536:
+        raise click.UsageError(
+            "Ports must be an integer from 1 to 65535"
+        )
+    return arg
+
+
+# XXX FIXME use an @frozen attr, not tuple for returns
+def _specifier_to_tuples(cmd):
+    """
+    Parse a local or remote listen/connect specifiers.
+
+    This always returns a 4-tuple of:
+      - listen interface
+      - listen port
+      - connect address
+      - connect port
+
+    TODO: tests, and IPv6
+    """
+    if '[' in cmd or ']' in cmd:
+        raise RuntimeError("Have not considered IPv6 parsing yet")
+
+    colons = cmd.count(':')
+    if colons > 3:
+        raise ValueError(
+            f"Too many colons: {colons} > 3"
+        )
+    if colons == 3:
+        # everything is specified
+        listen_interface, listen_port, connect_address, connect_port = cmd.split(':')
+        listen_port = _to_port(listen_port)
+        connect_port = _to_port(connect_port)
+    elif colons == 2:
+        # one of the interface / address is specified, but we're not
+        # sure which yet
+        a, b, c = cmd.split(':')
+        try:
+            # maybe the first thing is a port
+            listen_port = _to_port(a)
+            listen_interface = "localhost"
+            connect_address = b
+            connect_port = _to_port(c)
+        except ValueError:
+            # no, the first thing is a string, so the connect address
+            # must be missing
+            listen_interface = a
+            listen_port = _to_port(b)
+            connect_address = "localhost"
+            connect_port = _to_port(c)
+    elif colons == 1:
+        # we only have one split. this could be "interface:port" or "port:port"
+        a, b = cmd.split(':')
+        try:
+            listen_port = _to_port(a)
+            listen_interface = "localhost"
+            try:
+                # the second thing could be a connect address or a
+                # port
+                connect_port = _to_port(b)
+                connect_address = "localhost"
+            except ValueError:
+                connect_address = b
+                connect_port = listen_port
+        except ValueError:
+            # okay, first thing isn't a port so it's the listen interface
+            listen_interface = a
+            listen_port = connect_port = _to_port(b)
+            connect_address = "localhost"
+    else:
+        # no colons, it's a port and we're "symmetric"
+        listen_port = connect_port = _to_port(cmd)
+        listen_interface = "localhost"
+        connect_address = "localhost"
+
+    # XXX ipv6?
+    return (
+        listen_interface, listen_port,
+        connect_address, connect_port,
+    )
+
+
 def tui(cfg):
     """
     Run an interactive text user-interface (TUI)
diff --git a/src/fowl/policy.py b/src/fowl/policy.py
index 1815b21..cbf758c 100644
--- a/src/fowl/policy.py
+++ b/src/fowl/policy.py
@@ -72,6 +72,23 @@ class LocalhostTcpPortsListenPolicy(LocalhostAnyPortsListenPolicy):
         return False
 
 
+@implementer(IClientListenPolicy)
+@frozen
+class ArbitraryInterfaceTcpPortsListenPolicy:
+    # interface, port pairs we accept
+    listeners: list[tuple]
+
+    def can_listen(self, endpoint) -> bool:
+        if isinstance(endpoint, (TCP6ServerEndpoint, TCP4ServerEndpoint)):
+            iface = endpoint._interface
+            port = endpoint._port
+            for allowed_iface, allowed_port in self.listeners:
+                if iface == allowed_iface:
+                    if port == allowed_port:
+                        return True
+        return False
+
+
 @implementer(IClientListenPolicy)
 class AnyListenPolicy:
     """
@@ -93,6 +110,22 @@ class LocalhostAnyPortsConnectPolicy:
         return False
 
 
+@implementer(IClientListenPolicy)
+@frozen
+class ArbitraryAddressTcpConnectPolicy:
+    # interface, port pairs we accept
+    connecters: list[tuple]
+
+    def can_connect(self, endpoint) -> bool:
+        if isinstance(endpoint, (TCP6ClientEndpoint, TCP4ClientEndpoint)):
+            addr, port = endpoint._host, endpoint._port
+            for allowed_addr, allowed_port in self.connecters:
+                if addr == allowed_addr:
+                    if port == allowed_port:
+                        return True
+        return False
+
+
 @implementer(IClientConnectPolicy)
 class AnyConnectPolicy:
     """
diff --git a/src/fowl/test/test_cli.py b/src/fowl/test/test_cli.py
index f9000bf..504c1ad 100644
--- a/src/fowl/test/test_cli.py
+++ b/src/fowl/test/test_cli.py
@@ -112,7 +112,7 @@ async def test_happy_path(reactor, request, mailbox):
     # listener) and connect on 2222 (where this test is listening)
 
     listener = ServerFactory(reactor)
-    await serverFromString(reactor, "tcp:2121").listen(listener)  # returns server_port
+    await serverFromString(reactor, "tcp:2121:interface=localhost").listen(listener)  # returns server_port
 
     client = clientFromString(reactor, "tcp:localhost:2222")
     client_proto = await client.connect(ClientFactory(reactor))
