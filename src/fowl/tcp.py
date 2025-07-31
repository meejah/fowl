import sys
import socket
from twisted.python.runtime import platformType


def allocate_tcp_port():
    """
    Return an (integer) available TCP port on localhost. This briefly
    listens on the port in question, then closes it right away.
    """
    # originally from "foolscap"

    # Making this work correctly on multiple OSes is non-trivial:
    # * on OS-X:
    #   * Binding the test socket to 127.0.0.1 lets the kernel give us a
    #     LISTEN port that some other process is using, if they bound it to
    #     ANY (0.0.0.0). These will fail when we attempt to
    #     listen(bind=0.0.0.0) ourselves
    #   * Binding the test socket to 0.0.0.0 lets the kernel give us LISTEN
    #     ports bound to 127.0.0.1, although then our subsequent listen()
    #     call usually succeeds.
    #   * In both cases, the kernel can give us a port that's in use by the
    #     near side of an ESTABLISHED socket. If the process which owns that
    #     socket is not owned by the same user as us, listen() will fail.
    #   * Doing a listen() right away (on the kernel-allocated socket)
    #     succeeds, but a subsequent listen() on a new socket (bound to
    #     the same port) will fail.
    # * on Linux:
    #   * The kernel never gives us a port in use by a LISTEN socket, whether
    #     we bind the test socket to 127.0.0.1 or 0.0.0.0
    #   * Binding it to 127.0.0.1 does let the kernel give us ports used in
    #     an ESTABLISHED connection. Our listen() will fail regardless of who
    #     owns that socket. (note that we are using SO_REUSEADDR but not
    #     SO_REUSEPORT, which would probably affect things).
    #
    # So to make this work properly everywhere, allocate_tcp_port() needs two
    # phases: first we allocate a port (with 0.0.0.0), then we close that
    # socket, then we open a second socket, bind the second socket to the
    # same port, then try to listen. If the listen() fails, we loop back and
    # try again.
    #
    # In addition, on at least OS-X, the kernel will give us a port that's in
    # use by some other process, when that process has bound it to 127.0.0.1,
    # and our bind/listen (to 0.0.0.0) will succeed, but a subsequent caller
    # who tries to bind it to 127.0.0.1 will get an error in listen(). So we
    # must actually test the proposed socket twice: once bound to 0.0.0.0,
    # and again bound to 127.0.0.1. This probably isn't complete for
    # applications which bind to a specific outward-facing interface, but I'm
    # ok with that; anything other than 0.0.0.0 or 127.0.0.1 is likely to use
    # manually-selected ports, assigned by the user or sysadmin.
    #
    # Ideally we'd refrain from doing listen(), to minimize impact on the
    # system, and we'd bind the port to 127.0.0.1, to avoid making it look
    # like we're accepting data from the outside world (in situations where
    # we're going to end up binding the port to 127.0.0.1 anyways). But for
    # the above reasons, neither would work. We *do* add SO_REUSEADDR, to
    # make sure our lingering socket won't prevent our caller from opening it
    # themselves in a few moments (note that Twisted's
    # tcp.Port.createInternetSocket sets SO_REUSEADDR, among other flags).

    count = 0
    while True:
        s = _make_socket()
        s.bind(("0.0.0.0", 0))
        port = s.getsockname()[1]
        s.close()

        s = _make_socket()
        try:
            s.bind(("0.0.0.0", port))
            s.listen(5) # this is what sometimes fails
            s.close()
            s = _make_socket()
            s.bind(("127.0.0.1", port))
            s.listen(5)
            s.close()
            return port
        except socket.error:
            s.close()
            count += 1
            if count > 100:
                raise
            # try again


def _make_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if platformType == "posix" and sys.platform != "cygwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s

