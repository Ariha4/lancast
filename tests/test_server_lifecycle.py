"""FileReceiverServer start/stop behaviour and resilience of its accept loop."""

import errno
import socket
import threading
from pathlib import Path

from lancast import transfer
from lancast.transfer import FileReceiverServer, send_file_to_peer


def _trust_each_other(first, second) -> None:
    first.trust_store.trust(second.cert_pem, name=second.home.name)
    second.trust_store.trust(first.cert_pem, name=first.home.name)


def _start(server: FileReceiverServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.ready.wait(timeout=2)
    return thread


def test_stop_unblocks_serve_forever_and_frees_the_port(tmp_path: Path, make_device) -> None:
    """Before: stop() only closed the listening socket. On Linux that doesn't
    wake a thread blocked in accept(), so serve_forever kept running and the
    port stayed bound until some client happened to connect."""
    device = make_device("receiver")
    server = FileReceiverServer(tmp_path / "in", device.identity, device.trust_store, port=0, bind_host="127.0.0.1")
    thread = _start(server)

    server.stop()
    thread.join(timeout=2)

    assert not thread.is_alive(), "serve_forever is still blocked in accept()"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", server.port))  # raises if the old listener is still there
        probe.listen(1)


def test_stop_before_start_makes_serve_forever_return(tmp_path: Path, make_device) -> None:
    device = make_device("receiver")
    server = FileReceiverServer(tmp_path / "in", device.identity, device.trust_store, port=0, bind_host="127.0.0.1")
    server.stop()

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    thread.join(timeout=2)

    assert not thread.is_alive()


class _ListenerThatFailsOnce(socket.socket):
    """A listening socket whose first accept() fails the way Linux reports a
    client that reset the connection before we got to it."""

    failures_left = 1

    def accept(self):
        if _ListenerThatFailsOnce.failures_left:
            _ListenerThatFailsOnce.failures_left -= 1
            raise OSError(errno.ECONNABORTED, "Software caused connection abort")
        return super().accept()


def test_transient_accept_error_does_not_stop_the_server(tmp_path: Path, make_device, monkeypatch) -> None:
    """Before: any OSError from accept() broke out of the loop, so one client
    aborting its connection at the wrong moment shut the receiver down."""
    receiver = make_device("receiver")
    sender = make_device("sender")
    _trust_each_other(receiver, sender)
    received = []
    server = FileReceiverServer(
        tmp_path / "in",
        receiver.identity,
        receiver.trust_store,
        port=0,
        bind_host="127.0.0.1",
        on_received=lambda path, addr, peer: received.append(path),
    )

    with monkeypatch.context() as patch:
        # Only the server's listening socket is created while this is active.
        patch.setattr(transfer.socket, "socket", _ListenerThatFailsOnce)
        thread = _start(server)

    try:
        source = tmp_path / "after-error.txt"
        source.write_text("still here")
        send_file_to_peer("127.0.0.1", server.port, source, sender.identity, sender.trust_store, timeout=3)

        assert _ListenerThatFailsOnce.failures_left == 0, "the injected accept() failure never happened"
        assert thread.is_alive()
        assert (tmp_path / "in" / "after-error.txt").read_text() == "still here"
    finally:
        server.stop()
        thread.join(timeout=2)
