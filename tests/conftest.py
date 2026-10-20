import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from lancast.identity import Identity, load_or_create_identity
from lancast.transfer import FileReceiverServer
from lancast.trust import TrustStore


@dataclass
class Device:
    """One simulated machine: its own home dir, identity, and trust store."""

    home: Path
    identity: Identity
    trust_store: TrustStore

    @property
    def cert_pem(self) -> str:
        return self.identity.cert_path.read_text()


@pytest.fixture
def make_device(tmp_path: Path):
    def _make(name: str) -> Device:
        home = tmp_path / name
        identity = load_or_create_identity(home, name)
        return Device(home=home, identity=identity, trust_store=TrustStore(home))

    return _make


@pytest.fixture
def running_server(tmp_path: Path):
    """Start a FileReceiverServer for a device on a random port; stop it after the test."""
    started_servers = []

    def _start(device: Device, **server_options) -> FileReceiverServer:
        received = []
        rejected = []
        server = FileReceiverServer(
            dest_dir=tmp_path / "received",
            identity=device.identity,
            trust_store=device.trust_store,
            port=0,
            bind_host="127.0.0.1",
            on_received=lambda path, addr, sender: received.append((path, sender)),
            on_rejected=lambda addr, error: rejected.append(error),
            **server_options,
        )
        server.received = received
        server.rejected = rejected

        def wait_for_received(count: int, timeout: float = 2.0) -> list:
            # The sender gets its final status as soon as the file is on disk,
            # slightly before the server thread runs on_received.
            deadline = time.time() + timeout
            while len(received) < count and time.time() < deadline:
                time.sleep(0.01)
            return received

        server.wait_for_received = wait_for_received
        threading.Thread(target=server.serve_forever, daemon=True).start()
        assert server.ready.wait(timeout=2)
        started_servers.append(server)
        return server

    yield _start
    for server in started_servers:
        server.stop()
