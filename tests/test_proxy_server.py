"""Integration tests for the pin proxy's actual MITM + swap + relay path.

A fake upstream HTTPS server stands in for api.anthropic.com. The proxy MITMs
it, and we assert the Authorization it forwards: swapped on pinned routes,
original on everything else.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import types
import pathlib
import re
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import pytest

from cswap_pin.proxy import ensure_ca

from conftest import PIN_STAMP, run_cases


@pytest.fixture(autouse=True)
def _stdlib_ssl():
    """cli.main() tests inject truststore into global ssl (OS-native verify),
    which rejects our ad-hoc test CA. Undo it for real-handshake tests here."""
    try:
        import truststore
        truststore.extract_from_ssl()
    except ImportError:
        pass
    yield


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeUpstream:
    """A minimal TLS server that records the Authorization header it received
    and replies 200. Uses the same leaf cert the proxy MITMs with, so the
    proxy's own upstream TLS (servername api.anthropic.com) validates it."""

    def __init__(self, certdir: Path,
                 reject_bearer: "str | set[str] | None" = None,
                 reject_status: int = 403, reply: bytes | None = None,
                 reject_missing_auth: bool = False,
                 extra_headers: bytes = b""):
        # reject_bearer: answer `reject_status` to exactly this credential
        # (or any credential in the set), 200 to any other. Models an
        # endpoint the pinned account may not use — the shape that makes a
        # misrouted swap terminal for the client.
        # reject_missing_auth: also answer `reject_status` to a request
        # carrying NO Authorization header at all -- a pinned route the
        # client reached with nothing to swap.
        # reply: the whole response to send instead of the 200, for a case
        # that needs the origin to answer something the pin then rewrites.
        self._reject = ({reject_bearer} if isinstance(reject_bearer, str)
                         else set(reject_bearer or ()))
        self._reject_missing_auth = reject_missing_auth
        self.reject_status = reject_status
        self.reply = reply
        # Raw `Name: value\r\n` lines added to every 200 reply.
        self.extra_headers = extra_headers
        self.seen_auth: str | None = None
        # Every Authorization this server has seen, in order — a single
        # request-response case reconnects per attempt (`Connection: close`
        # below), so `seen_auth` alone loses everything but the last one.
        self.auths_seen: list[str] = []
        self.seen_path: str | None = None
        self.seen_body: bytes = b""
        self.seen_head: str = ""
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            try:
                tls = self._ctx.wrap_socket(conn, server_side=True)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                head = head.decode("latin1")
                # Read the full body before replying — closing early races the
                # proxy's body send into an RST (a real server reads it all).
                m = [l for l in head.lower().split("\r\n") if l.startswith("content-length:")]
                want = int(m[0].split(":")[1]) if m else 0
                while len(rest) < want:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
                self.seen_body = bytes(rest)
                self.seen_head = head
                lines = head.split("\r\n")
                self.seen_path = lines[0].split(" ")[1]
                for line in lines[1:]:
                    if line.lower().startswith("authorization:"):
                        self.seen_auth = line.split(":", 1)[1].strip()
                self.auths_seen.append(self.seen_auth)
                if (self.seen_auth in {f"Bearer {b}" for b in self._reject}
                        or (self.seen_auth is None
                            and self._reject_missing_auth)):
                    tls.sendall(
                        f"HTTP/1.1 {self.reject_status} Rejected\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n"
                        .encode("latin1")
                    )
                    tls.close()
                    continue
                tls.sendall(self.reply or (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    + self.extra_headers +
                    b"Content-Type: application/json\r\n\r\n{}"
                ))
                tls.close()
            except Exception:
                pass

    def stop(self):
        self._stop = True
        # WAKE IT, THEN JOIN. Closing a listening socket does NOT interrupt
        # another thread blocked in `accept()`, so a plain join here pays its
        # full timeout and the thread is still alive when the case ends. One
        # loopback connect makes `accept()` return at once — the same trick
        # `release_listener` uses in production, and for the same reason.
        try:
            with socket.create_connection(self._srv.getsockname(),
                                          timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class _RecordingChain:
    """A plain-HTTP chain hop that records each request and answers a canned
    reply. `answer(request_bytes) -> response_bytes` decides what to send.

    READS THE BODY BEFORE ANSWERING, because a hop that replies on the headers
    alone cannot show a request whose body was never forwarded — the shape that
    deadlocked every swapped POST for a release.

    Teardown wakes the accept thread before joining: closing a listening socket
    does NOT interrupt another thread blocked in `accept()`, which is the same
    reason `_ProbeChain.stop` does it.
    """

    def __init__(self, answer):
        self.answer, self.seen, self._stop = answer, [], False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            if self._stop:
                c.close()
                return
            try:
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 65536:
                    d = c.recv(1)
                    if not d:
                        break
                    buf += d
                want = 0
                for ln in buf.split(b"\r\n"):
                    if ln.lower().startswith(b"content-length:"):
                        want = int(ln.split(b":", 1)[1])
                while len(buf.split(b"\r\n\r\n", 1)[-1]) < want:
                    d = c.recv(65536)
                    if not d:
                        break
                    buf += d
                self.seen.append(buf)
                c.sendall(self.answer(buf))
            except OSError:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass

    def stop(self):
        self._stop = True
        try:
            with socket.create_connection(self._srv.getsockname(), timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


def _request_through_proxy(proxy_port: int, ca_path: Path, path: str,
                           bearer: "str | None" = None,
                           ua: str | None = None, body: str = "{}",
                           extra_headers: "dict[str, str] | None" = None,
                           method: str = "POST"):
    """Make an HTTPS request to api.anthropic.com<path> via the proxy (CONNECT),
    trusting the proxy's CA. Returns the response status.

    `bearer=None` sends no `Authorization` header at all -- a client that
    never had one, not one that was cleared. `extra_headers` merges in
    anything else the case needs on the wire, e.g. `x-claude-code-session-id`."""
    ctx = ssl.create_default_context(cafile=str(ca_path))
    conn = http.client.HTTPSConnection(
        "api.anthropic.com", context=ctx, timeout=10
    )
    conn.set_tunnel("api.anthropic.com", 443)
    # Point the socket at the proxy instead of resolving api.anthropic.com.
    conn._create_connection = lambda *a, **k: socket.create_connection(
        ("127.0.0.1", proxy_port), timeout=10
    )
    headers = {} if bearer is None else {"Authorization": f"Bearer {bearer}"}
    if ua is not None:
        headers["User-Agent"] = ua
    if extra_headers:
        headers.update(extra_headers)
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


def _refetch_switcher(certdir, token_for_read):
    """A switcher for `make_pin_token_provider`, shared by every T1155
    pass 3 refetch-through-the-real-provider case below (they otherwise
    repeat this same shape). `token_for_read(n)` returns the accessToken
    for the n-th (1-based) `read_account_credentials` call: "" for an
    empty read, or it may raise to model a locked store."""
    import json as _json

    class _Switcher:
        backup_dir = certdir

        def __init__(self):
            self.reads = 0

        def current_account_number(self):
            return "1"

        def read_account_credentials(self, n, e):
            self.reads += 1
            token = token_for_read(self.reads)
            if not token:
                return ""
            return _json.dumps({"claudeAiOauth": {
                "accessToken": token, "expiresAt": 4102444800000,
                "refreshToken": "rt"}})

        def resolve_account(self, i):
            return ("2", "pin@example.com", "org")

    return _Switcher()


def _post_and_abandon(proxy_port: int, ca_path: Path, path: str, body: str):
    """Send one POST through the proxy's CONNECT tunnel and close WITHOUT
    reading a response -- the client that aborts its own socket, which is
    what T0955 is about: a request held on the pin whose sender is already
    gone by the time the hold ends."""
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    raw.sendall(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = raw.recv(4096)
        if not chunk:
            break
        buf += chunk
    ctx = ssl.create_default_context(cafile=str(ca_path))
    tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
    body_b = body.encode()
    req = (f"POST {path} HTTP/1.1\r\nHost: api.anthropic.com\r\n"
          f"Authorization: Bearer t\r\nContent-Length: {len(body_b)}\r\n\r\n"
          ).encode() + body_b
    tls.sendall(req)
    tls.close()


_CA_CACHE: list = []




def _make_certdir(tmp_path):
    """A cert dir with a CA already in it.

    COPIED from one session-wide CA rather than generated. `ensure_ca` mints
    two RSA-2048 keys (~70 ms) and this runs for most of the file, so
    generating per case was the single largest cost in the suite. Nothing
    here asserts on a key's VALUE — the tests need a CA that signs its leaf,
    which a copy is.
    """
    import shutil

    from cswap_pin.proxy import ensure_ca

    if not _CA_CACHE:
        # NOTHING FAILS FROM A LEAK HERE, which is why the old one survived:
        # `mkdtemp` is reached once per PROCESS and xdist gives every worker
        # its own, so a loop of runs piles them up and no test asserts on
        # /tmp. Counted 1,619 in one hour of repeated runs when it was found,
        # and 1,627 twelve days after the "fix".
        #
        # UNDER PYTEST'S OWN TREE, not a fresh mkdtemp. `atexit` was the old
        # cleanup and it does not run on the exits this suite takes: a daemon
        # teardown ends in `os._exit(0)`, which skips handlers by definition,
        # and a killed xdist worker runs nothing. Measured — the sweep landed
        # 2026-08-06 and the newest orphan was dated 2026-08-18, 1,627 of them.
        #
        # `tmp_path` is `<basetemp>/<run>/<case>`, so its parent is the run
        # directory, and pytest reaps all but the last three runs itself. Same
        # mechanism that already removes every `tmp_path`, on every exit path
        # including the ones that execute no Python.
        src = pathlib.Path(tmp_path).parent / "ca-cache"
        src.mkdir(parents=True, exist_ok=True)
        ensure_ca(src, "api.anthropic.com")
        _CA_CACHE.append(src)
    for f in ("ca.pem", "ca.key", "leaf.pem", "leaf.key"):
        shutil.copy2(_CA_CACHE[0] / f, tmp_path / f)
    return tmp_path


# Built PER CASE by `run_cases`, because the cases WRITE into it (`upstream.json`,
# `proxy.json`) and a shared one let a case read what the previous one recorded.
case_fixtures = {"certdir": _make_certdir}


def _mkdir(p):
    p.mkdir(parents=True, exist_ok=True)
    return p


@pytest.fixture
def certdir(tmp_path):
    return _make_certdir(tmp_path)


class _StallableBridgeUpstream:
    """A TLS server that stalls whichever request's body carries ``STALL``
    until ``release`` fires, and answers everything else at once. Accepts
    MULTIPLE connections, each served on its own thread -- the shape a
    `/bridge` POST and its client-side retry actually take (SEPARATE
    connections), which one accepted socket cannot reproduce.

    ``received`` records ``(body, arrival time)`` in the order each request
    was FULLY read, so a case can assert not just that both arrived but
    that the second did not arrive before the first was released.
    """

    def __init__(self, certdir: Path):
        self.release = threading.Event()
        self.received: list[tuple[bytes, float]] = []
        self._lock = threading.Lock()
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._accept_loop, daemon=True)
        self._thr.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            if self._stop:
                conn.close()
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            m = [l for l in head.lower().split(b"\r\n")
                 if l.startswith(b"content-length:")]
            want = int(m[0].split(b":")[1]) if m else 0
            while len(rest) < want:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                rest += chunk
            with self._lock:
                self.received.append((bytes(rest), time.monotonic()))
            if b"STALL" in rest:
                self.release.wait(timeout=10)
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Content-Type: application/json\r\n\r\n{}"
            )
            tls.close()
        except Exception:
            pass

    def stop(self):
        self._stop = True
        try:
            with socket.create_connection(self._srv.getsockname(), timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class _StatusThenHoldChain:
    """A plain-HTTP chain hop (see `_RecordingChain`), but concurrent and
    able to hold a connection open PAST its own status line: it answers
    with headers only (chunked, no body yet), records when that happened
    in ``status_sent_at``, then blocks on ``release`` before writing the
    chunked body and closing. Lets a case prove a caller distinguishes
    "the status line arrived" from "the exchange, and this connection,
    are over" -- the same distinction `_StallableBridgeUpstream` lets a
    case draw on the MITM path's own upstream.
    """

    def __init__(self):
        self.release = threading.Event()
        self.status_gate = threading.Event()
        self.received: list[bytes] = []
        self.status_sent_at: list[float] = []
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._accept_loop, daemon=True)
        self._thr.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            if self._stop:
                conn.close()
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            m = [l for l in head.lower().split(b"\r\n")
                 if l.startswith(b"content-length:")]
            want = int(m[0].split(b":")[1]) if m else 0
            while len(rest) < want:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                rest += chunk
            self.received.append(bytes(rest))
            if b"STALL" in rest:
                # HELD BEFORE THE STATUS LINE ITSELF -- proves the caller's
                # own hold (not this chain) is what keeps a same-cse sibling
                # off the wire until this gate opens.
                self.status_gate.wait(timeout=10)
            # THE STATUS LINE AND HEADERS ARRIVE NOW, chunked body still
            # to come -- the exchange has not SETTLED yet even though a
            # caller can already classify the response.
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            self.status_sent_at.append(time.monotonic())
            self.release.wait(timeout=10)
            conn.sendall(b"2\r\nok\r\n0\r\n\r\n")
            conn.close()
        except Exception:
            pass

    def stop(self):
        self._stop = True
        try:
            with socket.create_connection(self._srv.getsockname(), timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class TestPinProxyServer:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_pinned_route_gets_swapped_bearer(self, certdir):
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions", bearer="disk-token",
            )
            assert status == 200
            assert upstream.seen_auth == "Bearer PIN-TOKEN"
        finally:
            proxy.stop()
            upstream.stop()

    def case_profile_route_is_swapped_for_claude_code_only(self, certdir):
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            for ua, want in (
                ("claude-code/2.1.257", "Bearer PIN-TOKEN"),
                ("claude-swap/1.0", "Bearer disk-token"),
                (None, "Bearer disk-token"),
            ):
                status = _request_through_proxy(
                    proxy.port, certdir / "ca.pem",
                    "/api/oauth/profile", bearer="disk-token", ua=ua,
                )
                assert status == 200, ua
                assert upstream.seen_auth == want, ua
        finally:
            proxy.stop()
            upstream.stop()

    def case_inference_route_keeps_original_bearer(self, certdir):
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/messages", bearer="disk-token",
            )
            assert status == 200
            # Inference must NOT be swapped — it bills the swapped account.
            assert upstream.seen_auth == "Bearer disk-token"
        finally:
            proxy.stop()
            upstream.stop()

    def case_upstream_signed_by_foreign_ca_via_node_extra(self, certdir, tmp_path, monkeypatch):
        # Chained through CCF, the "upstream" presents CCF's cert, not the
        # real one. The proxy must trust whatever NODE_EXTRA_CA_CERTS names.
        from cswap_pin.proxy import PinProxy

        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(foreign / "ca.pem"))
        upstream = _FakeUpstream(foreign)  # leaf signed by the FOREIGN CA
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200
        finally:
            proxy.stop()
            upstream.stop()

    def _bridge_post(self, certdir, monkeypatch, seed_verdict, expect_swapped,
                      profile_answer=lambda token: {
                          "emailAddress": "pin@example.com"},
                      expect_refused=False):
        """Drives a REAL `make_pin_token_provider` through the actual HTTP
        egress path (`PinProxy` end to end, real upstream TLS) for a pinned
        `.../bridge` POST. `seed_verdict(pp, provider)` seeds whatever the
        case is testing before the request fires (or does nothing, for the
        healthy/positive-control case). `profile_answer` stands in for the
        mint-time `pin_profile_for` probe and is ALWAYS patched -- a foreign-
        verdict case that forgot to override it must still never dial
        api.anthropic.com, it must just get an "ok" verdict from the
        default. `expect_swapped` picks which invariant this drive proves:
        `swapped=True` (a healthy verdict DOES splice) or `swapped=False`
        (a foreign one never does, and never relays either -- see
        `expect_refused`).

        `expect_refused`: the bridge ATTACH is now a `should_wait_for_pin`
        route (T0867), so a real failed mint -- a foreign verdict included,
        it sets `blind_reason` exactly like a missing credential does --
        raises `_BlindMintRefusal` after the bounded retry instead of
        falling through to the old silent relay. Relaying a foreign bearer
        here would still give the bridge to whichever account is active,
        permanently -- the same fault class the create route is already
        guarded against.

        Not the provider in isolation: a provider-level-only test would still
        pass if a future splice site read the credential store directly
        instead of calling the provider.
        """
        import json as _json

        from cswap_pin import proxy as pp

        monkeypatch.setattr(pp, "pin_profile_for", profile_answer)

        live = _json.dumps({"claudeAiOauth": {
            "accessToken": "pin-live-token", "expiresAt": 4102444800000,
            "refreshToken": "rt"}})

        class _Switcher:
            backup_dir = certdir
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e): return live
            def resolve_account(self, i): return ("2", "pin@example.com", "org")

        pp.save_pin(certdir, "pin@example.com", "org")
        switcher = _Switcher()
        provider = pp.make_pin_token_provider(switcher, "2", "pin@example.com")
        seed_verdict(pp, provider)

        upstream = _FakeUpstream(certdir)
        proxy = pp.PinProxy(
            certdir=certdir,
            pin_token_provider=provider,
            upstream=("127.0.0.1", upstream.port),
        )
        trace = certdir / "armed-trace.log"
        (certdir / pp._TRACE_SWITCH_FILE).write_text(str(trace))
        pp._TRACE_CACHE.clear()
        proxy.start()
        try:
            proxy._trace_tick()  # the only thing that opens the handle
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions/SID123/bridge", bearer="client-own-token",
            )
            if expect_refused:
                assert status == 503, (
                    f"a foreign verdict on the bridge attach was relayed "
                    f"({status}) instead of refused -- the same permanent "
                    "give-away the create route is already guarded against")
                assert upstream.seen_auth is None, (
                    "the bridge attach reached upstream on a foreign "
                    f"bearer: {upstream.seen_auth!r}")
                return
            assert status == 200
            want = "Bearer pin-live-token" if expect_swapped else "Bearer client-own-token"
            assert upstream.seen_auth == want, (
                f"expected {want!r}, upstream saw {upstream.seen_auth!r}")
            # ALSO the pinned-ness, or this goes green on a broken pin the
            # moment `.../bridge` ever drops off the pinned route table --
            # `swapped=` alone cannot tell "correctly decided" from "never
            # reached the decision at all".
            assert f"/bridge pinned=True swapped={expect_swapped}" in trace.read_text()
        finally:
            proxy.stop()
            upstream.stop()

    def case_a_healthy_verdict_still_swaps_the_bridge_post(
            self, certdir, monkeypatch):
        """Positive control for the two foreign-verdict cases below. Without
        this, at least four ways the shared fixture could quietly decay --
        `load_pin` no longer parsing what `save_pin` writes, so
        `_current_target()` reads None; `read_account_credentials` moving
        off the stub's `(n, e)` shape, so `not creds`; `extract_oauth_data`
        no longer accepting this `claudeAiOauth` blob, so `_live_token`
        reads None; or the stub's "1"/"2" ever agreeing, so
        `_pin_is_the_live_login` short-circuits -- would make BOTH
        foreign-verdict cases pass for a reason that is not the guard,
        silently. If the fixture decays, THIS case reds and says why."""
        self._bridge_post(
            certdir, monkeypatch,
            seed_verdict=lambda pp, provider: None,
            expect_swapped=True,
        )

    def case_a_foreign_verdict_refuses_the_bridge_post(
            self, certdir, monkeypatch):
        """A foreign verdict from the MINT-time probe (`_identity_ok`, via
        `pin_profile_for`) must never splice -- see `_identity_ok`'s
        invariant. Since T0867 the bridge attach also waits and then
        refuses (503) rather than relaying on the foreign bearer -- see
        `_bridge_post`'s `expect_refused`; before that it silently gave the
        bridge to whichever account was active, unswapped and unrecorded,
        which is the same permanent loss the create route already closed."""
        self._bridge_post(
            certdir, monkeypatch,
            seed_verdict=lambda pp, provider: None,
            expect_swapped=False,
            profile_answer=lambda token: {
                "emailAddress": "someone-else@example.com"},
            expect_refused=True,
        )

    def case_a_foreign_verdict_from_the_identity_beat_refuses_the_bridge_post(
            self, certdir, monkeypatch):
        """The INCIDENT's own path: the 12h identity beat
        (`_freshen_pin_identity`) reports a foreign verdict through
        `provider.note_verdict`, not through a mint-time `pin_profile_for`
        probe. Both land in the same `_identity_cache` today, but that is an
        implementation detail one refactor could break -- this case reaches
        the splice guard the way wmac's incident actually did. `profile_answer`
        stays the healthy default: if the cache key shape ever moved and the
        mint fell through to a real probe, this case must still never dial
        out, and a healthy answer there is also the correct one -- the
        provider ignores it while its own foreign verdict stands. Since
        T0867 the bridge attach also waits and then refuses (503) rather
        than relaying on the foreign bearer -- see `expect_refused`."""
        self._bridge_post(
            certdir, monkeypatch,
            seed_verdict=lambda pp, provider: provider.note_verdict(
                "pin-live-token", "foreign"),
            expect_swapped=False,
            expect_refused=True,
        )

    def case_a_stalled_bridge_attach_is_not_overtaken_by_its_own_retry(
            self, certdir, monkeypatch):
        """T0955. Claude Code POSTs `.../bridge` with a 10s timeout, ABORTS
        the socket on timeout and retries -- but the pin kept relaying the
        aborted request upstream regardless, so during a hop stall the
        aborted request could reach the server AFTER the retry's and become
        the newest worker registration, 409ing the retry off its own
        session. The retry's own POST for the SAME cse must not reach
        upstream before the first attempt's exchange has settled."""
        import cswap_pin.proxy as pp

        holds: list[tuple[str, bool]] = []
        real_hold = pp.PinProxy._hold_bridge_attach

        def _spy_hold(self, cse):
            event, waited = real_hold(self, cse)
            holds.append((cse, waited))
            return event, waited

        monkeypatch.setattr(pp.PinProxy, "_hold_bridge_attach", _spy_hold)

        upstream = _StallableBridgeUpstream(certdir)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "TESTTOK",
                            upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            results = {}

            def _run(name, body):
                results[name] = _request_through_proxy(
                    proxy.port, certdir / "ca.pem",
                    "/v1/code/sessions/cse_X/bridge", bearer="t", body=body)

            t1 = threading.Thread(target=_run, args=("first", "STALL"),
                                  daemon=True)
            t1.start()
            deadline = time.monotonic() + 5
            while not upstream.received and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(upstream.received) == 1, (
                "the first request never reached upstream")

            t2 = threading.Thread(target=_run, args=("second", "SECOND"),
                                  daemon=True)
            t2.start()
            # REAL TIME, not an instant check -- a held request that races
            # ahead by scheduling luck would still pass a check made too
            # soon, and the case would prove nothing.
            time.sleep(0.3)
            assert len(upstream.received) == 1, (
                "the second POST reached upstream before the first "
                f"settled: {upstream.received}")

            upstream.release.set()
            t1.join(timeout=5)
            t2.join(timeout=5)
            assert results.get("first") == 200 and results.get("second") == 200, results
            # THE SPY MARKER, checked only now that both are done: a slow
            # box that let t2 schedule late enough to pass the timed check
            # above vacuously (never even reaching the hold in that 0.3s)
            # could still not fake ("cse_X", True) here -- `_hold_bridge_attach`
            # only returns it once t2 actually registered on cse_X AND
            # found the first one still there to wait on.
            assert ("cse_X", True) in holds, (
                "the second request never actually reached the hold and "
                f"registered as waiting on the first: {holds}")

            assert len(upstream.received) == 2, upstream.received
            bodies = [b for b, _ in upstream.received]
            assert bodies == [b"STALL", b"SECOND"], (
                f"upstream received out of order: {bodies}")
        finally:
            proxy.stop()
            upstream.stop()

    def case_a_held_request_whose_client_hung_up_is_never_relayed(
            self, certdir, monkeypatch):
        """T0955. A held request settles only when the hold releases; if
        the client that sent it is already gone by then, relaying it
        anyway would make IT the stray newest registration -- the exact
        fault the hold exists to prevent, just moved one request later.

        THE ABSENCE ALONE IS NOT ENOUGH: a request that never even PARSED
        (a bad CONNECT, say) would also leave `upstream.received` at one
        entry and pass. The spy on `_hold_bridge_attach` proves the
        abandoned request was actually read far enough to reach the hold
        for cse_X and find one already in place (`waited=True`) -- so the
        drop below is the hold doing its job, not a parse failure that
        never got this far."""
        import cswap_pin.proxy as pp

        holds: list[tuple[str, bool]] = []
        real_hold = pp.PinProxy._hold_bridge_attach

        def _spy_hold(self, cse):
            event, waited = real_hold(self, cse)
            holds.append((cse, waited))
            return event, waited

        monkeypatch.setattr(pp.PinProxy, "_hold_bridge_attach", _spy_hold)

        upstream = _StallableBridgeUpstream(certdir)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "TESTTOK",
                            upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            results = {}

            def _run_first():
                results["first"] = _request_through_proxy(
                    proxy.port, certdir / "ca.pem",
                    "/v1/code/sessions/cse_X/bridge", bearer="t", body="STALL")

            t1 = threading.Thread(target=_run_first, daemon=True)
            t1.start()
            deadline = time.monotonic() + 5
            while not upstream.received and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(upstream.received) == 1, (
                "the first request never reached upstream")

            # THE SECOND ARRIVES AND IS HELD, then its own client hangs up
            # -- sent, never read back, socket closed -- before the hold
            # ever ends.
            _post_and_abandon(proxy.port, certdir / "ca.pem",
                              "/v1/code/sessions/cse_X/bridge", "SECOND")
            time.sleep(0.2)  # let the abandoned send actually land

            upstream.release.set()
            t1.join(timeout=5)
            assert results.get("first") == 200, results

            # GIVE THE HELD REQUEST TIME TO RUN, now that the hold has
            # released -- and confirm it was DROPPED, not relayed.
            time.sleep(0.5)
            bodies = [b for b, _ in upstream.received]
            assert bodies == [b"STALL"], (
                "a held request whose client hung up reached upstream "
                f"anyway: {bodies}")
            assert ("cse_X", True) in holds, (
                "the abandoned request never actually parsed far enough "
                f"to hold on cse_X and find the first one still there: "
                f"{holds}")
        finally:
            proxy.stop()
            upstream.stop()

    def case_the_very_first_attempt_for_a_cse_still_checks_hung_up(
            self, certdir, monkeypatch):
        """T0955 [I]. The hung-up check used to run only when
        `_hold_bridge_attach` found something to wait on -- but order at
        the hold is the order requests REACH it, not the order they
        arrived: a retry can reach the hold first (its sibling stalled
        earlier, in `_wait_for_pin_token`) and settle before the ORIGINAL
        attempt gets there, leaving that original with `prev is None`
        just like any genuine first attempt. A hung-up client on THAT
        attempt -- no earlier entry to wait on at all -- must still be
        dropped, never relayed."""
        import cswap_pin.proxy as pp

        holds: list[tuple[str, bool]] = []
        real_hold = pp.PinProxy._hold_bridge_attach

        def _spy_hold(self, cse):
            event, waited = real_hold(self, cse)
            holds.append((cse, waited))
            return event, waited

        monkeypatch.setattr(pp.PinProxy, "_hold_bridge_attach", _spy_hold)

        upstream = _StallableBridgeUpstream(certdir)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "TESTTOK",
                            upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            _post_and_abandon(proxy.port, certdir / "ca.pem",
                              "/v1/code/sessions/cse_first/bridge", "FIRST")
            time.sleep(0.5)  # let the abandoned send actually land
            assert upstream.received == [], (
                "a first attempt (no earlier hold entry) whose client "
                f"hung up was relayed anyway: {upstream.received}")
            # THE SPY MARKER, proving the abandoned request actually parsed
            # far enough to reach the hold for cse_first and find NOTHING
            # to wait on (`waited=False`) -- so the drop above is the
            # first-attempt hung-up check doing its job, not a parse
            # failure that never got this far.
            assert ("cse_first", False) in holds, (
                "the abandoned request never actually reached the hold "
                f"as a genuine first attempt: {holds}")
        finally:
            proxy.stop()
            upstream.stop()

    def case_two_different_cse_ids_are_not_serialized(self, certdir):
        """T0955. The hold is keyed per cse, not a single global lock -- a
        stalled attach for one session must never delay an unrelated one."""
        from cswap_pin.proxy import PinProxy

        upstream = _StallableBridgeUpstream(certdir)
        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: "TESTTOK",
                          upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            results = {}

            def _run(name, cse, body):
                results[name] = _request_through_proxy(
                    proxy.port, certdir / "ca.pem",
                    f"/v1/code/sessions/{cse}/bridge", bearer="t", body=body)

            t1 = threading.Thread(target=_run, args=("a", "cse_A", "STALL"),
                                  daemon=True)
            t1.start()
            deadline = time.monotonic() + 5
            while not upstream.received and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(upstream.received) == 1

            t2 = threading.Thread(target=_run, args=("b", "cse_B", "OTHER"),
                                  daemon=True)
            t2.start()
            t2.join(timeout=5)
            assert results.get("b") == 200, (
                "an unrelated cse waited on a different session's stalled "
                f"attach: {results}")

            upstream.release.set()
            t1.join(timeout=5)
            assert results.get("a") == 200, results
        finally:
            proxy.stop()
            upstream.stop()

    def case_the_bound_releases_the_hold(self, certdir, monkeypatch):
        """T0955. A request that never settles must not hold a later one
        forever -- past `_BRIDGE_ATTACH_HOLD_S` the second proceeds too."""
        import cswap_pin.proxy as pp

        monkeypatch.setattr(pp, "_BRIDGE_ATTACH_HOLD_S", 0.2)
        upstream = _StallableBridgeUpstream(certdir)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "TESTTOK",
                            upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            results = {}

            def _run(name, body):
                results[name] = _request_through_proxy(
                    proxy.port, certdir / "ca.pem",
                    "/v1/code/sessions/cse_X/bridge", bearer="t", body=body)

            # THE FIRST NEVER SETTLES: `release` is never set and the
            # upstream never answers it.
            t1 = threading.Thread(target=_run, args=("first", "STALL"),
                                  daemon=True)
            t1.start()
            deadline = time.monotonic() + 5
            while not upstream.received and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(upstream.received) == 1

            t2 = threading.Thread(target=_run, args=("second", "SECOND"),
                                  daemon=True)
            t2.start()
            t2.join(timeout=5)
            assert results.get("second") == 200, (
                "the second request waited past the bound: " + str(results))
        finally:
            proxy.stop()
            upstream.stop()

    def case_the_absolute_form_hold_releases_at_the_status_line(
            self, certdir):
        """T0955 [I]. `_plain_relay` used to release the bridge-attach hold
        only when `_pump` RETURNED -- for a swapped request that is the
        whole keep-alive connection's lifetime, not the moment the
        exchange actually settled. A same-cse retry on a NEW connection
        must proceed once the status line is read, not once this
        connection's body finishes -- and must NOT proceed before then:
        the chain holds the first request's own status line behind
        `status_gate`, so the second reaching it at all proves the
        absolute-form hold (`_hold_bridge_attach` at the MITM entry
        point) is doing the blocking, not merely releasing early."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _StatusThenHoldChain()
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "TESTTOK",
                             rediscover_chain=True)
            proxy.start()

            results = {}

            def _run(name, body):
                c = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                try:
                    body_b = body.encode()
                    c.sendall(
                        b"POST https://api.anthropic.com/v1/code/sessions"
                        b"/cse_X/bridge HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                        b"Authorization: Bearer ACTIVE\r\n"
                        + f"Content-Length: {len(body_b)}\r\n\r\n".encode()
                        + body_b)
                    c.settimeout(10)
                    got = b""
                    # READ THE FULL CHUNKED RESPONSE, not until EOF: T0986
                    # CHANGE 1 gives every request the same HTTP-aware relay
                    # (`_relay_response`) the connection's first always got,
                    # so a keep-alive-eligible response (no `Connection:
                    # close`, chunked framing intact) leaves the socket OPEN
                    # for a next request instead of hanging up -- waiting
                    # for a close here would wait past this test's own
                    # timeout for a request that never comes.
                    while not got.endswith(b"0\r\n\r\n"):
                        d = c.recv(4096)
                        if not d:
                            break
                        got += d
                    results[name] = got
                finally:
                    c.close()

            t1 = threading.Thread(target=_run, args=("first", "STALL"),
                                  daemon=True)
            t1.start()
            deadline = time.monotonic() + 5
            while not chain.received and time.monotonic() < deadline:
                time.sleep(0.01)
            assert chain.received, (
                "the first request never reached the chain")

            # THE SECOND, SAME CSE: the chain is holding the first's status
            # line behind `status_gate`, so only the PROXY's own
            # `_hold_bridge_attach` -- not the chain -- can still be
            # keeping this off the wire. Proves the hold itself blocks,
            # not just that it releases early.
            t2 = threading.Thread(target=_run, args=("second", "SECOND"),
                                  daemon=True)
            t2.start()
            time.sleep(0.3)
            assert len(chain.received) == 1, (
                "the second request reached the chain before the first's "
                f"status line was even sent: {chain.received}")

            # AND NOW OPEN IT: the second must reach the chain once the
            # status line settles the hold's own question, even though the
            # first connection stays open, still streaming its chunked
            # body.
            chain.status_gate.set()
            deadline = time.monotonic() + 5
            while len(chain.received) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(chain.received) == 2, (
                "the second request never reached the chain after the "
                f"status-line gate opened: {chain.received}")

            chain.release.set()
            t1.join(timeout=5)
            t2.join(timeout=5)
            assert results.get("first", b"").startswith(b"HTTP/1.1 200"), (
                results.get("first"))
            assert results.get("second", b"").startswith(b"HTTP/1.1 200"), (
                results.get("second"))
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_client_past_fd_setsize_is_not_read_as_hung_up(self):
        """T0955 [I]. `_client_hung_up` used a `select.select` readable
        check, which raises ValueError for any fd >= FD_SETSIZE (1024).
        The pin caps no RLIMIT_NOFILE, so a pin that has piled up past
        1024 open fds (what a hop stall produces) read a still-connected
        client's fd as an error and, on the fail-CLOSED branch, as
        "gone" -- dropping a LIVE client's own /bridge POST. A client
        fd >= 1024 that is still connected and has sent nothing must
        read as NOT hung up."""
        import os

        from cswap_pin.proxy import _client_hung_up

        a, b = socket.socketpair()
        target = 2000
        while True:
            try:
                os.fstat(target)
            except OSError:
                break
            target += 1
        os.dup2(a.fileno(), target)
        high = socket.socket(fileno=target)
        try:
            assert high.fileno() >= 1024, high.fileno()
            assert _client_hung_up(high) is False, (
                "a live client past FD_SETSIZE was read as hung up")
        finally:
            high.close()
            a.close()
            b.close()


class _StreamingUpstream:
    """A TLS server that sends response headers + a first SSE event, then
    BLOCKS on ``release`` before sending the second event. Lets a test prove
    the proxy relays the first event before the response finishes — i.e. it
    streams instead of buffering to EOF."""

    def __init__(self, certdir: Path):
        self.release = threading.Event()
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        try:
            conn, _ = self._srv.accept()
            tls = self._ctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"8\r\nevent: a\r\n"
            )
            self.release.wait(timeout=10)
            tls.sendall(b"8\r\nevent: b\r\n0\r\n\r\n")
            tls.close()
        except Exception:
            pass

    def stop(self):
        try:
            with socket.create_connection(self._srv.getsockname(),
                                          timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class TestStreamingRelay:

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_first_event_arrives_before_upstream_finishes(self, certdir):
        from cswap_pin.proxy import PinProxy

        upstream = _StreamingUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            # Raw client through the proxy so we can read incrementally.
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n"
            )
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += raw.recv(1)
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            tls.sendall(
                b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                b"Authorization: Bearer t\r\n\r\n"
            )
            # Read until the first event lands. If the proxy buffered to EOF,
            # nothing arrives (upstream is blocked on release) → recv times out.
            tls.settimeout(5)
            got = b""
            while b"event: a" not in got:
                chunk = tls.recv(4096)
                assert chunk, "connection closed before first event"
                got += chunk
            # First event relayed while upstream still holds the second one.
            assert not upstream.release.is_set()
            upstream.release.set()
            while b"event: b" not in got:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                got += chunk
            assert b"event: b" in got
            tls.close()
        finally:
            proxy.stop()
            upstream.stop()


    def case_a_recycle_mid_stream_does_not_cut_the_reply(self, certdir):
        """THE MEASUREMENT THE WHOLE DRAIN EXISTS FOR, taken end to end.

        Everything else about the drain is asserted on counters. This drives a
        REAL reply that is mid-body, performs the REAL teardown a recycle
        performs, and then reads the rest of the body off the wire. If the
        drain cuts, `event: b` never arrives and the client sees EOF or a
        reset — which is exactly what three sessions got on 2026-08-18 as
        "API Error: Connection lost mid-response".

        WHY THIS IS NOT ALREADY COVERED by `case_a_planned_restart_under_a_
        holder_loses_nothing`: that one sends a CONNECT and reads a short
        answer, so it proves no request went UNANSWERED. It cannot see a long
        answer being TRUNCATED, because its requests finish faster than any
        drain. The user's failure was the truncation, and nothing measured it —
        which is why "the mechanism is fixed" was as far as anyone could
        honestly go before this case existed.

        The old code fails here for a reason worth stating precisely: it
        waited on `live_client_count()`, this connection holds that count at
        1, so the wait ran to its ceiling and `_close_open_connections()` then
        cut the very stream it had spent the ceiling waiting for.
        """
        from cswap_pin.proxy import PinProxy

        upstream = _StreamingUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n"
            )
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += raw.recv(1)
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            tls.sendall(
                b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                b"Authorization: Bearer t\r\n\r\n"
            )
            tls.settimeout(10)
            got = b""
            while b"event: a" not in got:
                chunk = tls.recv(4096)
                assert chunk, "connection closed before the reply even started"
                got += chunk

            # THE RECYCLE, MID-BODY. `stop(drain=...)` is what both handover
            # paths and `_teardown` call. Run it in a thread because a correct
            # drain BLOCKS here — it is waiting for this very reply — and the
            # reply cannot finish until the origin is released below.
            # THE TIMING IS THE DISCRIMINATOR, and a first version got it
            # wrong: it drained for 8s and released the origin after 0.3s, so
            # the reply finished long before ANY ceiling expired and the case
            # passed on the old code too. A control that passes proves
            # nothing, and it nearly shipped as proof.
            #
            # Here the reply needs ~1.5s and the drain budget is 1.0s. The old
            # drain waits on `live_client_count()`, which this connection
            # holds at 1, so it burns the whole 1.0s and then cuts a reply
            # that had 0.5s left. The fixed drain sees a request in flight and
            # returns only once it is done.
            done = threading.Event()

            def _recycle():
                proxy.stop(drain=1.0)
                done.set()

            def _finish_late():
                time.sleep(1.5)
                upstream.release.set()

            threading.Thread(target=_finish_late, daemon=True).start()
            threading.Thread(target=_recycle, daemon=True).start()
            while b"event: b" not in got:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                got += chunk
            assert b"event: b" in got, (
                "the reply was CUT mid-stream by a recycle — this is the exact "
                "failure the drain exists to prevent, and the one three "
                "sessions hit on 2026-08-18")
            assert done.wait(timeout=10), "the drain never returned"
            tls.close()
        finally:
            proxy.stop()
            upstream.stop()

    def case_the_drain_outlasts_the_reply_it_is_waiting_for(self, certdir):
        """WHAT ACTUALLY CUTS IS `os._exit`, and the drain is what delays it.

        Measured, after the first version of the case above passed against the
        OLD drain too and therefore proved nothing:

            before wrap: raw.fileno() = 3
            after  wrap: raw.fileno() = -1     <- ssl.wrap_socket DETACHES
                         tls.fileno() = 3

        `_open_conns` holds the RAW accepted socket, whose fileno is -1 by the
        time anything is streaming. So `_close_open_connections()` closes
        objects that no longer own the connection: on the MITM path it cuts
        NOTHING, and the "cut N in-flight request(s)" line counts sockets it
        cannot reach. The reply dies when the process exits and the kernel
        closes the real fds.

        That makes the drain's only job DELAYING THE EXIT until the reply is
        done — and the thing to assert is therefore how long `await_inflight`
        blocks, not what it closes. A drain that returns while a reply is in
        flight is a reply cut, one `os._exit()` later.

        This is what `_HELD_DRAIN_SECONDS = 2.0` did on 2026-08-18:
            03:42:04 stopping (refcount)  ->  03:42:06 drained
        two seconds on the nose, with a reply streaming, then exit.
        """
        from cswap_pin.proxy import PinProxy

        upstream = _StreamingUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n"
            )
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += raw.recv(1)
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            tls.sendall(
                b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                b"Authorization: Bearer t\r\n\r\n"
            )
            tls.settimeout(20)
            got = b""
            while b"event: a" not in got:
                chunk = tls.recv(4096)
                assert chunk, "closed before the reply started"
                got += chunk

            assert proxy.inflight_requests() >= 1, (
                "precondition: the drain must have something to wait for, or "
                "this case measures nothing — which is how its predecessor "
                "passed against the old code")

            # The origin finishes at +1.5s. A correct drain must still be
            # blocking then, because that is the whole reason it exists.
            threading.Thread(
                target=lambda: (time.sleep(1.5), upstream.release.set()),
                daemon=True).start()

            # THE HANDOVER CEILING, not a literal — and driving the real one
            # is what answers the only objection to raising it. Ten minutes
            # sounds like ten minutes of teardown; it is not, because the loop
            # exits on zero owed. This waits for a reply that lands at +1.5s
            # under a 600s budget and must return there, not at the ceiling.
            from cswap_pin.proxy import _HANDOVER_DRAIN_SECONDS

            t0 = time.monotonic()
            proxy.await_inflight(_HANDOVER_DRAIN_SECONDS)
            waited = time.monotonic() - t0

            assert waited >= 1.4, (
                f"the drain returned after {waited:.2f}s while the reply was "
                f"still streaming. os._exit() lands next, and the reply dies "
                f"there — this is the 2.0s _HELD_DRAIN_SECONDS cut, reproduced")
            assert waited < 25, (
                f"waited {waited:.1f}s after the reply finished — the drain is "
                "counting something that never reaches zero again, so the "
                "600s handover ceiling would be paid in full on every recycle")
        finally:
            proxy.stop()
            upstream.stop()


class _IdleClosingUpstream(_FakeUpstream):
    """Answers every request on a connection and closes the connection once
    it has been idle for ``hold`` seconds: a server-side keep-alive timeout,
    the shape a Node proxy has by default at 5 s."""

    def __init__(self, certdir: Path, hold: float):
        self.hold = hold
        self.accepted = 0
        super().__init__(certdir)

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            self.accepted += 1
            tls = None
            try:
                tls = self._ctx.wrap_socket(conn, server_side=True)
                tls.settimeout(self.hold)
                while True:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            raise OSError("client closed")
                        data += chunk
                    head, _, rest = data.partition(b"\r\n\r\n")
                    m = [l for l in head.decode("latin1").lower().split("\r\n")
                         if l.startswith("content-length:")]
                    want = int(m[0].split(":")[1]) if m else 0
                    while len(rest) < want:
                        chunk = tls.recv(4096)
                        if not chunk:
                            raise OSError("client closed")
                        rest += chunk
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except (OSError, ssl.SSLError):
                pass
            finally:
                # The TLS object owns the fd after wrap_socket; closing the
                # raw socket would close nothing and send no FIN.
                try:
                    (tls or conn).close()
                except OSError:
                    pass


class _FramingUpstream:
    """A TLS server that answers with a caller-chosen raw response.

    Lets a test drive the exact framing shapes a real origin produces —
    chunked, 204, 304 — and then read the result with a REAL HTTP client,
    which is the only thing that proves the framing we forward is parseable.
    """

    def __init__(
        self,
        certdir: Path,
        response: bytes,
        keep_open: bool = True,
        parts: "list[bytes] | None" = None,
    ):
        # ``parts`` sends the response in separate writes with a gap. An
        # interim response is only interesting when the final one has NOT
        # arrived yet: sent in one write it rides along in the bytes already
        # read past the head, and reaches the client whatever the relay does.
        self.parts = parts
        self.response = response
        self.keep_open = keep_open
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._held = []
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(
                target=self._serve, args=(conn,), daemon=True
            ).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            self._held.append(tls)
            # A keep-alive origin serves request after request on the same
            # connection and never closes on its own. That is what makes a
            # mis-framed bodyless response detectable: the relay blocks on
            # recv for a body that never comes, so the SECOND request on the
            # client's connection is never served.
            while not self._stop:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                if self.parts:
                    for i, part in enumerate(self.parts):
                        if i:
                            time.sleep(0.15)
                        tls.sendall(part)
                else:
                    tls.sendall(self.response)
                if not self.keep_open:
                    tls.close()
                    return
        except Exception:
            pass

    def stop(self):
        self._stop = True
        for t in self._held:
            try:
                t.close()
            except OSError:
                pass
        try:
            with socket.create_connection(self._srv.getsockname(),
                                          timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class TestResponseFramingIsParseable:
    """What we forward must be framed the way we CLAIM it is.

    The relay strips hop-by-hop headers (Transfer-Encoding among them) and
    then forwards chunk-size lines verbatim, so the client saw chunk syntax
    with no framing declared — free to read "1a\\r\\n" as payload or to wait
    for a close a keep-alive origin never sends. And 204/304 carry no body by
    definition but usually declare no framing either, so they fell into the
    read-until-EOF branch and hung.

    Every assertion here goes through http.client: a hand-rolled reader can
    agree with a hand-rolled writer and still be wrong.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _connect(self, proxy_port, ca_path):
        ctx = ssl.create_default_context(cafile=str(ca_path))
        conn = http.client.HTTPSConnection(
            "api.anthropic.com", context=ctx, timeout=5
        )
        conn.set_tunnel("api.anthropic.com", 443)
        conn._create_connection = lambda *a, **k: socket.create_connection(
            ("127.0.0.1", proxy_port), timeout=5
        )
        return conn

    def _get(self, proxy_port, ca_path, method="GET"):
        conn = self._connect(proxy_port, ca_path)
        conn.request(method, "/v1/messages", headers={"Authorization": "Bearer t"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp, body

    def _get_twice(self, proxy_port, ca_path, method="GET"):
        """Two requests on ONE connection.

        A bodyless response the relay mis-frames does not fail the FIRST
        request: http.client knows 204/304/HEAD carry no body and returns
        without waiting, while the relay thread is still blocked on recv for
        a body that will never come. The damage shows on the next request —
        the connection is never released back, so it never gets served. Only
        the second request can see the bug.
        """
        conn = self._connect(proxy_port, ca_path)
        out = []
        try:
            for _ in range(2):
                conn.request(
                    method, "/v1/messages", headers={"Authorization": "Bearer t"}
                )
                resp = conn.getresponse()
                out.append((resp, resp.read()))
        finally:
            conn.close()
        return out

    def _proxy(self, certdir, upstream):
        from cswap_pin.proxy import PinProxy

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        return proxy

    def case_a_chunked_response_stays_framed_as_chunked(self, certdir):
        upstream = _FramingUpstream(
            certdir,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        proxy = self._proxy(certdir, upstream)
        try:
            resp, body = self._get(proxy.port, certdir / "ca.pem")
            assert resp.status == 200
            assert body == b"hello world", (
                "chunk syntax reached the client as payload — the framing "
                "header was stripped while the chunk lines were kept"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def case_204_completes_without_waiting_for_a_close(self, certdir):
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 204 No Content\r\nDate: now\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem")
            assert [r.status for r, _ in got] == [204, 204], (
                "the relay blocked waiting for a body a 204 cannot have"
            )
            assert [b for _, b in got] == [b"", b""]
        finally:
            proxy.stop()
            upstream.stop()

    def case_304_completes_without_waiting_for_a_close(self, certdir):
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem")
            assert [r.status for r, _ in got] == [304, 304]
            assert [b for _, b in got] == [b"", b""]
        finally:
            proxy.stop()
            upstream.stop()

    def case_connection_close_is_relayed_not_swallowed(self, certdir):
        """`Connection` is hop-by-hop, so the filter drops it — but `close`
        was read into the keep-alive verdict and never re-declared. The proxy
        was about to close while the client still believed the connection
        reusable, so its next request died on a dead socket instead of
        opening a new one.

        Accidentally right before `_HOP_BY_HOP_BYTES`: the filter compared
        bytes against a str set and never matched, so the header rode along.
        """
        upstream = _FramingUpstream(
            certdir,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        proxy = self._proxy(certdir, upstream)
        try:
            conn = self._connect(proxy.port, certdir / "ca.pem")
            conn.request("GET", "/v1/messages", headers={"Authorization": "Bearer t"})
            resp = conn.getresponse()
            body = resp.read()
            assert (resp.status, body) == (200, b"ok")
            assert resp.getheader("Connection") == "close", (
                "the close signal was swallowed — the client will reuse a "
                "connection the proxy is closing"
            )
            assert resp.will_close, "http.client did not see the close"
            conn.close()
        finally:
            proxy.stop()
            upstream.stop()

    def case_a_keep_alive_response_is_not_marked_close(self, certdir):
        """...and the re-declaration must not fire on a healthy response, or
        every connection becomes single-use."""
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem")
            assert [r.status for r, _ in got] == [200, 200]
            assert all(r.getheader("Connection") is None for r, _ in got)
        finally:
            proxy.stop()
            upstream.stop()

    def _raw_exchange(self, proxy_port, ca_path, requests=1, stop_on=None):
        """Two requests through the proxy with a RAW TLS client.

        http.client cannot be the witness here: it discards interim (1xx)
        responses before returning, and its bodyless set is {204, 304} — it
        does not know 205, so it waits for a body a correct relay never
        sends. Both would report our own correct behaviour as a failure.
        """
        raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
        raw.sendall(
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
            b"Host: api.anthropic.com:443\r\n\r\n"
        )
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += raw.recv(1)
        ctx = ssl.create_default_context(cafile=str(ca_path))
        tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
        try:
            got = b""
            for _ in range(requests):
                tls.sendall(
                    b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer t\r\n\r\n"
                )
                tls.settimeout(3)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        chunk = tls.recv(4096)
                    except (OSError, ssl.SSLError):
                        break
                    if not chunk:
                        break
                    got += chunk
                    if stop_on and stop_on in got:
                        break
                    if not stop_on and got.endswith(b"\r\n\r\n"):
                        break
            return got
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def case_an_interim_1xx_is_not_delivered_as_the_final_response(self, certdir):
        """A 1xx is INTERIM: the real response follows on the same connection.

        Treating it as complete delivered the 103 as the answer and left the
        200 in the upstream buffer, so the next request on that connection
        read a stale response — a desync, not just a wrong status.
        """
        upstream = _FramingUpstream(
            certdir,
            b"",
            parts=[
                b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            ],
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._raw_exchange(
                proxy.port, certdir / "ca.pem", stop_on=b"ok"
            )
            assert b"103 Early Hints" in got, "the interim head was dropped"
            assert b"200 OK" in got and got.endswith(b"ok"), (
                "the FINAL response never arrived — the interim was "
                f"delivered as the answer:\n{got!r}"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def case_205_reset_content_carries_no_body(self, certdir):
        """RFC 9110 §15.3.6 — same class as 204, and it was missing.

        Raw client: http.client's bodyless set is {204, 304}, so it would
        block waiting for a body that must not exist.
        """
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 205 Reset Content\r\nDate: now\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._raw_exchange(proxy.port, certdir / "ca.pem", requests=2)
            assert got.count(b"205 Reset Content") == 2, (
                "the relay blocked on a body a 205 cannot have, so the "
                f"second request was never served:\n{got!r}"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def case_a_head_response_does_not_wait_for_its_absent_body(self, certdir):
        """HEAD mirrors GET's headers — Content-Length included — with no
        body. Only the request method says so."""
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem", method="HEAD")
            assert [r.status for r, _ in got] == [200, 200], (
                "the relay waited for a body the HEAD response does not carry"
            )
            assert [b for _, b in got] == [b"", b""]
        finally:
            proxy.stop()
            upstream.stop()


class TestChunkedRequestBodiesReachUpstream:
    """A chunked request arrived upstream with NO body.

    `_read_body` recognized only `Content-Length`, so it read zero bytes,
    while the forwarder stripped `Transfer-Encoding` (it is hop-by-hop). The
    upstream therefore saw a bodyless request and every chunked message or
    artifact upload silently lost its payload.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_chunked_body_is_decoded_and_reframed(self, certdir):
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            raw.sendall(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n"
            )
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += raw.recv(1)
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            tls.sendall(
                b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                b"Authorization: Bearer t\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
            )
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                resp += chunk
            tls.close()
        finally:
            proxy.stop()
            upstream.stop()

        assert upstream.seen_body == b"hello world", (
            "the upstream received a bodyless request — the chunked payload "
            f"was dropped (got {upstream.seen_body!r})"
        )
        head = upstream.seen_head.lower()
        # The body is decoded, so the chunk framing must NOT be claimed...
        assert "transfer-encoding" not in head, (
            "a decoded body was announced as chunked — the upstream would "
            f"read the payload as a chunk-size line:\n{upstream.seen_head!r}"
        )
        # ...and the framing that IS true has to be declared, or a
        # standards-conforming upstream reads no body at all.
        assert "content-length: 11" in head, (
            "the decoded body was sent with no framing declared:\n"
            f"{upstream.seen_head!r}"
        )


class TestTheChainsCredentialIsSent:
    """An authenticated corporate proxy answers 407 without it.

    Reducing the inherited proxy URL to ``(host, port)`` discarded the
    userinfo, so every CONNECT went out unauthenticated — and where that
    proxy is the only route out, ALL pinned traffic fails.
    """


    def _recording_chain(self):
        """A CONNECT proxy that records the request head and then refuses.

        Refusing is enough: the credential rides on the CONNECT itself, so
        the head is captured before anything downstream matters.
        """
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        seen = []

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = conn.recv(4096)
                        if not d:
                            break
                        buf += d
                    seen.append(buf.decode("latin1"))
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                finally:
                    conn.close()

        threading.Thread(target=loop, daemon=True).start()
        return srv, srv.getsockname()[1], seen

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_connect_carries_proxy_authorization(self, certdir):
        import base64

        from cswap_pin.proxy import PinProxy, write_upstream_hint

        srv, port, seen = self._recording_chain()
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        write_upstream_hint(certdir, f"http://alice:s3cr3t@127.0.0.1:{port}")
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            raw.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
            )
            deadline = time.monotonic() + 5
            while not seen and time.monotonic() < deadline:
                time.sleep(0.02)
            raw.close()
        finally:
            proxy.stop()
            srv.close()

        assert seen, "the proxy never reached the chain"
        expected = base64.b64encode(b"alice:s3cr3t").decode()
        assert f"Proxy-Authorization: Basic {expected}" in seen[0], (
            "the CONNECT went out unauthenticated — an authenticated "
            f"corporate proxy answers 407 to this:\n{seen[0]!r}"
        )

    def case_the_plain_relay_carries_it_too_with_no_client_credential(
        self, certdir
    ):
        """The absolute-form path (`_plain_relay`) used to demand a
        credential from the CLIENT before it would relay at all. That demand
        is gone; this is the CONTROL proving authorization did not stop
        working with it — the chain's OWN credential, configured through
        `upstream.json`, must still reach the next hop, from a client that
        never sent a `Proxy-Authorization` header of its own.

        Deliberately broken (a wrong `write_upstream_hint` password) this
        assertion fails, which is what makes it a control and not a shape
        check: verified by hand while writing this case, not kept as a
        second test that fails on purpose.
        """
        import base64
        import secrets

        from cswap_pin.proxy import PinProxy, write_upstream_hint

        # A proxy.secret DOES exist in this cert dir — a stale one, or one an
        # older install minted — which is the case today's gate is armed
        # by. Written directly rather than through `ensure_proxy_secret`,
        # which this change deletes.
        (certdir / "proxy.secret").write_text(secrets.token_urlsafe(32))
        srv, port, seen = self._recording_chain()
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        write_upstream_hint(certdir, f"http://alice:s3cr3t@127.0.0.1:{port}")
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            # NO Proxy-Authorization header at all — the row that separates
            # "the credential left the environment" from "the daemon still
            # requires one".
            raw.sendall(
                b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            deadline = time.monotonic() + 5
            while not seen and time.monotonic() < deadline:
                time.sleep(0.02)
            raw.settimeout(5)
            try:
                client_saw = raw.recv(64)
            except OSError:
                client_saw = b""
            raw.close()
        finally:
            proxy.stop()
            srv.close()

        assert b"407" not in client_saw, (
            f"a credential-less client was answered 407: {client_saw!r}"
        )
        assert seen, (
            "the plain relay never reached the chain — a credential-less "
            "client was refused instead of served"
        )
        expected = base64.b64encode(b"alice:s3cr3t").decode()
        assert f"Proxy-Authorization: Basic {expected}" in seen[0], (
            "the chain's own credential did not reach the next hop — "
            f"authorization stopped working, not just left the client's "
            f"environment:\n{seen[0]!r}"
        )


class _LoopbackConnectProxy:
    """A localhost CONNECT proxy (stands in for CCF) that forwards to a fake
    upstream signed by a CA the pin proxy does NOT trust. Proves the pin proxy
    relays through a loopback MITM without being able to verify its cert."""

    def __init__(self, target: tuple[str, int]):
        self._target = target
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self.connects = 0
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        try:
            conn, _ = self._srv.accept()
            self.connects += 1
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += conn.recv(1)
            up = socket.create_connection(self._target, timeout=10)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            # blind-pipe both directions
            import select
            while True:
                r, _, _ = select.select([conn, up], [], [], 10)
                if not r:
                    break
                for s in r:
                    d = s.recv(65536)
                    if not d:
                        return
                    (up if s is conn else conn).sendall(d)
        except Exception:
            pass

    def stop(self):
        try:
            with socket.create_connection(self._srv.getsockname(),
                                          timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class TestLoopbackChainTrust:

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_relays_through_untrusted_loopback_mitm(self, certdir, tmp_path):
        from cswap_pin.proxy import PinProxy

        # Fake upstream signed by a FOREIGN CA the pin proxy has no way to trust.
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)
        chain = _LoopbackConnectProxy(("127.0.0.1", upstream.port))

        proxy = PinProxy(
            certdir=certdir,  # pin proxy's own CA != foreign CA
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            chain_proxy=("127.0.0.1", chain.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200  # verification was skipped for the loopback hop
        finally:
            proxy.stop()
            chain.stop()
            upstream.stop()

    def case_a_dead_loopback_chain_does_not_disarm_verification(
        self, certdir, tmp_path, monkeypatch
    ):
        """Skipping verification is a property of the HOP, not of the hint.

        The dial falls back to a direct socket when the recorded chain is
        unreachable. Deriving the TLS context from the (still loopback) hint
        instead of from the dial meant that fallback reached the real
        api.anthropic.com with CERT_NONE, carrying account bearers — a MITM
        window that opens exactly when the local proxy is down.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        # Since 0.1.251 a host with a configured chain refuses the direct
        # dial (NoChainHopError -> 503); the fall-through this case measures
        # exists only behind the opt-in.
        monkeypatch.setenv("CSWAP_PIN_ALLOW_DIRECT", "1")
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)  # cert the pin proxy cannot trust

        # A loopback chain that is recorded but NOT listening: bind a port,
        # learn it, close it. The hint stays loopback; the dial must fail.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        write_upstream_hint(certdir, f"http://127.0.0.1:{dead_port}")
        proxy.start()
        try:
            raw, via_loopback = proxy._connect_upstream()
            raw.close()
            assert via_loopback is False, (
                "the chain was unreachable, so this dial was direct"
            )
            assert (
                proxy._upstream_ctx(via_loopback).verify_mode is ssl.CERT_REQUIRED
            ), "a direct dial to the real upstream must verify the certificate"

            # End to end: the foreign-signed upstream must now be REJECTED.
            # The proxy drops the connection on a TLS failure, so "no reply"
            # and "a non-200 reply" are both the refusal this asserts; only a
            # 200 would mean the bad cert was accepted.
            try:
                status = _request_through_proxy(
                    proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
                )
            except (OSError, http.client.HTTPException):
                status = None
            assert status != 200, (
                "an untrusted cert was accepted on a direct dial"
            )
        finally:
            proxy.stop()
            upstream.stop()


class TestPinTimeHopTrust:
    """T1612: `cswap pin N` makes ONE CONNECT to the API host through the
    recorded hop, with the trust the daemon will use, and names the fix when
    the hop re-signs with a CA nobody gave it.

    A NON-LOOPBACK hop is what the daemon verifies through (`_upstream_ctx`);
    a loopback one gets CERT_NONE, see
    `case_relays_through_untrusted_loopback_mitm`. These cases empty
    `_LOOPBACK` so a 127.0.0.1 fake stands in for a remote hop.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    @staticmethod
    def _mitm(tmp_path, signer=None):
        """A CONNECT hop in front of an origin whose leaf `signer` signed: a
        foreign CA (a MITM) by default, or the pin's own (a plain tunnel to
        an origin the daemon trusts)."""
        if signer is None:
            signer = tmp_path / "foreign"
            signer.mkdir()
            ensure_ca(signer, "api.anthropic.com")
        upstream = _FakeUpstream(signer)
        return signer, upstream, _LoopbackConnectProxy(("127.0.0.1", upstream.port))

    def _verdict(self, certdir, tmp_path, monkeypatch, *, ca=None,
                 remote=True, signer=None):
        from cswap_pin import proxy

        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        if remote:
            monkeypatch.setattr(proxy, "_LOOPBACK", frozenset())
        signer, upstream, hop = self._mitm(tmp_path, signer)
        try:
            proxy.write_upstream_hint(
                certdir, f"http://127.0.0.1:{hop.port}",
                str(signer / "ca.pem") if ca else None)
            return proxy.hop_trust_problem(certdir), hop.port
        finally:
            hop.stop()
            upstream.stop()

    def case_a_mitm_hop_without_its_ca_names_the_fix(
        self, certdir, tmp_path, monkeypatch
    ):
        msg, port = self._verdict(certdir, tmp_path, monkeypatch)
        assert msg and "NODE_EXTRA_CA_CERTS" in msg, msg
        assert f"127.0.0.1:{port}" in msg, msg

    def case_a_mitm_hop_with_its_ca_is_clean(self, certdir, tmp_path, monkeypatch):
        msg, _ = self._verdict(certdir, tmp_path, monkeypatch, ca=True)
        assert msg is None, msg

    def case_a_plain_connect_proxy_is_clean(self, certdir, tmp_path, monkeypatch):
        # The origin's own certificate comes through untouched, and it is one
        # the daemon's context trusts.
        msg, _ = self._verdict(certdir, tmp_path, monkeypatch, signer=certdir)
        assert msg is None, msg

    def case_a_loopback_mitm_is_clean_because_the_daemon_does_not_verify_it(
        self, certdir, tmp_path, monkeypatch
    ):
        msg, _ = self._verdict(certdir, tmp_path, monkeypatch, remote=False)
        assert msg is None, msg

    def case_no_proxy_is_no_check(self, certdir, monkeypatch):
        from cswap_pin import proxy

        def _no_dial(*a, **k):
            raise AssertionError("dialled with no proxy recorded")

        monkeypatch.setattr(proxy, "_dial_chain", _no_dial)
        assert proxy.hop_trust_problem(certdir) is None

    def case_a_hop_that_does_not_answer_is_reported_not_blamed_on_trust(
        self, certdir, monkeypatch
    ):
        from cswap_pin import proxy

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        monkeypatch.setattr(proxy, "_LOOPBACK", frozenset())
        proxy.write_upstream_hint(certdir, f"http://127.0.0.1:{dead}")
        msg = proxy.hop_trust_problem(certdir)
        assert msg and f"127.0.0.1:{dead}" in msg, msg
        assert "NODE_EXTRA_CA_CERTS" not in msg, msg

    @staticmethod
    def _slow_hop(chunk, every):
        """A hop that answers a CONNECT with `chunk` every `every` seconds,
        never a blank line, for at most 6 s (so a probe with no overall
        deadline still returns, late)."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        done = threading.Event()

        def serve():
            conn, _ = srv.accept()
            with conn:
                end = time.monotonic() + 6
                while time.monotonic() < end and not done.wait(every):
                    try:
                        conn.sendall(chunk)
                    except OSError:
                        return

        thr = threading.Thread(target=serve, daemon=True)
        thr.start()
        return srv, done, thr

    def _timed(self, certdir, monkeypatch, chunk, every, budget):
        from cswap_pin import proxy

        monkeypatch.setattr(proxy, "_LOOPBACK", frozenset())
        # raising=False: a misspelt name still fails, on the 10 s default.
        monkeypatch.setattr(proxy, "_HOP_PROBE_BUDGET_S", budget, raising=False)
        srv, done, thr = self._slow_hop(chunk, every)
        port = srv.getsockname()[1]
        try:
            proxy.write_upstream_hint(certdir, f"http://127.0.0.1:{port}")
            t0 = time.monotonic()
            msg = proxy.hop_trust_problem(certdir)
            took = time.monotonic() - t0
        finally:
            done.set()
            thr.join(timeout=8)
            srv.close()
        assert msg and f"127.0.0.1:{port}" in msg, msg
        assert "NODE_EXTRA_CA_CERTS" not in msg, msg
        return took

    def case_a_hop_that_trickles_its_reply_is_cut_at_the_deadline(
        self, certdir, monkeypatch
    ):
        """One byte every 0.3 s never trips the 6 s per-read timeout, so only
        an overall deadline stops `cswap pin` (and the TUI's repair on mount)
        waiting on it."""
        took = self._timed(certdir, monkeypatch, b"x", 0.3, budget=1.5)
        assert took < 1.5 + 1.0, took

    def case_a_hop_that_floods_its_reply_is_cut_at_the_cap(
        self, certdir, monkeypatch
    ):
        took = self._timed(certdir, monkeypatch, b"x" * 65536, 0.01, budget=30)
        assert took < 2.0, took

    def case_a_running_daemon_trusts_a_ca_recorded_after_it_started(
        self, certdir, tmp_path, monkeypatch
    ):
        """THE FIX TEXT MUST WORK ON A REUSED DAEMON. Re-running `cswap pin`
        with the CA exported records it in upstream.json, and `ensure_proxy`
        then reuses the daemon already serving, whose own environment never
        had it. So the origin leg has to read the recorded CA per connection,
        as the hop's own TLS (`_dial_chain`) already does."""
        from cswap_pin import proxy
        from cswap_pin.proxy import PinProxy

        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        monkeypatch.setattr(proxy, "_LOOPBACK", frozenset())
        foreign, upstream, hop = self._mitm(tmp_path)
        proxy.write_upstream_hint(
            certdir, f"http://127.0.0.1:{hop.port}", str(foreign / "ca.pem"))
        daemon = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        daemon.start()
        try:
            status = _request_through_proxy(
                daemon.port, certdir / "ca.pem", "/v1/messages", bearer="t")
        finally:
            daemon.stop()
            hop.stop()
            upstream.stop()
        assert status == 200


class TestPortReclamationAcrossRespawn:
    """A respawn must come back on the SAME port. A live session's
    HTTPS_PROXY is fixed at exec, so a new port strands it on a dead
    address — and a request to a dead proxy leaves WITHOUT the pin rather
    than failing loudly. proxy.json is deleted before the respawn (a stale
    record must never read as live), so the port travels via a hint."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_rebinds_the_port_carried_across_the_state_deletion(self, certdir):
        """The real daemon is a separate process, so its listening socket is
        gone by the time the successor binds. Model that by taking a free
        port, recording it the way _spawn_daemon does, and checking the
        successor lands on it rather than an ephemeral one."""
        import socket as _socket
        from cswap_pin.proxy import PinProxy, _write_port_hint

        probe = _socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()  # now free, as after a daemon exits

        # What _spawn_daemon does: carry the port forward, drop the state.
        _write_port_hint(certdir, port)
        (certdir / "proxy.json").unlink(missing_ok=True)

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        proxy.start()
        try:
            assert proxy.port == port, (
                f"respawn landed on {proxy.port}, stranding sessions wired to {port}"
            )
        finally:
            proxy.stop()

    def case_recycling_a_stale_daemon_carries_its_port(self, tmp_path, monkeypatch):
        """The stale-recycle path kills the old daemon first, and the daemon
        unlinks its own state on TERM — so the port must be saved BEFORE the
        kill or there is nothing left to reclaim from. Measured live: a
        recycle moved 59704 -> 59857 while sessions stayed on 59704."""
        from cswap_pin import proxy as pin_proxy

        backup = tmp_path
        certdir = backup / "pin-proxy"
        certdir.mkdir()
        pin_proxy.save_pin(backup, "pin@example.com", "org-1")
        pin_proxy.write_daemon_state(certdir, 51000, 4242, "STALE-fingerprint")

        class _Sw:
            backup_dir = backup
            def resolve_account(self, identifier):
                return ("1", "pin@example.com", "org-1")

        killed = []
        # 4242 is a pin daemon for THIS certdir — the recycle is legitimate.
        monkeypatch.setattr(pin_proxy, "_pin_daemon_pids", lambda cd: [4242])
        monkeypatch.setattr(pin_proxy, "_kill_daemon", lambda pid, certdir=None: killed.append(pid))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 51000)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)

        pin_proxy.ensure_proxy(_Sw())

        assert killed == [4242], "the stale daemon was not recycled"
        assert pin_proxy.read_port_hint(certdir) == 51000

    def case_a_reused_pid_is_not_killed(self, tmp_path, monkeypatch):
        """Alive is not "still ours".

        An unclean exit leaves proxy.json behind, and the OS reuses pids
        freely. Recycling on liveness alone therefore aims SIGTERM — then
        SIGKILL — at whatever unrelated process inherited the number, purely
        because a dead daemon once had it.
        """
        from cswap_pin import proxy as pin_proxy

        backup = tmp_path
        certdir = backup / "pin-proxy"
        certdir.mkdir()
        pin_proxy.save_pin(backup, "pin@example.com", "org-1")
        pin_proxy.write_daemon_state(certdir, 51000, 4242, "STALE-fingerprint")

        class _Sw:
            backup_dir = backup
            def resolve_account(self, identifier):
                return ("1", "pin@example.com", "org-1")

        killed = []
        # The pid is alive, but it is somebody else's process now: no pin
        # daemon for this certdir carries it.
        monkeypatch.setattr(pin_proxy, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(pin_proxy, "_pin_daemon_pids", lambda cd: [])
        monkeypatch.setattr(pin_proxy, "_kill_daemon", lambda pid, certdir=None: killed.append(pid))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 51000)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)

        pin_proxy.ensure_proxy(_Sw())

        assert killed == [], (
            "SIGTERM/SIGKILL sent to a process that is not our daemon"
        )

    def case_a_superseded_daemon_leaves_the_successors_state_alone(
        self, tmp_path
    ):
        """The other half of the same root: cleanup must check ownership too.

        _spawn_daemon publishes the successor's proxy.json and only THEN
        sweeps the orphans it replaces. So the old daemon's SIGTERM arrives
        after the file already names the successor — and an unconditional
        unlink deletes the record of the daemon that is currently serving.
        The next launch then reads no state and spawns another one on top.
        """
        import os as _os
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()

        # State published by the SUCCESSOR (a pid that is not ours).
        successor_pid = _os.getpid() + 1
        pin_proxy.write_daemon_state(certdir, 51000, successor_pid, "fp")

        assert pin_proxy._release_daemon_state(certdir) is True, (
            "a superseded daemon must report that it no longer owns the state"
        )
        st = pin_proxy.read_daemon_state(certdir)
        assert st is not None and int(st["pid"]) == successor_pid, (
            "the departing daemon deleted the serving successor's state"
        )

    def case_a_daemon_still_owning_its_state_clears_it(self, tmp_path):
        """The normal teardown must still leave nothing behind — a stale
        record reads as live and the next launch reuses a dead port."""
        import os as _os
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pin_proxy.write_daemon_state(certdir, 51000, _os.getpid(), "fp")

        assert pin_proxy._release_daemon_state(certdir) is False
        assert pin_proxy.read_daemon_state(certdir) is None

    def case_spawn_carries_the_port_forward(self, tmp_path, monkeypatch):
        """_spawn_daemon must record the outgoing port BEFORE deleting the
        state file it lives in — the regression that let a recycle land on a
        fresh port while .claude.json still named the old one."""
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pin_proxy.write_daemon_state(certdir, 54321, 999999, "fp")

        import subprocess as _subprocess
        monkeypatch.setattr(_subprocess, "Popen", lambda *a, **k: None)
        monkeypatch.setattr(pin_proxy, "_read_alive_port", lambda *a, **k: 54321)
        monkeypatch.setattr(pin_proxy, "_sweep_orphan_daemons", lambda *a, **k: None)
        pin_proxy._spawn_daemon("1", "pin@example.com", certdir)

        assert pin_proxy.read_port_hint(certdir) == 54321


class TestLongPollSurvives:
    """Remote Control's inbound channel is a long poll: GET .../worker holds
    its response open until the phone/web sends something. create_connection's
    timeout stays ON the socket, so it silently became a read deadline and
    killed that poll — heartbeats (answered at once) kept returning 200, so
    the session looked healthy while no inbound message ever arrived."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_upstream_socket_has_no_read_deadline(self, certdir):
        import socket as _socket
        import threading as _threading
        from cswap_pin.proxy import PinProxy

        # An upstream that accepts, then stays silent well past any dial budget.
        srv = _socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        held = []

        def _hold():
            c, _ = srv.accept()
            held.append(c)  # keep it open, send nothing

        _threading.Thread(target=_hold, daemon=True).start()

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", srv.getsockname()[1]),
        )
        try:
            up, _via_loopback = proxy._connect_upstream()
            assert up.gettimeout() is None, (
                "a read deadline on the upstream kills the RC long poll"
            )
            up.close()
        finally:
            for c in held:
                c.close()
            srv.close()


def _http_hop(status, body=b""):
    """A loopback hop answering every HTTP request with `status` and `body`.

    Returns ``(server, url, served)``. `served` counts requests that sent
    bytes, NOT bare connects: `_ambient_proxy`'s `_port_is_serving` opens one
    and closes it without a word, which is not a probe of the hop.
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    served = []

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                if buf:
                    served.append(1)  # before the reply: the client may race it
                    c.sendall(
                        b"HTTP/1.1 " + status + b"\r\nContent-Length: "
                        + str(len(body)).encode() + b"\r\n\r\n" + body
                    )
            except OSError:
                pass
            finally:
                c.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.getsockname()[1]}", served


def _launch_from(shell_proxy, tmp_path, monkeypatch):
    """``(ensure_proxy_once, certdir)``: the real call site, one launch whose
    shell exports `shell_proxy`, with everything past the hint block stubbed."""
    import functools

    import cswap_pin.proxy as pp

    certdir = tmp_path / "pin-proxy"
    certdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HTTPS_PROXY", shell_proxy)
    for name, fake in (
        ("load_pin", lambda _bd: ("a@b.c", "")),
        ("_carry_history_pointers", lambda _cd: None),
        ("daemon_fingerprint", lambda *_a: "FP"),
        ("ensure_ca", lambda *_a: None),
        ("publish_ca", lambda _p: None),
        ("wire_global_config", lambda *_a: None),
        ("_read_alive_port", lambda *_a, **_k: 41000),
        ("_ASKED_NOHEALTH", set()),
        # timeout=10: a server-thread reply, not the network (T1076).
        ("_probe_next_hop", functools.partial(pp._probe_next_hop, timeout=10)),
    ):
        monkeypatch.setattr(pp, name, fake)

    class _SW:
        backup_dir = tmp_path

        def resolve_account(self, email):
            return "1", email, None

    return lambda: pp.ensure_proxy(_SW()), certdir


class TestChainRediscovery:
    """The daemon outlives the launch that spawned it, and a cache proxy picks
    its port from a family and can restart. A chain bound once at spawn
    therefore goes stale — and a stale chain does not degrade, it BYPASSES the
    egress proxy. The daemon re-reads the hint every connection instead.

    AND A DEAD HOP FALLS THROUGH TO THE HOP BEHIND IT, never to a direct dial.
    Behind a corporate TLS-inspecting proxy a direct dial is not "no proxy",
    it is the inspector, and its leaf carries no Authority Key Identifier —
    so a strict verifier refuses it and OAuth against claude.ai fails with
    nothing on screen. Only the outermost proxy reaches the real leaf, which
    is why a hint recording ONE hop is not enough: when the recorded hop is an
    inner cache proxy and it goes away, the correct target is the outer proxy
    it was itself chaining to."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_follows_a_chain_that_appears_after_the_daemon_started(
        self, certdir, tmp_path
    ):
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)
        chain = _LoopbackConnectProxy(("127.0.0.1", upstream.port))

        # Daemon starts with NO chain recorded — a direct dial to the fake
        # upstream would fail TLS verification (foreign CA), so a request
        # succeeding proves it went through the loopback chain instead.
        write_upstream_hint(certdir, None)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        proxy.start()
        try:
            # A launch happens later and records the chain (what ensure_proxy
            # does on every launch).
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200
            assert chain.connects, "the daemon never used the newly-recorded chain"
        finally:
            proxy.stop()
            chain.stop()
            upstream.stop()

    def case_a_launch_that_sees_no_proxy_keeps_the_recorded_one(self, certdir):
        """`cswap pin` normally runs in an ordinary shell, while the launcher
        sets HTTPS_PROXY only in the env it execs Claude Code with. Treating
        "I can't see one" as "there is none" blanked a live upstream —
        measured: a re-pin from a plain shell dropped a recorded CCF and the
        daemon started bypassing it."""
        from cswap_pin.proxy import read_upstream_hint, write_upstream_hint

        write_upstream_hint(certdir, "http://127.0.0.1:9901")
        assert read_upstream_hint(certdir).address == ("127.0.0.1", 9901)

        write_upstream_hint(certdir, None)  # a launch with nothing in its env
        assert read_upstream_hint(certdir).address == ("127.0.0.1", 9901), (
            "a launch that could not see a proxy erased the recorded one"
        )

        # A launch that positively reports a DIFFERENT proxy still wins.
        write_upstream_hint(certdir, "http://127.0.0.1:9902")
        assert read_upstream_hint(certdir).address == ("127.0.0.1", 9902)

    def case_the_kept_hint_keeps_its_CREDENTIAL_and_scheme(self, certdir):
        """Keeping the address is not keeping the chain.

        The keep-previous branch rebuilt the URL from the parsed pair, which
        threw away the two fields the chain exists to carry. And this is the
        NORMAL path — `cswap pin` from a plain shell reports no proxy, and
        ensure_proxy re-stamps on every launch — so on a machine whose only
        route out is an authenticated or https:// corporate proxy, the
        credential survived until the next re-pin and then every pinned
        request 407'd.
        """
        from cswap_pin.proxy import read_upstream_hint, write_upstream_hint

        write_upstream_hint(certdir, "https://bob:s3cr%40t@corp.proxy:8443")
        first = read_upstream_hint(certdir)
        assert first.auth and first.tls, first

        write_upstream_hint(certdir, None)  # the re-stamp every launch does
        kept = read_upstream_hint(certdir)
        assert kept == first, (
            f"the re-stamp laundered the chain: {first} -> {kept}"
        )

    def case_the_recorded_upstream_is_returned_raw(self, certdir):
        """_recorded_upstream feeds back INTO the hint, so reconstructing the
        URL there launders the credential on the other side of the same round
        trip."""
        from cswap_pin.proxy import _recorded_upstream, write_upstream_hint

        url = "https://bob:s3cr%40t@corp.proxy:8443"
        write_upstream_hint(certdir, url)
        assert _recorded_upstream(certdir) == url

    def case_a_dead_recorded_chain_answers_503_by_default(
        self, certdir, tmp_path, monkeypatch
    ):
        """The hint cannot expire on its own (see above), so a chain that dies
        must not wedge every request. Since 2026-09-07 the answer is a 503
        with Retry-After, NOT a direct dial: on the hosts that configure a
        chain, direct is the corporate inspector and its 403 reads as
        "Please run /login" (49 direct dials, one fleet-wide login wave).
        `CSWAP_PIN_ALLOW_DIRECT=1` is the opt-in that restores the old
        fall-through, and the second half of this case proves the walk still
        reaches it."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        upstream = _FakeUpstream(certdir)
        # Point the chain at a port nothing is listening on.
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        write_upstream_hint(certdir, f"http://127.0.0.1:{dead_port}")

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 503, (
                f"a dead chain must answer 503 Retry-After, never wedge and "
                f"never dial direct: got {status!r}"
            )
            monkeypatch.setenv("CSWAP_PIN_ALLOW_DIRECT", "1")
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200, (
                "CONTROL FAILED: with the opt-in a dead chain no longer "
                f"falls through to the direct dial: got {status!r}"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def case_the_record_grows_and_refuses_a_hop_that_names_the_pin(
        self, certdir
    ):
        """WHAT THE DAEMON LEARNS ABOUT THE HOP BEHIND ITS OWN, and what it
        must refuse to learn.

        Two halves of one mechanism, so one case rather than two: the same
        `/health` stand-in answers both, and splitting them duplicated the
        server and the helper verbatim.

        1. THE RECORD MUST BE ABLE TO GROW AFTER THE LAUNCH THAT MADE IT.
        D1-D4 prove the walk USES a recorded next hop, and
        `case_the_next_hop_is_probed_from_the_cache_proxys_health` proves a
        LAUNCH records one. One was missing anyway: `_probe_next_hop` ran at
        hint-writing time and nowhere else, and `--ensure` — what an rc hook
        calls before every `claude` — routes to `heal`, which never re-stamps
        the hint. So the only chance to learn the outer hop was a launch that
        happened while the inner one was answering. Miss it once and the
        chain is single-hop for good. Measured, and it was the steady state:

            upstream.json {"proxy": "http://127.0.0.1:9901", ...} no "next",
            written 2026-08-04 01:32, unchanged a day later, while 9901's
            /health answered http://127.0.0.1:8118 the whole time

        When 9901 died the walk had one hop and went DIRECT — the corporate
        TLS inspector here, which 403s. The answer was one request away.

        2. A HOP THAT NAMES US IS A LOOP, NOT A NEXT HOP. `_probe_next_hop`
        guards a hop naming ITSELF, not one naming the PIN. That is what a
        peer session measured and fixed on its own side (dba90bd): a cache
        proxy launched from a shell that already exported the chain adopted
        the pin's port as its upstream, so the path became 9901 -> 36301 ->
        9901 and never reached privoxy. Measured here before the guard:

            hop reported: http://127.0.0.1:36301, own port 36301
            LOOP RECORDED: the pin would dial itself

        The peer's fix is not enough, because the RECORD OUTLIVES THE PROCESS:
        a chain learned during the polluted window keeps pointing here after
        the hop is repaired, and every version already on disk wrote records
        without the guard. So both ends — refuse to record one, and drop one
        already recorded before dialling.

        CONTROLS, one per claim: a hop reporting no upstream must record
        nothing (or "learned it" passes for code that records noise), a hop
        naming a different port must still be recorded (or "refuses a loop"
        passes for code that learns nothing), and dropping the loop must not
        drop the real hop with it.
        """
        import functools
        import http.server
        import threading

        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy, _read_upstream, write_upstream_hint

        class _Health(http.server.BaseHTTPRequestHandler):
            """A hop answering /health with whatever `answer` holds."""

            answer: dict = {}

            def do_GET(self):
                body = json.dumps(self.answer).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        def _learned(answer, my_port=0):
            """What the daemon records as `next` after asking a hop once."""
            _Health.answer = answer
            srv = http.server.HTTPServer(("127.0.0.1", 0), _Health)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            write_upstream_hint(
                certdir, f"http://127.0.0.1:{srv.server_address[1]}", next_hop="",
            )
            try:
                proxy = PinProxy(
                    certdir=certdir,
                    pin_token_provider=lambda: None,
                    upstream=("127.0.0.1", 1),
                    rediscover_chain=True,
                )
                proxy.port = my_port
                proxy.learn_next_hop()
                return _read_upstream(certdir, "next")
            finally:
                srv.shutdown()

        # timeout=10: `learn_next_hop` calls `_probe_next_hop` with its 1.0s
        # default, tight enough that a loaded runner's own thread scheduling
        # (not the network) can miss it — see `learn_next_hop`'s own
        # docstring (src/cswap_pin/proxy.py:17756-17758) for why the default
        # stays 1.0s in production.
        real_probe = pp._probe_next_hop
        pp._probe_next_hop = functools.partial(real_probe, timeout=10)
        try:
            # CONTROL: a hop that names no upstream must leave the record
            # alone.
            assert not _learned({"status": "ok"}), (
                "CONTROL FAILED: a hop reporting no upstream still got "
                "recorded"
            )
            # ...and a real one must be learned, unprompted.
            assert _learned({"https_proxy": "http://127.0.0.1:8118"}, 36301) == (
                "http://127.0.0.1:8118"
            ), (
                "a healthy hop was never asked what is behind it, so the "
                "chain stays single-hop and falls to DIRECT when that hop "
                "dies"
            )
            # A REFUSAL WRITES NOTHING, so a re-read returns whatever the
            # line above recorded. Assert on what is NOT written, not on an
            # empty read.
            assert _learned(
                {"https_proxy": "http://127.0.0.1:36301"}, 36301
            ) != "http://127.0.0.1:36301", (
                "the pin recorded ITSELF as its own next hop — every "
                "request would dial back into this daemon "
                "(9901 -> 36301 -> 9901)"
            )
        finally:
            pp._probe_next_hop = real_probe

        # AND THE WALK REFUSES ONE ALREADY ON DISK, written by an older
        # version or during the polluted window.
        write_upstream_hint(
            certdir, "http://127.0.0.1:9901", next_hop="http://127.0.0.1:36301",
        )
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        proxy.port = 36301
        dialled = [c.address for c in proxy._chain_candidates()]
        assert ("127.0.0.1", 36301) not in dialled, (
            f"the walk would dial the pin's own port: {dialled}"
        )
        assert ("127.0.0.1", 9901) in dialled, (
            f"CONTROL FAILED: dropping the loop also dropped the real hop: "
            f"{dialled}"
        )

    def case_a_chained_host_refuses_direct_when_every_hop_is_down(
        self, certdir, monkeypatch
    ):
        """A configured chain whose hops are all down is a 503, never DIRECT.

        MEASURED 2026-09-07 04:11-04:33Z on the linux host: the local hops
        (cache proxy 9901, privoxy 8118) stopped accepting under a load storm,
        `_connect_upstream` fell through to `_dial_with_no_chain` 49 times, the
        direct route was the corporate TLS-inspecting proxy, and it answered
        403 "Access restricted by network policy" to every API and Remote
        Control request. Claude Code renders a 403 as "Please run /login",
        clears goals and kills subagents. A 503 with Retry-After is retried.

        The opt-in `CSWAP_PIN_ALLOW_DIRECT=1` is the CONTROL: with it the old
        fall-through dials direct, which proves the refusal is the only thing
        that changed and the chain walk still ran.
        """
        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import NoChainHopError, PinProxy, write_upstream_hint

        # A configured hop nothing listens on: port 1 refuses instantly.
        write_upstream_hint(certdir, "http://127.0.0.1:1")
        monkeypatch.setattr(pin_proxy, "_CHAIN_HEAL_GRACE_S", 0.2)
        monkeypatch.setattr(pin_proxy, "_CHAIN_HEAL_POLL_S", 0.05)
        dialled = []

        def _direct(upstream, timeout=15):
            dialled.append(upstream)
            raise OSError("the direct dial is the thing under test")

        monkeypatch.setattr(pin_proxy, "_dial_with_no_chain", _direct)
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        assert proxy._chain_candidates(), "premise: this host has a chain"

        with pytest.raises(NoChainHopError):
            proxy._connect_upstream()
        assert dialled == [], (
            f"a host with a configured chain dialled DIRECT: {dialled}"
        )
        assert proxy._egress_refused is True, "the refusal was not noted"
        assert proxy._egress_refused_last is not None, (
            "the refusal left no sticky timestamp — a probe arriving after "
            "the chain heals would see nothing happened"
        )

        # CONTROL: the opt-in restores the fall-through, same walk, same hops.
        monkeypatch.setenv("CSWAP_PIN_ALLOW_DIRECT", "1")
        with pytest.raises(OSError):
            proxy._connect_upstream()
        assert dialled == [("127.0.0.1", 1)], (
            f"CONTROL FAILED: the opt-in did not reach the direct dial: {dialled}"
        )

    def case_a_chained_host_refuses_the_connect_tunnel_when_every_hop_is_down(
        self, certdir, monkeypatch
    ):
        """The same rule at the CONNECT path: Remote Control's WebSocket
        receives over a tunnel to the ingress host, not the MITM'd
        api.anthropic.com, so it is `_blind_tunnel` and not `_connect_upstream`
        that dials on that host's behalf. MEASURED 2026-09-07 04:11-04:33Z on
        the linux host: this is the path that reached the corporate
        TLS-inspecting proxy directly when every configured hop was down.
        """
        import socket as socket_module

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        # A configured hop nothing listens on: port 1 refuses instantly.
        write_upstream_hint(certdir, "http://127.0.0.1:1")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        real_create_connection = socket_module.create_connection
        dialled = []

        def _create_connection(address, *a, **kw):
            if address == ("127.0.0.1", 1):
                # The hop dial itself: real, so the walk exhausts it exactly
                # as it would in production and lands on the fall-through
                # under test.
                return real_create_connection(address, *a, **kw)
            dialled.append(address)
            raise OSError("the direct dial is the thing under test")

        monkeypatch.setattr(
            pin_proxy.socket, "create_connection", _create_connection
        )
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        assert proxy._chain_candidates(), "premise: this host has a chain"
        proxy.start()
        try:
            raw = socket_module.socket(
                socket_module.AF_INET, socket_module.SOCK_STREAM
            )
            raw.settimeout(10)
            raw.connect(("127.0.0.1", proxy.port))
            raw.sendall(
                b"CONNECT rc-ingress.example.test:443 HTTP/1.1\r\n"
                b"Host: rc-ingress.example.test:443\r\n\r\n"
            )
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                resp += chunk
            raw.close()

            assert resp.split(b"\r\n")[0] == b"HTTP/1.1 503 Service Unavailable", (
                f"a chained host must answer 503, never dial direct on the "
                f"CONNECT path: {resp[:120]!r}"
            )
            assert dialled == [], (
                f"a host with a configured chain dialled DIRECT: {dialled}"
            )
            assert proxy._egress_refused is True, "the refusal was not noted"

            # CONTROL: the opt-in restores the fall-through, same walk, same
            # target — proves the refusal is what changed, not the tunnel.
            monkeypatch.setenv("CSWAP_PIN_ALLOW_DIRECT", "1")
            raw = socket_module.socket(
                socket_module.AF_INET, socket_module.SOCK_STREAM
            )
            raw.settimeout(10)
            raw.connect(("127.0.0.1", proxy.port))
            raw.sendall(
                b"CONNECT rc-ingress.example.test:443 HTTP/1.1\r\n"
                b"Host: rc-ingress.example.test:443\r\n\r\n"
            )
            resp2 = raw.recv(4096)
            raw.close()

            # Asserted BEFORE stop(): stop() wakes its own accept() loop with
            # a loopback self-connect, which is a real call to the same
            # patched name and would otherwise show up as a second entry.
            assert resp2 == b"", (
                "CONTROL FAILED: the closed direct dial should drop the "
                f"tunnel with no response, got {resp2!r}"
            )
            assert dialled == [("rc-ingress.example.test", 443)], (
                f"CONTROL FAILED: the opt-in did not reach the direct dial: "
                f"{dialled}"
            )
        finally:
            proxy.stop()

    def case_a_host_with_no_chain_pays_nothing_for_the_heal_grace(self, certdir):
        """The grace is for a hop that is RESTARTING, not for having no hop.

        `_CHAIN_HEAL_GRACE_S` waits out a cache proxy coming back under a new
        pid (~1s, measured). A host with no chain configured has nothing to
        wait for — `_walk_chain_once` returns None instantly on an empty
        candidate list — and the loop still slept out 13 polls before the
        direct dial that was always the answer.

        MEASURED: 2.60s per `_connect_upstream`, which is per new MITM
        connection AND per bridge-sweep API call, on exactly the machines
        (no corporate proxy, no cache proxy) where direct IS the normal path.

        The constant's own comment claimed the opposite — "a host with no
        chain at all never enters this loop, because an empty candidate list
        falls straight through" — so the code and the comment disagreed and
        the comment was the one being believed.
        """
        import time

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PinProxy

        # THE SHIPPED GRACE, not the shrunken one conftest installs for speed.
        # With the test value (0.3s) the stall is 0.31s and reads as noise;
        # the defect is only visible at the value users actually run.
        keep = (pin_proxy._CHAIN_HEAL_GRACE_S, pin_proxy._CHAIN_HEAL_POLL_S)
        pin_proxy._CHAIN_HEAL_GRACE_S = 2.5
        pin_proxy._CHAIN_HEAL_POLL_S = 0.2

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        assert proxy._chain_candidates() == [], "premise: this host has no chain"

        started = time.monotonic()
        try:
            proxy._connect_upstream()
        except OSError:
            pass  # nothing listens on port 1; the TIMING is what is asserted
        finally:
            pin_proxy._CHAIN_HEAL_GRACE_S, pin_proxy._CHAIN_HEAL_POLL_S = keep
        elapsed = time.monotonic() - started
        assert elapsed < 1.0, (
            f"a chainless host paid {elapsed:.2f}s of heal grace per upstream "
            f"dial — there was never a hop to wait for"
        )

    def case_a_hop_that_comes_back_is_waited_for_not_bypassed(self, certdir):
        """A hop RESTARTING is not a hop that is gone.

        Measured on the cache proxy's deployed build, hammered across a
        `kill -9` of its holder: refused=32, accepted-then-silent=0, served=159
        — it returns in ~1s under a new pid and REFUSES throughout. A refused
        dial costs the walk nothing, so waiting is nearly free, while the
        direct fallback on host-a is the corporate TLS inspector.
        """
        from cswap_pin.proxy import PinProxy

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        sentinel = object()
        attempts = []

        def _walk():
            attempts.append(1)
            return sentinel if len(attempts) >= 3 else None

        proxy._walk_chain_once = _walk
        # A CANDIDATE MUST EXIST for the grace to apply at all: an empty list
        # means "no chain on this host" and falls straight through, which is
        # the sibling case above.
        proxy._chain_candidates = lambda: [object()]
        assert proxy._connect_upstream() is sentinel, (
            "the relay bypassed a hop that came back inside the grace period"
        )
        assert len(attempts) == 3, f"walked {len(attempts)} times, expected 3"

    def case_a_socket_the_selector_cannot_drive_still_carries_bytes(self):
        """The fallback for an undrivable socket must not be the selector.

        `_pump_detached` asks `_PumpLoop.can_take` and falls back to `_pump`
        for a socket the selector cannot drive — an `https://` chain hop
        (`_TLSInTLS`), which has no `setblocking`. But `_pump` was rewritten
        to be `_PUMP.add` plus an Event, so the fallback re-entered the very
        call that cannot take it and raised the same AttributeError. Measured
        on the shipped code:

            can_take: False
            fallback RAISED: AttributeError ... has no attribute 'setblocking'

        AttributeError is not in `_handle_one_request`'s except tuple, so it
        escapes and kills the connection: behind a TLS egress proxy that is
        Remote Control's inbound WebSocket dying on every launch — the exact
        failure `can_take` was added to prevent.

        THE CONTROL is the same shuttle over a plain socketpair, which the
        selector CAN take. Without it a fallback that silently carried
        nothing would read as a pass.
        """
        import socket
        import threading

        from cswap_pin.proxy import _PumpLoop, _pump_detached

        class _NoSetblocking:
            """`_TLSInTLS`'s surface: no `setblocking`, hence undrivable."""

            def __init__(self, sock):
                self._sock = sock

            def sendall(self, data):
                return self._sock.sendall(data)

            def recv(self, n=65536):
                return self._sock.recv(n)

            def fileno(self):
                return self._sock.fileno()

            def close(self):
                return self._sock.close()

        def _carries(wrap):
            """Bytes both ways through one tunnel. Returns what arrived."""
            feed, a = socket.socketpair()
            b, sink = socket.socketpair()
            closed = threading.Event()
            threading.Thread(
                target=_pump_detached, args=(wrap(a), wrap(b), closed.set),
                daemon=True,
            ).start()
            try:
                feed.sendall(b"ping")
                sink.settimeout(3)
                try:
                    return sink.recv(16)
                except (socket.timeout, OSError):
                    return b""
            finally:
                for s in (feed, a, b, sink):
                    try:
                        s.close()
                    except OSError:
                        pass

        assert _PumpLoop.can_take(_NoSetblocking(socket.socket())) is False, (
            "the shim is drivable after all — this case proves nothing"
        )
        assert _carries(lambda s: s) == b"ping", (
            "CONTROL FAILED: a plain socketpair carried nothing, so the "
            "undrivable result below says nothing about the fallback"
        )
        assert _carries(_NoSetblocking) == b"ping", (
            "a socket the selector cannot drive carried nothing — the "
            "fallback routed back into the selector that had just refused it"
        )

    def case_one_stalled_peer_does_not_stop_every_other_tunnel(self, certdir):
        """The shared pump must not re-couple what it decoupled.

        Removing the thread-per-connection put every tunnel on ONE selector
        thread. If that thread can block inside a write while holding the lock
        that `add` also takes, a single peer that stops reading stalls every
        other tunnel and every new one — the same "one bad connection stops
        everything" property, moved from thread count to a global mutex.

        A peer that stops reading is not hypothetical: it is a wedged hop, a
        stalled upstream, or a client that stopped draining, which is the
        exact condition the outage this class was written for produced.
        """
        import socket
        import threading
        import time

        from cswap_pin.proxy import _PumpLoop

        pump = _PumpLoop()

        def _pair():
            a, b = socket.socketpair()
            return a, b

        # TUNNEL 1: its far end never reads, so the pump's write will block
        # once the socket buffer fills.
        feed_1, in_1 = _pair()
        out_1, stuck_1 = _pair()
        pump.add(in_1, out_1)
        # Fill until OUR OWN send would block: by then the pump is inside its
        # write to a peer that is not reading, which is the condition. A
        # timeout, not sendall, or this test wedges on the same buffer.
        feed_1.setblocking(False)
        try:
            for _ in range(256):
                feed_1.send(b"x" * 65536)
        except (BlockingIOError, OSError):
            pass
        time.sleep(0.3)

        # TUNNEL 2: perfectly healthy, added AFTER the stall exists.
        started = time.monotonic()
        feed_2, in_2 = _pair()
        out_2, sink_2 = _pair()
        pump.add(in_2, out_2)                  # must not block on tunnel 1
        add_took = time.monotonic() - started

        feed_2.sendall(b"ping")
        sink_2.settimeout(3)
        try:
            got = sink_2.recv(16)
        except socket.timeout:
            got = b""

        for s in (feed_1, in_1, out_1, stuck_1, feed_2, in_2, out_2, sink_2):
            try:
                s.close()
            except OSError:
                pass

        assert add_took < 1.0, (
            f"registering a new tunnel waited {add_took:.1f}s on an unrelated "
            f"stalled one — the lock is held across the write"
        )
        assert got == b"ping", (
            "a healthy tunnel carried nothing while another peer stopped "
            "reading — one stalled connection stops them all"
        )

    def case_connections_do_not_become_threads(self, tmp_path, monkeypatch):
        """CONNECTIONS MUST NOT BECOME THREADS.

        MEASURED OUTAGE, host-a: the cache hop died and the pin served 27,491
        threads / 44,121 FDs in 40 minutes; load on a 48-core box reached
        16,483 and it was rescued by hand. The mechanism, measured here on the
        daemon before this changed, hop wedged and counted from OUTSIDE the
        process:

            idle          4 threads
             50 conns ->  54 threads
            150 conns -> 154 threads
            300 conns -> 304 threads

        Exactly 1:1, so the retry count IS the thread count. A ceiling was
        tried and removed: it turns the 257th retry into a refused connection
        while the coupling stays.

        COUNTED FROM ANOTHER PROCESS, deliberately. Every in-process count is
        wrong here — `threading.active_count()` also counts this test's own
        opener threads, which are the same order of magnitude as the thing
        being measured, and it read "grew=0" while every connection had its
        own server thread.

        WHAT THIS TEST DOES NOT PROVE, stated because a green test that cannot
        fail is worse than no test. Reverting the detach in `_blind_tunnel`
        leaves this case PASSING, while the same control run through
        `tools/thread_probe.py` reports 305 threads against 5. The probe is the
        instrument; this is a smoke check that the daemon still serves 300
        concurrent tunnels without the count exploding. Why the two disagree is
        open — do not read a pass here as evidence the coupling is gone.
        """
        import os
        import socket
        import threading

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        # BOUND THE SPAWN WAIT. The default polls 10s for the child to
        # publish, and a holder that appears after this case has reaped lives
        # forever — measured, 2 orphans a run from exactly that window.
        monkeypatch.setattr(pin_proxy, "_SPAWN_WAIT_S", 1.5)
        # TRACK THE CHILD AT BIRTH. Reaping by certdir afterwards races the
        # spawn — `_spawn_daemon` returns when the state file appears, but the
        # HOLDER it started keeps going, and one born a moment later was in no
        # sweep. Measured: 2 orphans a run surviving a reap that found nothing.
        import subprocess as _sp

        started = []
        _real_popen = _sp.Popen

        def _tracked(*a, **k):
            proc = _real_popen(*a, **k)
            started.append(proc)
            return proc

        _sp.Popen = _tracked
        try:
            port = pin_proxy._spawn_daemon("1", "a@example.com", tmp_path)
        finally:
            _sp.Popen = _real_popen
        assert port, "the daemon did not come up"
        st = pin_proxy.read_daemon_state(tmp_path)
        pid = int(st["pid"])

        def _threads():
            try:
                with open(f"/proc/{pid}/status") as fh:
                    for line in fh:
                        if line.startswith("Threads:"):
                            return int(line.split()[1])
            except OSError:
                pass
            return -1

        if _threads() < 0:
            return  # not Linux: /proc is the only portable answer here

        # THE FAR END OF THE TUNNEL, local and idle. The outage's connections
        # were OPEN TUNNELS, not half-finished handshakes: pointing them at
        # `api.anthropic.com` instead measures `wrap_socket` waiting for a TLS
        # ClientHello this test never sends, which is a different thread and a
        # different bug.
        far = socket.socket()
        far.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        far.bind(("127.0.0.1", 0))
        far.listen(512)
        far_port = far.getsockname()[1]

        def _accept_forever():
            while True:
                try:
                    far.accept()
                except OSError:
                    return

        threading.Thread(target=_accept_forever, daemon=True).start()

        held, lock = [], threading.Lock()

        def _hold():
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                s.sendall(
                    f"CONNECT 127.0.0.1:{far_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{far_port}\r\n\r\n".encode()
                )
                if b"200" not in s.recv(200):
                    return
                with lock:
                    held.append(s)
                s.recv(65536)   # park on an OPEN tunnel
            except OSError:
                pass

        idle = _threads()
        try:
            deadline = time.time() + 20
            while time.time() < deadline and len(held) < 300:
                want = 300 - len(held)
                for t in [threading.Thread(target=_hold, daemon=True)
                          for _ in range(want)]:
                    t.start()
                for _ in range(40):
                    if len(held) >= 300:
                        break
                    time.sleep(0.05)
            # SETTLE FIRST. A connection mid-setup still has its thread —
            # it is handed to the shared pump only once the tunnel is open —
            # so counting the instant the last one lands measures the ramp,
            # not the steady state this is about. Measured: 26 threads while
            # connecting, 5 a moment later, for the same 300 tunnels.
            time.sleep(1)
            live, grew = len(held), _threads() - idle
            assert live >= 250, f"only {live} connections landed; not loaded"
            assert grew < 20, (
                f"{live} connections cost {grew} threads (idle was {idle}) — "
                f"connections still become threads, which is what took the box "
                f"down"
            )
        finally:
            for s in held:
                try:
                    s.close()
                except OSError:
                    pass
            # PARENTS FIRST. `_spawn_daemon` starts a HOLDER, whose job is
            # to replace a daemon that dies — so killing `pid` alone gets it
            # replaced, and this case leaked 38 processes in one suite run.
            for proc in started:          # PARENTS FIRST: these are holders
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                except Exception:  # noqa: BLE001 — gone, or too slow
                    try:
                        proc.kill()
                    except Exception:  # noqa: BLE001
                        pass
            from conftest import _reap_pin_processes

            _reap_pin_processes(tmp_path)
            far.close()

    def case_health_reports_the_chain_the_relay_would_use(self, certdir):
        """A probe that says "no chain" while every request goes through one
        sends the next diagnosis the wrong way. Measured after a cc-update
        recycle: /health said chain=null with CCF live and recorded on disk."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        write_upstream_hint(certdir, None)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        proxy.start()
        try:
            write_upstream_hint(certdir, "http://127.0.0.1:9901")
            conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            conn.request("GET", "/health")
            body = json.loads(conn.getresponse().read())
            conn.close()
            assert body["chain"] == "127.0.0.1:9901"
        finally:
            proxy.stop()

    def case_ignores_a_hint_pointing_at_our_own_port(self, tmp_path):
        """A shell that eval'd pin-env exports the pin proxy as HTTPS_PROXY.
        Recording that would make the daemon CONNECT to itself."""
        from cswap_pin.proxy import _ambient_proxy

        env = {"HTTPS_PROXY": "http://127.0.0.1:45678", "CSWAP_PIN_PORT": "45678"}
        assert _ambient_proxy(env) is None
        # A DIFFERENT loopback proxy (CCF) is a legitimate chain.
        env = {"HTTPS_PROXY": "http://127.0.0.1:9901", "CSWAP_PIN_PORT": "45678"}
        assert _ambient_proxy(env) == "http://127.0.0.1:9901"

    def _dead_port(self) -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        assert port != 36301, port
        return port

    def _refusing_chain(self):
        """Accepts the CONNECT and answers 502 — a restarting cache proxy,
        whose listener is up before its proxy logic is ready."""
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        # BACKLOG, NOT 4. A full accept queue makes `connect()` to a LISTENING
        # loopback socket time out rather than refuse, and the daemon then logs
        # `hop unusable — dial failed: TimeoutError`, never reaches accept, and
        # the case's premise (`seen`) is empty. That is what turned CI red on
        # macos-latest for 0.1.94 while 33 consecutive Linux runs were green:
        #     hop 127.0.0.1:49793 unusable — dial failed: TimeoutError('timed out')
        # Loopback refusal is instant on Linux, so the queue never built there.
        # This class drives 23 cases through the same helper on a shared
        # runner; 128 costs nothing and removes the queue as a variable.
        srv.listen(128)
        assert srv.getsockname()[1] != 36301, srv.getsockname()
        seen = []

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                seen.append(1)
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    c.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        return srv, srv.getsockname()[1], seen

    def _proxy_over(self, certdir, tmp_path, first_url, next_url, monkeypatch):
        """A daemon whose recorded chain is ``first_url`` with ``next_url``
        behind it, pointed at an upstream signed by a CA it CANNOT trust.

        The foreign CA is the discriminator: verification is skipped only for a
        loopback hop, so a 200 proves the request went through a recorded hop
        and a refusal proves it did not.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        foreign = tmp_path / "foreign"
        foreign.mkdir(exist_ok=True)
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)

        write_upstream_hint(certdir, first_url, next_hop=next_url)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        proxy.start()
        assert proxy.port != 36301, proxy.port
        return proxy, upstream

    def case_the_log_names_the_hop_that_carried_and_stays_quiet_after(
        self, certdir
    ):
        """Falling through a dead hop is silent, so a request carried by the
        second hop and one carried by the first read identically. An observer
        had to infer it afterwards from the TLS issuer.

        The transition is logged, not the state: a steady chain costs nothing
        per connection, and losing a hop is visible the moment it happens.
        """
        import contextlib
        import io

        from cswap_pin import proxy as pin_proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        good = socket.socket()
        good.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        good.bind(("127.0.0.1", 0))
        good.listen(4)
        good_port = good.getsockname()[1]

        def _answer():
            while True:
                try:
                    conn, _ = good.accept()
                except OSError:
                    return
                try:
                    conn.recv(8192)
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except OSError:
                    pass

        threading.Thread(target=_answer, daemon=True).start()
        try:
            relay = pin_proxy.PinProxy(certdir, lambda: "tok")
            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", dead_port)),
                pin_proxy._as_chain(("127.0.0.1", good_port)),
            ]

            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sock, _ = relay._connect_upstream()
                sock.close()
            first = [l for l in buf.getvalue().splitlines() if "egress" in l]
            assert first, "the walk said nothing about which hop carried it"
            assert str(good_port) in first[0], first

            # The SAME hop again must be silent, or every connection logs.
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sock, _ = relay._connect_upstream()
                sock.close()
            assert not [
                l for l in buf.getvalue().splitlines() if "egress" in l
            ], "an unchanged chain logged again"

            # And with no hop left, the refusal is named (direct is not
            # dialled on a host with a chain; see NoChainHopError).
            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", dead_port))
            ]
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                try:
                    sock, _ = relay._connect_upstream()
                    sock.close()
                except OSError:
                    pass
            assert any(
                "REFUSED" in l for l in buf.getvalue().splitlines()
            ), buf.getvalue()
        finally:
            good.close()

    def case_a_host_with_no_proxy_chain_is_not_reported_as_degraded(
        self, certdir
    ):
        """"Nothing is configured" is not "nothing is reachable".

        On a host with no corporate proxy — and no cache proxy either — there
        is no chain to walk, so a direct dial is the ONLY thing a pin can do
        and it is the NORMAL path, not a downgrade. The line said otherwise:
        the same "no chain hop reachable, bypassing the configured proxy
        chain" that a genuinely dead hop produces. On such a host that
        sentence is the steady state and it is false twice over — nothing was
        unreachable, and there is no configured chain to bypass. Anyone
        reading it alone calls a healthy machine degraded.

        The two must be distinguishable in the log, because they need
        opposite responses: one is "go look at your egress proxy", the other
        is "this is how this machine is".
        """
        import contextlib
        import io

        from cswap_pin import proxy as pin_proxy

        # A reachable stand-in for the origin, so the direct dial COMPLETES
        # and the line under test is actually emitted.
        sink = socket.socket()
        sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sink.bind(("127.0.0.1", 0))
        sink.listen(4)
        def _accept_until_closed():
            """Accept and CLOSE, and stop when the listener goes.

            The comprehension this replaces held every accepted socket for the
            life of the session and raised out of the thread at teardown. A
            leaked descriptor per connection is affordable on a laptop and is
            not on a CI runner running four workers against a much smaller
            limit — and the way that failure arrives is a dead worker and an
            INTERNALERROR that names no test.
            """
            while True:
                try:
                    conn, _ = sink.accept()
                except OSError:
                    return  # the listener closed at test end; that is the exit
                conn.close()

        threading.Thread(target=_accept_until_closed, daemon=True).start()

        def _egress_line(candidates):
            relay = pin_proxy.PinProxy(certdir, lambda: "tok")
            relay._chain_candidates = lambda: candidates
            relay._upstream = ("127.0.0.1", sink.getsockname()[1])
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                try:
                    sock, _ = relay._connect_upstream()
                    sock.close()
                except OSError:
                    pass
            lines = [l for l in buf.getvalue().splitlines() if "egress" in l]
            return lines[-1] if lines else ""

        try:
            dead = socket.socket()
            dead.bind(("127.0.0.1", 0))
            dead_port = dead.getsockname()[1]
            dead.close()

            unconfigured = _egress_line([])
            degraded = _egress_line(
                [pin_proxy._as_chain(("127.0.0.1", dead_port))]
            )

            assert unconfigured, "a direct dial said nothing at all"
            assert degraded, "a dead hop said nothing at all"
            assert unconfigured != degraded, (
                f"a host with NO chain configured and a host whose chain is "
                f"DEAD produced the same line — the first is normal and the "
                f"second needs attention: {unconfigured!r}"
            )
            # And specifically: the normal case must not claim something was
            # unreachable, or that a configured chain was bypassed.
            assert "reachable" not in unconfigured, unconfigured
            assert "bypass" not in unconfigured, unconfigured
        finally:
            sink.close()

    def case_the_log_separates_a_refused_hop_from_one_that_answered_wrong(
        self, certdir
    ):
        """Two faults, one fall-through — and they belong to different owners.

        A hop whose PORT is dead and a hop that accepts and then will not
        tunnel are the same `continue` in the walk, and the log said the same
        nothing about both. They are opposite findings for whoever runs that
        hop: the first says its listener was down, the second says its
        listener was up and its logic was not. A supervisor that holds the
        port across restarts is a claim about exactly the first, so a log that
        cannot tell them apart cannot confirm or refute it.
        """
        import contextlib
        import io

        from cswap_pin import proxy as pin_proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        # Up, and answers CONNECT with a refusal — a proxy mid-restart whose
        # listener is live before its proxy logic is.
        rude = socket.socket()
        rude.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rude.bind(("127.0.0.1", 0))
        rude.listen(4)
        rude_port = rude.getsockname()[1]

        def _refuse():
            while True:
                try:
                    conn, _ = rude.accept()
                except OSError:
                    return
                try:
                    conn.recv(8192)
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    conn.close()
                except OSError:
                    pass

        threading.Thread(target=_refuse, daemon=True).start()
        try:
            relay = pin_proxy.PinProxy(certdir, lambda: "tok")

            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", dead_port))
            ]
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                try:
                    sock, _ = relay._connect_upstream()
                    sock.close()
                except OSError:
                    pass
            refused_lines = [
                l for l in buf.getvalue().splitlines()
                if f"{dead_port} unusable" in l
            ]
            assert refused_lines, (
                f"a hop whose port is dead was skipped silently: "
                f"{buf.getvalue()!r}")
            assert "dial failed" in refused_lines[0], refused_lines

            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", rude_port))
            ]
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                try:
                    sock, _ = relay._connect_upstream()
                    sock.close()
                except OSError:
                    pass
            wrong_lines = [
                l for l in buf.getvalue().splitlines()
                if f"{rude_port} unusable" in l
            ]
            assert wrong_lines, (
                f"a hop that answered and refused to tunnel was skipped "
                f"silently: {buf.getvalue()!r}")
            assert "dial failed" not in wrong_lines[0], (
                "a hop that ANSWERED was reported as a dead port — the two "
                "faults are indistinguishable again")
            assert "502" in wrong_lines[0], wrong_lines
            assert "api.anthropic.com:443" in wrong_lines[0], wrong_lines
        finally:
            rude.close()

    def case_the_absolute_form_dial_logs_the_hop_reason_before_REFUSED(
        self, certdir, monkeypatch
    ):
        """`_plain_relay`'s own `dial()` walks the chain exactly like
        `_walk_chain_once`, but its `except (OSError, ssl.SSLError): continue`
        never called `_note_hop_unusable` — so the `egress REFUSED` line this
        path also emits landed with no hop reason above it to explain why.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        dead = self._dead_port()
        write_upstream_hint(certdir, f"http://127.0.0.1:{dead}")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", dead),
            rediscover_chain=True,
        )
        assert proxy._chain_candidates(), "premise: this host has a chain"
        proxy.start()
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                raw = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                raw.settimeout(10)
                raw.sendall(
                    b"GET http://example.com/x HTTP/1.1\r\n"
                    b"Host: example.com\r\n\r\n"
                )
                resp = b""
                try:
                    while b"\r\n\r\n" not in resp:
                        chunk = raw.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                finally:
                    raw.close()
        finally:
            proxy.stop()
        lines = buf.getvalue().splitlines()
        unusable = [i for i, l in enumerate(lines) if f"{dead} unusable" in l]
        refused = [i for i, l in enumerate(lines) if "egress REFUSED" in l]
        assert unusable, f"no hop-unusable line at all: {buf.getvalue()!r}"
        assert refused, f"no REFUSED line at all: {buf.getvalue()!r}"
        assert "dial failed" in lines[unusable[0]], lines[unusable[0]]
        assert unusable[0] < refused[0], (
            "the hop reason must precede the REFUSED it explains: "
            f"{buf.getvalue()!r}")

    def case_the_blind_tunnel_dial_failure_logs_before_REFUSED(
        self, certdir, monkeypatch
    ):
        """`_blind_tunnel` is the OTHER walk that can emit `egress REFUSED`
        (Remote Control's own path). A dead hop's dial failure must reach
        `_note_hop_unusable`, not just the trace FILE (`_tunnel_trace`), so
        the REFUSED line it also emits carries a hop reason in the daemon
        log above it."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        dead = self._dead_port()
        write_upstream_hint(certdir, f"http://127.0.0.1:{dead}")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        proxy = PinProxy(
            certdir=certdir, pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        proxy.start()
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                raw = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                raw.settimeout(10)
                raw.sendall(
                    b"CONNECT rc-ingress.example.com:443 HTTP/1.1\r\n"
                    b"Host: rc-ingress.example.com:443\r\n\r\n"
                )
                resp = b""
                try:
                    while b"\r\n\r\n" not in resp:
                        chunk = raw.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                finally:
                    raw.close()
        finally:
            proxy.stop()
        lines = buf.getvalue().splitlines()
        unusable = [i for i, l in enumerate(lines) if f"{dead} unusable" in l]
        refused = [i for i, l in enumerate(lines) if "egress REFUSED" in l]
        assert unusable, f"no hop-unusable line at all: {buf.getvalue()!r}"
        assert refused, f"no REFUSED line at all: {buf.getvalue()!r}"
        assert "dial failed" in lines[unusable[0]], lines[unusable[0]]
        assert unusable[0] < refused[0], (
            "the hop reason must precede the REFUSED it explains: "
            f"{buf.getvalue()!r}")

    def case_the_blind_tunnel_CONNECT_refusal_names_the_reason(
        self, certdir, monkeypatch
    ):
        """A second `_blind_tunnel` fall-through, distinct from a dead dial:
        a hop that ACCEPTS the CONNECT and answers non-200 — a cache proxy
        mid-restart. The reason logged must say so, not read as a dead
        port."""
        refusing, refusing_port, seen = self._refusing_chain()
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        write_upstream_hint(certdir, f"http://127.0.0.1:{refusing_port}")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        proxy = PinProxy(
            certdir=certdir, pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        proxy.start()
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                raw = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                raw.settimeout(10)
                raw.sendall(
                    b"CONNECT rc-ingress.example.com:443 HTTP/1.1\r\n"
                    b"Host: rc-ingress.example.com:443\r\n\r\n"
                )
                resp = b""
                try:
                    while b"\r\n\r\n" not in resp:
                        chunk = raw.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                finally:
                    raw.close()
        finally:
            proxy.stop()
            refusing.close()
        wrong_lines = [
            l for l in buf.getvalue().splitlines()
            if f"{refusing_port} unusable" in l
        ]
        assert wrong_lines, (
            f"a hop that answered and refused to tunnel was skipped "
            f"silently: {buf.getvalue()!r}")
        assert "dial failed" not in wrong_lines[0], (
            "a hop that ANSWERED was reported as a dead port")
        assert "accepted but did not tunnel" in wrong_lines[0], wrong_lines
        assert "CONNECT ->" in wrong_lines[0], wrong_lines
        assert "rc-ingress.example.com:443" in wrong_lines[0], wrong_lines

    def case_an_empty_authority_CONNECT_is_refused_400_and_judges_no_hop(
        self, certdir, monkeypatch
    ):
        """Measured on lmd42-docker, 2026-09-15: some client on the host sent
        a 17-byte `CONNECT  HTTP/1.1` (empty authority — 3 tokens: `CONNECT`,
        ``, `HTTP/1.1`). `_handle_client` used to trace-log it and still hand
        the empty target to `_blind_tunnel`, which dialled every hop with
        `CONNECT  HTTP/1.1`; each hop refused in its own dialect, writing two
        FALSE `hop unusable` lines and one FALSE `egress REFUSED`, and the
        client got a 503 — one garbage request marking the whole pin's
        egress refused. It must now be answered 400 before any hop is asked.
        """
        refusing, refusing_port, seen = self._refusing_chain()
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        write_upstream_hint(certdir, f"http://127.0.0.1:{refusing_port}")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        proxy = PinProxy(
            certdir=certdir, pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        proxy.start()
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                raw = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                raw.settimeout(10)
                raw.sendall(b"CONNECT  HTTP/1.1\r\n\r\n")
                resp = b""
                try:
                    while b"\r\n\r\n" not in resp:
                        chunk = raw.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                finally:
                    raw.close()
        finally:
            proxy.stop()
            refusing.close()
        assert resp.startswith(b"HTTP/1.1 400 Bad Request"), resp
        lines = buf.getvalue().splitlines()
        assert not [l for l in lines if "unusable" in l], (
            f"an empty-authority CONNECT judged a hop: {buf.getvalue()!r}")
        assert not [l for l in lines if "egress REFUSED" in l], (
            f"an empty-authority CONNECT marked egress refused: "
            f"{buf.getvalue()!r}")
        assert proxy._egress_refused is False
        assert seen == [], "a hop was dialled for an empty-authority CONNECT"

    def case_an_empty_host_with_a_port_is_refused_the_same_way(
        self, certdir, monkeypatch
    ):
        """`CONNECT :443 HTTP/1.1` has a non-empty TARGET (`:443`) but an
        EMPTY HOST once split on `:` — the same host `_blind_tunnel` would
        dial as the fully-empty shape. A check on `target` alone lets this
        one through; the check has to read the host `_blind_tunnel` actually
        uses."""
        refusing, refusing_port, seen = self._refusing_chain()
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        write_upstream_hint(certdir, f"http://127.0.0.1:{refusing_port}")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        proxy = PinProxy(
            certdir=certdir, pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        proxy.start()
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                raw = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                raw.settimeout(10)
                raw.sendall(b"CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n")
                resp = b""
                try:
                    while b"\r\n\r\n" not in resp:
                        chunk = raw.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                finally:
                    raw.close()
        finally:
            proxy.stop()
            refusing.close()
        assert resp.startswith(b"HTTP/1.1 400 Bad Request"), resp
        assert seen == [], "a hop was dialled for an empty-host CONNECT"

    def case_the_blind_tunnel_EOF_after_200_logs_the_reason(
        self, certdir, monkeypatch
    ):
        """A FOURTH fall-through in the same function: a hop that ACCEPTS the
        CONNECT, answers 200, and then closes before carrying anything — a
        filtering proxy that answers optimistically and dials afterwards,
        closing when that dial fails (`_tunnel_is_open` catches exactly
        this). That path also fell through to `egress REFUSED` with no hop
        reason above it.
        """
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        srv_port = srv.getsockname()[1]

        def _serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    seen = b""
                    while b"\r\n\r\n" not in seen:
                        d = c.recv(4096)
                        if not d:
                            break
                        seen += d
                    c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()  # accepted, answered 200, and EOF right after

        threading.Thread(target=_serve, daemon=True).start()
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        write_upstream_hint(certdir, f"http://127.0.0.1:{srv_port}")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        proxy = PinProxy(
            certdir=certdir, pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        proxy.start()
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                raw = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                raw.settimeout(10)
                raw.sendall(
                    b"CONNECT rc-ingress.example.com:443 HTTP/1.1\r\n"
                    b"Host: rc-ingress.example.com:443\r\n\r\n"
                )
                resp = b""
                try:
                    while b"\r\n\r\n" not in resp:
                        chunk = raw.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                finally:
                    raw.close()
        finally:
            proxy.stop()
            srv.close()
        lines = buf.getvalue().splitlines()
        unusable = [i for i, l in enumerate(lines) if f"{srv_port} unusable" in l]
        refused = [i for i, l in enumerate(lines) if "egress REFUSED" in l]
        assert unusable, f"no hop-unusable line at all: {buf.getvalue()!r}"
        assert "EOF" in lines[unusable[0]], lines[unusable[0]]
        assert "rc-ingress.example.com:443" in lines[unusable[0]], (
            lines[unusable[0]])
        assert refused, f"no REFUSED line at all: {buf.getvalue()!r}"
        assert unusable[0] < refused[0], (
            "the hop reason must precede the REFUSED it explains: "
            f"{buf.getvalue()!r}")

    def case_a_hop_that_recovers_then_faults_again_logs_a_second_line(
        self, certdir
    ):
        """`_hop_fault`'s dedup is on the (hop, reason) TRANSITION, and must
        be reset by that hop's own recovery — so a hop that goes down, comes
        back and carries a request, then goes down again with the SAME
        reason logs a second time, not silence. On a real daemon.log that
        read 12 REFUSED lines behind 3 `unusable` lines, and the incident
        could not be attributed to a specific outage window.

        THE SAME HOP, not a different one behind it: reset the dedup for
        every carrying hop and a chain with a persistently dead FIRST hop and
        a healthy SECOND one floods a line per connection again — the exact
        shape the dedup exists to prevent. So this pins the port itself going
        down, up, then down again, not two different candidates.
        """
        from cswap_pin import proxy as pin_proxy

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()  # nothing listens here yet — the hop starts DOWN

        relay = pin_proxy.PinProxy(certdir, lambda: "tok")
        relay._chain_candidates = lambda: [
            pin_proxy._as_chain(("127.0.0.1", port))
        ]

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            try:
                sock, _ = relay._connect_upstream()
                sock.close()
            except OSError:
                pass
        first = [
            l for l in buf.getvalue().splitlines() if f"{port} unusable" in l
        ]
        assert first, f"the first fault was not logged: {buf.getvalue()!r}"

        # THE SAME PORT RECOVERS: a listener bound to the identical address.
        good = socket.socket()
        good.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        good.bind(("127.0.0.1", port))
        good.listen(4)

        def _answer():
            while True:
                try:
                    conn, _ = good.accept()
                except OSError:
                    return
                try:
                    conn.recv(8192)
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except OSError:
                    pass

        threading.Thread(target=_answer, daemon=True).start()
        try:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sock, _ = relay._connect_upstream()
                sock.close()
            # premise: the hop carried, which is what should reset the dedup
        finally:
            good.close()

        # CONFIRM THE PORT IS ACTUALLY DOWN before the next walk — closing a
        # listening socket and a fresh connect racing it is not instantaneous
        # everywhere, and `_connect_upstream` itself retries for 2.5s, which
        # would silently ride out a slow teardown and mask the very thing
        # this phase means to pin.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            except OSError:
                break
            time.sleep(0.02)
        else:
            pytest.fail(f"port {port} never closed after good.close()")

        # THE SAME PORT GOES DOWN AGAIN, the identical reason.
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            try:
                sock, _ = relay._connect_upstream()
                sock.close()
            except OSError:
                pass
        second = [
            l for l in buf.getvalue().splitlines() if f"{port} unusable" in l
        ]
        assert second, (
            "the SAME fault recurring after the SAME hop recovered was "
            f"suppressed — _hop_fault's dedup is never reset by that hop's "
            f"own recovery: {buf.getvalue()!r}")

    def case_a_persistently_dead_first_hop_does_not_flood_once_the_second_carries(
        self, certdir
    ):
        """A reset that clears `_hop_fault` on ANY hop carrying — not just the
        one that faulted — reintroduces the flood the dedup exists to
        prevent: a chain [A dead, B up] would re-log A's fault on every
        connection, because B's carry re-arms the dedup before the next
        walk. The reset must be scoped to the hop that just recovered.
        """
        from cswap_pin import proxy as pin_proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        good = socket.socket()
        good.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        good.bind(("127.0.0.1", 0))
        good.listen(4)
        good_port = good.getsockname()[1]

        def _answer():
            while True:
                try:
                    conn, _ = good.accept()
                except OSError:
                    return
                try:
                    conn.recv(8192)
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except OSError:
                    pass

        threading.Thread(target=_answer, daemon=True).start()
        try:
            relay = pin_proxy.PinProxy(certdir, lambda: "tok")
            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", dead_port)),
                pin_proxy._as_chain(("127.0.0.1", good_port)),
            ]

            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sock, _ = relay._connect_upstream()
                sock.close()
            first = [
                l for l in buf.getvalue().splitlines()
                if f"{dead_port} unusable" in l
            ]
            assert first, f"the first fault was not logged: {buf.getvalue()!r}"

            # SAME unchanged chain, again: A is still dead, B still carries.
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sock, _ = relay._connect_upstream()
                sock.close()
            second = [
                l for l in buf.getvalue().splitlines()
                if f"{dead_port} unusable" in l
            ]
            assert not second, (
                "A's fault was re-logged after B merely carried again — B "
                f"recovering does not mean A did: {buf.getvalue()!r}")
        finally:
            good.close()

    def case_D1_a_chain_that_refuses_the_dial_uses_the_next_hop(
        self, certdir, tmp_path, monkeypatch
    ):
        """CCF is DOWN: nothing is listening on the recorded hop.

        The dial raises OSError and the code dropped to
        `socket.create_connection(self._upstream)` — a direct dial, i.e. the
        corporate inspector on this host. No error, nothing on screen.
        """
        outer = _LoopbackConnectProxy(("127.0.0.1", 0))
        dead = self._dead_port()
        proxy = upstream = None
        try:
            outer._target = None  # set below, once the upstream exists
            proxy, upstream = self._proxy_over(
                certdir, tmp_path,
                f"http://127.0.0.1:{dead}",
                f"http://127.0.0.1:{outer.port}",
                monkeypatch,
            )
            outer._target = ("127.0.0.1", upstream.port)
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert outer.connects == 1, (
                "the dead hop fell through to a DIRECT dial instead of to the "
                "hop behind it — on this host that is the corporate inspector"
            )
            assert status == 200, "the next hop was not usable"
        finally:
            if proxy:
                proxy.stop()
            if upstream:
                upstream.stop()
            outer.stop()

    def case_D2_a_chain_that_refuses_the_CONNECT_uses_the_next_hop(
        self, certdir, tmp_path, monkeypatch
    ):
        """CCF is RESTARTING: its listener is up, its proxy logic is not.

        `_connect_ok` is false, and the `raise OSError` that follows was caught
        by nobody — the `except OSError` wrapped only the dial. So a hop that
        accepts and then fails did not even reach the (wrong) direct fallback:
        it killed the request outright.
        """
        refusing, refusing_port, seen = self._refusing_chain()
        outer = _LoopbackConnectProxy(("127.0.0.1", 0))
        proxy = upstream = None
        try:
            outer._target = None
            proxy, upstream = self._proxy_over(
                certdir, tmp_path,
                f"http://127.0.0.1:{refusing_port}",
                f"http://127.0.0.1:{outer.port}",
                monkeypatch,
            )
            outer._target = ("127.0.0.1", upstream.port)
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            # THE PREMISE IS SAMPLED, AND A SAMPLE LOSES A RACE. `seen` is
            # appended by the stub's accept thread, which runs on its own
            # schedule — the request can return before that thread is
            # scheduled, and on a loaded runner it does. Poll briefly instead
            # of reading it once: a hop that really was never dialled stays
            # empty for the whole window and still fails, loudly.
            deadline = time.monotonic() + 3.0
            while not seen and time.monotonic() < deadline:
                time.sleep(0.02)
            assert seen, "premise: the refusing hop was never dialled"
            assert outer.connects == 1, (
                "a hop that ACCEPTED and then refused the CONNECT did not fall "
                "through at all — the OSError it raises is caught by nobody"
            )
            assert status == 200, "the next hop was not usable"
        finally:
            if proxy:
                proxy.stop()
            if upstream:
                upstream.stop()
            outer.stop()
            refusing.close()

    def case_a_plain_user_with_only_HTTPS_PROXY_still_chains_through_it(
        self, certdir, tmp_path, monkeypatch
    ):
        """NO cc-wrapper, NO launcher, NO upstream.json. Just a corp proxy.

        The composition every other test assumes is the one a plain
        `pip install` user never gets: something else wrote the chain record
        first. Here nothing has, and the only evidence a corp proxy exists is
        `HTTPS_PROXY` in the shell that runs `cswap pin`.

        If the pin ignored that, a user behind a corporate proxy would get
        pin -> DIRECT: a dead session where the firewall is closed, and a
        silent skip of inspection where it is open. Neither is acceptable for
        an optional feature, and neither is visible from outside.

        THE HOP MUST SEE THE TRAFFIC, not merely appear in a candidate list.
        A peer measured its own version of this with a fake proxy that
        ANSWERED the CONNECT instead of relaying it: the leg died before
        anything was logged and the fixture reported a bypass that was not
        happening. `_LoopbackConnectProxy` relays, and the assertion is on
        what it SAW.
        """
        from cswap_pin.proxy import PinProxy, _ambient_chain, write_upstream_hint

        foreign = tmp_path / "foreign"
        foreign.mkdir(exist_ok=True)
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)
        corp = _LoopbackConnectProxy(("127.0.0.1", upstream.port))

        proxy = None
        try:
            # THE PLAIN SHELL, and nothing else. No upstream.json exists yet.
            assert not (certdir / "upstream.json").exists(), (
                "fixture invalid: something already recorded a chain, which is "
                "the very thing a plain user does not have"
            )
            env = {"HTTPS_PROXY": f"http://127.0.0.1:{corp.port}"}
            hop, next_hop = _ambient_chain(env=env, certdir=certdir)
            assert hop is not None, (
                "the pin saw a corp proxy in the shell and recorded nothing — "
                "every pinned request would bypass it"
            )
            # Exactly what `ensure_proxy` does with that answer.
            write_upstream_hint(certdir, hop, None, next_hop=next_hop)

            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                upstream=("127.0.0.1", upstream.port),
                rediscover_chain=True,
            )
            proxy.start()
            assert proxy.port != 36301, proxy.port

            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert corp.connects == 1, (
                "a REAL request through the pin never reached the corp proxy "
                "the user's shell named — on a host behind a firewall that is "
                "a dead session, and where it is open it silently skips "
                "inspection"
            )
            assert status == 200, "the request did not complete through it"
        finally:
            if proxy:
                proxy.stop()
            upstream.stop()
            corp.stop()

    def case_D3_the_blind_tunnel_uses_the_next_hop_too(
        self, certdir, tmp_path, monkeypatch
    ):
        """THE REMOTE CONTROL PATH, and it walked no chain at all.

        D1 and D2 cover the MITM path (api.anthropic.com). Everything else —
        including the WebSocket Remote Control RECEIVES on, whose host comes
        from the /bridge response and is NOT api.anthropic.com — takes
        `_blind_tunnel`, which read ONE hop and fell straight to a direct
        dial. So the fall-through those two tests pin did not exist on the
        path where a missed hop is least visible: Claude Code keeps
        heartbeating and posting through the MITM at 200 while nothing sent
        from claude.ai arrives.

        A direct dial is not "no proxy" here. On a host whose direct route is
        a TLS-inspecting corporate proxy it is the inspector, and on a host
        with no direct route out it is a dead connection.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        dead = self._dead_port()
        # The hop BEHIND the dead one. A blind tunnel is opaque by
        # definition, so the discriminator is whether this hop is DIALLED at
        # all — not what comes back through it.
        inner = _LoopbackConnectProxy(("127.0.0.1", 1))
        proxy = None
        try:
            write_upstream_hint(
                certdir,
                f"http://127.0.0.1:{dead}",
                next_hop=f"http://127.0.0.1:{inner.port}",
            )
            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                rediscover_chain=True,
            )
            proxy.start()
            assert proxy.port != 36301, proxy.port

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                # A host that is NOT api.anthropic.com: the blind-tunnel path.
                c.sendall(
                    b"CONNECT rc-ingress.example.com:443 HTTP/1.1\r\n"
                    b"Host: rc-ingress.example.com:443\r\n\r\n"
                )
                # WAIT FOR THE HOP, NOT FOR A RESPONSE. The inner hop points at
                # port 1, so nothing ever answers and a recv here simply burns
                # its own timeout — 3.2 s of it. What the test asserts is that
                # the hop was DIALLED, so wait for exactly that.
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and inner.connects == 0:
                    time.sleep(0.01)
            finally:
                c.close()

            assert inner.connects == 1, (
                "the blind tunnel fell through a dead hop to a DIRECT dial "
                "instead of to the hop behind it — on a host with an "
                "inspecting egress proxy that IS the inspector, and Remote "
                "Control receives on this path"
            )
        finally:
            if proxy:
                proxy.stop()
            inner.stop()

    def case_D4_the_plain_relay_uses_the_next_hop_too(
        self, certdir, tmp_path, monkeypatch
    ):
        """The absolute-form path, the third one, with the same single hop.

        `GET http://host/x` from the auto-updater and telemetry takes this
        branch. It read one hop and, when that hop was dead, dialled the
        ORIGIN direct — the same wrong fall-through D1 fixed for the MITM path
        and D3 for the blind tunnel. On a host with no direct route out that
        is not a downgrade, it is a failure.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        dead = self._dead_port()
        inner = _LoopbackConnectProxy(("127.0.0.1", 1))
        proxy = None
        try:
            write_upstream_hint(
                certdir,
                f"http://127.0.0.1:{dead}",
                next_hop=f"http://127.0.0.1:{inner.port}",
            )
            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                rediscover_chain=True,
            )
            proxy.start()
            assert proxy.port != 36301, proxy.port

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET http://example.com/x HTTP/1.1\r\n"
                    b"Host: example.com\r\n\r\n"
                )
                c.settimeout(10)
                try:
                    c.recv(256)
                except OSError:
                    pass
            finally:
                c.close()

            assert inner.connects == 1, (
                "the plain relay fell through a dead hop to a DIRECT dial at "
                "the ORIGIN instead of to the hop behind it — the auto-updater "
                "and telemetry take this path"
            )
        finally:
            if proxy:
                proxy.stop()
            inner.stop()

    def case_a_refusing_chain_answers_503_not_a_direct_dial_on_the_absolute_form_path(
        self, certdir, monkeypatch
    ):
        """The third egress path — `claude remote-control`'s bridge client
        speaks absolute-form and lands in `_plain_relay` (see its docstring
        and D4 above). `_connect_upstream` and `_blind_tunnel` both refuse a
        direct dial when every configured hop is down; `_plain_relay`'s own
        `dial()` still fell through to `socket.create_connection` at the
        ORIGIN. On a corporate host that handshake succeeds against the
        TLS-inspecting inspector, which answers 403 "Access restricted by
        network policy", and the plain relay relayed that 403 straight to
        the client — the login wave through an unguarded path.
        """
        import socket as socket_module

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        # A configured hop nothing listens on: port 1 refuses instantly, and
        # `_chain_candidates()` is non-empty — the premise the guard is on.
        write_upstream_hint(certdir, "http://127.0.0.1:1")
        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        real_create_connection = socket_module.create_connection
        dialled = []

        def _create_connection(address, *a, **kw):
            if address == ("127.0.0.1", 1):
                # The hop dial itself: real, so the walk exhausts it exactly
                # as production would and lands on the fall-through under
                # test.
                return real_create_connection(address, *a, **kw)
            dialled.append(address)
            raise OSError("the direct dial is the thing under test")

        monkeypatch.setattr(
            pin_proxy.socket, "create_connection", _create_connection
        )
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        assert proxy._chain_candidates(), "premise: this host has a chain"
        proxy.start()
        try:
            def _send():
                raw = socket_module.socket(
                    socket_module.AF_INET, socket_module.SOCK_STREAM
                )
                raw.settimeout(10)
                raw.connect(("127.0.0.1", proxy.port))
                raw.sendall(
                    b"GET http://example.com/x HTTP/1.1\r\n"
                    b"Host: example.com\r\n\r\n"
                )
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                raw.close()
                return resp

            resp = _send()
            assert resp.split(b"\r\n")[0] == b"HTTP/1.1 503 Service Unavailable", (
                f"a chained host must answer 503, never dial direct on the "
                f"absolute-form path: {resp[:120]!r}"
            )
            assert dialled == [], (
                f"a host with a configured chain dialled DIRECT: {dialled}"
            )
            assert proxy._egress_refused is True, "the refusal was not noted"

            # CONTROL: the opt-in restores the fall-through, same walk, same
            # target — proves the refusal is what changed, not the relay.
            monkeypatch.setenv("CSWAP_PIN_ALLOW_DIRECT", "1")
            _send()
            assert dialled == [("example.com", 80)], (
                f"CONTROL FAILED: the opt-in did not reach the direct dial: "
                f"{dialled}"
            )
        finally:
            proxy.stop()

    def case_the_absolute_form_path_swaps_a_pinned_route_too(
        self, certdir, monkeypatch
    ):
        """`claude remote-control` registers its environment THROUGH THIS PATH.

        Its bridge client uses the proxy in absolute form -- measured on the
        wire as `POST https://api.anthropic.com/v1/environments/bridge` with
        the OAuth bearer in the clear -- so it never becomes a CONNECT and the
        MITM never sees it. This branch was written for the auto-updater and
        telemetry and said in a comment that nothing Claude Code does reaches
        it, so it relayed verbatim: every environment was registered under the
        ACTIVE account while the route table read correct and every other
        check reported the pin healthy.

        Three assertions, because the swap has to be right in three ways at
        once: it fires for a pinned route, it does NOT fire for inference on
        the same host, and it does NOT fire for another host at all.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        chain_port = chain.port
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain_port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()

            def ask(url, host):
                c = socket.create_connection(("127.0.0.1", proxy.port),
                                             timeout=10)
                try:
                    c.sendall(
                        f"POST {url} HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer ACTIVE\r\n\r\n".encode())
                    c.settimeout(10)
                    try:
                        c.recv(256)
                    except OSError:
                        pass
                finally:
                    c.close()

            ask("https://api.anthropic.com/v1/environments/bridge",
                "api.anthropic.com")
            ask("https://api.anthropic.com/v1/messages", "api.anthropic.com")
            ask("https://example.com/v1/environments/bridge", "example.com")

            deadline = time.time() + 10
            while len(seen) < 3 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 3, f"the chain saw {len(seen)} request(s), not 3"

            env, msgs, other = seen
            assert b"Bearer PINTOKEN" in env, (
                "the environment registration went out on the ACTIVE bearer — "
                "`claude remote-control` gives the machine to the wrong "
                "account, which is invisible to every route-table check")
            assert b"Bearer ACTIVE" not in env
            # THE CONTROL THAT MATTERS MOST: inference must keep billing the
            # account the user swapped to. A swap that fires here is a
            # regression with no symptom until the bill arrives.
            assert b"Bearer ACTIVE" in msgs and b"Bearer PINTOKEN" not in msgs, (
                "inference was swapped to the pin on the absolute-form path")
            # AND A BEARER BELONGS TO ITS ORIGIN. Rewriting one en route to
            # somebody else's server hands out the pinned account's token.
            assert b"Bearer ACTIVE" in other and b"Bearer PINTOKEN" not in other, (
                "the pin token was sent to a host that did not mint it")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_second_pinned_request_on_the_same_socket_is_also_swapped_and_traced(
        self, certdir
    ):
        """T0986 CHANGE 1: `_plain_relay` used to route-decide only the
        FIRST request on a keep-alive absolute-form connection and hand
        every later one to a raw `_pump` -- unswapped and untraced.
        `claude remote-control` sends register, session create and the
        first work poll on ONE socket, so the register swapped while
        session create went out unswapped and 404'd. Both requests here
        must swap and both must trace."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        traced = []
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()
            proxy._tunnel_trace = traced.append

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"POST https://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\nContent-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                # SAME SOCKET, second request: the session create.
                c.sendall(
                    b"POST https://api.anthropic.com/v1/code/sessions"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\nContent-Length: 0\r\n\r\n")
                got2 = b""
                while b"\r\n\r\n" not in got2:
                    d = c.recv(4096)
                    if not d:
                        break
                    got2 += d
                assert got2.startswith(b"HTTP/1.1 200"), got2[:60]
            finally:
                c.close()

            deadline = time.time() + 10
            while len(seen) < 2 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 2, f"the chain saw {len(seen)} request(s), not 2"
            assert b"Bearer PINTOKEN" in seen[0], "the register was not swapped"
            assert b"Bearer PINTOKEN" in seen[1], (
                "the SECOND request on the socket went out unswapped -- "
                "the keep-alive gap this round closes")
            swapped_traces = sum("swapped=True" in t for t in traced)
            assert swapped_traces == 2, (
                f"only {swapped_traces} of 2 requests were traced as "
                f"swapped: {traced!r}")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_foreign_host_then_the_api_host_on_one_socket_only_the_second_swaps(
        self, certdir
    ):
        """A foreign-host request first, then a pinned API-host request on
        the SAME socket: only the second may swap -- a bearer belongs to
        the host it was minted for (:16093, 6257f67), and that guard must
        hold on every request, not only the connection's first."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"POST https://example.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: example.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\nContent-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                c.sendall(
                    b"POST https://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\nContent-Length: 0\r\n\r\n")
                got2 = b""
                while b"\r\n\r\n" not in got2:
                    d = c.recv(4096)
                    if not d:
                        break
                    got2 += d
                assert got2.startswith(b"HTTP/1.1 200"), got2[:60]
            finally:
                c.close()

            deadline = time.time() + 10
            while len(seen) < 2 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 2, f"the chain saw {len(seen)} request(s), not 2"
            assert b"Bearer ACTIVE" in seen[0] and b"Bearer PINTOKEN" not in seen[0], (
                "a foreign host's bearer was swapped -- the pinned token "
                "was sent to a host that did not mint it")
            assert b"Bearer PINTOKEN" in seen[1], (
                "the API-host request on the same socket was not swapped")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_chunked_second_request_on_the_socket_is_relayed_whole(
        self, certdir
    ):
        """The body-read/re-framing defence (568d8f8) must hold for a
        LATER request too, not only the connection's first: a chunked
        second request must reach the chain fully re-framed as
        Content-Length."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET https://example.com/first HTTP/1.1\r\n"
                    b"Host: example.com\r\nContent-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                body = b'{"session_id":"cse_X"}'
                chunked = (f"{len(body):x}\r\n".encode() + body
                          + b"\r\n0\r\n\r\n")
                c.sendall(
                    b"POST https://example.com/second HTTP/1.1\r\n"
                    b"Host: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + chunked)
                got2 = b""
                while b"\r\n\r\n" not in got2:
                    d = c.recv(4096)
                    if not d:
                        break
                    got2 += d
                assert got2.startswith(b"HTTP/1.1 200"), got2[:60]
            finally:
                c.close()

            deadline = time.time() + 10
            while len(seen) < 2 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 2, f"the chain saw {len(seen)} request(s), not 2"
            assert body in seen[1], (
                "the chunked second request's body did not reach the chain")
            assert b"transfer-encoding" not in seen[1].lower(), (
                "the chunked framing was relayed verbatim instead of being "
                "re-declared as Content-Length")
            assert f"Content-Length: {len(body)}".encode() in seen[1], (
                "the decoded body was not re-framed with its own "
                "Content-Length")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_client_connection_close_on_a_later_request_ends_the_loop(
        self, certdir
    ):
        """A LATER request's `Connection: close` must end the per-request
        loop, not only the connection's first: the socket must not
        silently accept a third request nor hang waiting for one."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET https://example.com/first HTTP/1.1\r\n"
                    b"Host: example.com\r\nContent-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                c.sendall(
                    b"GET https://example.com/second HTTP/1.1\r\n"
                    b"Host: example.com\r\nConnection: close\r\n"
                    b"Content-Length: 0\r\n\r\n")
                got2 = b""
                while b"\r\n\r\n" not in got2:
                    d = c.recv(4096)
                    if not d:
                        break
                    got2 += d
                assert got2.startswith(b"HTTP/1.1 200"), got2[:60]

                # THE PROXY MUST CLOSE ITS END. A `recv` on a still-open
                # socket blocks; on a closed one it returns b"" promptly.
                c.settimeout(5)
                assert c.recv(1024) == b"", (
                    "the socket stayed open past a client Connection: "
                    "close on the SECOND request")
            finally:
                c.close()

            deadline = time.time() + 10
            while len(seen) < 2 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 2, f"the chain saw {len(seen)} request(s), not 2"
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_an_http_1_0_request_without_keep_alive_is_closed_after_its_reply(
        self, certdir
    ):
        """T1025 finding 2 (RFC 9112 9.3): HTTP/1.0 defaults to CLOSE, not
        persistent -- `client_wants_close` read only an explicit
        `Connection: close`, so an HTTP/1.0 client that never asked for
        keep-alive still had its socket held open waiting for a second
        request that was never coming."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET https://example.com/first HTTP/1.0\r\n"
                    b"Host: example.com\r\nContent-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                # THE PROXY MUST CLOSE ITS END, same discipline as an
                # explicit `Connection: close` -- HTTP/1.0 without an
                # explicit keep-alive IS that, by default.
                c.settimeout(5)
                assert c.recv(1024) == b"", (
                    "the socket stayed open after an HTTP/1.0 reply with "
                    "no Connection: keep-alive")
            finally:
                c.close()

            deadline = time.time() + 5
            while len(seen) < 1 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 1, f"the chain saw {len(seen)} request(s), not 1"
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_an_http_1_0_request_with_keep_alive_is_closed_after_its_reply(
        self, certdir
    ):
        """T1041 finding 4: RFC 9112 9.3 persists an HTTP/1.0 `keep-alive`
        only when the recipient is not a proxy, or the message is a
        response -- this pin is a proxy receiving a REQUEST, so neither
        holds and the connection closes regardless of the client's own
        `Connection: keep-alive`."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET https://example.com/first HTTP/1.0\r\n"
                    b"Host: example.com\r\nConnection: keep-alive\r\n"
                    b"Content-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                # THE PROXY MUST CLOSE ITS END, same discipline as an
                # explicit `Connection: close` -- an HTTP/1.0 client's own
                # `keep-alive` does not persist a connection to a proxy.
                c.settimeout(5)
                assert c.recv(1024) == b"", (
                    "the socket stayed open after an HTTP/1.0 reply with "
                    "Connection: keep-alive")
            finally:
                c.close()

            deadline = time.time() + 5
            while len(seen) < 1 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 1, f"the chain saw {len(seen)} request(s), not 1"
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_connect_as_a_later_request_gets_a_prompt_close(self, certdir):
        """T1025 finding 3: the per-request loop only knows how to relay
        ABSOLUTE-FORM -- a CONNECT line arriving as a LATER request on a
        reused absolute-form socket is not one. `urlsplit` misparsing
        "host:port" as a scheme used to run the dial machinery past that
        into nowhere instead of a clean, prompt close."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET https://example.com/first HTTP/1.1\r\n"
                    b"Host: example.com\r\nConnection: keep-alive\r\n"
                    b"Content-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                c.sendall(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                          b"Host: api.anthropic.com:443\r\n\r\n")
                c.settimeout(5)
                assert c.recv(1024) == b"", (
                    "a CONNECT sent as a later request on an absolute-form "
                    "socket got a reply instead of a prompt close")
            finally:
                c.close()

            deadline = time.time() + 5
            while len(seen) < 1 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 1, (
                f"the chain saw {len(seen)} request(s), not 1 -- the "
                "CONNECT line was dialled as though it were absolute-form")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_blank_line_before_a_reused_requests_line_is_skipped(
        self, certdir
    ):
        """RFC 9112 2.2: a server SHOULD ignore at least one empty line
        received prior to a request-line -- some clients pipeline one as a
        buggy workaround. T1025 finding 3: treating it as the connection
        ending closed a socket that had a perfectly good second request
        right behind it."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET https://example.com/first HTTP/1.1\r\n"
                    b"Host: example.com\r\nConnection: keep-alive\r\n"
                    b"Content-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                c.sendall(
                    b"\r\nGET https://example.com/second HTTP/1.1\r\n"
                    b"Host: example.com\r\nContent-Length: 0\r\n\r\n")
                got2 = b""
                while b"\r\n\r\n" not in got2:
                    d = c.recv(4096)
                    if not d:
                        break
                    got2 += d
                assert got2.startswith(b"HTTP/1.1 200"), got2[:60]
            finally:
                c.close()

            deadline = time.time() + 10
            while len(seen) < 2 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 2, (
                f"the chain saw {len(seen)} request(s), not 2 -- the "
                "leading CRLF was read as the connection ending")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_websocket_upgrade_on_a_later_request_stays_opaque(
        self, certdir
    ):
        """T0986 CHANGE 1's per-request loop must still hand an Upgrade
        request off to the opaque `_pump` tail, not `_relay_response` --
        `_is_interim` counts a 101 as interim (100 <= code < 200), so
        routing it through the response parser would try to read a "real"
        status line out of the first WebSocket frame instead. Proven on
        the SECOND request of a connection, which only the per-request
        loop reaches -- the first request's own opaque handling was never
        in doubt."""
        from cswap_pin.proxy import PinProxy

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(2)
        oport = srv.getsockname()[1]
        got_after_101 = {}

        def origin():
            try:
                # First (plain) request, on its own fresh dial.
                c1, _ = srv.accept()
                data = b""
                while b"\r\n\r\n" not in data:
                    data += c1.recv(4096)
                c1.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                c1.close()

                # Second (upgrade) request -- CHANGE 1 dials fresh per
                # request, so this is a NEW connection to the origin.
                c2, _ = srv.accept()
                data = b""
                while b"\r\n\r\n" not in data:
                    data += c2.recv(4096)
                c2.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                frame = c2.recv(4096)
                got_after_101["upstream_saw"] = frame
                c2.sendall(b"PONG-FRAME")
                time.sleep(0.3)
                c2.close()
            except Exception:
                pass
        threading.Thread(target=origin, daemon=True).start()

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                f"GET http://127.0.0.1:{oport}/first HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{oport}\r\n"
                f"Content-Length: 0\r\n\r\n".encode())
            got = b""
            raw.settimeout(10)
            while b"\r\n\r\n" not in got:
                d = raw.recv(4096)
                if not d:
                    break
                got += d
            assert got.startswith(b"HTTP/1.1 200"), got[:60]

            raw.sendall(
                f"GET http://127.0.0.1:{oport}/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{oport}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\n\r\n".encode())
            got2 = b""
            while b"\r\n\r\n" not in got2:
                d = raw.recv(4096)
                if not d:
                    break
                got2 += d
            assert got2.startswith(b"HTTP/1.1 101"), (
                f"the upgrade handshake was not relayed intact: {got2[:80]!r}")

            raw.sendall(b"CLIENT-FRAME")
            raw.settimeout(5)
            tail = raw.recv(4096)
            assert tail == b"PONG-FRAME", (
                f"post-101 bytes were not pumped opaquely: {tail!r}")
            raw.close()
        finally:
            proxy.stop()
            srv.close()

        deadline = time.time() + 5
        while "upstream_saw" not in got_after_101 and time.time() < deadline:
            time.sleep(0.05)
        assert got_after_101.get("upstream_saw") == b"CLIENT-FRAME", (
            "the client's post-101 bytes were not pumped to the origin: "
            f"{got_after_101!r}")

    def case_a_held_upgrade_response_reads_as_owed_through_the_hold(
        self, certdir
    ):
        """T1041 finding 3: on the unpeeked path (`not (retry or
        _bridge_cse)`), `_plain_relay_request`'s Upgrade tail cleared the
        owed-answer debt the instant it decided not to peek -- before any
        upstream byte had reached the client, unlike `_mitm`'s own Upgrade
        tail (`_relay_upgrade`), which only clears it once the handshake
        response has actually been relayed. While the origin holds its 101,
        a drain reading `inflight_requests()` must still see this
        connection as owed."""
        from cswap_pin.proxy import PinProxy

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        oport = srv.getsockname()[1]
        reached_hold = threading.Event()
        release = threading.Event()

        def origin():
            try:
                c, _ = srv.accept()
                data = b""
                while b"\r\n\r\n" not in data:
                    data += c.recv(4096)
                reached_hold.set()
                release.wait(10)
                c.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                time.sleep(0.3)
                c.close()
            except Exception:
                pass
        threading.Thread(target=origin, daemon=True).start()

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                f"GET http://127.0.0.1:{oport}/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{oport}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\n\r\n".encode())

            assert reached_hold.wait(5), "the origin never saw the request"
            time.sleep(0.1)  # let the debt-clear decision, if any, happen
            assert proxy.inflight_requests() >= 1, (
                "the connection read as not owed while the 101 was still "
                "held upstream")

            release.set()
            got = b""
            raw.settimeout(10)
            while b"\r\n\r\n" not in got:
                d = raw.recv(4096)
                if not d:
                    break
                got += d
            assert got.startswith(b"HTTP/1.1 101"), (
                f"the upgrade handshake was not relayed: {got[:80]!r}")

            deadline = time.time() + 5
            while proxy.inflight_requests() and time.time() < deadline:
                time.sleep(0.02)
            assert proxy.inflight_requests() == 0, (
                "the debt never cleared once the 101 reached the client")
            raw.close()
        finally:
            proxy.stop()
            srv.close()

    def case_a_cleartext_second_request_to_the_api_host_is_never_swapped(
        self, certdir
    ):
        """`and secure` (568d8f8/6257f67) is the half that keeps the
        pinned token off a bare TCP wire: a host guard alone says WHO, not
        HOW, so a cleartext http:// request to the API host must never
        swap even though the host matches -- proven on request #2, which
        only the per-request loop reaches."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"POST https://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\nContent-Length: 0\r\n\r\n")
                got = b""
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
                assert got.startswith(b"HTTP/1.1 200"), got[:60]

                c.sendall(
                    b"POST http://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\nContent-Length: 0\r\n\r\n")
                got2 = b""
                while b"\r\n\r\n" not in got2:
                    d = c.recv(4096)
                    if not d:
                        break
                    got2 += d
                assert got2.startswith(b"HTTP/1.1 200"), got2[:60]
            finally:
                c.close()

            deadline = time.time() + 10
            while len(seen) < 2 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 2, f"the chain saw {len(seen)} request(s), not 2"
            assert b"Bearer PINTOKEN" in seen[0], "the https register was not swapped"
            assert b"Bearer ACTIVE" in seen[1] and b"Bearer PINTOKEN" not in seen[1], (
                "a cleartext http:// request to the API host was swapped "
                "-- the pinned bearer just went out on a bare TCP wire")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_the_environment_create_waits_for_the_pin_on_this_path(
        self, certdir
    ):
        """`should_wait_for_pin` gained `/v1/environments/bridge` — and its one
        caller is the MITM, which this create never reaches.

        That is the same gap as the route table's: a rule added for
        `claude remote-control` on the path `claude remote-control` does not
        use. The bargain it encodes is the whole reason the rule exists — a
        `consume-busy` instant costs the environment PERMANENTLY, because the
        server fixes the owner at registration and offers no transfer — so an
        unreachable retry is a permanent loss with a guard in front of it.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        # The `consume-busy` race exactly: the first ask finds the slot's
        # refresh lock held for an instant, the next one does not.
        asks = []

        def provider():
            asks.append(1)
            return None if len(asks) == 1 else "PINTOKEN"

        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                             rediscover_chain=True)
            proxy.start()
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"POST https://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\n\r\n")
                c.settimeout(10)
                try:
                    c.recv(256)
                except OSError:
                    pass
            finally:
                c.close()

            deadline = time.time() + 10
            while not chain.seen and time.time() < deadline:
                time.sleep(0.05)
            assert chain.seen, "the request never reached the chain"
            assert b"Bearer PINTOKEN" in chain.seen[0], (
                "the environment was registered on the ACTIVE account because "
                "the pin token was asked for once and the answer was a "
                "momentary None — permanently, the server offers no transfer")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def _blind_provider(self, blind_reason="", noop=False, noop_after_calls=None,
                         stalled=False):
        """A pin-token provider shaped like `make_pin_token_provider`'s real
        one for the states `_wait_for_pin_token`'s guard reads: `blind_reason`
        (a REAL failed mint, a stall included — see the guard's own comment),
        `pin_is_noop()` (nothing to swap) and `can_pin_cached` (present on
        every real provider — its absence here used to silently disable
        `_warm_mint_cache`, the daemon-start thread that calls `provider()`
        once off the request path; giving the fixture the REAL row shape
        means that thread runs exactly like it does in production). Always
        mints None — none of these states has a token to give.

        `noop_after_calls`: `pin_is_noop()` answers True only once `provider`
        has been called at least this many times. Real `_deferred` (the
        consume-busy flag `pin_is_noop` reads) flips mid-retry, not before
        the first call — a fixture that starts noop=True never reaches the
        code past `_wait_for_pin_token`'s entry check, which is exactly the
        vacuous test this guards against. Set high enough (4) that even the
        warm thread's own extra call can't trip it before the retry loop
        has actually run.

        `stalled`: `mint_stalled()` answers True — the PRE-check both
        `_plain_relay` and the MITM path make before ever calling
        `_wait_for_pin_token`, so a stalled store is refused fast instead of
        paying the retry loop's own `provider()` calls first.
        """
        def provider():
            provider.calls += 1
            return None
        provider.calls = 0
        provider.blind_reason = blind_reason
        provider.can_pin_cached = lambda: False
        provider.mint_stalled = lambda: stalled
        # THE REST OF THE PRODUCER'S REAL ROW SHAPE, present on every daemon
        # provider (`make_pin_token_provider`) — `_mint_lock_busy` reads
        # `refresh_lock` and answers None (not "busy") without it, and
        # `can_pin_cached` reads `identity_mismatch`. A fixture missing one
        # of these is how a negative here has already gone non-vacuous by
        # accident twice this round.
        provider.refresh_lock = threading.Lock()
        provider.identity_mismatch = None
        provider.note_verdict = lambda *a, **k: None
        if noop_after_calls is not None:
            provider.pin_is_noop = lambda: provider.calls >= noop_after_calls
        else:
            provider.pin_is_noop = lambda: noop
        return provider

    def _post_bridge_create(self, certdir, provider,
                             path="/v1/environments/bridge"):
        """POST an absolute-form request through `_plain_relay` and return
        `(status_line, chain.seen)`. The one shape the relay cases below
        need — chain, secret, proxy, socket, read the status line —
        differing only in the provider they hand the daemon and, for the
        scope-of-the-guard case, the path."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                             rediscover_chain=True)
            proxy.start()
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            got = b""
            try:
                c.sendall(
                    f"POST https://api.anthropic.com{path}"
                    " HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    "Authorization: Bearer ACTIVE\r\n\r\n".encode())
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
            finally:
                c.close()
            # `chain.seen` also carries PinProxy's OWN background hop-
            # discovery probes (`rediscover_chain=True`) — empty `buf`
            # entries with no bearer at all, unrelated to this request. Only
            # an entry carrying OUR marker is the bridge create actually
            # reaching the chain; a relay that DOES run has already put one
            # there by the time `got` finished reading (the client's
            # response IS the chain's canned reply, relayed back). One that
            # must NEVER run gets a grace beat instead, since no response
            # here proves its absence.
            if not any(b"Bearer ACTIVE" in s for s in chain.seen):
                time.sleep(0.3)
            return got, chain.seen
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_blind_mint_refuses_the_bridge_create_instead_of_relaying(
        self, certdir
    ):
        """A REAL failed mint (`blind_reason` set, not a no-op) on a
        bridge-create route must answer 503 and never reach the chain —
        relaying here gives the bridge to the ACTIVE account for good, which
        is exactly the defect this round exists to close."""
        provider = self._blind_provider(
            blind_reason="no credential for slot 1 (a@example.com)")
        got, seen = self._post_bridge_create(certdir, provider)
        assert got.startswith(b"HTTP/1.1 503"), (
            f"a blind mint was relayed instead of refused: {got[:60]!r}")
        assert not any(b"Bearer ACTIVE" in s for s in seen), (
            "the bridge create reached the chain on a blind mint — this "
            f"bridge is now owned by the ACTIVE account permanently: {seen!r}")

    def case_the_bridge_attach_waits_on_an_unexplained_miss_then_relays_untokened_and_logs(
        self, certdir
    ):
        """`should_wait_for_pin` now covers the bridge ATTACH too (T0867) —
        previously missing even though `is_pinned_route` already matches it
        (a prefix match on `/v1/code/sessions/`), so a token miss on this
        route relayed on Claude Code's own bearer with no retry and no
        record at all: `_wait_for_pin_token` returned the falsy token
        straight back because `should_wait_for_pin` said this route was not
        worth waiting for.

        NOT `consume-busy`: that shape sets `_deferred`, which makes
        `pin_is_noop()` read True for the whole window, so `_wait_for_pin_token`
        returns before this retry loop ever starts (see `should_wait_for_pin`'s
        docstring). A miss that leaves `blind_reason` unset and `pin_is_noop()`
        False — the shape this case drives — must still retry `_PIN_WAIT_TRIES`
        times and then keep today's fail-open relay unchanged — but it must
        now also say so, which it could not before this route was reachable."""
        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            provider = self._blind_provider()  # blind_reason="" — a miss
            got, seen = self._post_bridge_create(
                certdir, provider, path="/v1/code/sessions/cse_x/bridge")
            assert got.startswith(b"HTTP/1.1 200"), (
                f"a momentary miss with no blind_reason must still fail "
                f"open, not hang or refuse: {got[:60]!r}")
            assert any(b"Bearer ACTIVE" in s for s in seen), (
                "the exhausted retry did not fall back to the untokened "
                f"relay today's fail-open promises: {seen!r}")
            assert provider.calls >= pp._PIN_WAIT_TRIES, (
                f"only {provider.calls} provider() call(s) — the retry "
                "loop this route now arms never ran")
            assert any(
                "a bridge was created without the pin" in l for l in lines
            ), (
                "the pin stayed silent about an unpinned bridge attach — "
                "the exact gap this route closes")
        finally:
            pp._log_lifecycle = real_log

    def case_a_stalled_mint_refuses_the_bridge_attach_fast_too(self, certdir):
        """The absolute-form path's `mint_stalled()` pre-check (see
        `case_a_stalled_mint_is_refused_fast_not_relayed`) now also gates
        the bridge ATTACH (T0867), since that route only just became a
        `should_wait_for_pin` route: a stalled store must 503 immediately
        rather than pay `_wait_for_pin_token`'s three retries first, and
        rather than relay unpinned — the permanent give-away this whole
        route table exists to close."""
        provider = self._blind_provider(
            blind_reason="mint stalled: the refresh lock has been held "
                         "over 45s for slot 1 (a@example.com)",
            stalled=True)
        got, seen = self._post_bridge_create(
            certdir, provider, path="/v1/code/sessions/cse_x/bridge")
        assert got.startswith(b"HTTP/1.1 503"), (
            f"a stalled mint on the attach was relayed instead of "
            f"refused: {got[:60]!r}")
        assert b"Connection: close" in got, (
            f"a closed connection advertised keep-alive: {got!r}")
        assert not any(b"Bearer ACTIVE" in s for s in seen), (
            f"a stalled mint reached the chain on the bridge attach: {seen!r}")
        assert provider.calls <= 2, (
            f"{provider.calls} provider() call(s) — the retry loop ran "
            "instead of the fast pre-check refusing immediately")

    def case_a_noop_pin_still_relays_unpinned_not_503(self, certdir):
        """A no-op pin (`pin_is_noop()` True — the pinned account IS the
        active one, or the pin is cleared) has nothing to swap; today's
        fail-open relay must still run, unrefused. `noop_after_calls=4` is
        higher than the entry check can ever see on its own (the caller's
        first `provider()` call, plus at most one extra from the daemon's
        own `_warm_mint_cache` thread — see `_blind_provider`), so the entry
        check cannot short-circuit before the retry loop runs; the assertion
        on `provider.calls` proves that loop actually ran rather than taking
        the vacuous path a lower count would let it take by accident."""
        provider = self._blind_provider(
            blind_reason="no credential for slot 1 (a@example.com)",
            noop_after_calls=4)
        got, seen = self._post_bridge_create(certdir, provider)
        assert got.startswith(b"HTTP/1.1 200"), (
            f"a no-op pin was refused instead of relayed: {got[:60]!r}")
        assert any(b"Bearer ACTIVE" in s for s in seen), (
            f"the no-op case did not take today's unpinned relay path: {seen!r}")
        assert provider.calls >= 4, (
            f"only {provider.calls} provider() call(s) — the retry loop "
            "this case must exercise never ran, so the guard's noop "
            "exclusion is untested")

    def case_a_stalled_mint_is_refused_fast_not_relayed(self, certdir):
        """`_plain_relay` now makes the same `mint_stalled()` PRE-check the
        MITM path already made (round 4) — refused immediately, before
        `_wait_for_pin_token`'s own retry loop ever runs. Without this a
        stalled store cost `provider()` plus 3 retries, each blockable up to
        `_MINT_LOCK_BOUND_S` (45s) on `refresh_lock`, on a thread-per-
        connection server with no cap — paid ONCE before this whole round,
        but every backoff respawn since the guard 503s the bridge worker
        instead of relaying. `provider.calls == 1` proves the retry loop
        never ran; `Connection: close` matches this same non-keep-alive
        path's neighbouring refusals (`_refuse_stalled_mint`'s own
        `close=True` note)."""
        provider = self._blind_provider(
            blind_reason="mint stalled: the refresh lock has been held over "
                         "45s for slot 1 (a@example.com)",
            stalled=True)
        got, seen = self._post_bridge_create(certdir, provider)
        assert got.startswith(b"HTTP/1.1 503"), (
            f"a stalled mint was relayed instead of refused: {got[:60]!r}")
        assert b"Connection: close" in got, (
            f"a closed connection advertised keep-alive: {got!r}")
        assert not any(b"Bearer ACTIVE" in s for s in seen), (
            "a stalled mint reached the chain — the same permanent give-away "
            f"a plain failed mint would cause: {seen!r}")
        # <=2: this request's own entry call, plus at most one extra from
        # the daemon's own background `_warm_mint_cache` warm-up (see
        # `_blind_provider`). The retry loop this must NOT enter would push
        # this to >=4 (1 entry + 3 retries), so the two shapes stay apart
        # even with that extra call in the count.
        assert provider.calls <= 2, (
            f"{provider.calls} provider() call(s) — the retry loop ran "
            "instead of the fast pre-check refusing immediately")

    def case_a_stalled_mint_does_not_refuse_a_pinned_non_create_route(
        self, certdir
    ):
        """The pre-check is scoped to `should_wait_for_pin`, not merely to
        `is_pinned_route` — `/v1/environments/env_1/bridge/reconnect` is
        pinned (its ownership swap matters) but is NOT a create
        (`should_wait_for_pin` is False for it), so it never entered the
        retry loop the pre-check exists to shortcut and buys nothing there.
        Gating on `is_pinned_route` alone would 503 + close every such
        route for the whole length of a stall, where today's deliberate
        design is a single unpinned relay ("ONE REQUEST IS WORTH A RETRY,
        and only one") — this pins that scope."""
        from cswap_pin.proxy import is_pinned_route

        assert is_pinned_route("/v1/environments/env_1/bridge/reconnect"), (
            "this route is no longer pinned — the case would pass green "
            "while testing nothing, the same shape as a non-create route")
        provider = self._blind_provider(stalled=True)
        got, seen = self._post_bridge_create(
            certdir, provider, path="/v1/environments/env_1/bridge/reconnect")
        assert got.startswith(b"HTTP/1.1 200"), (
            f"a stalled mint refused a non-create pinned route: {got[:60]!r}")
        assert any(b"Bearer ACTIVE" in s for s in seen), (
            f"the non-create route did not take its usual unpinned relay: "
            f"{seen!r}")

    def case_a_blind_mint_refuses_the_bridge_create_on_the_mitm_path_too(
        self, certdir
    ):
        """The same guard, reached through CONNECT + real TLS — the path
        `POST /v1/code/sessions` actually arrives on, not `_plain_relay`'s.
        And the refusal must not cost the connection: a second request on
        the same socket must still get an answer, not a reset."""
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        provider = self._blind_provider(
            blind_reason="no credential for slot 1 (a@example.com)")
        proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                         upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            conn = http.client.HTTPSConnection(
                "api.anthropic.com", context=ctx, timeout=10)
            conn.set_tunnel("api.anthropic.com", 443)
            conn._create_connection = lambda *a, **k: socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=10)
            try:
                conn.request("POST", "/v1/code/sessions", body="{}",
                             headers={"Authorization": "Bearer ACTIVE"})
                resp = conn.getresponse()
                resp.read()
                assert resp.status == 503, (
                    f"a blind mint over MITM was relayed, not refused: "
                    f"{resp.status}")
                assert upstream.seen_auth is None, (
                    "the bridge create reached upstream on a blind mint")

                # KEEP-ALIVE: the same connection must still answer, or this
                # refusal cost every other request pipelined on it too.
                conn.request("POST", "/v1/code/sessions", body="{}",
                             headers={"Authorization": "Bearer ACTIVE"})
                resp2 = conn.getresponse()
                resp2.read()
                assert resp2.status == 503, (
                    "the connection did not survive the first refusal: "
                    f"second request got {resp2.status}")
            finally:
                conn.close()
        finally:
            proxy.stop()
            upstream.stop()

    def case_a_refused_swap_is_taken_back_on_the_absolute_form_path(
        self, certdir
    ):
        """A running Remote Control must survive the pin learning this route.

        An environment registered before the pin swapped `/v1/environments/`
        belongs to the account that registered it, so asking as the pin gets
        401 and the bridge client dies — a live session killed by an upgrade,
        which no deploy is allowed to do. The MITM path has always taken a
        refused swap back; this one did not, and the gap cost exactly that.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        # The pin's bearer is refused; the one that arrived is not.
        chain = _RecordingChain(
            lambda req: (b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                         if b"Bearer PINTOKEN" in req else
                         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
        seen = chain.seen
        chain_port = chain.port
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain_port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            got = b""
            try:
                # A ROUTE THAT IS STILL PINNED, and one with a BODY: the work
                # queue moved out of the table when the wire showed it carries
                # a token of its own, and a take-back test aimed there stops
                # exercising the take-back while still passing its own name.
                rbody = b'{"session_id":"cse_X"}'
                c.sendall(
                    b"POST https://api.anthropic.com/v1/environments/env_1"
                    b"/bridge/reconnect HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\n"
                    + f"Content-Length: {len(rbody)}\r\n\r\n".encode()
                    + rbody)
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
            finally:
                c.close()

            deadline = time.time() + 10
            while len(seen) < 2 and time.time() < deadline:
                time.sleep(0.05)
            assert len(seen) == 2, (
                f"the swap was not taken back — {len(seen)} attempt(s), so a "
                "401 reached the client and Remote Control ended")
            assert b"Bearer PINTOKEN" in seen[0], "the first try was not swapped"
            assert b"Bearer ACTIVE" in seen[1], (
                "the retry did not restore the bearer the client sent")
            assert got.startswith(b"HTTP/1.1 200"), (
                f"the client got {got.splitlines()[0][:40]!r}, not the "
                "answer the take-back earned")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_both_new_trace_lines_are_actually_written(self, certdir):
        """"Being untraced is half of what this cost" — so hold them.

        A whole feature travelled the absolute-form path leaving exactly the
        evidence a feature that was NOT RUNNING leaves, because that branch
        wrote nothing. Deleting either line back out was measured as a
        no-op against the whole suite, which makes the fix one edit from
        being undone by someone tidying.

        Read from the source rather than from a captured file: the trace's
        destination is a per-daemon path this case has no business arming,
        and what regressed is the CALL, not the sink.
        """
        import inspect
        import cswap_pin.proxy as pp

        # T0986 CHANGE 1 split the per-connection loop from the per-request
        # parse/route/swap/trace/relay -- both lines below live in the
        # latter now, so both sources are read together.
        relay = (inspect.getsource(pp.PinProxy._plain_relay)
                 + inspect.getsource(pp.PinProxy._plain_relay_request))
        assert "(absolute-form)" in relay, (
            "the swap on this path is silent again — a request travelling "
            "here leaves the same evidence as one that never ran")
        assert "swap refused" in relay, (
            "a take-back leaves no line, so a 401 that was survived is "
            "indistinguishable from one that never happened")
        handler = inspect.getsource(pp.PinProxy._handle_client)
        assert "unreadable authority" in handler, (
            "a CONNECT the proxy cannot parse is silently blind-tunnelled to "
            "host '' again, which is how a feature routes around the pin "
            "while every route check reports it correct")
        # AND THE SHAPE IT LOGS, not the text. That branch runs before any
        # credential check and the remainder of the line is whatever the
        # client wrote — a proxy URL with userinfo in it, say.
        assert "line[:120]" not in handler, (
            "the raw CONNECT line is being copied into the trace again")

    def case_the_take_back_fires_on_403_and_404_and_NOT_on_500(self, certdir):
        """WHICH codes take a swap back, in both directions.

        401 alone was exercised, so narrowing the set to `(401,)` and widening
        it to `>= 400` were both invisible. They fail in opposite ways: the
        narrow one lets a 403 kill Remote Control, and the wide one replays the
        WHOLE request on the client's bearer whenever the origin has a bad
        minute — a 500 is the origin's own answer and belongs to it.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        def ask(code):
            chain = _RecordingChain(
                lambda req: (f"HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n"
                             .encode()
                             if b"Bearer PINTOKEN" in req else
                             b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
            proxy = None
            try:
                write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
                proxy = PinProxy(certdir=certdir,
                                 pin_token_provider=lambda: "PINTOKEN",
                                 rediscover_chain=True)
                proxy.start()
                c = socket.create_connection(("127.0.0.1", proxy.port),
                                             timeout=10)
                try:
                    c.sendall(
                        b"POST https://api.anthropic.com/v1/environments/bridge"
                        b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                        b"Authorization: Bearer ACTIVE\r\n\r\n")
                    c.settimeout(10)
                    try:
                        c.recv(256)
                    except OSError:
                        pass
                finally:
                    c.close()
                return len(chain.seen)
            finally:
                if proxy:
                    proxy.stop()
                chain.stop()

        assert ask(403) == 2, "a 403 did not take the swap back"
        assert ask(404) == 2, "a 404 did not take the swap back"
        # THE CONTROL, and the half a widened set would break: an origin error
        # is the origin's answer, not a verdict on our bearer.
        assert ask(500) == 1, (
            "a 500 replayed the request on the client's bearer — the take-back "
            "is for a REFUSAL, not for any failure")

    def case_the_retraced_swap_refusal_names_its_status_code(self, certdir):
        """T1025 finding 1: `_relay_response` returned the bare
        `_AUTH_REJECTED` sentinel with no status code, so the absolute-form
        trace line read "swap refused -- retrying" with nothing to say
        WHICH code the swap was refused with. Each of 401/403/404 must
        appear by number, the way the same trace already does on
        `_plain_relay_request`'s own Upgrade tail (its `if upgrading:`
        branch's retry)."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        def ask(code):
            chain = _RecordingChain(
                lambda req: (f"HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n"
                             .encode()
                             if b"Bearer PINTOKEN" in req else
                             b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
            traced = []
            proxy = None
            try:
                write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
                proxy = PinProxy(certdir=certdir,
                                 pin_token_provider=lambda: "PINTOKEN",
                                 rediscover_chain=True)
                proxy.start()
                proxy._tunnel_trace = traced.append
                c = socket.create_connection(("127.0.0.1", proxy.port),
                                             timeout=10)
                try:
                    c.sendall(
                        b"POST https://api.anthropic.com/v1/environments/bridge"
                        b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                        b"Authorization: Bearer ACTIVE\r\n\r\n")
                    c.settimeout(10)
                    try:
                        c.recv(256)
                    except OSError:
                        pass
                finally:
                    c.close()
                return traced
            finally:
                if proxy:
                    proxy.stop()
                chain.stop()

        for code in (401, 403, 404):
            traced = ask(code)
            assert any(f"swap refused ({code})" in t for t in traced), (
                f"the {code} refusal was not traced with its status code: "
                f"{traced!r}")

    def case_the_absolute_form_take_back_retries_through_the_real_provider(
            self, certdir, monkeypatch):
        """T1155 pass 3: the absolute-form take-back (`_plain_relay_request`)
        shares `_refetch_swap_token` with the MITM path, so it must retry
        THROUGH the real provider the same way. Also pins the trace label
        (re-review m, proxy.py ~17054): `kind` must name the attempt
        actually about to run, not always "with a fresh swap" -- the
        first refusal's retry finds a genuinely different token ("with a
        fresh swap"), and when THAT one is also refused there is nothing
        left to retry with, so the second line must read "as it arrived",
        not repeat the first.

        T1182: `_tunnel_trace` above is opt-in (--debug only) -- this
        take-back reported to daemon.log's own readers (rc_six_gate.py
        row 13) not at all. It must call the SAME `_note_swap_refused`
        the MITM path does, in the SAME order: `retried-fresh` for the
        first refusal's retry, `fell-back` for the second.
        """
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})

        pp.save_pin(certdir, "pin@example.com", "org")
        switcher = _refetch_switcher(
            certdir, lambda n: "stale-token" if n == 1 else "fresh-token")
        provider = pp.make_pin_token_provider(switcher, "2", "pin@example.com")

        chain = _RecordingChain(
            lambda req: (b"HTTP/1.1 401 X\r\nContent-Length: 0\r\n\r\n"
                         if (b"Bearer stale-token" in req
                             or b"Bearer fresh-token" in req) else
                         b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        traced = []
        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                             rediscover_chain=True)
            proxy.start()
            proxy._tunnel_trace = traced.append
            c = socket.create_connection(("127.0.0.1", proxy.port),
                                         timeout=10)
            got = b""
            try:
                c.sendall(
                    b"POST https://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer disk-token\r\n\r\n")
                c.settimeout(10)
                try:
                    got = c.recv(256)
                except OSError:
                    pass
            finally:
                c.close()

            assert got.startswith(b"HTTP/1.1 200"), (
                f"the unswapped fallback did not answer: {got[:60]!r}")
            assert switcher.reads == 2, (
                "the refusal must force exactly one genuine re-read: "
                f"{switcher.reads}")
            refusal_lines = [t for t in traced if "swap refused" in t]
            assert len(refusal_lines) == 2, (
                f"expected exactly two refusal traces: {refusal_lines!r}")
            assert "retrying with a fresh swap" in refusal_lines[0], (
                "the first refusal's retry found a genuinely different "
                f"token and must say so: {refusal_lines[0]!r}")
            assert "retrying as it arrived" in refusal_lines[1], (
                "the second refusal has nothing left to retry with -- the "
                "unswapped fallback is next, not another fresh swap: "
                f"{refusal_lines[1]!r}")
            swap_lines = [ln for ln in lines if ln.startswith("swap refused")]
            assert swap_lines == [
                "swap refused (401) on POST /v1/environments/bridge: "
                "retried-fresh",
                "swap refused (401) on POST /v1/environments/bridge: "
                "fell-back",
            ], (
                "the absolute-form take-back must write the same "
                f"daemon.log lines the MITM path does: {lines!r}"
            )
        finally:
            if proxy:
                proxy.stop()
            chain.stop()
            pp._log_lifecycle = real_log

    def case_a_swapped_request_with_a_BODY_still_completes(self, certdir):
        """The registration this whole feature exists to pin carries a body.

        `_plain_relay` left the body to `_pump`, which runs AFTER the response
        is read — so once a take-back peeked at the status line first, the
        origin waited for Content-Length bytes nobody had sent while the proxy
        waited for a status line. Both blocked forever, one thread and two
        sockets per request. Observed on the fleet as a drain CUT: one request
        in flight, before headers, 90s content-free.

        The bodyless cases next door pass either way, which is exactly why
        this one exists.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        seen = chain.seen
        chain_port = chain.port
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain_port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()
            payload = b'{"machine_name":"m","max_sessions":32}'
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            got = b""
            try:
                c.sendall(
                    b"POST https://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\n"
                    + f"Content-Length: {len(payload)}\r\n\r\n".encode()
                    + payload)
                c.settimeout(10)
                while b"\r\n\r\n" not in got:
                    d = c.recv(4096)
                    if not d:
                        break
                    got += d
            finally:
                c.close()

            assert got.startswith(b"HTTP/1.1 200"), (
                f"the registration never completed — got {got[:40]!r}. The "
                "body was never forwarded, so the origin and the proxy each "
                "waited for the other")
            assert len(seen) == 1 and payload in seen[0], (
                "the origin received the request without its body, so the "
                "registration would be rejected or wrong")
            assert b"Bearer PINTOKEN" in seen[0], "and it must still be swapped"
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_a_cleartext_absolute_form_request_is_NEVER_swapped(self, certdir):
        """A bearer belongs on a wire that hides it.

        The host guard asks WHO and says nothing about HOW, so `http://` to the
        same host passed it and the direct dial would have written the pinned
        token onto a bare TCP socket. The MITM path cannot do this — it always
        wraps the upstream — so the exposure would have been this path's alone.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        seen = chain.seen
        chain_port = chain.port
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain_port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"POST http://api.anthropic.com/v1/environments/bridge"
                    b" HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer ACTIVE\r\n\r\n")
                c.settimeout(10)
                try:
                    c.recv(256)
                except OSError:
                    pass
            finally:
                c.close()

            deadline = time.time() + 10
            while not seen and time.time() < deadline:
                time.sleep(0.05)
            assert seen, "the request never reached the chain"
            assert b"Bearer PINTOKEN" not in seen[0], (
                "the pinned account's token was written to a cleartext socket")
            assert b"Bearer ACTIVE" in seen[0], (
                "the request must still go, unchanged — this is a refusal to "
                "SWAP, not a refusal to serve")
        finally:
            if proxy:
                proxy.stop()
            chain.stop()

    def case_the_next_hop_is_probed_from_the_cache_proxys_health(self, certdir):
        """Where the second hop comes from: the inner proxy reports its own
        upstream while it is alive, and a launch records both. Probed rather
        than inherited, because `cswap pin` runs in a plain shell that has
        neither value in its environment."""
        import cswap_pin.proxy as pp

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        assert port != 36301, port

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    body = json.dumps(
                        {"status": "ok", "forward_proxy": True,
                         "https_proxy": "http://127.0.0.1:8118"}
                    ).encode()
                    c.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n\r\n" + body
                    )
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            # timeout=10: a generous probe budget, the server thread's own
            # reply is what the assertion waits on, not the network.
            nxt = pp._probe_next_hop(f"http://127.0.0.1:{port}", timeout=10)
            assert nxt == "http://127.0.0.1:8118"
            pp.write_upstream_hint(
                certdir, f"http://127.0.0.1:{port}", next_hop=nxt
            )
            assert pp._chain_hops(certdir)[-1].address == ("127.0.0.1", 8118)
        finally:
            srv.close()

    def case_a_cache_proxy_that_is_not_answering_records_no_next_hop(self, certdir):
        """Never record a stale hop. A hop that cannot be confirmed right now
        is worse than none: the walk would spend a dial on it before reaching
        the branch that decides what to do with no chain at all."""
        import cswap_pin.proxy as pp

        dead = self._dead_port()
        nxt = pp._probe_next_hop(f"http://127.0.0.1:{dead}")
        assert nxt is None
        pp.write_upstream_hint(certdir, f"http://127.0.0.1:{dead}", next_hop=nxt)
        hops = pp._chain_hops(certdir)
        assert [h.address for h in hops] == [("127.0.0.1", dead)], hops

    def case_a_hop_that_answers_4xx_is_asked_once_and_leaves_no_disk_record(
        self, certdir
    ):
        """MEASURED (sandbox privoxy 4.2.0, the owner's own config): no
        request form `_probe_next_hop` could send is both quiet on privoxy's
        own log and answered by the local cache proxy, which matches
        origin-form ``GET /health`` only — origin-form, absolute-form and
        ``OPTIONS *`` each trip privoxy's own "isn't configured to accept
        intercepted requests" error, logged as THAT proxy's error, not ours
        to keep causing. A hop that answers with a real HTTP response
        carrying a 4xx status is exactly this shape — something is there,
        but it is not a /health server — so once known it must not be probed
        again.

        THE MEMO IS PROCESS-LOCAL, NOT ON DISK. The owner withdrew the
        earlier disk-persisted record for the shape of bug it was: it never
        expired, so one 400 poisoned an address for good, including after a
        real /health server took that port. `_ASKED_NOHEALTH` (see
        `_probe_next_hop`) carries the same "don't ask again" behaviour for
        exactly as long as this process runs, and `write_upstream_hint`'s
        own record carries nothing about it forward."""
        import cswap_pin.proxy as pp

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        handled = []

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                handled.append(1)
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    body = b"Error: invalid request"
                    c.sendall(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n\r\n" + body
                    )
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        address = f"127.0.0.1:{srv.getsockname()[1]}"
        try:
            url = f"http://{address}"
            # A baseline record on disk, written BEFORE either probe, so the
            # read below sees only what the probes themselves did to it —
            # not what a later re-stamp would carry regardless of the probe.
            pp.write_upstream_hint(certdir, "http://127.0.0.1:1")
            # timeout=10: the assertion below waits on the server thread's
            # own reply, not the network.
            nxt = pp._probe_next_hop(url, timeout=10)
            assert nxt is None
            assert handled == [1], handled

            # A second probe of the same address: the process-local memo
            # must return None without opening a socket at all.
            nxt2 = pp._probe_next_hop(url, timeout=10)
            assert nxt2 is None
            assert handled == [1], (
                "a hop already known to answer 4xx was asked again")

            # And nothing about it reached disk. Read the file directly, with
            # no intervening `write_upstream_hint` call — that function only
            # ever emits proxy/ca/next and would erase a `nohealth` key even
            # if the probe had written one, so a re-stamp before this read
            # would pass whatever the probe did.
            raw = json.loads((certdir / pp._UPSTREAM_FILE).read_text())
            # THE SCHEMA ALONE MISSES A REGRESSION THAT RECORDS THE 4xx HOP
            # INTO AN EXISTING KEY (`proxy`, `ca`, or `next`) rather than a
            # new one, so the values are pinned to the untouched baseline
            # too, not just the key set.
            assert raw == {"proxy": "http://127.0.0.1:1", "ca": "", "next": ""}, raw
        finally:
            pp._ASKED_NOHEALTH.discard(address)
            srv.close()

    def case_a_hop_that_answers_5xx_is_still_reprobed(self):
        """The process-local memo (see `_probe_next_hop`) is scoped to 4xx
        (privoxy's own answer, and the measured shape of "this isn't a
        /health server"). A 5xx is a genuine /health server having a bad
        moment — restarting, its own upstream down — and must still be
        asked once it recovers, not poisoned for good on one bad tick."""
        import cswap_pin.proxy as pp

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        handled = []

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                handled.append(1)
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    body = b"Internal Server Error"
                    c.sendall(
                        b"HTTP/1.1 500 Internal Server Error\r\n"
                        b"Content-Type: text/plain\r\nContent-Length: "
                        + str(len(body)).encode() + b"\r\n\r\n" + body
                    )
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        address = f"127.0.0.1:{srv.getsockname()[1]}"
        try:
            url = f"http://{address}"
            # timeout=10: the assertion below waits on the server thread's
            # own reply, not the network.
            nxt = pp._probe_next_hop(url, timeout=10)
            assert nxt is None
            assert handled == [1], handled
            assert address not in pp._ASKED_NOHEALTH, (
                "a 5xx was memoized as 4xx, poisoning a hop that is merely "
                "having a bad moment")

            # a second probe, same address: still asked, unlike the 4xx case.
            nxt2 = pp._probe_next_hop(url, timeout=10)
            assert nxt2 is None
            assert handled == [1, 1], (
                "a 5xx hop was not reprobed on the second call")
        finally:
            srv.close()

    def case_a_dead_hop_records_nothing_and_is_reprobed_once_it_answers(self):
        """A CCF that is merely DOWN must still be asked when it comes back —
        only a hop that positively answered something other than 200 is
        remembered. Same address, dead first, then serving: nothing about the
        earlier failure should have excluded it from being asked again."""
        import cswap_pin.proxy as pp

        dead = self._dead_port()
        nxt = pp._probe_next_hop(f"http://127.0.0.1:{dead}")
        assert nxt is None
        assert f"127.0.0.1:{dead}" not in pp._ASKED_NOHEALTH, (
            "a hop that never answered was memoized as 4xx")

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", dead))
        srv.listen(4)

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    body = json.dumps(
                        {"status": "ok", "https_proxy": "http://127.0.0.1:8118"}
                    ).encode()
                    c.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n\r\n" + body
                    )
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            nxt = pp._probe_next_hop(f"http://127.0.0.1:{dead}", timeout=10)
            assert nxt == "http://127.0.0.1:8118", (
                "the earlier failure to answer at all must not have "
                "excluded this address")
        finally:
            srv.close()

    def case_a_hop_that_is_the_launchs_own_proxy_is_never_asked(self, certdir):
        """A forward proxy answers a path-only request line with an error BY
        DEFINITION, and writes that error into its own log — somebody else's
        log, when that proxy is a machine's shared egress. Asking is only
        useful when something wired this launch OVER the hop; when the hop
        IS the launch's own proxy, nothing was wired over it, so the probe
        can only cause the error, never learn anything from it.

        The discriminator is connections accepted, not the return value: the
        old code also returns None for a hop that never answers, so a bare
        `is None` on the result would pass unchanged."""
        import cswap_pin.proxy as pp

        def health_server(next_hop):
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(4)
            accepted = []

            def serve():
                while True:
                    try:
                        c, _ = srv.accept()
                    except OSError:
                        return
                    accepted.append(1)
                    try:
                        buf = b""
                        while b"\r\n\r\n" not in buf:
                            d = c.recv(4096)
                            if not d:
                                break
                            buf += d
                        body = json.dumps(
                            {"status": "ok", "https_proxy": next_hop}
                        ).encode()
                        c.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Content-Length: " + str(len(body)).encode()
                            + b"\r\n\r\n" + body
                        )
                    except OSError:
                        pass
                    finally:
                        c.close()

            threading.Thread(target=serve, daemon=True).start()
            return srv, accepted

        ambient_srv, ambient_accepted = health_server("http://127.0.0.1:1")
        other_srv, other_accepted = health_server("http://127.0.0.1:2")
        try:
            ambient_url = f"http://127.0.0.1:{ambient_srv.getsockname()[1]}"
            other_url = f"http://127.0.0.1:{other_srv.getsockname()[1]}"

            # The hop asked IS the launch's own ambient proxy: nothing wired
            # this launch over it, so it is never even connected to.
            nxt = pp._probe_next_hop(ambient_url, own_proxy=ambient_url)
            time.sleep(0.2)
            assert nxt is None
            assert ambient_accepted == [], (
                "the launch's own proxy was asked for /health anyway"
            )

            # Positive control: a hop that is NOT the ambient proxy is still
            # asked, exactly once, and its answer still comes back. No sleep
            # needed here: `_probe_next_hop` only returns after the response
            # has already been read, so the accept is already recorded.
            nxt = pp._probe_next_hop(other_url, timeout=10, own_proxy=ambient_url)
            assert nxt == "http://127.0.0.1:2"
            assert other_accepted == [1], other_accepted
        finally:
            ambient_srv.close()
            other_srv.close()

    def case_ensure_proxy_never_probes_the_shells_own_exported_proxy(
        self, tmp_path, monkeypatch
    ):
        """The call site, not the comparison in isolation. When this
        launch's own shell exports HTTPS_PROXY directly at a hop — an
        ordinary shell, or an ssh shell, whose only proxy is the
        machine-wide egress the launcher itself chains to — `ensure_proxy`
        resolves that hop as `ambient` unchanged (nothing recorded yet to
        prefer instead), so it must never connect to it for `/health`
        either: a fresh launch is a fresh process, and `_ASKED_NOHEALTH`
        cannot amortise a probe it would only ever make once."""
        import cswap_pin.proxy as pp

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        accepted = []

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                accepted.append(1)
                c.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            exported = f"http://127.0.0.1:{srv.getsockname()[1]}"
            monkeypatch.setenv("HTTPS_PROXY", exported)
            monkeypatch.setattr(pp, "load_pin", lambda _bd: ("a@b.c", ""))
            monkeypatch.setattr(pp, "_carry_history_pointers", lambda _cd: None)
            monkeypatch.setattr(pp, "daemon_fingerprint", lambda *_a: "FP")
            monkeypatch.setattr(pp, "ensure_ca", lambda *_a: None)
            monkeypatch.setattr(pp, "publish_ca", lambda _p: None)
            monkeypatch.setattr(pp, "wire_global_config", lambda *_a: None)
            monkeypatch.setattr(pp, "_read_alive_port", lambda *_a, **_k: 41000)

            class _SW:
                backup_dir = tmp_path

                def resolve_account(self, email):
                    return "1", email, None

            got = pp.ensure_proxy(_SW())
            time.sleep(0.2)
            assert got == (41000, tmp_path / "pin-proxy" / "ca.pem")
            assert accepted == [], (
                "ensure_proxy asked its own shell's exported proxy for "
                "/health"
            )
        finally:
            srv.close()

    def case_learn_next_hop_still_probes_when_the_daemons_own_proxy_matches(
        self, certdir, monkeypatch
    ):
        """THE LAUNCHER-WITH-CACHE-PROXY CONFIGURATION: a daemon spawned with
        HTTPS_PROXY=<the very address it records as its chain> (a launcher
        that starts a per-session cache proxy and exports it directly) is the
        configuration `learn_next_hop`'s own docstring cites the 2026-08-04
        upstream.json for -- 9901 chaining to 8118 is the MEASURED half.
        BY CONSTRUCTION, not measured, is the rest: `_shell_proxy()` reads
        back whatever HTTPS_PROXY this process inherited, so a daemon started
        with it equal to `recorded` would have an `own_proxy` guard passed at
        this call site refuse the probe that matters. `ensure_proxy` still
        passes `own_proxy` (see the previous two cases); `learn_next_hop`
        does not, and this is the case that needs it not to."""
        import cswap_pin.proxy as pp

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    body = json.dumps(
                        {"status": "ok", "https_proxy": "http://127.0.0.1:8118"}
                    ).encode()
                    c.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n\r\n" + body
                    )
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            recorded = f"http://127.0.0.1:{srv.getsockname()[1]}"
            # The daemon's own environment inherits the same address it
            # recorded as its chain -- constructed, not the measured half
            # (see the case docstring: only the 9901->8118 chain is measured).
            monkeypatch.setenv("HTTPS_PROXY", recorded)
            pp.write_upstream_hint(certdir, recorded)

            proxy = pp.PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                upstream=("127.0.0.1", 1),
                rediscover_chain=True,
            )
            proxy.port = 36301
            import functools

            # timeout=10: the assertion below waits on the server thread's
            # own reply, not the network — see the analogous swap in
            # `case_the_record_grows_and_refuses_a_hop_that_names_the_pin`.
            monkeypatch.setattr(
                pp, "_probe_next_hop",
                functools.partial(pp._probe_next_hop, timeout=10),
            )
            proxy.learn_next_hop()
            assert pp._read_upstream(certdir, "next") == (
                "http://127.0.0.1:8118"
            ), (
                "the daemon's own inherited proxy matching the hop it "
                "records blocked the probe that learns the chain behind it"
            )
        finally:
            srv.close()

    def case_ensure_proxy_still_probes_a_preferred_inner_hop(
        self, tmp_path, monkeypatch
    ):
        """Positive control for the previous case. An ordinary shell only
        ever sees the outer egress proxy — but when a DIFFERENT, already
        recorded inner hop is still serving, `_ambient_proxy` prefers it
        over that shell value, and the two addresses now differ: this hop
        is still probed."""
        import cswap_pin.proxy as pp

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        # `_ambient_proxy`'s own preference check opens a bare liveness
        # connection to this hop (no HTTP request) before `_probe_next_hop`
        # makes the real `/health` request — so the discriminator here is a
        # RESPONSE actually sent, not merely a connection accepted.
        served = []

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    if not buf:
                        continue
                    body = json.dumps(
                        {"status": "ok", "https_proxy": "http://192.0.2.1:3128"}
                    ).encode()
                    c.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n\r\n" + body
                    )
                    served.append(1)
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            inner = f"http://127.0.0.1:{srv.getsockname()[1]}"
            certdir = tmp_path / "pin-proxy"
            certdir.mkdir(parents=True, exist_ok=True)
            # A previous launch already recorded this inner hop.
            pp.write_upstream_hint(certdir, inner)
            # This shell only has the outer egress proxy — a reserved,
            # documentation-only address (RFC 5737), never dialed here.
            monkeypatch.setenv("HTTPS_PROXY", "http://192.0.2.1:3128")
            monkeypatch.setattr(pp, "load_pin", lambda _bd: ("a@b.c", ""))
            monkeypatch.setattr(pp, "_carry_history_pointers", lambda _cd: None)
            monkeypatch.setattr(pp, "daemon_fingerprint", lambda *_a: "FP")
            monkeypatch.setattr(pp, "ensure_ca", lambda *_a: None)
            monkeypatch.setattr(pp, "publish_ca", lambda _p: None)
            monkeypatch.setattr(pp, "wire_global_config", lambda *_a: None)
            monkeypatch.setattr(pp, "_read_alive_port", lambda *_a, **_k: 41000)
            import functools

            # timeout=10: `served` (6526) needs the server thread's own
            # reply, not the network — see the analogous swap in
            # `case_the_record_grows_and_refuses_a_hop_that_names_the_pin`.
            monkeypatch.setattr(
                pp, "_probe_next_hop",
                functools.partial(pp._probe_next_hop, timeout=10),
            )

            class _SW:
                backup_dir = tmp_path

                def resolve_account(self, email):
                    return "1", email, None

            got = pp.ensure_proxy(_SW())
            time.sleep(0.2)
            assert got == (41000, certdir / "ca.pem")
            assert served == [1], (
                "the preferred inner hop, distinct from the shell's own "
                "export, was never asked"
            )
            assert pp._chain_hops(certdir)[-1].address == ("192.0.2.1", 3128)
        finally:
            srv.close()

    def case_ensure_proxy_re_records_a_chain_recorded_outer_first(
        self, tmp_path, monkeypatch
    ):
        """The first pin ran from a shell exporting the OUTER egress proxy
        (answers every /health with 400), so it is what upstream.json holds;
        a re-pin from a shell exporting the INNER cache proxy (whose /health
        names the outer one) used to keep it, record proxy=outer next=inner,
        and send every pinned request past the cache proxy, silently. The
        record must end up [inner, outer], and stay so on the next launch
        from the same shell, which must not ask the outer hop again."""
        import cswap_pin.proxy as pp

        outer_srv, outer, outer_served = _http_hop(b"400 Bad Request")
        body = json.dumps({"status": "ok", "https_proxy": outer}).encode()
        inner_srv, inner, _ = _http_hop(b"200 OK", body)
        try:
            launch, certdir = _launch_from(inner, tmp_path, monkeypatch)
            pp.write_upstream_hint(certdir, outer)
            want = [
                pp.parse_upstream_proxy(inner).address,
                pp.parse_upstream_proxy(outer).address,
            ]

            launch()
            assert [h.address for h in pp._chain_hops(certdir)] == want
            assert outer_served == [1], "the outer hop is asked once, to learn it"

            pp._ASKED_NOHEALTH.clear()  # a fresh process remembers nothing
            launch()  # the next launch from the same shell
            assert [h.address for h in pp._chain_hops(certdir)] == want
            assert outer_served == [1], "the settled record asks no one again"
        finally:
            outer_srv.close()
            inner_srv.close()

    def case_ensure_proxy_never_asks_the_shells_hop_while_the_recorded_one_answers(
        self, tmp_path, monkeypatch
    ):
        """The design case stays quiet: the recorded hop answers /health 200
        and names a third address, so there is no reversed record to find and
        the shell's own exported hop is never asked anything."""
        import cswap_pin.proxy as pp

        body = json.dumps({"https_proxy": "http://192.0.2.1:3128"}).encode()
        rec_srv, recorded, _ = _http_hop(b"200 OK", body)
        shell_srv, shell, shell_served = _http_hop(b"400 Bad Request")
        try:
            launch, certdir = _launch_from(shell, tmp_path, monkeypatch)
            pp.write_upstream_hint(certdir, recorded)

            launch()
            assert shell_served == [], "the shell's own hop was asked /health"
            assert pp._read_upstream(certdir, "proxy") == recorded
        finally:
            rec_srv.close()
            shell_srv.close()

    def case_ensure_proxy_never_asks_the_shells_hop_of_a_recorded_hop_that_did_not_decline(
        self, tmp_path, monkeypatch
    ):
        """The recorded hop answers 200 without an `https_proxy`: it is a
        /health server with nothing behind it, not a hop that declared itself
        a non-/health one, so the shell's hop (which WOULD name it) is never
        asked and the record is not swapped."""
        import cswap_pin.proxy as pp

        rec_srv, recorded, _ = _http_hop(b"200 OK", b"{}")
        body = json.dumps({"https_proxy": recorded}).encode()
        shell_srv, shell, shell_served = _http_hop(b"200 OK", body)
        try:
            launch, certdir = _launch_from(shell, tmp_path, monkeypatch)
            pp.write_upstream_hint(certdir, recorded)

            launch()
            assert shell_served == [], "the shell's own hop was asked /health"
            assert pp._read_upstream(certdir, "proxy") == recorded
        finally:
            rec_srv.close()
            shell_srv.close()

    def case_ensure_proxy_keeps_the_record_when_the_shells_hop_does_not_name_it(
        self, tmp_path, monkeypatch
    ):
        """The recorded hop declares itself non-/health (400) and the shell's
        hop is asked, but it names a THIRD address: not a chain through the
        recorded hop, so the record is not swapped."""
        import cswap_pin.proxy as pp

        rec_srv, recorded, _ = _http_hop(b"400 Bad Request")
        body = json.dumps({"https_proxy": "http://192.0.2.1:3128"}).encode()
        shell_srv, shell, shell_served = _http_hop(b"200 OK", body)
        try:
            launch, certdir = _launch_from(shell, tmp_path, monkeypatch)
            pp.write_upstream_hint(certdir, recorded)

            launch()
            assert shell_served == [1], "the gate was never reached: no control"
            assert pp._read_upstream(certdir, "proxy") == recorded
        finally:
            rec_srv.close()
            shell_srv.close()



class TestAbsoluteFormPassthrough:
    """The native auto-updater and telemetry use axios in plain-proxy mode:
    they send `GET http://host/path` (absolute-form, no CONNECT). The proxy
    must relay these through the chain, not drop them (dropping = the
    'Auto-update failed' banner). No MITM/swap — just forward."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_absolute_form_get_is_relayed(self, certdir):
        from cswap_pin.proxy import PinProxy

        # A plain HTTP origin the "updater" fetches (absolute-form target).
        origin_seen = {}
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        oport = srv.getsockname()[1]

        def origin():
            try:
                c, _ = srv.accept()
                data = b""
                while b"\r\n\r\n" not in data:
                    data += c.recv(4096)
                origin_seen["req"] = data.decode("latin1").splitlines()[0]
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                c.close()
            except Exception:
                pass
        threading.Thread(target=origin, daemon=True).start()

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                f"GET http://127.0.0.1:{oport}/releases/latest HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{oport}\r\n\r\n".encode()
            )
            resp = b""
            raw.settimeout(5)
            while b"OK" not in resp:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                resp += chunk
            raw.close()
            assert b"200 OK" in resp
            assert origin_seen.get("req", "").startswith("GET /releases/latest")
        finally:
            proxy.stop()
            srv.close()


class TestHealthEndpoint:
    """The pin proxy answers GET /health (absolute-form or origin-form to its
    own port) so a statusline/cc-update probe can tell it apart from CCF and
    read the chain it forwards to (mirrors CCF's /health with https_proxy)."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_health_reports_the_chain_and_whether_egress_uses_it(self, certdir):
        """/health carries BOTH the configured chain and what egress is doing.

        `chain` alone is not a health signal. It reports the hop the relay
        WOULD use, so a daemon that can reach no hop and is dialling DIRECT
        reported exactly what a healthy one did — every field was green
        through two measured outages, here and on the peer component.

        DIRECT is not degraded-but-fine on a corporate host: the direct route
        IS the TLS-inspecting proxy, and it answers 403. Owner's count on
        host-a for one day:

            egress DIRECT                61
            dial failed                 148
            accepted but did not tunnel  89
            egress via (healthy)        238

        61 is not an exception. The pin detected all four of that day's
        outages and wrote all four to daemon.log; nobody read it any of the
        four times, and a human repaired the chain by hand each time. The
        detection was already finished — only the wiring was missing.

        `egress` is null before the first dial, deliberately: "not dialled
        yet" and "we are direct" are different states, and a monitor that
        conflates them alarms on every daemon start. The three faults stay
        separate for the same reason — `dial failed` (no port), `accepted but
        did not tunnel` (up and looped) and DIRECT (chain given up on) are
        different incidents.

        THE CONTROL is a reachable hop, which must report itself rather than
        "direct" — otherwise the field would pass for one that says direct
        always.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        def _health(chain_target, **kw):
            if chain_target is not None:
                write_upstream_hint(certdir, chain_target)
            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                upstream=("127.0.0.1", 1),
                **kw,
            )
            proxy.start()
            try:
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
                raw.close()
                assert b"200" in resp.split(b"\r\n", 1)[0], resp[:40]
                return json.loads(body.decode() or "{}")
            finally:
                proxy.stop()

        # The configured chain, reported as configured.
        data = _health(None, chain_proxy=("127.0.0.1", 9901))
        assert data.get("pin_proxy") is True
        assert data.get("chain") == "127.0.0.1:9901"
        assert "egress" in data, (
            "/health reports the CONFIGURED chain and nothing about whether "
            "egress is actually using it — the field a monitor needs"
        )

        # CONTROL: a reachable hop must report ITSELF, not "direct".
        hop = _LoopbackConnectProxy(("127.0.0.1", 1))
        try:
            live = _health(f"http://127.0.0.1:{hop.port}", rediscover_chain=True)
            assert live.get("egress") != "direct", (
                f"CONTROL FAILED: a reachable hop was reported as DIRECT "
                f"({live.get('egress')!r}) — the field says direct always"
            )
        finally:
            hop.stop()

        # AND THE OUTAGE MUST OUTLIVE THE RECOVERY. `egress` is the state RIGHT
        # NOW, so a chain that breaks and comes back reads green to every probe
        # that arrives afterwards — which is every probe, because nobody is
        # watching at the instant it breaks. Measured on host-b
        # 2026-08-06, the fifth outage in the count above:
        #
        #   22:35:44Z  hop 9901 unusable — accepted but did not tunnel
        #   22:36:46Z  hop 8118 unusable — accepted but did not tunnel
        #   22:36:46Z  egress DIRECT
        #   22:36:47Z  egress via 127.0.0.1:9901       <- green again
        #
        # One second of green-again and the incident is gone. Nothing on this
        # host recorded that it happened except a log line, and a probe an hour
        # later reads a healthy daemon — which is how the four before it were
        # each repaired by hand without anyone knowing why.
        #
        # These are UTC; claude-swap.log is local. A session hunting an
        # unrelated artifact failure compared the two directly, matched this
        # outage to a symptom four hours away, and shipped it as the cause.
        # The field this test guards must not invite that: /health emits UTC.
        #
        # `direct_last` is the transition TIME, not a flag: "we went direct"
        # with no when cannot be told from an hour ago or a week ago, and the
        # only question a reader has is whether it explains what they are
        # looking at. Null until it happens — same reason `egress` is null
        # before the first dial.
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            chain_proxy=("127.0.0.1", 9901),
        )
        assert proxy.direct_last is None, (
            "a daemon that has never gone direct must not claim it did"
        )
        proxy._note_egress(direct=True, configured=True)
        fell_at = proxy.direct_last
        assert fell_at is not None, "the DIRECT transition was not recorded"
        proxy._note_egress(direct=False, hop=("127.0.0.1", 9901))
        assert proxy.direct_last == fell_at, (
            "recovering to a healthy hop erased the outage — this is the bug: "
            "every probe after the flap sees a green daemon and the incident "
            "becomes invisible"
        )

        # A HOST WITH NO CHAIN AT ALL IS NOT AN OUTAGE. `configured=False` is
        # the steady state on a machine with no egress proxy; stamping it would
        # leave every such machine permanently reporting a fault it does not
        # have — the same conflation the `egress`-vs-null split already avoids.
        never = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
        )
        never._note_egress(direct=True, configured=False)
        assert never.direct_last is None, (
            "a host with no configured chain was recorded as having fallen "
            "back to direct — it never had a chain to fall back from"
        )

    def case_direct_last_is_a_wire_contract_another_repo_reads(self, certdir):
        """The JSON KEY and its TYPE, not the Python property.

        The case above asserts `proxy.direct_last`, an attribute of this
        object. The consumer is in ANOTHER REPOSITORY and reads
        `json["direct_last"]` off the wire — cswap_fork's .claude/verify.sh,
        the chain-egress check, running per host on every deploy. Renaming the
        key or changing its type breaks that consumer and leaves BOTH suites
        green, because nothing here has ever looked at the payload.

        `chain` and `egress` are already pinned by name: the case above
        asserts `data.get("chain") == ...` and `"egress" in data`, so a rename
        of either fails. `direct_last` had neither, and it is the field with
        the subtler failure — a retype still renders in the consumer's
        f-string and produces a plausible wrong answer instead of a crash.

        THE Z IS LOAD-BEARING. daemon.log is UTC while claude-swap.log is
        local; a session compared the two directly, matched an outage to a
        symptom four hours away and shipped it as the cause. A naive
        `isoformat()` drops the suffix and re-opens exactly that.

        NULL, NOT ABSENT, before the first fallback: `.get()` cannot tell
        those apart, so it has to be asserted at the source.
        """
        import datetime
        import json as _json

        from cswap_pin.proxy import PinProxy

        def _payload(proxy):
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            try:
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1]
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
            finally:
                raw.close()
            return _json.loads(body.decode() or "{}")

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            chain_proxy=("127.0.0.1", 9901),
        )
        proxy.start()
        try:
            fresh = _payload(proxy)
            assert "direct_last" in fresh, (
                "/health dropped the direct_last KEY — the cross-repo "
                "chain-egress check reads it by that exact name"
            )
            assert fresh["direct_last"] is None, (
                f"a daemon that has never gone direct published "
                f"{fresh['direct_last']!r} — null is what 'not yet' looks like"
            )

            proxy._note_egress(direct=True, configured=True)
            fell = _payload(proxy)["direct_last"]
            assert isinstance(fell, str), (
                f"direct_last went out as {type(fell).__name__} ({fell!r}). A "
                f"retype breaks the consumer as hard as a rename, and worse: "
                f"an epoch float still renders in its message and reads as a "
                f"plausible timestamp"
            )
            assert fell.endswith("Z"), (
                f"direct_last published {fell!r} with no UTC marker. "
                f"daemon.log is UTC and claude-swap.log is local; a reader "
                f"already compared the two and blamed the wrong incident"
            )
            # Parses as a real instant, so "Z" cannot be satisfied by a string
            # that merely ends in one.
            datetime.datetime.strptime(fell, "%Y-%m-%dT%H:%M:%SZ")
        finally:
            proxy.stop()

    def case_health_names_who_holds_the_socket(self, certdir):
        """WHICH process owns the address, answered by the kernel, not a record.

        Nothing on the box published this and it cost a peer session a false
        finding: they read the ROLE off argv, which is fixed at exec, so a
        standby that ARMED and became the holder still reads `--standby`
        forever. They reported a machine as deviating when its triad was
        intact. proxy.json records the DAEMON pid, never the holder's.

        COMPUTED AT REQUEST TIME, NEVER STORED, and that is the whole design.
        A stored holder goes stale in exactly the event this field exists to
        report: the holder dies, a standby arms, and the record still names
        the dead one until the next daemon respawn. `held_by_a_holder()`
        compares the spawn-time marker against a LIVE `getppid()`, so the
        kernel owns the comparand and pid reuse cannot forge it — a reused pid
        would have to be this process's actual parent.

        NOT `getppid()` ALONE, which is the tempting one-liner. A daemon
        nobody holds — a bare `daemon_main`, a test harness — still has a
        parent, so the naive version names an unrelated process as the holder
        of a socket it has never heard of. `null` is the honest answer there,
        and it is also the useful one: no holder means this address dies with
        this process.

        NOT `ppid == 1` EITHER. A PR_SET_CHILD_SUBREAPER ancestor collects
        orphans instead of init, so an orphaned daemon never reads 1 — the
        same trap `_spawn_standby` already documents for the standby's arming
        predicate, where getting it wrong left the address ACCEPTING AND
        HANGING (a peer measured 15,010ms) rather than refusing.
        """
        import json as _json
        import os as _os

        from cswap_pin.proxy import _HELD_BY_ENV, PinProxy

        def _payload(proxy):
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            try:
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1]
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
            finally:
                raw.close()
            return _json.loads(body.decode() or "{}")

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
        )
        proxy.start()
        try:
            # UNHELD: this test process was not spawned by a holder.
            unheld = _payload(proxy)
            assert "holder_pid" in unheld, (
                "/health does not say who holds the socket — the one question "
                "argv cannot answer and proxy.json does not record"
            )
            assert unheld["holder_pid"] is None, (
                f"a daemon nobody holds named {unheld['holder_pid']!r} as its "
                f"holder — that is just getppid(), and it points at a process "
                f"that has never heard of this socket"
            )

            # HELD: the marker names our real parent, which is what a holder
            # sets at spawn. CONTROL below proves the field is not simply
            # echoing getppid() regardless.
            real_ppid = _os.getppid()
            saved = _os.environ.get(_HELD_BY_ENV)
            _os.environ[_HELD_BY_ENV] = str(real_ppid)
            try:
                held = _payload(proxy)["holder_pid"]
            finally:
                if saved is None:
                    _os.environ.pop(_HELD_BY_ENV, None)
                else:
                    _os.environ[_HELD_BY_ENV] = saved
            assert held == real_ppid, (
                f"held daemon reported holder_pid={held!r}, expected the live "
                f"parent {real_ppid}"
            )

            # CONTROL: a marker naming somebody who is NOT our parent must not
            # be believed. This is the pid-reuse case in miniature — a stored
            # number that no longer refers to the process that stored it.
            _os.environ[_HELD_BY_ENV] = str(real_ppid + 1000000)
            try:
                stale = _payload(proxy)["holder_pid"]
            finally:
                if saved is None:
                    _os.environ.pop(_HELD_BY_ENV, None)
                else:
                    _os.environ[_HELD_BY_ENV] = saved
            assert stale is None, (
                f"a marker naming a non-parent was reported as the holder "
                f"({stale!r}) — the field trusted a record over the kernel"
            )
        finally:
            proxy.stop()

    def case_health_names_its_own_pid_not_the_holders(self, certdir):
        """`pid` is THIS process's own os.getpid(), the one number
        comparable against proxy.json's `pid` (the daemon's own, self-
        written at start) -- `holder_pid` above answers a different
        question and stays constant across every generation one
        long-lived holder spawns in turn, so it cannot say whether THIS
        answer came from the generation proxy.json currently calls live."""
        import json as _json
        import os as _os

        from cswap_pin.proxy import PinProxy

        def _payload(proxy):
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            try:
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1]
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
            finally:
                raw.close()
            return _json.loads(body.decode() or "{}")

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
        )
        proxy.start()
        try:
            got = _payload(proxy)["pid"]
        finally:
            proxy.stop()
        assert got == _os.getpid(), (
            f"/health named pid {got!r}, expected this process's own "
            f"{_os.getpid()}"
        )

    def case_a_hop_that_self_heals_leaves_a_record(self, certdir):
        """A fall-through to a LATER hop, in a tense a later probe can read.

        `direct_last` covers the chain being abandoned entirely. It does not
        cover the chain being DEGRADED — the preferred hop dying and the walk
        carrying on through the one behind it. That is still egress through a
        configured proxy, so `direct` is False and nothing was stamped.

        MEASURED ON host-a, and this is the whole case:

            06:18:09Z  hop 9901 unusable — accepted but did not tunnel
            06:18:09Z  hop 9901 unusable — dial failed: ConnectionRefusedError
            06:18:09Z  egress via 127.0.0.1:8118      <- degraded
            06:18:10Z  egress via 127.0.0.1:9901      <- healthy again

        ONE SECOND. The peer's per-deploy chain check would have failed inside
        that window and no per-deploy probe can ever land in it. Afterwards the
        daemon reads green on every field, so the event is unreadable — which
        is `direct_last`'s own argument for existing, applied to a different
        hop. The sticky record was built for DIRECT and never generalised.

        DEGRADED IS DEFINED BY PREFERENCE, not by hop identity:
        `_chain_candidates()` returns the re-read current chain first and
        recorded next-hops behind it, so anything that is not candidates[0]
        means the preferred hop did not carry this request.

        CONTROL below is the healthy hop: it must NOT stamp, or the field
        would read as a permanent fault on every machine whose chain works.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        # Two ports nothing listens on. The fake dial keys on them, so they
        # only have to be distinct and unused.
        _s = socket.socket(); _s.bind(("127.0.0.1", 0)); dead_port = _s.getsockname()[1]; _s.close()
        _s = socket.socket(); _s.bind(("127.0.0.1", 0)); live_port = _s.getsockname()[1]; _s.close()

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            chain_proxy=("127.0.0.1", 9901),
        )
        assert proxy.hop_degraded_last is None, (
            "a daemon that has never fallen through claimed it had"
        )

        # CONTROL FIRST: the PREFERRED hop carrying the request must not stamp.
        # Without this the assertion below passes for a field that stamps on
        # every successful dial, which is the same as never stamping at all.
        proxy._note_egress(direct=False, hop=("127.0.0.1", 9901), preferred=True)
        assert proxy.hop_degraded_last is None, (
            "the preferred hop carrying traffic was recorded as degradation — "
            "the field would report a permanent fault on every healthy machine"
        )

        proxy._note_egress(direct=False, hop=("127.0.0.1", 8118), preferred=False)
        fell = proxy.hop_degraded_last
        assert fell is not None, (
            "the walk fell through to a later hop and nothing recorded it — "
            "this is the 06:18:09Z event, invisible one second later"
        )

        # AND IT MUST OUTLIVE THE RECOVERY, for the same reason direct_last
        # does: the probe that could read it arrives after the flap, always.
        proxy._note_egress(direct=False, hop=("127.0.0.1", 9901), preferred=True)
        assert proxy.hop_degraded_last == fell, (
            "recovering to the preferred hop erased the degradation — every "
            "probe after the flap sees a green daemon, which is the bug"
        )

        # AND THE WALK MUST ACTUALLY SAY SO. Everything above drives
        # `_note_egress` by hand, so it proves the STAMP and nothing about the
        # caller — `preferred=(i == 0)` could be inverted, or hardcoded True,
        # and every assertion above still passes while the field never fires
        # on a real dial. This drives `_walk_chain_once` itself with hop 0
        # dead and hop 1 answering.
        seen = {}

        # HELD, NOT CLOSED. Closing the peer before the walk writes its
        # CONNECT makes sendall raise EPIPE, which `_walk_chain_once` treats
        # as "hop unusable" — so the fixture reported hop 1 as dead too and
        # the walk returned None. The guard above caught it; without that
        # assertion this case would have gone green while proving nothing.
        peers = []

        def _fake_dial(chain, extra_ca=None):
            if chain.port == dead_port:
                raise OSError("refused")
            ours, theirs = socket.socketpair()
            theirs.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            peers.append(theirs)
            return ours

        import cswap_pin.proxy as _mod

        write_upstream_hint(
            certdir, f"http://127.0.0.1:{dead_port}",
            next_hop=f"http://127.0.0.1:{live_port}",
        )
        walker = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        # BOUND TO `walker`, and it has to be spelled out: the first draft
        # captured `proxy._note_egress` — the OTHER object — so the walk
        # stamped a proxy nobody was asserting on and `hop_degraded_last`
        # read None on the one under test. Right call, wrong instance.
        _real_note = walker._note_egress

        def _spy(**kw):
            seen.update(kw)
            return _real_note(**kw)

        walker._note_egress = _spy
        saved_dial = _mod._dial_chain
        _mod._dial_chain = _fake_dial
        try:
            got = walker._walk_chain_once()
        finally:
            _mod._dial_chain = saved_dial
        assert got is not None, (
            "the walk found no usable hop — the fixture never reached hop 1, "
            "so anything it reports about preference is vacuous"
        )
        assert seen.get("hop") == ("127.0.0.1", live_port), (
            f"hop 1 was expected to carry, but the walk reported "
            f"{seen.get('hop')!r} — wrong subject, the preference claim below "
            f"would be about a hop that never carried anything"
        )
        assert seen.get("preferred") is False, (
            f"the walk skipped the preferred hop and told _note_egress "
            f"preferred={seen.get('preferred')!r} — the stamp is wired to a "
            f"flag the caller never sets correctly, so it can never fire in "
            f"production"
        )
        assert walker.hop_degraded_last is not None, (
            "a real fall-through through the real walk recorded nothing"
        )

    def case_health_publishes_blind_reason_only_while_blind(self, certdir):
        """/health never published `blind_reason` before this round — the
        operator's only view of a daemon refusing bridge creates closed."""
        import json as _json

        from cswap_pin.proxy import PinProxy

        def _get_health(proxy):
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            try:
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1]
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
            finally:
                raw.close()
            return _json.loads(body.decode() or "{}")

        def provider():
            return None
        provider.blind_reason = ""  # clear at start

        proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                         upstream=("127.0.0.1", 1))
        proxy.start()
        try:
            clear = _get_health(proxy)
            assert "blind_reason" in clear, (
                "/health dropped the blind_reason KEY")
            assert clear["blind_reason"] is None, (
                f"a clear pin published blind_reason={clear['blind_reason']!r}")

            provider.blind_reason = "no credential for slot 1 (a@example.com)"
            blind = _get_health(proxy)
            assert blind["blind_reason"] == provider.blind_reason, (
                f"/health did not carry the real blind_reason: {blind!r}")
        finally:
            proxy.stop()


class _KeepAliveUpstream:
    """A TLS upstream that serves MULTIPLE requests per connection (HTTP/1.1
    keep-alive, like the real api.anthropic.com) and records each one.

    The RC worker holds one connection open and pipelines heartbeat/poll
    requests over it; a proxy that closes after the first request forces an
    endless reconnect loop ("Transport closed: server rejected connection").
    """

    def __init__(self, certdir: Path):
        self.paths: list[str] = []
        self.auths: list[str] = []
        self.conns = 0
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            self.conns += 1
            buf = b""
            while not self._stop:
                while b"\r\n\r\n" not in buf:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, buf = buf.partition(b"\r\n\r\n")
                text = head.decode("latin1")
                lines = text.split("\r\n")
                self.paths.append(lines[0].split(" ")[1])
                for line in lines[1:]:
                    if line.lower().startswith("authorization:"):
                        self.auths.append(line.split(":", 1)[1].strip())
                want = 0
                for line in lines[1:]:
                    if line.lower().startswith("content-length:"):
                        want = int(line.split(":")[1])
                while len(buf) < want:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                buf = buf[want:]
                # keep-alive reply: no Connection: close
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Content-Type: application/json\r\n\r\n{}"
                )
        except Exception:
            pass

    def stop(self):
        self._stop = True
        try:
            with socket.create_connection(self._srv.getsockname(),
                                          timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class TestKeepAlive:
    """The RC worker pipelines many requests over ONE connection. Closing
    after the first is what made /remote-control fail with 'Transport closed:
    server rejected connection' while every individual route swapped fine."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_multiple_requests_over_one_connection(self, certdir):
        from cswap_pin.proxy import PinProxy

        up = _KeepAliveUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PINTOKEN",
            upstream=("127.0.0.1", up.port),
        )
        proxy.start()
        try:
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            conn = http.client.HTTPSConnection(
                "api.anthropic.com", context=ctx, timeout=10
            )
            conn.set_tunnel("api.anthropic.com", 443)
            conn._create_connection = lambda *a, **k: socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=10
            )
            # /bridge is OAuth-pinned; /worker keeps its session JWT;
            # /v1/messages keeps the inference account. All three pipelined
            # over ONE connection.
            sent = [
                "/v1/code/sessions/cse_x/bridge",
                "/v1/code/sessions/cse_x/worker",
                "/v1/messages",
            ]
            for p in sent:
                conn.request("GET", p, headers={"Authorization": "Bearer DISK"})
                r = conn.getresponse()
                r.read()
                assert r.status == 200, f"{p} failed on a reused connection"
            conn.close()
        finally:
            proxy.stop()
            up.stop()

        assert up.paths == sent, f"upstream saw {up.paths}"
        # pinned routes swapped, inference untouched — even when pipelined
        assert up.auths == ["Bearer PINTOKEN", "Bearer DISK", "Bearer DISK"]


class _WebSocketUpstream:
    """A TLS upstream that only accepts a proper WebSocket handshake.

    Mirrors the real /worker/events/stream contract: without `Connection:
    Upgrade` + `Upgrade: websocket` it answers 403, which is exactly what the
    RC transport reported ("Transport closed: server rejected connection
    (code 403)") when the proxy stripped those hop-by-hop headers.
    """

    def __init__(self, certdir: Path):
        self.saw_upgrade = False
        self.echo = b""
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head = buf.split(b"\r\n\r\n")[0].decode("latin1").lower()
            if "upgrade: websocket" in head and "connection:" in head:
                self.saw_upgrade = True
                tls.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                )
                # after the upgrade the connection is a raw byte tunnel
                data = tls.recv(4096)
                self.echo = data
                tls.sendall(b"PONG")
            else:
                tls.sendall(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                )
        except Exception:
            pass

    def stop(self):
        self._stop = True
        try:
            with socket.create_connection(self._srv.getsockname(),
                                          timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


class _WebSocketAuthUpstream:
    """A TLS upstream for a pinned WebSocket route: answers `reject_status`
    (`Connection: close`, no upgrade) to a bearer in `reject_bearer`, a 101
    handshake to any other. Records every Authorization it saw, in order --
    like `_FakeUpstream`, a swap-refused case reconnects per attempt."""

    def __init__(self, certdir: Path,
                 reject_bearer: "str | set[str] | None" = None,
                 reject_status: int = 401):
        self._reject = ({reject_bearer} if isinstance(reject_bearer, str)
                         else set(reject_bearer or ()))
        self.reject_status = reject_status
        self.auths_seen: "list[str | None]" = []
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thr = threading.Thread(target=self._loop, daemon=True)
        self._thr.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head = buf.split(b"\r\n\r\n")[0].decode("latin1")
            auth = next((ln.split(":", 1)[1].strip()
                         for ln in head.split("\r\n")
                         if ln.lower().startswith("authorization:")), None)
            self.auths_seen.append(auth)
            if auth in {f"Bearer {b}" for b in self._reject}:
                tls.sendall(
                    f"HTTP/1.1 {self.reject_status} Rejected\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n"
                    .encode("latin1"))
                tls.close()
                return
            tls.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            data = tls.recv(4096)
            tls.sendall(b"PONG")
        except Exception:
            pass

    def stop(self):
        self._stop = True
        try:
            with socket.create_connection(self._srv.getsockname(),
                                          timeout=0.2):
                pass
        except OSError:
            pass
        self._srv.close()
        self._thr.join(timeout=2.0)


def _upgrade_via_proxy(proxy_port: int, ca_path: Path, path: str,
                       bearer: "str | None" = None):
    """CONNECT-tunnel through the proxy, TLS to api.anthropic.com, then send
    a WebSocket upgrade GET on `path`. Returns `(status_line, tls_socket)` so
    a 101 caller can keep pumping frames on the returned socket."""
    ctx = ssl.create_default_context(cafile=str(ca_path))
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    raw.sendall(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
               b"Host: api.anthropic.com:443\r\n\r\n")
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += raw.recv(4096)
    assert b"200" in resp.split(b"\r\n")[0]
    tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
    auth = f"Authorization: Bearer {bearer}\r\n" if bearer is not None else ""
    tls.sendall(
        f"GET {path} HTTP/1.1\r\n"
        f"Host: api.anthropic.com\r\n{auth}"
        f"Connection: Upgrade\r\nUpgrade: websocket\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = tls.recv(4096)
        if not chunk:
            break
        head += chunk
    return head.split(b"\r\n")[0], tls


class TestWebSocketUpgrade:
    """RC's transport is a WebSocket. Stripping Connection/Upgrade as
    hop-by-hop made the server answer 403 — the whole reason /remote-control
    never connected through the pin proxy."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_upgrade_headers_reach_upstream_and_tunnel_opens(
            self, certdir, monkeypatch):
        from cswap_pin import proxy as pp
        from cswap_pin.proxy import PinProxy

        lines: list[str] = []
        monkeypatch.setattr(pp, "_log_lifecycle", lines.append)

        up = _WebSocketUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PINTOKEN",
            upstream=("127.0.0.1", up.port),
        )
        proxy.start()
        try:
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n"
            )
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += raw.recv(4096)
            assert b"200" in resp.split(b"\r\n")[0]
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            tls.sendall(
                b"GET /v1/code/sessions/cse_x/worker/events/stream HTTP/1.1\r\n"
                b"Host: api.anthropic.com\r\n"
                b"Authorization: Bearer DISK\r\n"
                b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
                b"Sec-WebSocket-Version: 13\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = tls.recv(4096)
                assert chunk, "proxy closed during the upgrade"
                head += chunk
            status = head.split(b"\r\n")[0]
            assert b"101" in status, f"expected 101, got {status!r}"
            # the tunnel must carry raw frames both ways after the upgrade
            tls.sendall(b"PING")
            assert tls.recv(4096) == b"PONG"
            tls.close()
            # THE END IS NAMED. This upstream closes right after PONG, so
            # it usually wins the race with the client's close; which side
            # gets named is decided by the pump and proven in
            # TestStreamEndIsNamed. Here: the daemon wrote the line, for this
            # bridge, naming a side.
            for _ in range(60):
                if any("inbound stream for cse_x" in ln for ln in lines):
                    break
                time.sleep(0.05)
            ended = [ln for ln in lines if "inbound stream for cse_x" in ln]
            assert ended, lines
            assert ("closed by the upstream" in ended[0]
                    or "closed by the client" in ended[0]), ended[0]
        finally:
            proxy.stop()
            up.stop()

        assert up.saw_upgrade, "upstream never saw the Upgrade headers"


class TestStreamEndIsNamed:
    """A Remote Control give-up leaves no error in any proxy: the inbound
    stream just ends, again and again. The pump tells its callback which
    side ended it, and the daemon writes one line per bridge per minute."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_pump_names_the_side_that_closed(self):
        import socket
        import threading
        from cswap_pin.proxy import _PUMP
        feed, a = socket.socketpair()
        b, sink = socket.socketpair()
        got: list = []
        done = threading.Event()

        def cb(closed_by=None):
            got.append(closed_by)
            done.set()
        cb._wants_closer = True
        _PUMP.add(a, b, cb, "bridge")
        feed.close()
        assert done.wait(3.0), "the callback never ran"
        assert got == [a], "the side that saw EOF must be the one named"
        sink.close()
        # THE CONTROL: a callback that does not ask still gets the bare call.
        feed2, a2 = socket.socketpair()
        b2, sink2 = socket.socketpair()
        plain = threading.Event()
        _PUMP.add(a2, b2, plain.set, "bridge")
        sink2.close()
        assert plain.wait(3.0), "a plain callback stopped being called"
        feed2.close()

    def case_one_line_per_bridge_per_minute(self, monkeypatch):
        from cswap_pin import proxy as pp
        lines: list[str] = []
        monkeypatch.setattr(pp, "_log_lifecycle", lines.append)
        clock = {"t": 1000.0}
        monkeypatch.setattr(pp.time, "monotonic", lambda: clock["t"])
        d = pp.PinProxy.__new__(pp.PinProxy)
        d._note_stream_end("cse_A", 0.4, "upstream")
        d._note_stream_end("cse_A", 0.3, "upstream")
        d._note_stream_end("cse_B", 9.0, "client")
        assert len(lines) == 2 and "cse_A" in lines[0] and "cse_B" in lines[1]
        assert "closed by the upstream" in lines[0] and "0.4s" in lines[0]
        clock["t"] += 61
        d._note_stream_end("cse_A", 0.2, "upstream")
        assert len(lines) == 3 and "1 more" in lines[2], lines[2]


class TestAStaleUpstreamIsRedialled:
    """The hop behind the pin closes an idle keep-alive after a few seconds
    (Node's default is 5 s). The pin kept reusing that socket for the client's
    next request and, when the send met the closed side, dropped the client
    without an answer: a fresh session's first prompt, typed a few seconds
    after launch, failed once and worked on the retry."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    @staticmethod
    def _proxy(certdir, upstream):
        from cswap_pin.proxy import PinProxy
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        return proxy

    @staticmethod
    def _keepalive(proxy_port, ca_path):
        ctx = ssl.create_default_context(cafile=str(ca_path))
        conn = http.client.HTTPSConnection(
            "api.anthropic.com", context=ctx, timeout=5)
        conn.set_tunnel("api.anthropic.com", 443)
        conn._create_connection = lambda *a, **k: socket.create_connection(
            ("127.0.0.1", proxy_port), timeout=5)
        return conn

    @staticmethod
    def _ask(conn):
        conn.request("GET", "/v1/messages", headers={"Authorization": "Bearer t"})
        resp = conn.getresponse()
        return resp.status, resp.read()

    def case_a_request_after_the_hop_closed_its_idle_side_is_answered(
            self, certdir, monkeypatch):
        from cswap_pin import proxy as pp
        # The budget is parked out of the way: what saves this request is the
        # pending close being seen, not the clock.
        monkeypatch.setattr(pp, "_UPSTREAM_IDLE_REUSE_S", 60.0)
        up = _IdleClosingUpstream(certdir, hold=0.3)
        proxy = self._proxy(certdir, up)
        try:
            conn = self._keepalive(proxy.port, certdir / "ca.pem")
            assert self._ask(conn) == (200, b"ok")
            time.sleep(0.8)  # past the hop's hold: its side is closed
            assert self._ask(conn) == (200, b"ok"), (
                "the client's second request died on the hop's closed side")
            assert up.accepted == 2, "the pin did not dial a fresh upstream"
            conn.close()
        finally:
            proxy.stop()
            up.stop()

    def case_a_young_quiet_upstream_is_still_reused(self, certdir):
        up = _IdleClosingUpstream(certdir, hold=5.0)
        proxy = self._proxy(certdir, up)
        try:
            conn = self._keepalive(proxy.port, certdir / "ca.pem")
            assert self._ask(conn) == (200, b"ok")
            time.sleep(0.2)
            assert self._ask(conn) == (200, b"ok")
            assert up.accepted == 1, "a live keep-alive was dropped for nothing"
            conn.close()
        finally:
            proxy.stop()
            up.stop()

    def case_an_upstream_idle_past_the_budget_is_dialled_fresh(
            self, certdir, monkeypatch):
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_UPSTREAM_IDLE_REUSE_S", 0.2)
        up = _IdleClosingUpstream(certdir, hold=5.0)  # the hop would still serve
        proxy = self._proxy(certdir, up)
        try:
            conn = self._keepalive(proxy.port, certdir / "ca.pem")
            assert self._ask(conn) == (200, b"ok")
            time.sleep(0.5)
            assert self._ask(conn) == (200, b"ok")
            assert up.accepted == 2, "the idle budget did not force a fresh dial"
            conn.close()
        finally:
            proxy.stop()
            up.stop()


class TestBlindTunnelIsTraced:
    """Remote Control RECEIVES over a WebSocket to the ingress host named in
    the /bridge response, not to api.anthropic.com — so it is blind-tunnelled,
    never MITM'd. The tunnel used to log nothing, which made a session with no
    inbound channel at all read exactly like a healthy one: everything CC
    *sends* (worker/events, heartbeat, presence) showed 200 in the trace while
    the channel it *receives* on left no line. Diagnosing that cost a live
    debugging session; the tunnel must announce itself."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_tunnel_to_a_foreign_host_writes_a_trace_line(self, certdir, tmp_path):
        import cswap_pin.proxy as pp

        # A plain TCP peer standing in for the ingress host.
        peer = socket.socket()
        peer.bind(("127.0.0.1", 0))
        peer.listen(1)
        peer_port = peer.getsockname()[1]

        log = tmp_path / "trace.log"
        prev = pp._TRACE
        pp._TRACE = open(log, "a")
        try:
            proxy = pp.PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: "PINTOKEN",
                upstream=("127.0.0.1", 1),  # unused: we tunnel elsewhere
            )
            proxy.start()
            try:
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                raw.sendall(
                    f"CONNECT ingress.example.com:{peer_port} HTTP/1.1\r\n"
                    f"Host: ingress.example.com:{peer_port}\r\n\r\n".encode()
                )
                # WAIT FOR THE TRACE, NOT FOR A RESPONSE. `ingress.example.com`
                # does not resolve, so no response is ever coming and the old
                # `recv` loop simply raced the DNS resolver: it blocked until
                # its own 10s socket timeout while the resolver retried.
                # Measured, this test alone: 1 failure in 12 runs, the failing
                # one always ~10.3s against pass-times of 0.8-5.9s. The flake
                # was pre-existing and only became visible when a publish gate
                # started running the suite.
                #
                # The property under test is that the tunnel ANNOUNCES itself,
                # and that line is written before any dial — so waiting for it
                # tests the thing and waits on nothing else.
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    pp._TRACE.flush()
                    if "CONNECT ingress.example.com" in log.read_text():
                        break
                    time.sleep(0.02)
                raw.close()
            finally:
                proxy.stop()
                peer.close()
            pp._TRACE.flush()
        finally:
            pp._TRACE.close()
            pp._TRACE = prev

        text = log.read_text()
        assert "CONNECT ingress.example.com" in text, (
            f"blind tunnel left no trace line; log was:\n{text}"
        )
        # It must also say the pin cannot apply there — that is the whole point.
        assert "no pin" in text, text


class TestBlindTunnelFallsBackWhenChainRefuses:
    """Remote Control RECEIVES over a WebSocket to the ingress host the /bridge
    response names — a host the egress proxy has no forwarding rule for. A
    filtering chain (privoxy with per-domain forwards, a corporate MITM) can
    refuse the CONNECT outright, and closing on that refusal made a session
    silently deaf: heartbeat and worker/events kept answering 200 through the
    MITM path, the pin still read as applied, and nothing sent from claude.ai
    ever arrived. Measured on host-b against a machine whose chain did let
    the host through, where the same session received normally."""


    def _refusing_chain(self):
        """A proxy that answers every CONNECT with 403."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    while True:
                        line = c.recv(4096)
                        if not line or b"\r\n\r\n" in line:
                            break
                    c.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        return srv

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_refusing_chain_answers_503_not_a_direct_dial(
        self, certdir, tmp_path, monkeypatch
    ):
        """Since 2026-09-07 a chain that refuses every hop is the same "every
        hop failed" case `_blind_tunnel` answers with 503 — the chain
        REFUSING and the chain being DOWN converge on `up is None`, and a
        direct dial from a chained host is what reached the corporate
        TLS-inspecting proxy 49 times (see TestChainRediscovery). The class
        docstring's "same session received normally" measurement was on a
        host where direct is harmless; `CSWAP_PIN_ALLOW_DIRECT=1` is that
        opt-in and is the CONTROL below.
        """
        import cswap_pin.proxy as pp

        chain = self._refusing_chain()

        # Stands in for the ingress host: accepts and echoes, reached only
        # under the opt-in.
        peer = socket.socket()
        peer.bind(("127.0.0.1", 0))
        peer.listen(2)
        peer_port = peer.getsockname()[1]
        reached = threading.Event()

        def serve_peer():
            try:
                c, _ = peer.accept()
            except OSError:
                return
            reached.set()
            try:
                data = c.recv(64)
                if data:
                    c.sendall(b"PONG")
            finally:
                c.close()

        threading.Thread(target=serve_peer, daemon=True).start()

        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        log = tmp_path / "trace.log"
        prev = pp._TRACE
        pp._TRACE = open(log, "a")
        try:
            proxy = pp.PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: "PINTOKEN",
                upstream=("127.0.0.1", 1),
            )
            # The recorded chain refuses everything.
            proxy._current_chain = lambda: ("127.0.0.1", chain.getsockname()[1])
            proxy.start()
            try:
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                raw.sendall(
                    f"CONNECT 127.0.0.1:{peer_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{peer_port}\r\n\r\n".encode()
                )
                resp = raw.recv(4096)
                raw.close()
                assert resp.split(b"\r\n")[0] == b"HTTP/1.1 503 Service Unavailable", (
                    f"a refusing chain must answer 503, never dial direct: "
                    f"{resp[:80]!r}"
                )
                assert not reached.is_set(), (
                    "a refusing chain reached the ingress host directly"
                )

                # CONTROL: the opt-in restores the old fall-through.
                monkeypatch.setenv("CSWAP_PIN_ALLOW_DIRECT", "1")
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                raw.sendall(
                    f"CONNECT 127.0.0.1:{peer_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{peer_port}\r\n\r\n".encode()
                )
                resp2 = b""
                while b"\r\n\r\n" not in resp2:
                    chunk = raw.recv(4096)
                    assert chunk, (
                        "CONTROL FAILED: proxy closed instead of falling "
                        "back to a direct dial"
                    )
                    resp2 += chunk
                assert b"200" in resp2.split(b"\r\n")[0], resp2[:80]
                raw.sendall(b"PING")
                assert raw.recv(16) == b"PONG", (
                    "CONTROL FAILED: tunnel did not reach the host"
                )
                raw.close()
            finally:
                proxy.stop()
                peer.close()
                chain.close()
            pp._TRACE.flush()
        finally:
            pp._TRACE.close()
            pp._TRACE = prev

        assert reached.is_set(), "CONTROL FAILED: the ingress host was never dialled"
        assert "chain refused" in log.read_text(), log.read_text()


def _fake_pids(base: int, count: int) -> list[int]:
    """`count` pids starting at `base` that are NOT this process.

    A CASE THAT ANNOUNCES FOR A FAKE PID MUST NOT ANNOUNCE FOR OURS.
    `this_process_is_draining` reads the depth map filtered to our own pid, so
    a fixture that happens to pick our number makes this process look like it
    is handing over — and every relay in that worker then sheds keep-alives.

    Found on macOS CI 2026-08-18, where a `range(7000, 7009)` fixture collided
    with the runner's own pid: green on Linux, where pids are large, and red on
    a machine that hands out low ones. The block is shifted rather than
    filtered so the count stays exact.
    """
    import os

    if base <= os.getpid() < base + count:
        base += count
    return list(range(base, base + count))


class _Chatty:
    """One live pair of `kind`, never quiet."""

    released = []

    def __init__(self, kind="bridge"):
        self.kind = kind
        self.live = 1

    def live_pairs(self, kind=None):
        # GONE MEANS GONE. Reporting the pair after it was released
        # spins the drain for ever -- and `kind is None` must not
        # match a released pair whose kind was merely cleared.
        if not self.live:
            return 0
        return 1 if kind in (None, self.kind) else 0

    def quiet_for(self):
        return 0.0

    def release_pairs(self, kind=None):
        if not self.live or kind not in (None, self.kind):
            return 0
        type(self).released.append(kind)
        self.live = 0
        return 1


def test_a_hot_stamp_left_by_a_plain_test_does_not_blind_the_first_run_cases_deaf_case(
        request, tmp_path_factory):
    """T1327 #3: `run_cases` (`conftest.py`) resets `_hop_trouble_at` only
    AFTER each case it drives. A plain test outside that loop which pokes the
    global directly and never restores it -- no `finally` of its own, exactly
    what `TestATransportOutageIsNotASessionEnding` does in `test_proxy.py` --
    leaves it hot for whatever `run_cases` call comes next: the after-reset
    only clears it once THAT case has already run under the polluted value.
    """
    import cswap_pin.proxy as pp

    # SIMULATES THE POLLUTION, wall clock (matches `_note_hop_trouble`, not
    # `time.monotonic`): a plain test just stamped it and left.
    with pp._hop_trouble_lock:
        pp._hop_trouble_at = time.time()

    lines = []
    real_log = pp._log_lifecycle
    pp._log_lifecycle = lines.append

    class _Holder:
        def case_first(self):
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_HOT/worker/messages")
            srv._connected_bridges = {"cse_HOT"}
            srv._report_deaf_bridges()
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]

    try:
        run_cases(_Holder(), request, tmp_path_factory)
    finally:
        pp._log_lifecycle = real_log
        with pp._hop_trouble_lock:
            pp._hop_trouble_at = 0.0


class TestDrainReportsWhatItCut:
    """The drain line must say what was still open, not always zero.

    `await_inflight` ends with `_close_open_connections()`, which does
    `conns, self._open_conns = list(self._open_conns), set()` — it EMPTIES the
    set. The caller then logs `live_client_count()`, which reads that set. So
    "drained, N client(s) still open" is N=0 by construction, whatever it cut.

    Measured across all three machines' daemon logs: every non-zero value is
    from 2026-08-04/05 (`drained, 634 client(s)`, `6`, `7`, `8`, `4`); every
    value from 08-08 onward is 0. The ordering changed in between, and the one
    line that exists to say whether a recycle cost anything has been a constant
    ever since — while the user was losing a response mid-stream and nobody
    could tell from the log whether the pin did it.

    That is the shape where a fix deletes the evidence its own check reads.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_count_survives_the_cut(self, certdir):
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        err = io.StringIO()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            # OWED, NOT MERELY OPEN. This case used to put the connection in
            # `_open_conns` alone and assert the drain reported 1 — which
            # pinned the conflation rather than the behaviour: the loop waits
            # on owed answers and the message counted open sockets, so an
            # opaque tunnel that owed nobody anything was reported as a cut
            # request. Both numbers quoted to the user on 2026-08-18 (34, then
            # 30) came out of that gap.
            proxy._owe_answer(a, True)
            assert proxy.live_client_count() == 1, "precondition"
            with contextlib.redirect_stderr(err):
                cut = proxy.await_inflight(0.0)
            assert cut == 1, (
                "await_inflight must report what it cut; the set it counted is "
                "the set it just emptied")
            assert proxy.live_client_count() == 0, "and the set is emptied"
            # THE PATH THAT CUT SOMETHING TONIGHT WAS `_teardown`, not a code
            # handover — so the warning belongs in the one function all three
            # drains go through, or it misses the event that prompted it.
            assert "cut 1 in-flight request(s)" in err.getvalue(), err.getvalue()
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_an_idle_drain_reports_zero(self, certdir):
        """THE CONTROL. Without it, "reports what it cut" also passes on a
        version that returns a constant 1 — and "warns when it cut" also
        passes on one that warns every time."""
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            assert proxy.await_inflight(0.0) == 0
        # NOT SILENCE — a clean drain now says it drained clean, because "no
        # line" meant both that and "this daemon never drained at all".
        # ANCHORED, NOT THE BARE WORD. "cut" appears in the drain's own
        # ANNOUNCEMENT on a capped arm ("...and cuts whatever is still moving
        # when it expires"), so a substring test cannot tell a warning from a
        # cut. The cut LINE is `cut <n> in-flight`, which is exactly what the
        # fleet's drain watcher greps for -- one shape, checked the same way in
        # both places.
        assert not re.search(r"cut \d+ in-flight", err.getvalue()), \
            err.getvalue()
        assert "drained clean" in err.getvalue(), err.getvalue()

    def case_an_open_connection_with_no_request_does_not_hold_the_drain(self, certdir):
        """THE DEADLINE MUST STOP FIRING EVERY TIME, and this is why it did.

        The drain waited for the CONNECTION count to reach zero. It cannot:
        Remote Control's WebSocket is opaque after the 101 and lives as long as
        the session, so a connection is always open. The wait therefore always
        ran to the full ceiling and then cut EVERYTHING still open — including a
        `/v1/messages` stream that had started two seconds earlier. Measured on
        host-a 2026-08-18: one code change produced two full swaps 70s apart and
        three sessions took "API Error: Connection lost mid-response".

        The pin's own comment had already written down the premise — "Remote
        Control's WebSocket lives as long as the session does, so the count is
        never zero" — and nobody followed it to the conclusion that the ceiling
        is therefore paid in full on every single recycle.

        A LONG-LIVED CONNECTION WITH NO REQUEST IN FLIGHT IS NOT WORK. So the
        drain must count REQUESTS. Here: a connection is open, no request is in
        flight, and the drain must return AT ONCE rather than burn the budget.
        The budget is deliberately large so that a version still counting
        connections cannot pass by being fast.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            # OPEN, AND OWING NOTHING — an RC WebSocket after its 101, or a
            # keep-alive socket between requests. Both are connections nobody
            # is waiting on, and the drain must not hold for either. Modelled
            # by simply not putting it in `_owed`, which is what the accept
            # path does and then undoes at the 101 and between requests.
            assert proxy.live_client_count() == 1, "precondition: a conn is open"
            assert proxy.inflight_requests() == 0, (
                "precondition: a tunnel owes nobody an answer")
            started = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(20.0)
            waited = time.monotonic() - started
            assert waited < 2.0, (
                f"waited {waited:.1f}s for a connection carrying no request; "
                "the drain is still counting connections, so an RC WebSocket "
                "makes it pay the full ceiling on every recycle")
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_a_moving_reply_holds_the_drain_and_a_silent_one_does_not(
        self, certdir, monkeypatch
    ):
        """THE DISCRIMINATOR A DEADLINE CANNOT MAKE.

        Measured on host-a 2026-08-18, the 0.1.102 rollout:

            09:02:20Z cut 12 in-flight request(s) after 600.0s of a 600s budget
                      (12 mid-response, 0 before headers)

        Twelve replies were STILL STREAMING when the clock cut them. A wedged
        connection and a four-minute answer are identical to a deadline — which
        is why the deadline was there — and not identical to the connection:
        one is moving bytes and one is not.

        BOTH DIRECTIONS IN ONE CASE, because either alone passes on a version
        that always waits or always returns. The stall window is shrunk so this
        runs in seconds; the production value is ninety.
        """
        import cswap_pin.proxy as pp

        monkeypatch.setattr(pp, "_DRAIN_STALL_SECONDS", 0.3)

        # --- SILENT: owed, and nothing has moved since well before the drain.
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)
            proxy._note_response_started(a)
            time.sleep(0.4)                      # past the stall window
            t0 = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(30.0)
            silent_wait = time.monotonic() - t0
            assert silent_wait < 2.0, (
                f"waited {silent_wait:.1f}s on a connection that has sent "
                "nothing since before the drain began — that is a wedged "
                "socket holding the budget, which is what the stall window "
                "exists to end")
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

        # --- MOVING: the same shape, but bytes keep arriving for a while.
        proxy2 = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                             upstream=("127.0.0.1", 1))
        c, d = socket.socketpair()
        stop = threading.Event()
        try:
            with proxy2._live_lock:
                proxy2._open_conns.add(c)
            proxy2._owe_answer(c, True)

            def _stream():
                # A reply delivering a chunk every 100ms for a second, then
                # finishing — the shape the 600s ceiling was cutting.
                for _ in range(10):
                    if stop.is_set():
                        return
                    proxy2._note_response_started(c)
                    time.sleep(0.1)
                proxy2._owe_answer(c, False)     # the reply completed

            # AND THE WIRING FOR THE BEAT, on the drain that actually loops.
            # A marker refreshed by a function nothing calls is the fourth
            # orphaned guard tonight; the drain is the only thing that knows
            # it is still alive, so it is the only thing that can say so.
            beats = []
            real_beat = pp.beat_draining
            monkeypatch.setattr(pp, "_DRAINING_BEAT_SECONDS", 0.05)
            monkeypatch.setattr(
                pp, "beat_draining",
                lambda cd, pid=None, owed=None, live=None, quiet=None,
                **k: (beats.append(owed),
                      real_beat(cd, pid, owed, live, quiet, **k))[1])

            threading.Thread(target=_stream, daemon=True).start()
            t0 = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                cut = proxy2.await_inflight(30.0)
            moving_wait = time.monotonic() - t0

            assert sum(b is not None for b in beats) >= 2, (
                "only the drain's opening beat published what it owes. The "
                "count changes as replies land, so a loop beat that drops it "
                "leaves the sweep reading a number from minutes ago — and a "
                f"predecessor that has finished still looks expensive. beats={beats}")
            assert len(beats) >= 3, (
                f"the drain beat {len(beats)} time(s) while it waited a second "
                "on a moving reply. Without the beat the marker goes stale on "
                "its own TTL and the orphan sweep kills a daemon mid-reply")

            assert moving_wait > 0.8, (
                f"the drain returned after {moving_wait:.2f}s while bytes were "
                "still going to the client. A stall window shorter than the "
                "gaps in a live stream cuts exactly the replies it exists to "
                "protect")
            assert cut == 0, (
                f"cut {cut} — the reply finished on its own and the drain "
                "should have had nothing left to cut")
        finally:
            stop.set()
            for s_ in (c, d):
                try: s_.close()
                except OSError: pass

    def case_fake_pids_are_never_this_process(self, monkeypatch):
        """THE FIXTURE THAT MADE macOS CI RED, pinned.

        `this_process_is_draining` reads the depth map filtered to our own pid,
        so a case that announces for a made-up pid which HAPPENS to be ours
        makes this process look like it is handing over — and every relay in
        that worker then sheds keep-alives. Green on Linux, where pids are
        large; red on a runner that hands out low ones.

        The helper shifts the whole block rather than filtering, so the count
        a caller asked for is the count it gets.
        """
        import os

        import cswap_pin.proxy as pp  # noqa: F401 — the module under test's home

        monkeypatch.setattr(os, "getpid", lambda: 7003)
        got = _fake_pids(7000, 9)
        assert 7003 not in got, f"handed out our own pid: {got}"
        assert len(got) == 9, f"lost or gained a pid while avoiding ours: {got}"

        monkeypatch.setattr(os, "getpid", lambda: 999999)
        assert _fake_pids(7000, 9) == list(range(7000, 7009)), (
            "shifted when there was no collision — the block should only move "
            "to get out of our own way")

    def case_a_departing_daemon_stops_taking_new_requests(self, certdir):
        """`release_listener` SHEDS ARRIVALS; NOTHING SHED THE KEEP-ALIVES.

        A departing daemon stopped accepting new CONNECTIONS and kept accepting
        new REQUESTS on the ones it already held, indefinitely. From the
        client's side nothing was wrong with the socket, so it never
        reconnected — measured on host-a 2026-08-18, eleven sessions whose ONLY
        path to the pin was a process that had stopped being the front door.

        The reply still COMPLETES; the header only says "do not send another".
        The client then opens a fresh connection and lands on the successor
        through the shared listener, so sessions migrate one completed reply at
        a time.
        """
        import os as _os

        import cswap_pin.proxy as pp

        def _relay_once():
            up_a, up_b = socket.socketpair()
            cl_a, cl_b = socket.socketpair()
            try:
                def _upstream():
                    try:
                        up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                                     b"Content-Length: 2\r\n\r\nhi")
                        time.sleep(0.05)
                        up_b.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

                threading.Thread(target=_upstream, daemon=True).start()
                pp._relay_response(up_a, cl_a, 0)
                cl_a.shutdown(socket.SHUT_WR)
                got = b""
                while True:
                    chunk = cl_b.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                return got
            finally:
                for s_ in (up_a, up_b, cl_a, cl_b):
                    try:
                        s_.close()
                    except OSError:
                        pass

        # OUR OWN DEPTH, SET EXPLICITLY. Asserting the ambient value made this
        # case depend on what ran before it in the same worker — see
        # `_fake_pids`. The case is about the TRANSITION, so it establishes
        # both ends itself and puts back whatever it found.
        with pp._DRAINING_LOCK:
            saved = dict(pp._DRAINING_DEPTH)
            mine = f"{pp._DRAINING_PREFIX}{_os.getpid()}"
            for key in [k for k in pp._DRAINING_DEPTH
                        if k.rsplit("/", 1)[-1] == mine]:
                pp._DRAINING_DEPTH.pop(key)

        # SERVING: the connection stays reusable.
        assert not pp.this_process_is_draining(), "precondition"
        serving = _relay_once()
        assert b"hi" in serving, serving[:120]
        assert b"Connection: close" not in serving, (
            "a serving daemon told the client to stop reusing the connection; "
            "every request would then pay a fresh TLS handshake: "
            + serving[:200].decode("latin1"))

        # HANDING OVER: same reply, delivered in full, and the last one.
        # OUR OWN PID: the predicate asks whether THIS process is leaving, and
        # announcing on another pid's behalf must not answer yes for us.
        done = pp.announce_draining(certdir, _os.getpid())
        try:
            assert pp.this_process_is_draining(), "precondition"
            departing = _relay_once()
        finally:
            done()
            with pp._DRAINING_LOCK:
                pp._DRAINING_DEPTH.clear()
                pp._DRAINING_DEPTH.update(saved)

        assert b"hi" in departing, (
            "the reply was not delivered — this must shed the CONNECTION, "
            "never the answer: " + departing[:200].decode("latin1"))
        assert b"Connection: close" in departing, (
            "a departing daemon kept the connection reusable, so the client "
            "sends its next request into a process that has stopped being the "
            "front door and never reaches the successor: "
            + departing[:200].decode("latin1"))

    def case_a_keepalive_is_told_from_an_answer_by_NAME(self, certdir):
        """NO THRESHOLD, NO RATE, NO FRAME WIDTH — the protocol says which is
        which, and the pin has the plaintext because it is the MITM.

        FAILS SAFE, which is the whole reason this is shippable where a byte
        threshold was not. The test is "is EVERY event here a keepalive", so an
        event name nobody has seen counts as CONTENT and the drain keeps
        waiting. Phrased the other way — "does this contain a known content
        event" — the day a new event type is added it would cut live replies.
        """
        import cswap_pin.proxy as pp

        assert pp._is_only_keepalive(b"event: ping\ndata: {}\n\n") is True
        assert pp._is_only_keepalive(
            b"event: ping\ndata: {}\n\nevent: ping\ndata: {}\n\n") is True

        for content in (
            b"event: content_block_delta\ndata: {}\n\n",
            b"event: ping\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
            b"event: some_event_added_next_year\ndata: {}\n\n",
            b'{"id":"msg_1"}',
            b"data: {}\n\n",
            b"",
        ):
            assert pp._is_only_keepalive(content) is False, (
                f"classified as a keepalive: {content!r} — anything this "
                "cannot positively identify as all-keepalive must count as an "
                "answer, or the drain stops waiting on a live reply")

    def case_the_response_head_is_movement_but_not_an_answer(self, certdir):
        """THE HEAD GOES THROUGH THE SAME WRITER, and counting it as content
        would make every response look answered from its first byte — a rule
        that ships, reads like a fix, and never fires.

        It must still STAMP: a head reaching the client is the connection
        moving, and the stall window is what reads that.
        """
        import cswap_pin.proxy as pp

        seen = []
        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        try:
            def _upstream():
                try:
                    up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Type: text/event-stream\r\n\r\n")
                    time.sleep(0.15)
                    up_b.sendall(b"event: ping\ndata: {}\n\n")
                    time.sleep(0.05)
                    up_b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            threading.Thread(target=_upstream, daemon=True).start()
            pp._relay_response(up_a, cl_a, 0,
                               on_headers=lambda n, c: seen.append(c))
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try:
                    s_.close()
                except OSError:
                    pass

        assert seen, "nothing was stamped at all; the case proves nothing"
        assert seen[0] is False, (
            "the response HEAD was reported as content, so every reply looks "
            "answered from its first byte and nothing can ever be classified "
            "as a stopped one")
        assert all(c is False for c in seen), (
            f"a keepalive-only body was reported as content: {seen}")

    def case_content_before_the_drain_does_not_make_a_reply_live(
        self, certdir, monkeypatch
    ):
        """SINCE THE DRAIN BEGAN, NOT SINCE THE REQUEST BEGAN.

        Measured on host-a 2026-08-18: the twelve that mattered delivered real
        content in the FIRST 20 SECONDS of their drain and nothing but
        keepalives for the thirty minutes after. A counter that starts at the
        request would call every one of them live, and the reaper would then
        protect a process holding twelve stopped replies over one still
        writing.

        Drives `await_inflight`, not `live_replies` directly: the snapshot is
        taken inside the drain and that wiring is the part that can be lost.
        """
        import cswap_pin.proxy as pp

        monkeypatch.setattr(pp, "_DRAIN_STALL_SECONDS", 0.2)
        seen = []
        real_beat = pp.beat_draining
        monkeypatch.setattr(
            pp, "beat_draining",
            lambda cd, pid=None, owed=None, live=None, quiet=None, **k: (
                seen.append((owed, live)),
                real_beat(cd, pid, owed, live, quiet, **k))[1])

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)
            # AN ANSWER, DELIVERED BEFORE ANY OF THIS — then silence but for a
            # keepalive, which is what the drain will actually see.
            proxy._note_response_started(a, 4000, True)
            proxy._note_response_started(a, 39, False)

            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(1.0)
        finally:
            for s_ in (a, b):
                try:
                    s_.close()
                except OSError:
                    pass

        assert seen, "the drain never beat, so nothing published a count"
        owed, live = seen[0]
        assert owed == 1, f"precondition: one reply is owed, got {owed}"
        assert live == 0, (
            "a reply whose only content predates the drain was counted as "
            "still being written, so the reaper will protect a predecessor "
            f"holding nothing but stopped replies. live={live}")

    def case_the_reaper_prefers_the_predecessor_with_no_live_answers(
        self, certdir
    ):
        """TWELVE CORPSES OUTWEIGHED TWO LIVE REPLIES.

        The sort keyed on replies OWED, and a connection that stopped half an
        hour ago is owed exactly as much as one still streaming — so at the
        limit the reaper preferred to kill the process still doing real work.
        Measured on host-a 2026-08-18: `12 mid-response` over twelve
        connections carrying nothing but a fixed frame.
        """
        import cswap_pin.proxy as pp

        killed = []
        real_kill, real_pids = pp._kill_daemon, pp._pin_daemon_pids
        pp._kill_daemon = lambda pid, certdir=None: killed.append(pid)
        pids = _fake_pids(7000, pp._MAX_DRAINING_PREDECESSORS + 1)
        pp._pin_daemon_pids = lambda certdir: list(pids)
        try:
            for pid in pids:
                pp.announce_draining(certdir, pid)
                # pids[0] holds the MOST replies and none is being written;
                # every other one holds fewer and all of theirs are live.
                if pid == pids[0]:
                    pp.beat_draining(certdir, pid, owed=12, live=0)
                else:
                    pp.beat_draining(certdir, pid, owed=2, live=2)

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert killed == [pids[0]], (
                "the reaper took a predecessor that was still writing answers "
                "while one holding twelve stopped ones survived — owed counts "
                f"debts, not answers. killed={killed}")
        finally:
            pp._kill_daemon, pp._pin_daemon_pids = real_kill, real_pids

    def case_a_reply_that_has_gone_quiet_is_timed_not_guessed(self, certdir):
        """THE NUMBER `await_inflight` SAYS THE DECISION IS WAITING ON.

        That comment names its own unblocking condition — "it becomes decidable
        the day somebody measures the longest content-free interval a live
        reply produces" — and nothing was measuring it. A peer tried, from
        `/proc/<pid>/io` deltas with a burst detector, and could not: that rate
        is process-wide, so its gap means "no burst on ANY of twelve replies"
        while the rule needs "no content on ONE". Twelve replies staggered ten
        seconds apart produce a burst every ten seconds while each one is
        content-free for two minutes, so the aggregate reads small and safe and
        a threshold chosen from it cuts live work.

        `_StampingWriter` is the only thing that sees bytes attributed to one
        connection, and `_is_only_keepalive` already separates content from a
        ping BY NAME. So the interval is exact here and a heuristic anywhere
        else.

        AND IT GOES IN THE MARKER, not only the exit line. The daemon this
        question exists for is the one that NEVER exits — measured on host-a
        2026-08-18, pid 609285, twelve live sessions, keepalive-only for 45
        minutes and still draining. A number printed on the way out is a
        number that case never produces.

        AN INSTRUMENT ONLY. Nothing decides on it yet; see `_owed_still_moving`
        for why a content-based stall stays refused until this has run.
        """
        import os
        import re

        import cswap_pin.proxy as pp

        class _Clock:
            t = 1000.0

            def monotonic(self):
                return self.t

            def time(self):
                return 1787000000.0 + self.t

            def sleep(self, _s):
                pass

        clock = _Clock()
        real_time = pp.time
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        e, f = socket.socketpair()
        err = io.StringIO()
        # BOUND BEFORE THE `try`, or a failure earlier in the body makes the
        # `finally` raise NameError and hide it.
        _depth_before = dict(pp._DRAINING_DEPTH)
        try:
            pp.time = clock
            # `e` IS OWED AND NEVER WRITTEN TO — a request on the wire whose
            # upstream has said nothing. It is the SILENTEST thing here, and
            # timing it from its first content byte would report the silentest
            # reply on the box as the busiest: there is no first byte, so the
            # clock would start now and read 0 s. It is timed from the debt.
            for sock in (a, c, e):
                with proxy._live_lock:
                    proxy._open_conns.add(sock)
                proxy._owe_answer(sock, True)
            proxy._note_response_started(a, 500, True)
            proxy._note_response_started(c, 500, True)

            # `a` GOES QUIET AND KEEPS PINGING; `c` KEEPS ANSWERING. Both stay
            # owed, both keep moving bytes, both look identical to
            # `_owed_still_moving` — which is exactly the pair a byte rate
            # cannot separate and this line has to.
            clock.t = 1300.0
            proxy._note_response_started(a, 39, False)
            clock.t = 1305.0
            proxy._note_response_started(c, 500, True)

            clock.t = 1310.0
            # THE NEVER-WRITTEN REPLY SCORES ITS FULL SILENCE, same as the one
            # that went quiet 310s ago. Read before the drain, because
            # `await_inflight` closes the connections this counts over.
            assert proxy.content_free_intervals() == [5.0, 310.0, 310.0], (
                "a reply that has sent nothing did not report the silence it "
                "has actually been sitting in — timed from its first content "
                "byte it has none, so the worst case on the box reads as the "
                f"best: {proxy.content_free_intervals()}")

            with contextlib.redirect_stderr(err):
                proxy.await_inflight(0.0)
            line = err.getvalue()

            # MIN AND MAX, not the median: with three samples the middle is
            # still a formatter detail. The fact is that the quiet replies and
            # the busy one land at opposite ends of the same line.
            assert "content-free 5/" in line and "/310 s min/med/max" in line, (
                "the drain line does not say how long each reply has gone "
                "without content, so the interval a stall threshold would "
                "have to clear is still unmeasured: " + line)

            # AND READABLE ON A DAEMON THAT HAS NOT FINISHED. The exit line is
            # written by a drain that ended; this marker is what a stuck one
            # publishes every beat.
            pid = os.getpid()
            # SAVED AND RESTORED. The depth map is a module global keyed by
            # marker basename, and `this_process_is_draining()` matches on it,
            # so an announcement left standing here makes every later case in
            # this worker take the draining branch — `Connection: close` on
            # every response and `handed_over=True` in the teardown budget.
            # Only definition order kept the sibling case's precondition green.
            pp.announce_draining(certdir, pid)
            pp.beat_draining(certdir, pid, owed=2, live=2, quiet=310.0)
            assert pp.draining_quiet(certdir, pid) == 310.0, (
                "the beat marker does not carry the quiet interval, so the "
                "one daemon this question is about — the one that never "
                "exits — publishes no answer to it")
            # A MARKER FROM A VERSION THAT DID NOT RECORD IT MUST NOT READ AS
            # ZERO. Zero means "answering right now", the safest possible
            # reading, and this fleet runs mixed versions through every
            # upgrade.
            pp.draining_marker_path(certdir, pid).write_text("1787000000\n2\n2")
            assert pp.draining_quiet(certdir, pid) is None, (
                "a marker with no quiet line answered a number, so an older "
                "daemon would be reported as freshly answering")

            # AND THE CLEAN BRANCH, which is the one the number is FOR and the
            # one where a snapshot of the live set is 0 by construction:
            # `drained clean` means nothing is owed. Only a reply that went
            # quiet and then FINISHED can raise a ceiling, so that is what the
            # line has to carry.
            #
            # DRIVEN IN THE ORDER `_mitm` PRODUCES, which the first version of
            # this case did not. It called `_note_reply_finished` at a clock
            # 400s past the last content write — a state the relay cannot
            # reach, because that call sits at the top of the next loop
            # iteration, immediately after the last `sendall` refreshed the
            # stamp. So the assertion was green about behaviour that never
            # happens, and the field it certified banked the TRAILING gap
            # (~0 for every streaming reply) instead of the longest one.
            #
            # `c` is the shape that matters: quiet from t=1305 to t=1395, then
            # DELIVERS, then completes one tick later. The peak has to be the
            # 90s it survived, not the ~0s between its last token and its end.
            clock.t = 1395.0
            proxy._note_response_started(c, 500, True)
            # THE MID-STREAM GAP, ASSERTED PER CONNECTION, because the fleet
            # maximum cannot isolate it: `a` and `e` end after long TRAILING
            # silences that legitimately dominate. `c` delivered at t=1000,
            # 1305 and 1395, so its longest quiet-then-delivered interval is
            # 305s — a number the old code could not produce at all, since it
            # only ever read the gap after the LAST content byte.
            assert proxy._gap[c] == 305.0, (
                "the longest interval between content writes was not banked, "
                "so a reply that pings through a long think and then delivers "
                f"scores nothing: {proxy._gap.get(c)}")
            clock.t = 1395.5
            # `c` FINISHES ALONE FIRST, so the peak it produces can only have
            # come from its MID-STREAM gap. Finished alongside `a` and `e` — as
            # the first version did — their 395s TRAILING silences dominate the
            # process-wide maximum, and dropping `_gap` from the peak entirely
            # changes nothing observable. That mutation survived until this
            # ordering existed.
            proxy._note_reply_finished(c)
            proxy._owe_answer(c, False)
            assert proxy._quiet_peak == 305.0, (
                "the peak did not come from the longest gap BETWEEN content "
                "writes; this reply's trailing silence was 0.5s and its "
                f"mid-stream quiet was 305s: {proxy._quiet_peak}")
            for sock in (a, e):
                proxy._note_reply_finished(sock)
                proxy._owe_answer(sock, False)
            # AND THE DEBT BOUNDARY CLEARS IT, like every other per-debt
            # counter — or the next request on a keep-alive starts already
            # holding the last one's silence.
            assert c not in proxy._gap, (
                "the gap survived the debt it belongs to; the next reply on "
                "this connection would inherit it")
            clock.t = 1400.0
            clean = io.StringIO()
            with contextlib.redirect_stderr(clean):
                proxy.await_inflight(0.0)
            got = clean.getvalue()
            assert "drained clean" in got, (
                "the second drain still had debts, so this proves nothing "
                "about the clean branch: " + got)
            assert "content-free wait a completed reply survived 396s" in got, (
                "the clean drain reported no content-free interval, or "
                "reported it from the live set — which is empty on every "
                "clean drain, so the field could never be anything but "
                "zero: " + got)

            # THE PHRASES OTHER PEOPLE MATCH ON, checked against the rendered
            # lines rather than against my memory of them. Two peer readers on
            # this fleet grep these UNANCHORED, so the component tag added to
            # `_log_lifecycle` had to go ahead of `pid=` and leave both tokens
            # in place. Asserting it here, where the real lines exist, is the
            # only place that can tell a safe insertion from a rename.
            for pat, where in ((r"cut \d+ in-flight", line),
                               (r"drained clean", got)):
                assert re.search(pat, where), (
                    f"the format change broke `{pat}`, which peer tooling "
                    f"greps unanchored: {where}")
            # NAME AND VERSION. The name alone was not enough: 0.1.113-0.1.115
            # printed a `content-free` value measuring the wrong quantity and
            # 0.1.116 fixed it, and both spell the line identically — so every
            # reader had to know when each machine was upgraded to tell a
            # usable number from a worthless one.
            assert re.search(PIN_STAMP, line), (
                "the drain line does not name the component AND VERSION that "
                f"wrote it, so its numbers carry no provenance: {line}")
        finally:
            pp.time = real_time
            with pp._DRAINING_LOCK:
                pp._DRAINING_DEPTH.clear()
                pp._DRAINING_DEPTH.update(_depth_before)
            try:
                pp.draining_marker_path(certdir, os.getpid()).unlink()
            except OSError:
                pass
            for s_ in (a, b, c, d, e, f):
                try: s_.close()
                except OSError: pass

    def case_an_unwritable_marker_does_not_shorten_our_own_drain(self, certdir):
        """FAILING OPEN FOR THE SWEEP, NOT FOR US.

        `announce_draining` promises in its own docstring that this file "may
        only ever REMOVE a kill, never cause one" — the marker is advice to
        OTHER processes, so a certdir that cannot be written just leaves the
        sweep as blind as it was before markers existed.

        Then `teardown_drain_budget(handed_over=this_process_is_draining())`
        started reading the same state, and the rollback broke the promise: an
        ENOSPC or a read-only certdir made a daemon mid-handover report
        `handed_over=False`, take the 30s held ceiling instead of the uncapped
        one, and cut exactly the live mid-response replies that ceiling was
        removed to save.

        The DEPTH is in-process knowledge and is true whether or not the file
        landed. Only the file is advice, and only the file may fail.
        """
        import os

        import cswap_pin.proxy as pp

        before = dict(pp._DRAINING_DEPTH)
        real_write = pathlib.Path.write_text
        try:
            def _boom(self, *a, **kw):
                if self.name.startswith(pp._DRAINING_PREFIX):
                    raise OSError(28, "No space left on device")
                return real_write(self, *a, **kw)

            pathlib.Path.write_text = _boom
            # ASSERTED ON THIS CASE'S OWN KEY, not on the process-wide
            # predicate. `this_process_is_draining()` matches ANY entry whose
            # marker basename is `.draining-<our pid>`, across every certdir in
            # the map — so a sibling case in the same xdist worker that
            # announced for this pid makes both directions vacuous. It passed
            # on linux and failed on macOS purely on which cases shared the
            # worker, which is a scheduling detail, not a fact about the fix.
            key = str(pp.draining_marker_path(certdir, os.getpid()))
            done = pp.announce_draining(certdir, os.getpid())
            assert pp._DRAINING_DEPTH.get(key, 0) == 1, (
                "a marker that could not be written made this daemon forget "
                "it is draining, so its next teardown takes the short ceiling "
                f"and cuts the replies the uncapped one exists to finish: "
                f"{pp._DRAINING_DEPTH.get(key)}")
            assert pp.this_process_is_draining(), (
                "the depth is set but the predicate production reads does not "
                "see it")
            done()
            assert key not in pp._DRAINING_DEPTH, (
                "the releaser handed back nothing, so the state it set on the "
                "failed-write path leaks for the life of the process")
        finally:
            pathlib.Path.write_text = real_write
            with pp._DRAINING_LOCK:
                pp._DRAINING_DEPTH.clear()
                pp._DRAINING_DEPTH.update(before)

    def case_the_opt_in_trace_files_are_capped_like_the_daemon_log(self, tmp_path):
        """THE CAP WAS ON THE FILE NOBODY ENABLES.

        `daemon.log` is bounded — 64 KiB, rotated through `.1` and `.2`, so a
        machine can hold ~192 KiB of it however long the daemon runs. That care
        was taken for the log that is always on and always small.

        `CSWAP_PIN_DEBUG` and `CSWAP_PIN_SHAPE` open in append mode and write
        one line PER REQUEST through a path `_LOG_MAX_BYTES` never touched. Off
        by default, so a fresh install is safe — but a human turns them on
        precisely when something is going wrong, which is also when they stop
        watching the disk. The careful bound was on the file that could not
        grow and absent from the two that can.

        Asserted by WRITING PAST THE CAP rather than by reading the source: the
        question is what a downstream user's disk does, and only bytes answer
        it.
        """
        import os

        import cswap_pin.proxy as pp

        # UNDER PYTEST'S OWN TREE, not a bare mkdtemp: pytest reaps this on
        # every exit path, and a plain /tmp dir outlives the run. A peer
        # counted 297 of ours left on this box.
        d = str(tmp_path / "cap-probe")
        os.makedirs(d, exist_ok=True)
        for env, writer in (
            ("CSWAP_PIN_DEBUG", "debug"),
            ("CSWAP_PIN_SHAPE", "shape"),
        ):
            target = os.path.join(d, f"{writer}.log")
            line = "x" * 512 + "\n"
            # FIVE TIMES THE CAP, so the rotation runs several times. At one
            # overflow an unbounded-generations bug leaves a single extra file
            # and hides under any sane threshold; it only becomes visible once
            # the policy has been applied repeatedly.
            need = 5 * (pp._LOG_MAX_BYTES // len(line))
            fh = None
            try:
                for _ in range(need):
                    fh = pp._append_capped(target, line, fh)
            finally:
                if fh is not None:
                    try:
                        fh.close()
                    except OSError:
                        pass
            live = os.path.getsize(target)
            assert live <= pp._LOG_MAX_BYTES, (
                f"{env} grew to {live} B with no cap; a trace left on after an "
                "incident fills the disk of somebody who installed this")
            # AND THE ROTATIONS ARE BOUNDED TOO, or the cap just moves the
            # growth one filename over.
            #
            # GLOBBED, NOT A SUFFIX LIST. The first version summed `""`, `.1`
            # and `.2`, so a rotation that minted a fresh name per pass — the
            # unbounded-generations mutation — produced files it never looked
            # at and passed. A check whose input is a hardcoded list goes stale
            # the first time the thing it watches grows a new shape, which is
            # the defect being tested one level up.
            siblings = [
                f for f in os.listdir(os.path.dirname(target))
                if f.startswith(os.path.basename(target))
            ]
            total = sum(
                os.path.getsize(os.path.join(os.path.dirname(target), f))
                for f in siblings
            )
            assert len(siblings) <= 3, (
                f"{env} left {len(siblings)} generations behind ({siblings}); "
                "the rotation keeps two plus the live file, or the ceiling is "
                "per file and the directory is unbounded")
            assert total <= 3 * pp._LOG_MAX_BYTES, (
                f"{env} plus its rotations reached {total} B; the ceiling has "
                "to hold across generations, not per file")
            # CONTROL: it must still be WRITING. A cap that works by dropping
            # everything passes both asserts above and records nothing.
            assert live > 0, f"{env} is capped because it writes nothing"

    def case_the_cut_line_says_how_much_each_reply_delivered(self, certdir):
        """`mid-response` CANNOT TELL A LIVE STREAM FROM A CORPSE.

        It means headers went out and nothing finished. A keepalive is bytes,
        so `_owed_still_moving` counts it as movement and the connection stays
        `mid-response` forever. Measured on host-a 2026-08-18: twelve logged as
        `12 mid-response` had delivered nothing but a fixed 39-byte frame for
        thirty minutes, and the reaper's "cheapest to lose" sort weighed those
        twelve corpses exactly as heavily as twelve live replies.

        PER CONNECTION, which is why this cannot come from `/proc/<pid>/io`:
        that is a process-wide rate and nobody could say how many connections
        the content was flowing on. `_StampingWriter` sees bytes attributed to
        one connection, so the count comes from there.

        AN INSTRUMENT ONLY. Nothing decides on this number yet; it exists so
        the population a threshold would be chosen from arrives in a log line
        rather than from somebody sampling at the right moment.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        err = io.StringIO()
        try:
            for sock in (a, c):
                with proxy._live_lock:
                    proxy._open_conns.add(sock)
                proxy._owe_answer(sock, True)
            # ONE CORPSE AND ONE LIVE REPLY, told apart only by volume: both
            # are owed, both are mid-response, both have moved recently.
            for _ in range(3):
                proxy._note_response_started(a, 39)
            proxy._note_response_started(c, 5000)

            with contextlib.redirect_stderr(err):
                proxy.await_inflight(0.0)
            line = err.getvalue()

            # MIN AND MAX, not the median: with two samples the middle is a
            # tie-break convention and asserting it would pin the formatter
            # rather than the fact. The fact is that the corpse and the live
            # reply land at opposite ends of the same line.
            # AND IT BELONGS TO THE DEBT. A keep-alive socket that has paid
            # and is waiting for its next request starts the next one at zero,
            # or a long-lived connection looks busier the longer it lives and
            # outranks a genuinely streaming one forever.
            proxy._owe_answer(a, False)
            proxy._owe_answer(a, True)
            with proxy._live_lock:
                carried = proxy._delivered.get(a, 0)
            assert carried == 0, (
                f"{carried} bytes carried across the debt boundary — the next "
                "request on this connection starts already looking busy")

            assert "delivered 117/" in line and "/5000 B min/med/max" in line, (
                "the cut line does not carry per-connection byte counts, so a "
                "reply that stopped thirty minutes ago is indistinguishable "
                "from one still streaming: " + line)
        finally:
            for s_ in (a, b, c, d):
                try: s_.close()
                except OSError: pass

    def case_the_accept_debt_survives_until_the_first_answer(self, certdir):
        """THE ACCEPT-TIME OWE WAS UNDONE ONE FRAME LATER.

        `accept` marks a connection OWED because a client that has connected
        is waiting on us whether or not its request bytes have arrived — added
        after `case_a_planned_restart_under_a_holder_loses_nothing` failed with
        "1 requests connected and were never answered".

        `_mitm`'s loop then cleared the debt at the TOP of every iteration,
        including the first, which runs after CONNECT and the TLS handshake
        and BEFORE `_read_line`. So for every MITM'd connection the accept-time
        debt was gone while the request was on the wire, and
        `inflight_requests()` reported zero for a client that was mid-request.

        BETWEEN requests it must still clear — that is the third unreachable
        zero, a keep-alive socket nobody waits on holding a drain — so this
        checks the boundary rather than the release.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        seen = []

        class _Ctx:
            def wrap_socket(self, sock, server_side=False):
                return sock

        def _one_request(tls, conn=None):
            seen.append(proxy.inflight_requests())
            return len(seen) < 2          # one served, then end the loop

        proxy._server_ctx = _Ctx()
        proxy._handle_one_request = _one_request
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)     # what `accept` does
            proxy._mitm(a)
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

        assert seen, "the loop never ran; the case proves nothing"
        assert seen[0] == 1, (
            "the accept-time debt was cleared before the first request line "
            "was even read, so a recycle drops a client whose request is on "
            f"the wire — inflight_requests() was {seen[0]}")
        assert len(seen) > 1 and seen[1] == 0, (
            "the debt was not released BETWEEN requests, so a keep-alive "
            f"socket nobody is waiting on holds the drain: {seen}")

    def case_the_relay_stamps_every_write_not_only_the_head(self, certdir):
        """THE WIRING, for the fourth time — and the first three were misses.

        `_blind_tunnel` never cleared its drain debt, the relay never marked a
        reply started, and `await_inflight` never announced it was draining.
        Each was a correct function nothing called, and each passed a suite
        that tested the function directly.

        Here the question is whether BODY bytes stamp, not just the head. A
        version that notifies once — which is exactly what `on_headers` did
        before this change — keeps every long reply looking frozen after its
        first chunk, so the stall window cuts it. That is the 600s bug back in
        a smaller window.
        """
        from cswap_pin.proxy import _relay_response

        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        stamps = []
        try:
            # PACED, because writing it all at once is not the case under test.
            # The first version of this sent the head and both events before
            # the relay read anything, so one `recv` took the lot and the whole
            # response went out in a single write — the assertion failed on a
            # premise, not on the code. A stream the drain has to survive
            # arrives in separate reads, so the upstream has to produce it that
            # way.
            def _upstream():
                up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                             b"Content-Type: text/event-stream\r\n\r\n")
                time.sleep(0.15)
                up_b.sendall(b"event: a\n\n")
                time.sleep(0.15)
                up_b.sendall(b"event: b\n\n")
                time.sleep(0.05)
                up_b.shutdown(socket.SHUT_WR)

            threading.Thread(target=_upstream, daemon=True).start()
            _relay_response(up_a, cl_a, 0,
                            on_headers=lambda n, c: stamps.append((time.monotonic(), n, c)))

            # AND THE SIZE IS REAL, not merely non-zero. The count is what
            # separates a live reply from one delivering a keepalive, so a
            # writer that reports every write as 0 bytes is the same defect as
            # one that does not report at all — and the sibling case that
            # drives `_note_response_started` directly cannot see it.
            sizes = [n for _, n, _c in stamps]
            assert all(n > 0 for n in sizes), (
                f"a write was reported as {min(sizes)} bytes: {sizes}")
            assert sum(sizes) >= len(b"event: a\n\n") + len(b"event: b\n\n"), (
                f"reported {sum(sizes)} bytes total, less than the body the "
                f"client actually received: {sizes}")

            assert len(stamps) >= 3, (
                f"the relay reported {len(stamps)} write(s). The head plus two "
                "body chunks is three: a relay that notifies only on the head "
                "leaves a streaming reply looking frozen from its second chunk "
                "onward, and the stall window then cuts it")
            # AND THE CLIENT REALLY GOT THE BODY, or a wrapper that notifies
            # and swallows would pass.
            cl_a.shutdown(socket.SHUT_WR)
            got = b""
            while True:
                chunk = cl_b.recv(4096)
                if not chunk:
                    break
                got += chunk
            assert b"event: a" in got and b"event: b" in got, got[:120]
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

        # --- AND ONE WRAPPER PER RESPONSE, not one per interim head.
        # `client` is rebound to the `_StampingWriter` before the 1xx branch,
        # and that branch recursed with the wrapper AND the callback — so a
        # response preceded by two 103 Early Hints was written through three
        # nested writers, each stamping on the way down. The count is what
        # `_owed_still_moving` reads, and a stamp is also a lock acquisition.
        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        stamps = []
        try:
            def _with_interim():
                # Tolerant of the teardown race: the assertions below finish
                # first and the fixture closes these, which is not a failure.
                try:
                    up_b.sendall(b"HTTP/1.1 103 Early Hints\r\n\r\n")
                    time.sleep(0.1)
                    up_b.sendall(b"HTTP/1.1 103 Early Hints\r\n\r\n")
                    time.sleep(0.1)
                    up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Length: 5\r\n\r\nhello")
                    time.sleep(0.05)
                    up_b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            threading.Thread(target=_with_interim, daemon=True).start()
            _relay_response(up_a, cl_a, 0,
                            on_headers=lambda n, c: stamps.append(n))

            cl_a.shutdown(socket.SHUT_WR)
            got = b""
            while True:
                chunk = cl_b.recv(4096)
                if not chunk:
                    break
                got += chunk
            writes = got.count(b"HTTP/1.1")
            assert b"hello" in got, got[:160]
            assert len(stamps) <= writes + 1, (
                f"{len(stamps)} stamps for {writes} response head(s) plus a "
                "body — the interim recursion is nesting a writer per 1xx, so "
                "every byte of the real answer is stamped once per layer")
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

    def case_on_status_reaches_the_final_line_behind_an_interim(self, certdir):
        """An interim response must not swallow `on_status` for the real one.

        The two 1xx recursions dropped `on_status` entirely (`on_headers=None`,
        no `on_status=`), so a takeover 409 behind a 103 Early Hints reached
        `_note_bridge_superseded` never: the callback fired once for the 103
        itself (a no-op there) and then had nothing to call for the real
        answer, because the recursion that reads it did not carry it.
        """
        import socket
        import threading
        import time

        from cswap_pin.proxy import _relay_response

        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        calls = []
        try:
            def _send():
                try:
                    up_b.sendall(b"HTTP/1.1 103 Early Hints\r\n\r\n")
                    time.sleep(0.05)
                    up_b.sendall(
                        b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n")
                    up_b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            threading.Thread(target=_send, daemon=True).start()
            _relay_response(
                up_a, cl_a, 0, method="POST",
                path="/v1/code/sessions/cse_X/worker/events",
                on_status=lambda st: calls.append(st))

            cl_a.shutdown(socket.SHUT_WR)
            got = b""
            while True:
                chunk = cl_b.recv(4096)
                if not chunk:
                    break
                got += chunk
            assert b"409" in got, got[:120]
            assert len(calls) == 1, (
                f"on_status fired {len(calls)} time(s) behind an interim "
                f"response, wanted exactly 1 for the final line: {calls!r}")
            assert calls[0].startswith(b"HTTP/1.1 409"), calls
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

    def case_the_orphan_sweep_spares_a_daemon_that_is_draining(self, certdir):
        """THE FIFTH CAUSE, and it is two of my own fixes in direct opposition.

        `_spawn_daemon` runs `_sweep_orphan_daemons(keep_pid=<successor>)` the
        moment the successor is serving and recorded. A predecessor that handed
        the port on and is patiently finishing its replies is, to that filter,
        exactly "a pin daemon for this certdir that is not keep_pid".

        Measured on host-a 2026-08-18, the 0.1.100 rollout — one second between
        the two lines:

            08:21:19Z  pid=616877  serving on port 36301
            08:21:19Z  pid=2932386 stopping (signal SIGTERM)
            08:21:49Z  pid=2932386 cut 13 (13 mid-response, 0 before headers)

        AND THE HANDOVER CEILING IS WHAT MADE IT BITE. Before 0.1.99 the
        predecessor exited inside thirty seconds and the sweep usually found
        nothing; widening the wait twentyfold widened the window to be killed
        in. Each fix was right alone. Nothing in either said the other existed.

        THE POPULATIONS ARE GENUINELY DIFFERENT and the sweep's own docstring
        says so — it targets daemons that "hold ports and never idle-teardown".
        A drainer accepts nothing and exits by itself. So the fix is in the
        sweep, not in the drain, and NOT in making the drainer ignore SIGTERM:
        that would defeat a real supervisor and buy a SIGKILL at 32s, which
        cuts harder than the drain it was meant to protect.
        """
        import cswap_pin.proxy as pp

        killed = []
        real_kill = pp._kill_daemon
        real_pids = pp._pin_daemon_pids
        pp._kill_daemon = lambda pid, certdir=None: killed.append(pid)
        # A PREDECESSOR AND A REAL ORPHAN, so the case cannot pass by sparing
        # everything — which is the failure mode of a guard that only ever
        # removes a kill.
        pp._pin_daemon_pids = lambda certdir: [4242, 7777]
        try:
            pp.announce_draining(certdir, 4242)
            assert pp.is_draining(certdir, 4242) is True, "precondition"
            assert pp.is_draining(certdir, 7777) is False, "precondition"

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert 4242 not in killed, (
                "the sweep TERMed a daemon that had announced it was draining. "
                "That is the 08:21:19Z line: a handover that cut nothing, "
                "followed one second later by a signal that cut 13 replies")
            assert killed == [7777], (
                "a real orphan must still be killed — a sweep that spares "
                "everything is not a fix, it is a disabled sweep. "
                f"killed={killed}")

            # --- AND A PILE OF THEM IS A LEAK, which is the bound that
            # replaces the wall clock. ONE predecessor lingering three hours
            # on a box serving a three-hour reply is CORRECT behaviour, and a
            # per-process clock cannot tell it from a leak. A count can. The
            # quantity moved because the old one answered the wrong question,
            # not because the number was too small.
            killed.clear()
            pids = _fake_pids(5000, pp._MAX_DRAINING_PREDECESSORS + 2)
            pp._pin_daemon_pids = lambda certdir: list(pids)
            for i, pid in enumerate(pids):
                pp.announce_draining(certdir, pid)
                # OLDEST LAST, against the order they are enumerated in. Ages
                # ascending with the pid would make "take the first two" and
                # "take the two oldest" the same answer, and the ordering —
                # the only judgement this bound makes — would go untested.
                pp.draining_marker_path(certdir, pid).write_text(
                    str(time.time() - 1000 - i))

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert sorted(killed) == pids[-2:], (
                "with no ceiling on a drain, nothing else bounds a drainer "
                "that never finishes. Over the limit the sweep must take the "
                "ones draining LONGEST, and only the excess. "
                f"killed={killed}, oldest two are {pids[-2:]}")

            # --- AND AGE IS THE TIEBREAK, NOT THE RULE. Measured on host-a
            # 2026-08-18: a draining predecessor's connections carry a fixed
            # 39-byte frame at ~1/s (GCD exact across 17 samples), so EVERY
            # predecessor stays "moving" and age stops tracking doneness — it
            # tracks how long a reply has been RUNNING. Reaping longest-first
            # then takes the stream with the most work already sunk. Reap the
            # one with the FEWEST replies to lose.
            killed.clear()
            owed = {pids[0]: 9, pids[1]: 0, pids[2]: 1}
            for i, pid in enumerate(pids):
                # Oldest FIRST this time, so age alone would pick pids[0..1]
                # and only the owed counts can produce the expected answer.
                pp.announce_draining(certdir, pid)
                pp.beat_draining(certdir, pid, owed=owed.get(pid, 5))
                path = pp.draining_marker_path(certdir, pid)
                body = path.read_text().split("\n")
                body[0] = str(time.time() - 1000 + i)
                # ONE MARKER THAT DOES NOT SAY, and it is the OLDEST — written
                # by a version that recorded no count, or caught between the
                # announce and the first beat. Unknown must sort EXPENSIVE:
                # this orders what to kill, and a file we cannot read is not
                # permission to take the one that may be holding the most.
                if pid == pids[3]:
                    body = [str(time.time() - 2000)]
                path.write_text("\n".join(body))

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert sorted(killed) == sorted([pids[1], pids[2]]), (
                "the sweep reaped by age while every predecessor was equally "
                "alive. The cheapest one to lose is the one owing the fewest "
                f"replies. killed={killed}, owed={owed}")
            assert pids[3] not in killed, (
                "the sweep took the one marker that does not say what it "
                "would cost, and it was the oldest — an unknown count sorted "
                "as if it were cheap")

            # --- AND THE DEAD ONES' MARKERS ARE COLLECTED. A drainer that is
            # SIGKILLed cannot unlink its own, and every reap above produces
            # one. `is_draining` already stops honouring it past the TTL, so
            # this is litter rather than a safety hole — but it is litter in
            # the one directory a human reads while debugging a handover, and
            # the sweep already walks this exact set.
            import os as _os
            ghost = pp.draining_marker_path(certdir, 6001)
            ghost.write_text(str(time.time() - 9999))
            stale = time.time() - pp._DRAINING_MARKER_TTL - 1
            _os.utime(ghost, (stale, stale))
            live = pp.draining_marker_path(certdir, pids[0])
            pp._pin_daemon_pids = lambda certdir: [pids[0]]

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert not ghost.exists(), (
                "a marker whose writer is long gone survived the sweep. One "
                "per hard-killed daemon accumulates forever in the directory "
                "somebody opens to find out what a handover did")
            assert live.exists(), (
                "the sweep collected a marker that is still being beaten — "
                "that is a live drainer losing its protection mid-reply")

            # --- AND A PREDECESSOR CARRYING A BRIDGE IS NOT PART OF THE PILE.
            # It has zero live replies — its remaining job is a held-open
            # subscription, not an answer — so every rule above scored it as
            # the CHEAPEST thing on the box and it was always the one taken.
            # That is the one cut a session cannot recover from by itself:
            # claude.ai pushes through that stream, and the client does not
            # get it back without reconnecting.
            killed.clear()
            pids = _fake_pids(8000, pp._MAX_DRAINING_PREDECESSORS + 2)
            pp._pin_daemon_pids = lambda certdir: list(pids)
            for i, pid in enumerate(pids):
                pp.announce_draining(certdir, pid)
                # EVERY ONE CHEAP BY THE OLD RULES, so only the subscription
                # count can produce the expected answer. The two WITHOUT one
                # are the youngest, so age cannot pick them either.
                pp.beat_draining(certdir, pid, owed=0, live=0, quiet=0.0,
                                 streams=0 if i >= len(pids) - 2 else 3)
                path = pp.draining_marker_path(certdir, pid)
                body = path.read_text().split("\n")
                body[0] = str(time.time() - 1000 - i)
                path.write_text("\n".join(body))

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert sorted(killed) == sorted(pids[-2:]), (
                "the sweep took a predecessor still delivering a held-open "
                "subscription while stream-less ones were available. Every "
                "other cost here can be retried; that one cannot be reopened "
                f"by the session that lost it. killed={killed}")

            # AND WHEN THERE IS NOTHING CHEAP TO TAKE, IT TAKES NOTHING. A
            # reaper with no safe choice must say so, not pick the least-bad
            # session to cut.
            killed.clear()
            for pid in pids:
                pp.beat_draining(certdir, pid, owed=0, live=0, quiet=0.0,
                                 streams=2)

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert killed == [], (
                "over the limit with every predecessor carrying a bridge, the "
                f"sweep still cut one. killed={killed}")
        finally:
            pp._kill_daemon = real_kill
            pp._pin_daemon_pids = real_pids

    def case_two_teardowns_at_once_do_not_unprotect_each_other(self, certdir):
        """MEASURED, SAME PID, SAME SECOND — both terminators fired.

            08:41:19Z pid=616877 stopping (refcount)
            08:41:19Z pid=616877 stopping (signal SIGTERM)
            08:41:49Z pid=616877 cut 14 (14 mid-response, 0 before headers)

        Two teardowns in one process means two `stop()` calls, two drains, and
        two announcements. They take DIFFERENT ceilings by design — refcount
        600s, signal 30s — so the short one finishes first, and the first
        version of the marker had it unlink the file out from under the drain
        still waiting. That hands the sweep exactly the process the marker
        exists to protect, at the moment it is most exposed.

        The bug was one hour old and its evidence was already in the log that
        motivated the marker. Counted rather than flagged: the LAST release
        removes it.
        """
        import cswap_pin.proxy as pp

        first = pp.announce_draining(certdir, 4242)   # the long, still waiting
        second = pp.announce_draining(certdir, 4242)  # the short, about to end
        assert pp.is_draining(certdir, 4242) is True, "precondition"

        second()
        assert pp.is_draining(certdir, 4242) is True, (
            "the short drain's release unprotected the long one that is still "
            "running — the sweep can now TERM a daemon mid-reply, which is the "
            "whole fault this marker was added for")

        first()
        assert pp.is_draining(certdir, 4242) is False, (
            "the marker outlived every drain that announced it, so a genuine "
            "orphan on this pid is spared until the TTL expires")

        # A CALLER THAT RELEASES TWICE MUST NOT SPEND SOMEBODY ELSE'S COUNT.
        # The first version of this assertion released twice AFTER everything
        # had already released, where `dict.get(key, 1) - 1` lands on zero
        # either way — so the mutation that removes the idempotence guard
        # SURVIVED it. Tested where it can fail: a second drain is still
        # running, and the double release must not take the count to zero
        # under it.
        long_drain = pp.announce_draining(certdir, 4242)
        short_drain = pp.announce_draining(certdir, 4242)
        short_drain()
        short_drain()      # the same caller, twice
        assert pp.is_draining(certdir, 4242) is True, (
            "one caller's double release spent the OTHER drain's count and "
            "unlinked the marker while it was still waiting — the sweep can "
            "now TERM it mid-reply")
        long_drain()
        assert pp.is_draining(certdir, 4242) is False

    def case_the_handover_announces_before_the_successor_can_exist(self, certdir):
        """ANNOUNCING WHEN THE DRAIN STARTS IS ONE STEP TOO LATE.

        `await_inflight` announces, and at the fd-handdown site it runs AFTER
        `_spawn_daemon` returns. The successor publishes `proxy.json` the
        instant it serves, so from that publish until the predecessor reaches
        the drain, `read_daemon_state` names the successor as keep_pid while
        the predecessor has written no marker. Any concurrent `ensure_proxy`
        sweeps in that window and TERMs a daemon that is about to finish its
        replies — the 08:21:19Z race through a door one frame higher.

        Same shape at the ask-the-holder site: the holder spawns the successor
        while we are still sleeping out `_ASK_SETTLE_SECONDS`.

        READ OUT OF THE SOURCE because the property is an ORDERING, and the
        window is a few hundred milliseconds wide on a machine that has to be
        recycling and launching at the same moment to show it.
        """
        import inspect
        import cswap_pin.proxy as pp

        src = inspect.getsource(pp._watch_own_code)
        ask = src.find("_REPLACE_ME_SIGNAL")
        spawn = src.find("_spawn_daemon(")
        assert -1 not in (ask, spawn) and ask < spawn, (
            "the scan is broken: it assumes the ask-the-holder site precedes "
            f"the fd-handdown site in this function. ask={ask} spawn={spawn}")

        # ONE PER SITE, and the case must fail if EITHER is removed — a single
        # "an announce exists somewhere above" check passes with the second
        # site unprotected, because the first site's call is above both.
        before_ask = src.rfind("announce_draining", 0, ask)
        assert before_ask != -1, (
            "nothing announces before the holder is asked to replace us. The "
            "holder spawns the successor on that signal, and the successor's "
            "publish is what makes this daemon sweepable")
        between = src.rfind("announce_draining", ask, spawn)
        assert between != -1, (
            "nothing announces between the ask and `_spawn_daemon`, so the "
            "fd-handdown site is protected only from inside `await_inflight` "
            "— which runs after the spawn has already published a successor")

    def case_the_drain_is_what_announces_itself(self, certdir):
        """THE WIRING, and it is the third time tonight the guard was orphaned.

        The sibling cases call `announce_draining` themselves, so removing the
        call from `await_inflight` leaves them green — a correct function that
        nothing invokes, which is the exact shape of `_blind_tunnel` never
        clearing its debt and of the relay never marking a reply started.

        ANNOUNCED INSIDE `await_inflight` ON PURPOSE. There are four exit paths
        that drain and tonight's whole bug list is fixes that landed on some
        paths and not the one that mattered, so the announcement lives in the
        one function all four go through. This case is what makes that claim
        checkable rather than aspirational.
        """
        import cswap_pin.proxy as pp

        calls, released, seeded = [], [], []
        real = pp.announce_draining

        # `server=` IS PART OF THE CONTRACT, so the spy names it rather than
        # swallowing it in `**kwargs`. A marker that cannot be read is one the
        # successor reports as predating the held-bridge record, and the
        # successor is spawned INSIDE the announce->beat window every time.
        def _spy(certdir_arg, pid=None, server=None):
            calls.append(Path(certdir_arg))
            seeded.append(server)
            done = real(certdir_arg, pid, server=server)
            return lambda: (released.append(True), done())[1]

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        pp.announce_draining = _spy
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(0.0)
        finally:
            pp.announce_draining = real

        assert calls, (
            "the drain did not announce itself, so the orphan sweep will TERM "
            "this daemon while it is finishing replies — the 08:21:19Z line")
        assert calls[0] == Path(certdir), (
            f"announced against the wrong certdir: {calls[0]} != {certdir}. A "
            "marker under another daemon's directory protects nobody")
        assert seeded and seeded[0] is proxy, (
            "announced without the server, so the marker is one line long "
            "until the first beat and the successor spawned in that window "
            "reads this daemon as predating the held-bridge record")
        assert released, (
            "the marker was never removed. It expires on a TTL, so this is not "
            "a leak that lasts — but until it does, a genuinely orphaned pin "
            "daemon on that pid is spared by a sweep that should have taken it")

    def case_a_draining_marker_does_not_outlive_its_writer(self, certdir):
        """A SIGKILLED DRAINER CANNOT CLEAN UP AFTER ITSELF, and pids are reused.

        The marker's only power is to spare a process, so a stale one is a
        pin daemon that never gets swept — the orphan this sweep exists for,
        wearing a dead process's badge. Past the TTL the answer goes back to
        what it was before any of this existed, which is the safe direction.
        """
        import cswap_pin.proxy as pp

        import os

        pp.announce_draining(certdir, 4242)
        assert pp.is_draining(certdir, 4242) is True

        # STALE MEANS UNTOUCHED, NOT OLD, and that distinction is the change.
        # A handover drain has no ceiling any more, so age cannot mean
        # abandoned — a drain that has run three hours because a reply has run
        # three hours is healthy. Only silence separates them.
        path = pp.draining_marker_path(certdir, 4242)
        old_t = time.time() - pp._DRAINING_MARKER_TTL - 1
        os.utime(path, (old_t, old_t))
        assert pp.is_draining(certdir, 4242) is False, (
            "a marker nothing has touched since before the TTL still protected "
            "a pid — an orphan inheriting that number would never be swept")

        # AND A BEAT BRINGS IT BACK. This is what lets a drain outlive its own
        # marker TTL: an hour-long reply keeps its protection by SAYING SO
        # every few seconds, not by having been handed a big enough number in
        # advance. Every number handed out in advance tonight was wrong.
        pp.beat_draining(certdir, 4242)
        assert pp.is_draining(certdir, 4242) is True, (
            "a beat did not refresh the marker, so a long drain loses its "
            "protection mid-reply and the sweep TERMs it — the 08:21:19Z line "
            "again, with the clock moved from the drain into the marker")

        # AND AN UNWRITABLE MARKER MUST NOT BREAK THE DRAIN. Failing open here
        # means the outcome is exactly what it was before this existed; failing
        # closed would mean a drain that cannot start.
        done = pp.announce_draining(Path("/nonexistent-dir-for-a-marker"), 1)
        done()

    def case_a_refcount_shutdown_is_not_a_recycle_and_not_a_signal(self, certdir):
        """THE FOURTH EXIT PATH, found by fixing the other three.

        Measured on host-a, the 0.1.99 rollout, in this order:

            08:04:18Z  handover — NO drain line at all. The departing daemon
                       handed the port on and kept living, which is what
                       `_HANDOVER_DRAIN_SECONDS` is for. Nothing cut.
            08:08:18Z  `stopping (refcount)` on that same lingering daemon,
                       cut 13 (13 mid-response, 0 before headers), 30s budget.

        So the handover stopped costing anything and a shutdown four minutes
        later cost the same as before. The cost was MOVED, not removed — which
        is only visible because the other three were fixed first.

        WHAT EACH ARM IS REALLY ASKING is who is waiting for this process to be
        gone, and the three answers are genuinely different:

          held      the holder cannot put the successor on the socket until we
                    exit, so waiting is unserved port time
          signal    a supervisor is counting `_DRAIN_SECONDS + 2` and then
                    SIGKILLs. Waiting past that does not save a reply, it
                    guarantees a harder kill partway through one
          refcount  nobody is waiting at all: no successor, no supervisor, and
                    the listener is already released so a fresh daemon could
                    bind now

        THE SIGNAL ROW IS THE ONE THAT MATTERS MOST, because "a shutdown is a
        shutdown" would give it the long ceiling and make things WORSE than
        before — a SIGKILL at 32 seconds cuts harder than an orderly drain.
        """
        from cswap_pin.proxy import (
            teardown_drain_budget,
            _DRAIN_SECONDS,
            _HANDOVER_DRAIN_SECONDS,
            _HELD_DRAIN_SECONDS,
        )

        assert teardown_drain_budget("refcount", False) == _HANDOVER_DRAIN_SECONDS, (
            "a refcount shutdown cut 13 mid-response replies on the short "
            "ceiling. Nobody is waiting for this process — no successor, no "
            "supervisor — so the only cost of waiting is finishing what it owes")

        assert teardown_drain_budget("signal TERM", False) == _DRAIN_SECONDS, (
            "a signalled shutdown took the long ceiling. The supervisor "
            "SIGKILLs at _DRAIN_SECONDS + 2, so draining past it cuts a reply "
            "harder than an orderly drain would have")
        assert teardown_drain_budget("signal INT", False) == _DRAIN_SECONDS

        # HELD WINS OVER EVERY REASON, including refcount: the holder is
        # blocked on our exit whatever brought us here.
        assert teardown_drain_budget("refcount", True) == _HELD_DRAIN_SECONDS, (
            "a held shutdown took a ceiling other than the held one — that is "
            "unserved port time, however the shutdown started")
        assert teardown_drain_budget("signal TERM", True) == _HELD_DRAIN_SECONDS

        # ...UNLESS THE SUCCESSOR IS ALREADY SERVING, and that is the whole
        # premise of the held arm rather than a corner of it. Its reasoning is
        # "the holder cannot put the successor on the socket until we are
        # gone", which was true before the replace-ask existed and is FALSE
        # for a daemon that has already handed over: `_watch_own_code` asks,
        # verifies the holder survived, and the successor is serving on the
        # same socket while this process drains.
        #
        # MEASURED ON host-b 2026-08-18, and this is what it cost:
        #   20:01:32Z pid=96075 code on disk changed — asked the holder to
        #             replace us while we keep serving      (uncapped drain)
        #   20:01:32Z pid=25445 serving on port 53749       (successor is UP)
        #   20:02:01Z pid=96075 stopping (refcount)         (second drain)
        #   20:02:31Z pid=96075 cut 4 in-flight request(s) after 30.1s of a
        #             30s budget (4 mid-response, content-free 0/2/9 s)
        # Four replies, every one still delivering — the content-free field is
        # what proves that; `4 mid-response` alone cannot tell a live stream
        # from one that stopped. The uncapped handover ceiling was overridden
        # by a second drain that re-armed a clock the first had removed.
        assert teardown_drain_budget(
            "refcount", True, handed_over=True) == _HANDOVER_DRAIN_SECONDS, (
            "a daemon that had already handed over took the held ceiling. "
            "Its successor is on the socket, so there is no unserved port "
            "time to buy, and the 30s bought instead cut four live replies")
        # THE SIGNAL ROW DOES NOT MOVE. A supervisor still SIGKILLs at
        # _DRAIN_SECONDS + 2 whether or not we handed over, so a long ceiling
        # here still buys a harder kill partway through a reply.
        #
        # ASSERTED AGAINST THE UNCAPPED CEILING, not against `_DRAIN_SECONDS`.
        # `_HELD_DRAIN_SECONDS IS _DRAIN_SECONDS` (both 30.0), so `== _DRAIN_
        # SECONDS` passes with the handed-over guard, without it, and with it
        # inverted — a verdict it can never produce. What can actually go wrong
        # here is the row going UNCAPPED, so that is what is pinned.
        assert teardown_drain_budget(
            "signal TERM", True, handed_over=True) != _HANDOVER_DRAIN_SECONDS, (
            "a signalled shutdown took the uncapped ceiling; the supervisor "
            "SIGKILLs at _DRAIN_SECONDS + 2, so waiting past it buys a harder "
            "kill partway through a reply rather than a finished one")
        assert teardown_drain_budget(
            "signal TERM", True, handed_over=True) == _DRAIN_SECONDS

    def case_a_pin_names_itself_in_the_live_config(self, certdir, tmp_path,
                                                   monkeypatch):
        """A pin that does not SPLICE does nothing until the next switch.

        `apply_pin` saved the record, wired the proxy env and started the
        daemon, and never wrote `oauthAccount` — the field Claude Code reads to
        decide who OWNS a bridge. The only writer was cswap's switch, so a pin
        set while another account was active left the config naming THAT
        account, and every bridge minted afterwards belonged to it.

        MEASURED on a live machine before this: pin=slot 1,
        `~/.claude.json`=slot 4, and cswap's own bridge-owner check reporting
        "all 13 live bridge pointers match the current login" — the current
        login, not the pin. Re-running `cswap pin` did not move it.

        THE RULE IS HERE, THE LOOKUP IS NOT. Which identity to write means
        reading cswap's backup store, whose layout this package must not know,
        so it arrives as an argument.
        """
        import json

        import cswap_pin.proxy as pp

        cfg = tmp_path / "claude.json"
        cfg.write_text(json.dumps({
            "oauthAccount": {"emailAddress": "active@example.com",
                             "organizationUuid": "org-ACTIVE"},
            "env": {"HTTPS_PROXY": "http://127.0.0.1:1"},
        }))
        # PATCH THE SEAM, not a name this module does not own: the path is
        # fetched through `require("paths")` at call time.
        import types
        monkeypatch.setattr(
            pp, "require",
            lambda name, _r=pp.require: (
                types.SimpleNamespace(get_global_config_path=lambda: cfg)
                if name == "paths" else _r(name)))

        want = {"emailAddress": "pinned@example.com",
                "organizationUuid": "org-PIN", "accountUuid": "uuid-PIN"}
        assert pp.splice_config_identity(want) is True, (
            "setting a pin did not name it in the live config, so Claude Code "
            "keeps minting bridges under the ACTIVE account and the pin is "
            "inert until the next switch")
        after = json.loads(cfg.read_text())
        assert after["oauthAccount"] == want
        assert after["env"] == {"HTTPS_PROXY": "http://127.0.0.1:1"}, (
            "the splice rewrote a field that belongs to Claude Code; only "
            "oauthAccount is ours to touch")

        # IDEMPOTENT. Every live session watches this file, so a rewrite that
        # changes nothing is a wake-up for all of them.
        assert pp.splice_config_identity(want) is False

        # NOTHING TO WRITE IS NOT AN ERROR — no pin, or a lookup that failed.
        assert pp.splice_config_identity(None) is False

        # AND A CONFIG WE CANNOT PARSE IS LEFT FOR ITS OWNER.
        for bad in ("[]", "null", '"a string"', "{torn"):
            cfg.write_text(bad)
            assert pp.splice_config_identity(want) is False, (
                f"a {bad!r} config was rewritten; a file we do not understand "
                "is one we must not touch")
            assert cfg.read_text() == bad

        # A MALFORMED oauthAccount IS STILL OURS TO REPAIR, and the diagnostic
        # that names what it replaced must not be what stops it. `null` and
        # `[]` are falsy, so a `(here or {})` guard covers them and reads as
        # complete; a truthy non-dict walks straight into `.get` and the
        # blanket except turns the whole splice into a silent no-op, leaving
        # the field wrong on every future launch.
        for broken in ("somebody", ["x"], 7):
            cfg.write_text(json.dumps({"oauthAccount": broken}))
            assert pp.splice_config_identity(want) is True, (
                f"an oauthAccount of {broken!r} was left as it was; the pin "
                "cannot repair a config it fails to describe")
            assert json.loads(cfg.read_text())["oauthAccount"] == want

        # AND apply_pin IS THE PATH THAT CARRIES IT. Reaching a real apply_pin
        # needs a switcher and a daemon, so read the wiring out of the source.
        import inspect

        src = inspect.getsource(pp.apply_pin)
        assert "splice_config_identity(identity)" in src, (
            "apply_pin does not name the pin in the config, so the rule exists "
            "and nothing calls it")
        assert "identity" in inspect.signature(pp.apply_pin).parameters, (
            "apply_pin cannot be handed an identity, so cswap has no way to "
            "pass the one it looked up")

    def case_clearing_a_pin_stops_naming_it(self, certdir, tmp_path,
                                            monkeypatch):
        """`--clear` left the ex-pin in the live config.

        `apply_pin(email=None)` returns from its own branch, above the splice,
        so clearing unwired the proxy and dropped the record while
        `~/.claude.json` still named the account that had been pinned. Claude
        Code reads that field as the OWNER of every bridge it mints, so an
        unpinned machine kept minting under the ex-pin until the next switch
        happened to rewrite it -- and nothing says so.

        The identity comes from the CALLER, as it does when setting: only
        cswap can look up an account in its own backup store, and teaching the
        package that layout is the dependency inversion this seam exists to
        prevent.
        """
        import json
        import types

        import cswap_pin.proxy as pp

        cfg = tmp_path / "claude-clear.json"
        cfg.write_text(json.dumps({
            "oauthAccount": {"emailAddress": "expin@example.com",
                             "organizationUuid": "org-EXPIN"},
        }))
        monkeypatch.setattr(
            pp, "require",
            lambda name, _r=pp.require: (
                types.SimpleNamespace(get_global_config_path=lambda: cfg)
                if name == "paths" else _r(name)))
        monkeypatch.setattr(pp, "save_pin", lambda *a, **k: None)
        monkeypatch.setattr(pp, "wire_global_config", lambda *a, **k: None)

        sw = types.SimpleNamespace(backup_dir=tmp_path)
        live = {"emailAddress": "active@example.com",
                "organizationUuid": "org-ACTIVE", "accountUuid": "uuid-ACTIVE"}

        assert pp.apply_pin(sw, None, None, identity=live) is False, (
            "clearing still reports whether a proxy serves, which is False"
        )
        assert json.loads(cfg.read_text())["oauthAccount"] == live, (
            "the cleared pin is still named in the live config, so every "
            "bridge minted afterwards is owned by an account nothing is "
            "pinned to"
        )

        # NO IDENTITY IS NOT AN ERASURE. A caller that could not look one up
        # passes None, and leaving the field alone is the safe half: cswap's
        # own switch rewrites it on the next rotation.
        cfg.write_text(json.dumps({"oauthAccount": {"emailAddress": "keep"}}))
        assert pp.apply_pin(sw, None, None) is False
        assert json.loads(cfg.read_text())["oauthAccount"] == {
            "emailAddress": "keep"}


    def case_a_bridge_that_posts_but_never_listens_is_named(self, certdir):
        """Remote Control's inbound channel dies silently, and only the pin
        can see it.

        Claude Code 2.1.220, in the binary:

            async connect(){ if(this.state!=="idle"&&this.state!=="reconnecting"){return} }
            close(){ ... this.state="closed" ... }

        Once closed, `connect()` returns immediately, forever. Outbound is a
        separate path, so the session keeps POSTing, keeps heartbeating, and
        reports `connection_status: connected` while receiving NOTHING. Every
        external check says healthy; the one that matters is invisible.

        Measured on this fleet: 6 of 13 live sessions in that state at once,
        found only by a 45-second opt-in trace capture nobody runs. The pin is
        the single point that sees BOTH directions, so it can answer the
        question directly instead of leaving it to an errand.

        THE PAIR AGAIN, as with the squatting standby: posting alone is not
        the signal (a healthy bridge posts too) and a missing stream alone is
        not either (a session that has said nothing yet has no stream and is
        fine). Deaf means posted RECENTLY and holds no stream.
        """
        import cswap_pin.proxy as pp

        import threading

        srv = pp.PinProxy.__new__(pp.PinProxy)
        srv._reset_bridge_traffic()
        srv._live_lock = threading.Lock()
        srv._stream_conns = set()
        srv._open_conns = set()

        # WHAT PRODUCTION ACTUALLY HANDS OVER. `_handle_one_request` holds a
        # raw request line and must split it, because every route pattern is
        # `^`-anchored to a path. Feeding bare paths here is what let the
        # accounting record NOTHING on every machine while this stayed green,
        # so the line is split the way the caller splits it.
        def _path(request_line):
            parts = request_line.split(" ")
            return parts[1] if len(parts) > 1 else "/"

        A = _path("POST /v1/code/sessions/cse_AAA/worker/messages HTTP/1.1")
        A_STREAM = _path(
            "GET /v1/code/sessions/cse_AAA/worker/events/stream HTTP/1.1")
        B = _path("POST /v1/code/sessions/cse_BBB/worker/messages HTTP/1.1")
        assert A.startswith("/v1/"), "the split did not produce a path"

        # AND THE CALLER MUST DO THAT SPLIT. The bug was never in this
        # function; it was one level up, handing over the whole line.
        import inspect
        caller = inspect.getsource(pp.PinProxy._handle_one_request)
        assert "_note_bridge_traffic(request_line" not in caller, (
            "the caller passes the raw request line, which matches no route "
            "pattern — the accounting records nothing on every machine")

        # A posts and HOLDS a stream. B posts and never opens one.
        # The stream is a connection that stays open, not an event that
        # recurs — asking when it was last opened is what made an earlier cut
        # call every long-lived session deaf.
        conn_a = object()
        srv._note_bridge_traffic(A, now=100.0)
        srv._note_bridge_traffic(A_STREAM, now=100.5, conn=conn_a)
        srv._stream_conns.add(conn_a)
        srv._open_conns.add(conn_a)
        srv._note_bridge_traffic(B, now=101.0)

        deaf = srv.deaf_bridges(window=60.0, now=110.0)
        assert deaf == ["cse_BBB"], (
            f"the pin could not name the bridge that posts and never listens: "
            f"{deaf}")

        # THE CONTROL, and it is what stops this reporting the whole fleet:
        # a bridge that has not posted inside the window is silent, not deaf.
        assert srv.deaf_bridges(window=60.0, now=1000.0) == [], (
            "a bridge that stopped posting long ago was reported deaf; every "
            "ended session would be flagged forever")

        # THE REAL CONSTRUCTOR MUST DO THIS, or the accounting is dead in
        # production and green here. `_note_bridge_traffic` swallows its own
        # errors on purpose (it sits on the request path), so a dict that was
        # never created is a silent no-op nobody would ever see.
        import inspect
        src = inspect.getsource(pp.PinProxy.__init__)
        assert "_reset_bridge_traffic()" in src, (
            "the proxy never starts the per-bridge accounting, so "
            "deaf_bridges() answers [] forever on a real machine")

        # AND A STREAM ARRIVING LATE CLEARS IT. The transport can reconnect
        # while state is still `reconnecting`; a verdict that never revises
        # would tell the user to restart a session that just healed.
        conn_b = object()
        srv._note_bridge_traffic("/v1/code/sessions/cse_BBB/worker/events/stream",
                                 now=111.0, conn=conn_b)
        srv._stream_conns.add(conn_b)
        srv._open_conns.add(conn_b)
        assert srv.deaf_bridges(window=60.0, now=112.0) == []

        # THE REGRESSION THIS SHAPE EXISTS FOR: A's stream was opened long
        # before the window and has never been re-issued, because it is held.
        # A recency test calls A deaf here; a held test does not.
        srv._note_bridge_traffic(A, now=100000.0)
        assert srv.deaf_bridges(window=60.0, now=100001.0) == [], (
            "a session HOLDING its inbound stream was called deaf because the "
            "stream was opened before the window — the stream is issued once "
            "and kept, so it never falls inside a recent window")

        # AND SOMETHING MUST ASK. `deaf_bridges` answered correctly and had
        # NO CALLER in either repo for three releases — one definition, no CLI,
        # and a method on the daemon's own instance, so no other process could
        # reach it. A check nothing invokes is not a check, and the suite could
        # not tell the difference.
        import inspect
        wired = inspect.getsource(pp.PinProxy._report_deaf_bridges)
        # A PREFIX, because the reporter now passes the predecessors' held
        # bridges in and an exact-match guard fails on its own fix.
        assert "self.deaf_bridges(" in wired
        # AND IT MUST STILL UNION. Dropping `elsewhere` would restore the
        # local-only answer that called every pre-existing session deaf.
        assert "elsewhere=" in wired, (
            "the reporter asks only about streams this process holds, so a "
            "handover makes it name every session that predates it")
        caller = inspect.getsource(pp.PinProxy._handle_one_request_inner)
        assert "_report_deaf_bridges()" in caller, (
            "nothing on a machine invokes the deaf check, so the fleet cannot "
            "self-report and this test proves only that the maths is right")

        # AND A CLOSED CONNECTION IS NOT A HELD STREAM.
        srv._open_conns.discard(conn_a)
        srv._note_bridge_traffic(A, now=100002.0)
        assert "cse_AAA" in srv.deaf_bridges(window=60.0, now=100003.0)

    def case_a_bridge_that_has_just_registered_is_not_yet_deaf(self, certdir):
        """The burst measured on a mac after `cc-update --apply --force`:
        six bridges registered in six seconds, each posted before it had
        opened its stream, and the daemon named every one deaf although the
        stream GET followed within seconds on all of them — the ordinary
        gap between register and subscribe, not a loss.

        The grace is earned by a CREATE THIS DAEMON SERVED, not by merely
        being new to `_bridge_posts`: a bridge this daemon only inherited on
        a handover never posted its create here and must be judged at once
        (case c) — the shape the grace must never cover, because a handover
        is every cswap deploy.
        """
        import threading

        import cswap_pin.proxy as pp

        srv = pp.PinProxy.__new__(pp.PinProxy)
        srv._stream_lost = {}
        srv._reset_bridge_traffic()
        srv._live_lock = threading.Lock()
        srv._stream_conns = set()
        srv._open_conns = set()

        # (a) a create THIS daemon served, then its bridge posts before its
        # stream GET -- shielded inside the grace, judged past it.
        NEW = "/v1/code/sessions/cse_NEW/worker/messages"
        srv._should_sweep_bridges("POST", "/v1/code/sessions", now=999.0)
        srv._note_bridge_traffic(NEW, now=1000.0)
        assert srv.deaf_bridges(window=60.0, now=1005.0) == [], (
            "a bridge whose create this daemon just served was named deaf "
            "before its stream GET had a chance to arrive: "
            + repr(srv.deaf_bridges(window=60.0, now=1005.0)))
        past_grace = 1000.0 + pp._DEAF_STARTUP_GRACE_S + 1.0
        assert srv.deaf_bridges(window=60.0, now=past_grace) == ["cse_NEW"], (
            "the grace never expires, so a bridge that truly never opened "
            "its ear is never reported: "
            + repr(srv.deaf_bridges(window=60.0, now=past_grace)))

        # (b) a bridge whose stream WAS held and then dropped, inside its
        # own dwell -- a fresh loss is not yet judged (a sweep can land in
        # the ordinary close/reopen gap), and the SAME loss still there past
        # the dwell is judged exactly as before.
        LOST = "/v1/code/sessions/cse_LOST/worker/messages"
        LOST_STREAM = "/v1/code/sessions/cse_LOST/worker/events/stream"
        conn = object()
        srv._should_sweep_bridges("POST", "/v1/code/sessions", now=1999.0)
        srv._note_bridge_traffic(LOST, now=2000.0)
        srv._note_bridge_traffic(LOST_STREAM, now=2001.0, conn=conn)
        srv._stream_conns.add(conn)
        srv._open_conns.add(conn)
        srv._forget_stream(conn)
        # EXPLICIT, not the real clock `_forget_stream` just stamped: the
        # rest of this case runs on the fake timeline above and a real
        # `time.monotonic()` value would make `deaf_for` answer a huge
        # negative instead of the 2.0s this loss actually aged.
        srv._stream_lost["cse_LOST"] = 2003.0
        srv._note_bridge_traffic(LOST, now=2005.0)
        assert srv.deaf_bridges(window=60.0, now=2005.0) == [], (
            "a loss only 2s old was already named deaf -- the sweep that "
            "lands in the ordinary close/reopen gap must stay silent: "
            + repr(srv.deaf_bridges(window=60.0, now=2005.0)))
        past_dwell = 2003.0 + pp._DEAF_STARTUP_GRACE_S + 1.0
        srv._note_bridge_traffic(LOST, now=past_dwell)
        assert srv.deaf_bridges(window=60.0, now=past_dwell) == ["cse_LOST"], (
            "a loss still there past the dwell was never named: "
            + repr(srv.deaf_bridges(window=60.0, now=past_dwell)))

        # (c) THE SUCCESSOR SHAPE: no create ever passed through this
        # daemon (`_last_create` stays None, as on a handover), so the
        # bridge earns no grace and is judged the moment it posts. A fresh
        # instance, not this daemon's own `_last_create` from (a)/(b) above.
        succ = pp.PinProxy.__new__(pp.PinProxy)
        succ._stream_lost = {}
        succ._reset_bridge_traffic()
        succ._live_lock = threading.Lock()
        succ._stream_conns = set()
        succ._open_conns = set()
        SUCC = "/v1/code/sessions/cse_SUCC/worker/messages"
        succ._note_bridge_traffic(SUCC, now=3000.0)
        assert succ.deaf_bridges(window=60.0, now=3001.0) == ["cse_SUCC"], (
            "a bridge this daemon never served a create for was shielded "
            "as though it had just registered here, which on a handover "
            "hides a genuinely deaf inherited bridge for the whole grace: "
            + repr(succ.deaf_bridges(window=60.0, now=3001.0)))

        # (d) AN OLD BRIDGE, already posting before any create fired, must
        # not be backdated into the grace by an UNRELATED create that
        # happens later: only a bridge NEW to `_bridge_posts` at the moment
        # of its post earns an entry.
        old = pp.PinProxy.__new__(pp.PinProxy)
        old._stream_lost = {}
        old._reset_bridge_traffic()
        old._live_lock = threading.Lock()
        old._stream_conns = set()
        old._open_conns = set()
        OLD = "/v1/code/sessions/cse_OLD/worker/messages"
        old._note_bridge_traffic(OLD, now=100.0)
        assert old.deaf_bridges(window=60.0, now=101.0) == ["cse_OLD"], (
            "a bridge posting before any create fired was shielded with no "
            "create to shield it: " + repr(old.deaf_bridges(window=60.0, now=101.0)))
        old._should_sweep_bridges("POST", "/v1/code/sessions", now=200.0)
        old._note_bridge_traffic(OLD, now=201.0)
        assert old.deaf_bridges(window=60.0, now=202.0) == ["cse_OLD"], (
            "an old bridge reposting after an unrelated create was shielded "
            "as though it had just registered, backdating a grace that had "
            "nothing to do with it: "
            + repr(old.deaf_bridges(window=60.0, now=202.0)))

    def case_a_bridge_reregistered_through_bridge_is_not_yet_deaf(self):
        """A pin-brokered re-registration is a birth too, not only a create.

        Measured after the 0.1.245 fix above: `pin=cse_X`'s worker POST hit
        `deaf_bridges` a second after `POST .../<id>/bridge 200`, because
        `/bridge` matches neither `_WORKER_SUBTREE` nor `_EVENT_STREAM` and
        was dropped by `_note_bridge_traffic`'s own guard before it ever
        reached the accounting -- no create had run in this daemon's life
        either, so the startup grace (case above) never applied. The fix
        must record `/bridge` as a birth of its own.
        """
        import threading

        import cswap_pin.proxy as pp

        srv = pp.PinProxy.__new__(pp.PinProxy)
        srv._reset_bridge_traffic()
        srv._live_lock = threading.Lock()
        srv._stream_conns = set()
        srv._open_conns = set()
        srv._stream_lost = {}
        srv._connected_bridges = {"cse_X"}

        REGISTER = "/v1/code/sessions/cse_X/bridge"
        EVENTS = "/v1/code/sessions/cse_X/worker/events"

        # NO CREATE EVER SERVED: `_last_create` stays None, so the only
        # thing that can shield cse_X is the `/bridge` registration itself.
        srv._note_bridge_traffic(REGISTER, now=100.0)
        srv._note_bridge_traffic(EVENTS, now=100.5)
        assert srv.deaf_bridges(now=101.0) == [], (
            "a bridge re-registered through the pin's own /bridge route "
            "was named deaf before its stream GET had a chance to arrive: "
            + repr(srv.deaf_bridges(now=101.0)))
        past_grace = 100.0 + pp._DEAF_STARTUP_GRACE_S + 1.0
        assert srv.deaf_bridges(now=past_grace) == ["cse_X"], (
            "the grace never expires, so a re-registered bridge that truly "
            "never opened its ear is never reported: "
            + repr(srv.deaf_bridges(now=past_grace)))

        # THE 409 INTERACTION. A worker POST superseded by a 409 pops both
        # `_bridge_posts` and `_bridge_first_post` (`_note_bridge_superseded`).
        # A re-registration AFTER that pop must still earn a fresh grace; a
        # 409 with no re-registration must never resurrect the id.
        srv2 = pp.PinProxy.__new__(pp.PinProxy)
        srv2._reset_bridge_traffic()
        srv2._live_lock = threading.Lock()
        srv2._stream_conns = set()
        srv2._open_conns = set()
        srv2._stream_lost = {}
        srv2._connected_bridges = {"cse_Y"}
        REGISTER_Y = "/v1/code/sessions/cse_Y/bridge"
        WORKER_Y = "/v1/code/sessions/cse_Y/worker/events"

        srv2._note_bridge_traffic(REGISTER_Y, now=200.0)
        srv2._note_bridge_traffic(WORKER_Y, now=200.5)
        srv2._note_bridge_superseded("POST", WORKER_Y, b"HTTP/1.1 409 Conflict")
        assert srv2.deaf_bridges(now=201.0) == [], (
            "a 409 with no re-registration must not resurrect the id: "
            + repr(srv2.deaf_bridges(now=201.0)))
        assert "cse_Y" not in srv2._bridge_first_post, (
            "the 409 must clear the birth stamp along with the post, or a "
            "later unrelated post inherits a grace that is not its own")

        # NOW RE-REGISTER, and the fresh `/bridge` must earn a fresh grace
        # rather than staying judged from the stale, popped birth.
        srv2._note_bridge_traffic(REGISTER_Y, now=202.0)
        srv2._note_bridge_traffic(WORKER_Y, now=202.5)
        assert srv2.deaf_bridges(now=203.0) == [], (
            "a re-registration after a 409 was not graced: "
            + repr(srv2.deaf_bridges(now=203.0)))
        past_grace_y = 202.0 + pp._DEAF_STARTUP_GRACE_S + 1.0
        assert srv2.deaf_bridges(now=past_grace_y) == ["cse_Y"], (
            "the re-registration's own grace never expired: "
            + repr(srv2.deaf_bridges(now=past_grace_y)))

    def case_a_stream_that_reopens_within_the_dwell_is_never_marked_deaf(
            self, monkeypatch):
        """`daemon.log` line 300 on a mac: `1 of 3 bridge(s) post but hold no
        inbound stream ... (deaf 0s)`, followed 11 minutes later by a plain
        clear -- the sweep landed in the ordinary gap between a stream
        closing and Claude Code reopening it on the same connection
        (`trace.log`: two `GET .../stream` calls ~250 of the bridge's own
        posts apart). `deaf_for` answered a real, momentary age and the
        report named it at once; only the dwell this case pins stops that.

        A loss STILL there once the dwell has passed is reported exactly as
        before -- the dwell delays a verdict, it does not withhold one.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._stream_lost = {}

            FLICKER = "/v1/code/sessions/cse_FLICKER/worker/messages"
            FLICKER_STREAM = (
                "/v1/code/sessions/cse_FLICKER/worker/events/stream")
            conn = object()
            srv._note_bridge_traffic(FLICKER, now=1000.0)
            srv._note_bridge_traffic(FLICKER_STREAM, now=1000.5, conn=conn)
            srv._stream_conns.add(conn)
            srv._open_conns.add(conn)
            srv._forget_stream(conn)
            # EXPLICIT, as the create-grace case above does: the rest of
            # this case runs on the fake timeline above, not the real clock
            # `_forget_stream` just stamped.
            srv._stream_lost["cse_FLICKER"] = 2000.0
            srv._note_bridge_traffic(FLICKER, now=2002.0)
            srv._connected_bridges = {"cse_FLICKER"}

            # 2s INTO THE LOSS -- the ordinary close/reopen gap, measured at
            # age 0 on the mac. The report must claim nothing either way.
            monkeypatch.setattr(pp.time, "monotonic", lambda: 2002.0)
            srv._report_deaf_bridges()
            assert lines == [], (
                "a loss only 2s old was already named deaf: " + repr(lines))

            # THE STREAM REOPENS inside the gap the sweep must not have
            # marked -- the pair is healthy, with no false record behind it.
            conn2 = object()
            srv._note_bridge_traffic(FLICKER_STREAM, now=2003.0, conn=conn2)
            srv._stream_conns.add(conn2)
            srv._open_conns.add(conn2)
            assert srv.deaf_bridges(now=2004.0) == [], (
                "the reopened bridge was still carrying a false deaf record")

            # A SECOND BRIDGE, whose loss is STILL there once the dwell has
            # passed -- the check must still name it, same as before this
            # round.
            STILL = "/v1/code/sessions/cse_STILLGONE/worker/messages"
            STILL_STREAM = (
                "/v1/code/sessions/cse_STILLGONE/worker/events/stream")
            conn3 = object()
            srv._note_bridge_traffic(STILL, now=3000.0)
            srv._note_bridge_traffic(STILL_STREAM, now=3000.5, conn=conn3)
            srv._stream_conns.add(conn3)
            srv._open_conns.add(conn3)
            srv._forget_stream(conn3)
            srv._stream_lost["cse_STILLGONE"] = 3010.0
            srv._note_bridge_traffic(STILL, now=3012.0)
            srv._connected_bridges = {"cse_FLICKER", "cse_STILLGONE"}

            monkeypatch.setattr(pp.time, "monotonic", lambda: 3012.0)
            srv._report_deaf_bridges()
            assert lines == [], (
                "a loss only 2s old was named deaf on its own bridge too: "
                + repr(lines))

            monkeypatch.setattr(
                pp.time, "monotonic",
                lambda: 3010.0 + pp._DEAF_STARTUP_GRACE_S + 1.0)
            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], lines
            assert "cse_STILLGONE" in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log

    def case_the_owner_map_is_pruned_wherever_the_stream_set_is(self):
        """`_stream_owner` is keyed on the connection object, so it must be
        dropped wherever `_stream_conns` is.

        An earlier cut popped it in the 101-upgrade branch — a path a real
        event stream NEVER takes, because Remote Control's inbound arrives over
        a WebSocket to the ingress host and goes through `_blind_tunnel`, not
        `_handle_one_request`. Measured then: after a full teardown
        `_stream_conns` was empty and `_stream_owner` still held the entry, one
        socket object pinned per finished subscription for the life of the
        daemon. The whole suite stayed green, because nothing drives that
        teardown.

        STRUCTURAL, because behavioural coverage of `_serve_client`'s release
        needs a real client and this is the property that actually matters: the
        two are pruned TOGETHER. It also catches the next discard site added
        without a pop, which is how this happened in the first place.
        """
        import inspect
        import re

        import cswap_pin.proxy as pp

        src = inspect.getsource(pp)
        lines = src.splitlines()
        discards = [i for i, ln in enumerate(lines)
                    if re.search(r"_stream_conns\.discard\(", ln)]
        assert discards, "no discard site found — this guard is watching nothing"

        # ONE SITE NOW, AND IT IS THE HELPER. The three call sites each spelled
        # discard + pop, and the pairing was a rule a reader had to keep. They
        # are `_forget_stream` now, so the two cannot be separated by an edit
        # that forgets one -- a strictly stronger form of what this guarded.
        assert len(discards) == 1, (
            "more than one place drops a stream socket; they were unified into "
            f"`_forget_stream` so the pairing cannot rot: {[lines[i].strip() for i in discards]}")
        window = "\n".join(lines[max(0, discards[0] - 2):discards[0] + 12])
        assert "_stream_owner" in window and ".pop(" in window, (
            "the sole discard site no longer drops the owner map with it, so a "
            "socket object is pinned for the life of the daemon")

        # AND EVERY CALLER GOES THROUGH IT, or a new site could discard
        # directly and this count would still read 1.
        assert src.count("self._forget_stream(") >= 3, (
            "a stream-ending site stopped routing through the helper")

    def case_the_deaf_report_says_it_in_words_a_watcher_can_match(self):
        """The two log lines are an INTERFACE, not prose.

        The cswap session matches on them to raise a fleet alert, so a silent
        reword breaks a watcher on three machines and the failure is silence —
        the same failure the line exists to end. Pinned here so a change has to
        be deliberate and gets noticed in the same commit.

        Driven end to end with REAL request lines, split the way the caller
        splits them, because every layer of this feature has been
        correct-and-unreachable at some point: the regexes never matched, then
        nothing called the check, then the log had no reader.

        THE CONTROL IS THE THIRD ASSERTION. A reporter that logged "deaf" on
        every call would satisfy the first two; only "no new line when nothing
        changed" proves it reports TRANSITIONS, which is what keeps the file
        readable enough to be worth watching.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            def wire(request_line, conn=None):
                parts = request_line.split(" ")
                srv._note_bridge_traffic(
                    parts[1] if len(parts) > 1 else "/", conn=conn)
                # THE SERVER HOLDS WHAT THIS CASE POSTS. `deaf_bridges` only
                # judges bridges claude.ai is attached to, so a case that
                # posts without saying so is asserting about an empty scope.
                srv._connected_bridges = set(srv._bridge_posts)

            # NOTHING RECORDED YET: no claim either way. Logging the
            # all-clear here asserts health over an EMPTY population, which a
            # monitor reads as "the check ran and passed".
            srv._report_deaf_bridges()
            assert lines == [], (
                f"it certified health before any bridge had posted: {lines}")

            wire("POST /v1/code/sessions/cse_DEAF/worker/messages HTTP/1.1")
            srv._report_deaf_bridges()
            assert lines, (
                "a bridge that posts and holds no stream produced no line, so "
                "the fleet cannot self-report")
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]
            assert "1 of 1 bridge(s)" in lines[-1], (
                f"the deaf line carries no denominator: {lines[-1]!r}")
            assert "cse_DEAF" in lines[-1], (
                "the line names no bridge, so a reader cannot act on it")

            conn = object()
            wire("GET /v1/code/sessions/cse_DEAF/worker/events/stream HTTP/1.1",
                 conn=conn)
            srv._stream_conns.add(conn)
            srv._open_conns.add(conn)
            srv._report_deaf_bridges()
            assert lines[-1].startswith(pp.DEAF_REPORT_CLEAR), (
                f"the recovery line is not verbatim: {lines[-1]!r}")
            # A DENOMINATOR, or "0 of 0" and "0 of 13" print the same sentence.
            assert "(1 posting)" in lines[-1], lines[-1]

            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) == before, (
                "it logged again with nothing changed; a line per sweep buries "
                "the transition and trains a reader to skim the file")
        finally:
            pp._log_lifecycle = real_log

    def case_the_report_makes_no_claim_while_the_grace_hides_a_bridge(self,
                                                                       monkeypatch):
        """A shielded bridge must leave `_report_deaf_bridges` SILENT, not
        certified clear: the false CLEAR measured on the branch's own
        incident (six bridges posting inside 6s, none judged yet) read
        `every posting bridge holds an inbound stream (6 posting)` over six
        bridges nothing had judged, and the same shape on a successor
        downgrades the honest `DEAF_REPORT_BLIND` third answer to an
        all-clear.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            def wire(request_line, conn=None, now=None):
                parts = request_line.split(" ")
                srv._note_bridge_traffic(
                    parts[1] if len(parts) > 1 else "/", conn=conn, now=now)
                srv._connected_bridges = set(srv._bridge_posts)

            # A CREATE THIS DAEMON SERVED, then its bridge posts before its
            # stream GET has a chance to arrive -- inside the grace.
            srv._should_sweep_bridges("POST", "/v1/code/sessions", now=999.0)
            wire("POST /v1/code/sessions/cse_GRACE/worker/messages HTTP/1.1",
                 now=1000.0)
            monkeypatch.setattr(pp.time, "monotonic", lambda: 1005.0)
            srv._report_deaf_bridges()
            assert lines == [], (
                "the report claimed a verdict while the grace still hides "
                f"cse_GRACE, judged or not: {lines}")

            # PAST THE GRACE, still streamless: the next sweep judges it for
            # real and the measured MARK line appears.
            monkeypatch.setattr(
                pp.time, "monotonic",
                lambda: 1000.0 + pp._DEAF_STARTUP_GRACE_S + 1.0)
            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], lines
            assert "cse_GRACE" in lines[-1], lines[-1]

            # A SUCCESSOR-SHAPED BRIDGE on a FRESH instance, no create ever
            # served here (a handover, not this daemon's own bookkeeping),
            # posts with no stream: judged AT ONCE, no grace to hide behind.
            srv2 = pp.PinProxy.__new__(pp.PinProxy)
            srv2._reset_bridge_traffic()
            srv2._live_lock = threading.Lock()
            srv2._stream_conns = set()
            srv2._open_conns = set()
            srv2._note_bridge_traffic(
                "/v1/code/sessions/cse_SUCC/worker/messages", now=2000.0)
            srv2._connected_bridges = set(srv2._bridge_posts)
            monkeypatch.setattr(pp.time, "monotonic", lambda: 2001.0)
            srv2._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], lines
            assert "cse_SUCC" in lines[-1], (
                "a bridge this daemon never served a create for was "
                f"shielded as though it had just registered here: {lines[-1]!r}")
        finally:
            pp._log_lifecycle = real_log

    def case_the_union_makes_no_claim_while_the_grace_hides_a_bridge(
            self, certdir, monkeypatch):
        """The same silence as the cheap branch, on the UNION path: a
        predecessor confirming it holds every bridge the local, graced list
        named does not make a shielded one judged. The union can only ever
        REMOVE bridges, never add the one grace is hiding, so a `now` that
        reads empty here is exactly as unearned a CLEAR as the cheap
        branch's.
        """
        import os
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        real_pids = pp._pin_daemon_pids
        real_draining = pp.is_draining
        real_held = pp.draining_bridges
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._certdir = certdir

            # A: posted long before any create fired here -- judged locally,
            # not shielded, and its stream turns out to be held by a
            # predecessor this daemon cannot see.
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_A/worker/messages", now=100.0)
            # B: a create THIS daemon served, then B posts before its
            # stream GET has a chance to arrive -- shielded by the grace.
            srv._should_sweep_bridges("POST", "/v1/code/sessions", now=199.0)
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_B/worker/messages", now=200.0)
            srv._connected_bridges = {"cse_A", "cse_B"}

            pp._pin_daemon_pids = lambda _c: [os.getpid(), 4242]
            pp.is_draining = lambda _c, pid: pid == 4242
            pp.draining_bridges = lambda _c, pid: ({"cse_A"}, True)

            monkeypatch.setattr(pp.time, "monotonic", lambda: 205.0)
            srv._report_deaf_bridges()
            assert lines == [], (
                "the union read the predecessor holding cse_A as an "
                "all-clear while the grace still hides cse_B, judged or "
                f"not: {lines}")
        finally:
            pp._log_lifecycle = real_log
            pp._pin_daemon_pids = real_pids
            pp.is_draining = real_draining
            pp.draining_bridges = real_held

    def case_both_counts_come_from_ONE_snapshot(self):
        """A NUMERATOR LARGER THAN ITS DENOMINATOR, measured in the wild:
        `4 of 1 bridge(s) post but hold no inbound stream`.

        `posted` was sampled ABOVE the predecessor loop, which reads pid files
        and asks each draining daemon what it holds. That is real time, and on
        a handover posts keep arriving into `_bridge_posts` while it runs, so
        the two counts described the same set seconds apart. Both are taken
        after that work now.

        THE POST IS INJECTED THROUGH THE INSTANCE, never by rebinding a module
        global: `run_cases` walks 63 cases in ONE process, so a global patched
        here leaks into every case after it -- measured, seven of them failed
        on the first attempt at this test.
        """
        import threading
        lines = []
        from cswap_pin import proxy as pp
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            def wire(bid):
                srv._note_bridge_traffic(
                    f"/v1/code/sessions/{bid}/worker/messages")
                srv._connected_bridges = set(srv._bridge_posts)

            wire("cse_ONE")

            # A POST LANDS WHILE THE DEAF SET IS BEING BUILT -- the same
            # window the predecessor loop opens on a real handover.
            real_deaf = srv.deaf_bridges

            def deaf_then_a_late_post(*a, **k):
                out = real_deaf(*a, **k)
                wire("cse_TWO")
                return out
            srv.deaf_bridges = deaf_then_a_late_post

            srv._report_deaf_bridges()
            assert lines, "no deaf line at all"
            last = lines[-1]
            m = re.search(r"(\d+) of (\d+) bridge\(s\)", last)
            assert m, last
            num, den = int(m.group(1)), int(m.group(2))
            assert num <= den, (
                f"numerator above denominator: {last!r} -- the two counts came "
                f"from different snapshots")
        finally:
            pp._log_lifecycle = real_log

    def case_a_deaf_verdict_is_withdrawn_when_its_subject_is_gone(self):
        """A STANDING CLAIM OUTLIVES ITS SUBJECT OTHERWISE.

        Every reader takes the newest transition for the current state, so a
        daemon that says "N bridges are deaf" and then goes quiet leaves that
        verdict standing with nothing behind it. MEASURED: a person ran
        `claude daemon stop --any`, every worker went down, and the remote gate
        FAILed on a deaf line from before the stop -- an alarm for a state a
        person had chosen. The cause does not matter (stopped, slept, crashed,
        redeployed); what matters is that the population is gone.
        """
        import threading
        from cswap_pin import proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_DEAF/worker/messages")
            srv._connected_bridges = set(srv._bridge_posts)
            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], lines

            # every session goes away: nothing posts any more
            srv._reset_bridge_traffic()
            lines.clear()
            srv._report_deaf_bridges()
            assert lines, (
                "the deaf verdict was left standing with no subject -- a "
                "reader takes the newest transition for the current state")
            assert pp.DEAF_REPORT_CLEAR in lines[-1], lines[-1]

            # CONTROL: it withdraws ONCE, not on every quiet sweep
            lines.clear()
            srv._report_deaf_bridges()
            assert lines == [], (
                "it repeats the withdrawal every sweep, which buries the "
                "transition it exists to mark: %r" % lines)
        finally:
            pp._log_lifecycle = real_log

    def case_CONTROL_a_daemon_that_never_claimed_stays_silent(self):
        """Silence IS right for a fresh daemon. Withdrawing unconditionally
        would assert health over a population that never existed, which is the
        defect the early return was written for."""
        import threading
        from cswap_pin import proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._report_deaf_bridges()
            assert lines == [], (
                "it certified something before any bridge had posted: %r"
                % lines)
        finally:
            pp._log_lifecycle = real_log

    def case_deaf_means_the_server_holds_it_and_we_do_not(self, certdir):
        """POSTING WITHOUT A STREAM HAS TWO READINGS and only one is a fault.

        A background job posts worker events whether or not anybody is
        listening; claude.ai is not attached to it and no popup follows. A
        bridge the SERVER calls connected while no stream reaches it is the
        real thing this verdict is for.

        Measured on a mac: 8 of 8 bridges reported deaf were absent from the
        server's connected set while that set was non-empty -- the entire
        population was the harmless kind, and the host running more background
        jobs looked worse than the one running fewer for that reason alone.
        """
        import threading

        import cswap_pin.proxy as pp

        srv = pp.PinProxy.__new__(pp.PinProxy)
        srv._reset_bridge_traffic()
        srv._live_lock = threading.Lock()
        srv._stream_conns = set()
        srv._open_conns = set()

        def wire(path):
            srv._note_bridge_traffic(path)

        wire("/v1/code/sessions/cse_WATCHED/worker/messages")
        wire("/v1/code/sessions/cse_NOBODY/worker/messages")

        srv._connected_bridges = {"cse_WATCHED"}
        assert srv.deaf_bridges() == ["cse_WATCHED"], (
            "a bridge nobody is attached to was reported as a lost ear: "
            + repr(srv.deaf_bridges()))

        # CONTROL 1: the scope must not empty the verdict. With the server
        # holding both, both are deaf.
        srv._connected_bridges = {"cse_WATCHED", "cse_NOBODY"}
        assert srv.deaf_bridges() == ["cse_NOBODY", "cse_WATCHED"], (
            "the scope swallowed a real loss: " + repr(srv.deaf_bridges()))

        # CONTROL 2: UNKNOWN IS NOT "CONNECTED TO NOTHING". A failed listing
        # must not silently empty the verdict -- that would hide a real loss
        # for as long as the listing keeps failing, which is exactly when a
        # loss is most likely. So the scope simply does not apply, and the
        # reporter's own blind/predecessor machinery is what speaks.
        srv._connected_bridges = None
        assert srv.deaf_bridges() == ["cse_NOBODY", "cse_WATCHED"], (
            "an unknown connected set was read as an empty one, so a real "
            "loss would go unreported while the listing is failing: "
            + repr(srv.deaf_bridges()))

    def case_nothing_marks_a_session_for_repair_any_more(self, certdir):
        """The `_recycled` mark went with the repair it bounded.

        It existed so a session recycled into the same denial was not recycled
        forever, and it had to be CLEARED on recovery or a long-lived daemon
        spent its whole lifetime of repairs on first faults (measured: a daemon
        20 hours old had marked eleven sessions and could help none of them
        again). Both halves are moot now: the pin ends no session's worker, so
        there is no repair to bound and no mark to clear.

        Kept as a case rather than deleted, because the mark and the repair
        arrived together and would return together.
        """
        import cswap_pin.proxy as pp
        import pathlib as _p

        src = _p.Path(pp.__file__).read_text(encoding="utf-8")
        assert "_recycled" not in src, (
            "the recycle bookkeeping is back without its repair, or the repair "
            "is back with it")

    def case_the_denominator_is_the_population_the_verdict_judges(
            self, certdir):
        """TWO HALVES OF ONE RATIO MUST COUNT THE SAME THING.

        `deaf_bridges` filters by the window; the denominator was
        `len(_bridge_posts)`, which is every bridge this daemon has EVER seen
        and is never pruned. The two drift apart for the life of the process,
        so "8 of 47" was 8 deaf now against 47 seen since boot -- a ratio that
        shrinks on its own and reads as the fleet improving.

        Measured on a mac: 47 in the denominator while the daemon held nine
        upstream connections, which cannot serve 47 streams.
        """
        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lambda m: lines.append(m)
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = __import__("threading").Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            def wire(request_line, conn=None):
                parts = request_line.split(" ")
                srv._note_bridge_traffic(
                    parts[1] if len(parts) > 1 else "/", conn=conn)
                # THE SERVER HOLDS WHAT THIS CASE POSTS. `deaf_bridges` only
                # judges bridges claude.ai is attached to, so a case that
                # posts without saying so is asserting about an empty scope.
                srv._connected_bridges = set(srv._bridge_posts)

            # Two bridges long gone, one posting now.
            for old in ("cse_OLD1", "cse_OLD2"):
                wire(f"POST /v1/code/sessions/{old}/worker/messages HTTP/1.1")
            for old in ("cse_OLD1", "cse_OLD2"):
                srv._bridge_posts[old] -= pp._DEAF_WINDOW_S + 1
            wire("POST /v1/code/sessions/cse_NOW/worker/messages HTTP/1.1")

            srv._report_deaf_bridges()
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]
            assert "1 of 1 bridge(s)" in lines[-1], (
                "the denominator counted bridges the verdict never judged: "
                + lines[-1])
        finally:
            pp._log_lifecycle = real_log

    def case_a_bridge_that_went_quiet_is_not_reported_as_recovered(
            self, certdir):
        """THE THIRD STATE THE CLEAR LINE USED TO SWALLOW.

        `deaf_bridges` only judges bridges that posted inside its window, so a
        deaf one leaves the population by falling SILENT -- and the all-clear
        that follows is true of everything still posting and says nothing
        about it. Deafness is the one state CC cannot leave on its own, so a
        reader taking that as a recovery inverts the fact.

        Measured on a mac: one bridge deaf, clear ten minutes later, deaf
        again six hours after that. A gate downstream read the middle line as
        a recovery and reported the fleet quiet for the whole interval.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lambda m: lines.append(m)
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            def wire(request_line, conn=None):
                parts = request_line.split(" ")
                srv._note_bridge_traffic(
                    parts[1] if len(parts) > 1 else "/", conn=conn)
                # THE SERVER HOLDS WHAT THIS CASE POSTS. `deaf_bridges` only
                # judges bridges claude.ai is attached to, so a case that
                # posts without saying so is asserting about an empty scope.
                srv._connected_bridges = set(srv._bridge_posts)

            wire("POST /v1/code/sessions/cse_QUIET/worker/messages HTTP/1.1")
            srv._report_deaf_bridges()
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]

            # IT NEVER GOT A STREAM. It simply stopped posting, which is what
            # ages it out of the window -- no recovery happened.
            srv._bridge_posts["cse_QUIET"] -= pp._DEAF_WINDOW_S + 1
            srv._report_deaf_bridges()
            assert lines[-1].startswith(pp.DEAF_REPORT_CLEAR), lines[-1]
            assert "cse_QUIET" in lines[-1], (
                "the all-clear silently absorbed a bridge that was deaf when "
                "it was last seen: " + lines[-1])
            assert "stopped posting" in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log

    def case_CONTROL_a_bridge_that_really_recovered_is_a_plain_clear(
            self, certdir):
        """The control that keeps the fix from smearing a caveat over every
        recovery. A bridge that got its stream while still posting IS
        repaired, and the line must stay the verbatim all-clear a monitor
        matches on."""
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lambda m: lines.append(m)
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            def wire(request_line, conn=None):
                parts = request_line.split(" ")
                srv._note_bridge_traffic(
                    parts[1] if len(parts) > 1 else "/", conn=conn)
                # THE SERVER HOLDS WHAT THIS CASE POSTS. `deaf_bridges` only
                # judges bridges claude.ai is attached to, so a case that
                # posts without saying so is asserting about an empty scope.
                srv._connected_bridges = set(srv._bridge_posts)

            wire("POST /v1/code/sessions/cse_OK/worker/messages HTTP/1.1")
            srv._report_deaf_bridges()
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]

            conn = object()
            wire("GET /v1/code/sessions/cse_OK/worker/events/stream HTTP/1.1",
                 conn=conn)
            srv._stream_conns.add(conn)
            srv._open_conns.add(conn)
            srv._report_deaf_bridges()
            assert lines[-1] == f"{pp.DEAF_REPORT_CLEAR} (1 posting)", (
                "a real recovery grew a caveat it has not earned: "
                + lines[-1])
        finally:
            pp._log_lifecycle = real_log

    def _splice_probe(self, *, state):
        """Run the mint re-assert with `live_pin_identity_state` stubbed.

        NO `splice=` KNOB. A first cut had one and it was INERT — the code
        discards `splice_config_identity`'s return, so the knob reached
        nothing and only `state` drove the outcome. With cases at (F,F) and
        (T,T) a reverted implementation that logs on the BOOLEAN — the exact
        defect this change removes — passed both. The pair that separates
        them is a failed splice whose field is already correct, and it is
        `case_CONTROL_already_correct_stays_silent` below.

        EVERY GLOBAL RESTORED: a module-level patch that is not restored is a
        test that edits the NEXT test, measured here when a stub leaked into
        another file's cases.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        saved = {n: getattr(pp, n) for n in
                 ("_log_lifecycle", "splice_config_identity",
                  "live_pin_identity_state", "remembered_pin_identity")}
        pp._log_lifecycle = lines.append
        # False on purpose: the splice reporting failure must NOT decide the
        # verdict — only what the config holds afterwards may.
        pp.splice_config_identity = lambda *a, **k: False
        pp.live_pin_identity_state = lambda _i: state
        pp.remembered_pin_identity = lambda _c: {"accountUuid": "PIN"}
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._certdir = None
            srv._live_lock = threading.Lock()
            srv._reassert_pin_identity()
            return lines
        finally:
            for n, v in saved.items():
                setattr(pp, n, v)

    def case_a_skipped_splice_is_logged_at_the_moment_it_costs(self):
        """A SKIPPED WRITE IS INVISIBLE, AND THIS IS THE ONE PATH IT COSTS.

        `splice_config_identity` returns False for four states and one of them
        — lock not taken — is a skipped write its own comment says leaves the
        field drifted. Here the owner is stamped from that field on the
        request being forwarded, so a skipped write mints a bridge Claude Code
        can refuse to reattach.
        """
        lines = self._splice_probe(state=(False, "OTHER"))
        assert lines, "a skipped splice said nothing at all"
        last = lines[-1]
        import cswap_pin.proxy as pp
        assert pp.PIN_NOT_NAMED_AT_MINT in last, last
        assert "requirement 1" in last.lower(), last
        assert "OTHER" in last, (
            "the line does not say what the field holds, which is the whole "
            "reason it is worth logging: " + last)

    def case_CONTROL_already_correct_stays_silent(self):
        """THE PAIR THAT SEPARATES THIS FIX FROM THE BUG IT REPLACES.

        The splice reports False and the field is ALREADY the pin — the
        benign fourth state. An implementation that logged on the boolean
        would cry wolf here on a perfectly healthy mint; this one must be
        silent. Without this case the suite cannot tell the two apart.
        """
        assert self._splice_probe(state=(True, "PIN")) == []

    def case_CONTROL_an_unreadable_config_names_itself(self):
        """Unreadable is NOT live, and the log must say so rather than
        reporting a value it never read."""
        import cswap_pin.proxy as pp

        real = pp.require
        pp.require = lambda _n: (_ for _ in ()).throw(RuntimeError("no host"))
        try:
            live, holds = pp.live_pin_identity_state({"accountUuid": "PIN"})
            assert live is False and holds == "unreadable", (live, holds)
        finally:
            pp.require = real

    def case_CONTROL_the_log_never_carries_the_object_around_the_uuid(self):
        """This string ships to a log on other people's machines, and the
        object beside `accountUuid` carries an address."""
        import json
        import cswap_pin.proxy as pp

        real = pp.require
        cfg = pathlib.Path(tempfile.mkdtemp()) / "c.json"
        cfg.write_text(json.dumps(
            {"oauthAccount": {"email": "someone@example.com"}}))
        pp.require = lambda _n: types.SimpleNamespace(
            get_global_config_path=lambda: cfg)
        try:
            live, holds = pp.live_pin_identity_state({"accountUuid": "PIN"})
            assert live is False, holds
            assert "@" not in holds and "{" not in holds, holds
            assert holds == "no-uuid", holds
        finally:
            pp.require = real

    def _silent_deaf(self, connected):
        """One bridge, deaf, then aged out by falling silent. Returns the line.

        `connected` is what the daemon last learned claude.ai holds -- a set,
        or None for a listing that did not answer.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lambda m: lines.append(m)
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_QUIET/worker/messages", conn=None)
            srv._connected_bridges = {"cse_QUIET"}
            srv._report_deaf_bridges()
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]
            srv._bridge_posts["cse_QUIET"] -= pp._DEAF_WINDOW_S + 1
            srv._connected_bridges = connected
            srv._report_deaf_bridges()
            return lines[-1]
        finally:
            pp._log_lifecycle = real_log

    def case_a_silent_bridge_the_server_still_holds_is_named_as_such(self):
        """THE ONE A POPUP CAN ACTUALLY APPEAR IN.

        A bridge that went deaf and then quiet is unobservable for RECOVERY,
        but not for whether anybody is looking at it -- and only the ones
        somebody is looking at can show the disconnect popup. The daemon
        already holds that set; a reader downstream was fetching its own copy
        to answer the same question.
        """
        line = self._silent_deaf({"cse_QUIET"})
        assert "STILL ATTACHED" in line, line
        assert "cse_QUIET" in line, line

    def case_CONTROL_a_silent_bridge_nobody_holds_says_so(self):
        """The other side. A background job posts whether or not anybody is
        listening, so a silent bridge the server does not hold has no view
        and must not read as something waiting to be fixed."""
        line = self._silent_deaf(set())
        assert "attached to none of them" in line, line
        assert "STILL ATTACHED" not in line, line

    def case_CONTROL_an_unreadable_listing_is_not_an_all_clear(self):
        """UNKNOWN IS NOT ZERO -- the rule the verdict above already follows.
        Spending a listing that never answered as "nobody is attached" turns
        an outage of the listing into good news."""
        line = self._silent_deaf(None)
        assert "no listing was available" in line, line
        assert "attached to none of them" not in line, line
        assert "STILL ATTACHED" not in line, line

    def case_an_armed_trace_shows_responses_not_just_requests(self, certdir):
        """The file-armed trace could not show what the server ANSWERED.

        `_relay_response` writes its `<- HTTP/1.1 NNN` line to `_TRACE` only,
        and `_TRACE` is opened once at import from an env var — so it is off
        on a daemon that is already serving. The `trace-to` file switch, the
        only one reachable during an incident, never saw a single response.

        Measured while chasing a live stall: 25 requests captured, ZERO
        responses. I read that as "the server is not answering" for a moment
        before checking the instrument, which is the same shape as
        `bdf10c6` — that commit fixed this trace's other blind spot.

        No new plumbing: the `on_status` hook already carries the status back
        to a method that CAN reach the file target.
        """
        import inspect

        import cswap_pin.proxy as pp

        src = inspect.getsource(pp.PinProxy._forward)
        assert "on_status=" in src, "the status hook is gone"
        assert "_tunnel_trace" in src, (
            "the status never reaches the two-target trace, so an armed "
            "`trace-to` still shows requests and no responses")

    def case_the_token_is_fetched_once_per_request(self, certdir):
        """A PINNED route that also sweeps fetched the same token TWICE.

        Moving the sweep out of the bearer gate was right, but it carried its
        own `_pin_token_provider()` call with it while the `if pinned:` block
        kept its own. That provider re-reads the pin and the credential from
        disk on every call, takes a cross-process lock, and on expiry POSTs a
        refresh — so the doubling is not a spare dict lookup, it is real work
        in front of the client on the request path.

        Read from the SOURCE, because the alternative is standing up a full
        MITM request just to count one call, and this reads the same fact.
        """
        import inspect

        import cswap_pin.proxy as pp

        body = inspect.getsource(pp.PinProxy._handle_one_request_inner)
        # THE SHAPE, NOT A COUNT. A count of the call text caught my own
        # COMMENT and the legitimate retry — three "calls" of which one was
        # prose. The invariant is that the pinned block REUSES the sweep's
        # fetch instead of making its own; that is one line, and reverting it
        # is what brings the double fetch back.
        assert "token = _tok if _tok_fetched else self._pin_token_provider()" in body, (
            "the pinned block fetches its own token again instead of reusing "
            "the sweep's — a pinned route that also sweeps pays twice")
        assert "_tok_fetched" in body, (
            "no sentinel, so a falsy test would re-fetch whenever the "
            "provider legitimately answers None")

    def case_a_slow_request_is_timed_at_the_status_line(self, certdir):
        """NOT around the relay, because the relay can be an SSE stream.

        A response body here is held open for as long as the stream lives —
        one drained for 5735.9s on this fleet — so a timer that closes when
        `_forward` returns reports a perfectly healthy inbound channel as a
        multi-hour stall, every time one ends. Time to the first byte is the
        number that means the same thing for a JSON reply and a stream.

        Read from the SOURCE: the alternative is standing up a MITM
        connection and an SSE server to watch a timer not fire.
        """
        import inspect

        import cswap_pin.proxy as pp

        # THE CALL, NOT THE NAME. The first cut of this asserted the bare
        # name and failed on its own doc comment in the outer method — the
        # same way the sibling above caught its author's prose.
        call = "self._note_slow_request("
        fwd = inspect.getsource(pp.PinProxy._forward)
        assert call in fwd, (
            "the round trip is not timed where it ends — a stall is only "
            "visible at the status line, and a stream never reaches the end "
            "of the relay")
        outer = inspect.getsource(pp.PinProxy._handle_one_request_inner)
        assert call not in outer, (
            "timed around the relay instead: an SSE stream that lived for "
            "hours would be reported as a stall of that length")

    def case_nothing_deaf_locally_costs_no_process_spawn(self, certdir):
        """THE HOT PATH. `_report_deaf_bridges` runs on every bridge CREATE,
        and the union I added made it shell out to `ps -ww -axo` there —
        measured at ~30ms against 565 processes, inside the request handler.

        It is also unnecessary. The union can only ever REMOVE bridges from
        the deaf list: a predecessor holding a stream makes a bridge NOT deaf.
        So when the local answer is already empty there is nothing a
        predecessor could change, and the enumeration must not run at all.
        """
        import threading

        import cswap_pin.proxy as pp

        calls = []
        real_log = pp._log_lifecycle
        real_pids = pp._pin_daemon_pids
        pp._log_lifecycle = lambda *_a: None

        def counting(certdir_arg):
            calls.append(1)
            return real_pids(certdir_arg)

        pp._pin_daemon_pids = counting
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._certdir = certdir

            conn = object()
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_OK/worker/messages", conn=conn)
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_OK/worker/events/stream", conn=conn)
            srv._stream_conns.add(conn)
            srv._open_conns.add(conn)

            srv._report_deaf_bridges()
            assert calls == [], (
                "it enumerated daemons with `ps` although nothing was deaf "
                "locally — that runs on every bridge create, in the request "
                "handler")
        finally:
            pp._log_lifecycle = real_log
            pp._pin_daemon_pids = real_pids

    def case_a_draining_predecessor_hides_the_streams_from_this_one(
            self, certdir, monkeypatch):
        """A successor cannot answer this question, and must not guess at it.

        `deaf_bridges` reads `_stream_conns & _open_conns`, which is
        per-process in-memory state. A handover passes the LISTENING socket
        down, so posts arrive at the successor immediately, while every
        established inbound stream stays with the predecessor that accept()ed
        it. For the width of a drain this process therefore sees every bridge
        posting and none holding — and says so, about sessions that are fine.

        Measured: a daemon four minutes into a handover logged "12 of 12
        bridge(s) post but hold no inbound stream" while five daemons were
        alive holding 98 connections between them. The predecessor's own line
        named nine long-lived channels left intact and /proc showed it holding
        exactly nine. Nothing was deaf; the reporter was blind.

        Watchers on three machines match these lines to raise a fleet alert,
        so a confident wrong one is worse than no line at all.

        SUPPRESSING THE REPORT WHILE ANY PREDECESSOR DRAINS IS NOT THE FIX,
        and this case pins that too. A predecessor is almost never absent
        here: two were still serving at 93 and 134 minutes old, because they
        stay until their channels close and a session can outlive a day of
        recycles. That rule would silence the check permanently — the same
        silent-absence failure as certifying health over an empty
        denominator, only quieter. So a predecessor that CAN say what it
        holds is asked, and only one that predates the record is refused.
        """
        import os
        import threading

        import cswap_pin.proxy as pp

        real_mono = time.monotonic
        skew = [0.0]
        monkeypatch.setattr(pp.time, "monotonic",
                            lambda: real_mono() + skew[0])
        lines = []
        real_log = pp._log_lifecycle
        real_pids = pp._pin_daemon_pids
        real_draining = pp.is_draining
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._certdir = certdir
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_LIVE/worker/messages")
            srv._connected_bridges = {"cse_LIVE"}

            # A PREDECESSOR IS STILL DRAINING, so the stream for cse_LIVE may
            # be held by it. This process cannot see it either way.
            pp._pin_daemon_pids = lambda _c: [os.getpid(), 4242]
            pp.is_draining = lambda _c, pid: pid == 4242
            srv._report_deaf_bridges()
            assert lines, (
                "it went silent; a reader cannot tell a suppressed report "
                "from a check that never ran")
            assert pp.DEAF_REPORT_MARK not in lines[-1], (
                "it called a bridge deaf while a predecessor was holding the "
                f"streams it cannot see: {lines[-1]!r}")
            assert pp.DEAF_REPORT_BLIND in lines[-1], (
                f"the refusal is not verbatim, so no watcher can match it: "
                f"{lines[-1]!r}")
            assert "4242" in lines[-1], (
                "it does not name the predecessor, so a reader cannot check "
                f"whether it is still there: {lines[-1]!r}")

            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) == before, (
                "it repeated the refusal with nothing changed; transitions "
                "only, or the file stops being worth watching")

            # AND NOW IT CAN BE ASKED. The predecessor publishes the bridge
            # it is holding, so the union answers and the session is NOT
            # deaf. This is the steady state — the refusal above lasts only
            # until the last pre-record daemon leaves.
            pp.draining_marker_path(certdir, 4242).write_text(
                f"{time.time()}\n0\n0\n0.0\n1\ncse_LIVE")
            srv._report_deaf_bridges()
            assert pp.DEAF_REPORT_MARK not in lines[-1], (
                "a bridge whose stream a predecessor is holding was called "
                f"deaf; the union did not reach it: {lines[-1]!r}")
            assert lines[-1].startswith(pp.DEAF_REPORT_CLEAR), (
                f"the union produced no all-clear: {lines[-1]!r}")

            # THE CONTROL. The same state with no predecessor MUST still
            # report — a gate that suppressed everything would pass every
            # assertion above and silence the check this feature exists for.
            # PAST THE GRACE (T1592): the predecessor has just left, and a
            # bridge it held is shielded for `_DEAF_STARTUP_GRACE_S` from the
            # report that saw it go (see the next case).
            pp._pin_daemon_pids = lambda _c: [os.getpid()]
            pp.draining_marker_path(certdir, 4242).unlink()
            srv._report_deaf_bridges()
            skew[0] += pp._DEAF_STARTUP_GRACE_S + 1
            srv._report_deaf_bridges()
            assert pp.DEAF_REPORT_MARK in lines[-1], (
                "with no predecessor to hide the stream the bridge really is "
                f"deaf, and the report stayed quiet: {lines[-1]!r}")
            # THE SAME PROCESS REOPENING ITS STREAM CLEARS IT TOO (T1586), so
            # the line must not claim that only a new process does.
            assert "only a NEW PROCESS" not in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log
            pp._pin_daemon_pids = real_pids
            pp.is_draining = real_draining

    def case_a_predecessor_that_has_just_exited_does_not_leave_its_bridge_deaf(
            self, certdir, monkeypatch):
        """T1592 (T1587, via-work-mac 2026-09-29 03:51:31Z): a bridge whose
        stream a draining predecessor held drops out of `elsewhere` the moment
        that predecessor exits (its marker is deleted before "drained clean"
        is logged). A sweep landing in the few seconds before Claude Code
        reopens the stream on THIS process then called it deaf, and the mark
        stood for a whole sweep cooldown (600 s), though the stream was back
        seconds later. `_too_young` shielded only a loss this process
        measured or a first post inside the grace; this process never saw
        that stream, so neither applied.

        (a) the predecessor exits and a report inside the grace does not mark
        the bridge, and does not clear it either (nothing was judged).
        (b) a report after the grace with still no stream marks it: the
        shield is a dwell, not an amnesty (1f8bcbe, e489cba)."""
        import os
        import threading

        import cswap_pin.proxy as pp

        real_mono = time.monotonic
        skew = [0.0]
        monkeypatch.setattr(pp.time, "monotonic",
                            lambda: real_mono() + skew[0])
        lines = []
        monkeypatch.setattr(pp, "_log_lifecycle", lines.append)
        pids = [os.getpid(), 4242]
        monkeypatch.setattr(pp, "_pin_daemon_pids", lambda _c: list(pids))
        monkeypatch.setattr(pp, "is_draining", lambda _c, pid: pid == 4242)
        monkeypatch.setattr(pp, "draining_bridges",
                            lambda _c, _pid: ({"cse_HELD"}, True))
        srv = pp.PinProxy.__new__(pp.PinProxy)
        srv._reset_bridge_traffic()
        srv._live_lock = threading.Lock()
        srv._stream_conns = set()
        srv._open_conns = set()
        srv._certdir = certdir
        srv._note_bridge_traffic("/v1/code/sessions/cse_HELD/worker/messages")
        srv._connected_bridges = {"cse_HELD"}

        srv._report_deaf_bridges()
        assert lines[-1].startswith(pp.DEAF_REPORT_CLEAR), (
            f"the draining predecessor's stream was not counted: {lines!r}")

        # THE PREDECESSOR EXITS: its marker is gone, its bridges leave.
        pids.remove(4242)
        skew[0] += 5.0
        before = list(lines)
        srv._report_deaf_bridges()
        assert lines == before, (
            "a report seconds after the predecessor left judged a bridge "
            f"whose stream has not had time to reopen: {lines[len(before):]!r}")

        skew[0] += pp._DEAF_STARTUP_GRACE_S
        srv._report_deaf_bridges()
        assert pp.DEAF_REPORT_MARK in lines[-1] and "cse_HELD" in lines[-1], (
            "still no stream after the grace, and the report stayed quiet: "
            f"{lines[-1]!r}")

    def case_a_draining_process_must_not_claim_a_deaf_bridge_is_fresh(
            self, certdir):
        """The predecessor in the incident stood down at 01:18:28Z and still
        logged `9 of 9 bridge(s) post but hold no inbound stream` at
        01:42:33Z, `only a NEW PROCESS clears it`, while a successor already
        held those very streams — 66 and 39 established connections against
        its own 2 and 1. `_report_deaf_bridges` asks OTHER draining pids what
        they hold (the case above), but never asks whether IT is the one
        draining, so a bridge whose stream migrated away from it reads
        exactly like one that lost its stream for good.

        `this_process_is_draining()`, not `is_draining(certdir, pid)`: the
        marker lags the first beat, which is the whole width of this window.
        """
        import os
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        real_pids = pp._pin_daemon_pids
        pp._log_lifecycle = lines.append
        pp._pin_daemon_pids = lambda _c: [os.getpid()]
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._certdir = certdir
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_MIGRATED/worker/messages")
            srv._connected_bridges = {"cse_MIGRATED"}

            done = pp.announce_draining(certdir, os.getpid())
            # THE DISCRIMINATING CASE. The marker file is gone, so a
            # regression to `is_draining(certdir, os.getpid())` would read
            # this process as NOT draining and MARK cse_MIGRATED instead —
            # `this_process_is_draining()` must still answer True from the
            # in-memory depth map alone.
            pp.draining_marker_path(certdir, os.getpid()).unlink()
            try:
                srv._report_deaf_bridges()
            finally:
                done()
            assert lines, (
                "it went silent while draining; a reader cannot tell a "
                "suppressed report from a check that never ran")
            assert pp.DEAF_REPORT_MARK not in lines[-1], (
                "a draining process claimed a bridge is deaf although its "
                f"own view cannot see where the stream went: {lines[-1]!r}")
            assert "only a NEW PROCESS" not in lines[-1], (
                "it promised a remedy that already happened — the successor "
                f"holding the stream IS the new process: {lines[-1]!r}")
            assert pp.DEAF_REPORT_BLIND in lines[-1], (
                f"the refusal is not verbatim, so no watcher can match it: "
                f"{lines[-1]!r}")
            assert "cse_MIGRATED" in lines[-1], (
                "it does not name the bridge, so a reader cannot check "
                f"whether it is really gone: {lines[-1]!r}")

            # THE CONTROL. The same bridge, the same daemon, NOT draining —
            # the report must still name it deaf, or the fix silenced the
            # alarm instead of correcting its wording.
            before = len(lines)
            srv._last_deaf = None
            srv._report_deaf_bridges()
            assert len(lines) > before, (
                "a non-draining process with the same deaf bridge produced "
                "no line")
            assert pp.DEAF_REPORT_MARK in lines[-1], (
                "a genuinely deaf bridge, reported by a process that is not "
                f"draining, must still get the ordinary MARK: {lines[-1]!r}")
        finally:
            pp._log_lifecycle = real_log
            pp._pin_daemon_pids = real_pids

    def case_a_drain_that_aborts_does_not_silence_the_bridge_forever(
            self, certdir):
        """The reviewer's trace: the watchdog handover announces the drain,
        `_spawn_daemon` times out waiting for a successor, `done_draining()`
        fires, and this process keeps serving as the live pid. The deaf set
        never changed, so `now == prev` alone would dedupe the MARK away —
        for the rest of this process's life, once a BLIND for it was ever
        latched into `_last_deaf` while draining. Every consumer of the MARK
        line would go permanently quiet on a bridge that is genuinely deaf.

        `_with_deaf_age` is the same field that separated the incident's own
        migration burst from a real loss (`deaf 156s-162s` on nine ids was
        nine SSE legs closing in ~6s, not nine losses) — it belongs on the
        BLIND line exactly as much as on the MARK it replaces.
        """
        import os
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        real_pids = pp._pin_daemon_pids
        pp._log_lifecycle = lines.append
        pp._pin_daemon_pids = lambda _c: [os.getpid()]
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._stream_lost = {}
            srv._certdir = certdir
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_ABORT/worker/messages")
            srv._connected_bridges = {"cse_ABORT"}
            # A REAL, MEASURED AGE: this process itself once held the stream
            # and lost it, so `deaf_for` answers a number, never None.
            # -42.4, NOT -42: `int(age)` truncates in `_with_deaf_age`, and
            # the I/O between this stamp and the read (announce_draining's
            # own `_collect_dead_markers` scan) only adds time, never
            # removes it. The 0.6s of headroom below the 43s rounding
            # boundary is what a loaded runner needs to still read 42.
            srv._stream_lost["cse_ABORT"] = time.monotonic() - 42.4

            # THE DRAIN STARTS, and while it runs this bridge looks deaf.
            done = pp.announce_draining(certdir, os.getpid())
            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_BLIND in lines[-1], (
                f"a genuinely-aged loss while draining was not BLIND: {lines}")
            assert "(deaf 42s)" in lines[-1], (
                "the BLIND line drops the one field that tells a migration "
                f"burst from a real loss: {lines[-1]!r}")

            # THE DRAIN ABORTS (the successor never came up) and this
            # process keeps serving — `announce_draining`'s own release.
            done()

            # THE SAME DEAF SET, one sweep later: the dedupe must not let
            # the stale draining-BLIND stand forever now that this process
            # is no longer draining.
            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) > before, (
                "the aborted drain's BLIND latched permanently — no MARK "
                "ever followed for a bridge that is genuinely still deaf")
            assert pp.DEAF_REPORT_MARK in lines[-1], (
                "a drain that aborted and left this process serving must "
                f"MARK an unchanged deaf set: {lines[-1]!r}")

            # THE CONTROL. Once the MARK itself stands with nothing changed,
            # the ordinary dedupe still applies — this fix must not turn
            # every sweep into a fresh log line.
            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) == before, (
                "an ordinary unchanged MARK was re-logged; the fix for the "
                "stale-BLIND case must not defeat the dedupe generally")
        finally:
            pp._log_lifecycle = real_log
            pp._pin_daemon_pids = real_pids

    def case_a_deaf_verdict_inside_a_refusal_window_is_blind_not_a_mark(
            self, monkeypatch):
        """A bridge's post is stamped the moment the request LINE arrives,
        before the pin dials upstream. During an egress refusal the pin
        answers 503 without ever posting to claude.ai, so a post stamped
        inside that window may never have reached the server at all -- a
        DEAF verdict taken from it is unproven and must read BLIND, not
        the ordinary MARK.

        Measured on an egress outage: `_report_deaf_bridges` fired MARK
        four times across a 76-minute refusal on the same pin process and
        cleared the moment the chain returned, with no restart in between
        -- the bridges were never deaf, their posts just never landed.

        Once the refusal window passes and the deaf set is unchanged, the
        MARK must return -- the BLIND must not dedupe-silence it forever,
        same shape as the draining-BLIND case above.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._egress_refused = False
            srv._egress_refused_last = None

            monkeypatch.setattr(pp.time, "monotonic", lambda: 1000.0)
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_MAYBE/worker/messages")
            srv._connected_bridges = {"cse_MAYBE"}
            srv._note_egress_refused()

            # (a) INSIDE THE WINDOW: BLIND, not MARK.
            monkeypatch.setattr(pp.time, "monotonic", lambda: 1010.0)
            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_BLIND in lines[-1], (
                "a deaf verdict inside a refusal window was not BLIND: "
                + repr(lines))
            assert pp.DEAF_REPORT_MARK not in lines[-1], lines[-1]
            assert "cse_MAYBE" in lines[-1], lines[-1]

            # (b) PAST THE WINDOW, the bridge still posting (egress healthy
            # again) and still no stream: the MARK must return, not stay
            # dedupe-silenced by the BLIND above.
            past_window = 1010.0 + pp._DEAF_WINDOW_S + 1.0
            monkeypatch.setattr(pp.time, "monotonic", lambda: past_window)
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_MAYBE/worker/messages")
            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) > before, (
                "the refusal-BLIND latched permanently -- no MARK ever "
                "followed for a bridge that is genuinely still deaf")
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]

            # THE ORDINARY DEDUPE STILL APPLIES once the MARK itself stands.
            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) == before, (
                "an unchanged MARK was re-logged; the refusal-window fix "
                "must not defeat the dedupe generally")
        finally:
            pp._log_lifecycle = real_log

    def case_CONTROL_no_refusal_ever_marks_exactly_as_before(self):
        """No refusal recorded at all: the same deaf set must MARK exactly
        as before this change -- the control that proves the refusal check
        does not swallow every verdict."""
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_PLAIN/worker/messages")
            srv._connected_bridges = {"cse_PLAIN"}
            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], (
                "with no refusal ever recorded, an ordinary deaf bridge "
                f"must still MARK: {lines!r}")
        finally:
            pp._log_lifecycle = real_log

    def case_a_young_process_names_its_own_blind_spot_not_a_mark(
            self, monkeypatch):
        """Measured: a successor 4s old inherited a bridge from a
        predecessor that had just closed every connection. The bridge's
        first request on the NEW process is the worker POST that stamps
        `_bridge_posts`; the stream GET that would prove it healthy is the
        NEXT request on the same connection and had not arrived yet when
        this sweep ran. Its upstream hop was accepting CONNECT and relaying
        a 502 INSIDE the tunnel, so `_egress_refused_last_monotonic` was
        never stamped either and `blind_refused` could not fire.

        DEAF_REPORT_MARK stood for this bridge for the whole
        `_BRIDGE_SWEEP_COOLDOWN_S`, and a downstream gate reads MARK as
        FAIL. A process this young never watched the bridge through a
        whole `_DEAF_WINDOW_S` and must say so instead of asserting a
        verdict it has no basis for.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            monkeypatch.setattr(pp.time, "monotonic", lambda: 1000.0)
            srv._started_monotonic = 996.0  # 4s old
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_INHERITED/worker/messages")
            srv._connected_bridges = {"cse_INHERITED"}

            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_BLIND in lines[-1], (
                "a process 4s old marked a bridge it never watched deaf, "
                f"instead of admitting it cannot say: {lines!r}")
            assert pp.DEAF_REPORT_MARK not in lines[-1], lines[-1]
            assert "cse_INHERITED" in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log

    def case_CONTROL_an_old_process_still_marks_the_same_bridge(
            self, monkeypatch):
        """The same bridge, the same shape, on a process old enough to have
        watched the whole window: a true verdict must not be suppressed --
        the control that proves `young` does not swallow every MARK."""
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            monkeypatch.setattr(pp.time, "monotonic", lambda: 1000.0)
            srv._started_monotonic = 1000.0 - pp._DEAF_WINDOW_S - 1.0
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_OLDPROC/worker/messages")
            srv._connected_bridges = {"cse_OLDPROC"}

            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], (
                "a process older than the window it judges suppressed a "
                f"true MARK: {lines!r}")
            assert pp.DEAF_REPORT_BLIND not in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log

    def case_a_bridge_born_in_a_young_process_still_marks(self, monkeypatch):
        """T1327 #4: `young` exists for a bridge this process only INHERITED
        and never watched hold a stream -- `cse_INHERITED` above. A bridge
        BORN here (`_bridge_first_post` holds it) is not that case: this
        process watched its whole life, so a deaf verdict for it is real and
        must MARK even though the process itself is still young."""
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            monkeypatch.setattr(pp.time, "monotonic", lambda: 1000.0)
            srv._started_monotonic = 960.0  # 40s old: still young (<300s)
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_BORN/worker/messages")
            # BORN HERE, not inherited: its first post predates the grace
            # window (40s ago, past `_DEAF_STARTUP_GRACE_S` of 30s) but is
            # still within this young process's own life.
            srv._bridge_first_post["cse_BORN"] = 960.0
            srv._connected_bridges = {"cse_BORN"}

            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], (
                "a bridge born in this process, never streamed, was named "
                f"BLIND instead of a real MARK: {lines!r}")
            assert pp.DEAF_REPORT_BLIND not in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log

    def case_a_young_blind_ages_into_a_mark_with_the_same_deaf_set(
            self, monkeypatch):
        """The latch, same shape as the draining- and refusal-BLIND cases
        above: a young sweep's BLIND must not stand forever once this
        process has aged past the window with the IDENTICAL deaf set --
        `now == prev` alone would otherwise dedupe the MARK away for the
        rest of this process's life."""
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            monkeypatch.setattr(pp.time, "monotonic", lambda: 1000.0)
            srv._started_monotonic = 996.0  # 4s old
            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_LATCH/worker/messages")
            srv._connected_bridges = {"cse_LATCH"}

            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_BLIND in lines[-1], (
                f"the young sweep was not BLIND: {lines!r}")

            # PAST THE WINDOW this process is judging (996 + 300), the SAME
            # post still inside ITS OWN window (1000 + 300): the MARK must
            # return, not stay dedupe-silenced by the young-BLIND above.
            past_window = 1298.0
            monkeypatch.setattr(pp.time, "monotonic", lambda: past_window)
            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) > before, (
                "the young-BLIND latched permanently -- no MARK ever "
                "followed for a bridge that is genuinely still deaf")
            assert pp.DEAF_REPORT_MARK in lines[-1], lines[-1]

            # THE ORDINARY DEDUPE STILL APPLIES once the MARK itself stands.
            before = len(lines)
            srv._report_deaf_bridges()
            assert len(lines) == before, (
                "an unchanged MARK was re-logged; the young-window fix "
                "must not defeat the dedupe generally")
        finally:
            pp._log_lifecycle = real_log

    def case_a_relayed_5xx_blinds_an_old_process_too(self, monkeypatch):
        """I1: `_egress_refused_last_monotonic` is stamped only for a DIAL
        the hop itself refused. A hop that accepts CONNECT and relays the
        pin's own upstream's 5xx INSIDE the tunnel never stamps it, so an
        OLD process (unlike the young-process case above, this one has no
        `_started_monotonic` at all) still MARKed a bridge whose post may
        never have reached the server. `_note_hop_trouble` already records
        this on the module global `_hop_trouble_at`; `_report_deaf_bridges`
        must read it too.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        real_hop_trouble_at = pp._hop_trouble_at
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            # No `_started_monotonic`: an old process, same as every
            # instance built via `__new__` before that attribute existed --
            # the `young` latch must not be why this fires.

            monkeypatch.setattr(pp.time, "time", lambda: 2000.0)
            pp._hop_trouble_at = 2000.0 - 10.0  # the upstream's 5xx, 10s ago

            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_RELAYED/worker/messages")
            srv._connected_bridges = {"cse_RELAYED"}

            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_BLIND in lines[-1], (
                "a relayed 5xx inside the tunnel did not blind an old "
                f"process's verdict: {lines!r}")
            assert pp.DEAF_REPORT_MARK not in lines[-1], lines[-1]
            assert "cse_RELAYED" in lines[-1], lines[-1]
            assert "10s ago" in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log
            pp._hop_trouble_at = real_hop_trouble_at

    def case_CONTROL_a_stale_hop_trouble_stamp_still_marks(self, monkeypatch):
        """The control: a 5xx from long before the window must not blind a
        verdict it has nothing to do with."""
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        real_hop_trouble_at = pp._hop_trouble_at
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._reset_bridge_traffic()
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()

            monkeypatch.setattr(pp.time, "time", lambda: 2000.0)
            pp._hop_trouble_at = 2000.0 - pp._DEAF_WINDOW_S - 1.0

            srv._note_bridge_traffic(
                "/v1/code/sessions/cse_STALEHOP/worker/messages")
            srv._connected_bridges = {"cse_STALEHOP"}

            srv._report_deaf_bridges()
            assert lines and pp.DEAF_REPORT_MARK in lines[-1], (
                "a hop-trouble stamp older than the window suppressed a "
                f"true MARK: {lines!r}")
            assert pp.DEAF_REPORT_BLIND not in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log
            pp._hop_trouble_at = real_hop_trouble_at

    def case_the_production_wiring_stamps_started_monotonic(self, certdir):
        """m2: nothing exercised `PinProxy.__init__` itself for this stamp --
        every deaf-report case above builds one through `__new__`, which
        skips `__init__` entirely and would stay green even if the real
        constructor stopped setting it."""
        from cswap_pin.proxy import PinProxy

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        assert isinstance(proxy._started_monotonic, float), (
            "a PinProxy built through __init__ must carry its own start "
            "clock")

    def case_an_attachment_fetch_says_whether_it_worked(self, certdir):
        """Nothing recorded whether a claude.ai attachment ever downloaded.

        `/api/oauth/files/` is a pinned route because the file belongs to the
        pinned account, and Claude Code renders any non-200 as "could not be
        downloaded" — a message the user sees and no machine records. So the
        requirement "read claude.ai image attachments from the CLI" had no
        instrument at all: not a check that passed, a question nobody could
        ask. That is the same gap the deaf report had, and it shipped for the
        same reason — the swap was verified in code and never in traffic.

        ON CHANGE, like every other report in this file. An attachment fetch
        per keystroke would bury the one that failed.

        THE FAILURE IS THE POINT, so it carries the status. "It did not work"
        is not actionable; 403 says the swap was refused and 404 says the file
        is not the pinned account's, which are different bugs.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._live_lock = threading.Lock()
            P = "/api/oauth/files/8f14e45f-ea/content"

            srv._note_attachment(P, b"HTTP/1.1 200 OK")
            assert lines, (
                "a successful attachment fetch left no record, so the one "
                "requirement it serves cannot be certified from any machine")
            assert pp.ATTACH_REPORT_OK in lines[-1], lines[-1]

            before = len(lines)
            srv._note_attachment(P, b"HTTP/1.1 200 OK")
            assert len(lines) == before, (
                "it logged again with nothing changed; one line per fetch "
                "buries the one that failed")

            srv._note_attachment(P, b"HTTP/1.1 403 Forbidden")
            assert pp.ATTACH_REPORT_FAIL in lines[-1], lines[-1]
            assert "403" in lines[-1], (
                "the failure does not carry its status, so a reader cannot "
                f"tell a refused swap from a missing file: {lines[-1]!r}")

            # AND BACK, or a machine that recovers keeps reading as broken.
            srv._note_attachment(P, b"HTTP/1.1 200 OK")
            assert pp.ATTACH_REPORT_OK in lines[-1], lines[-1]

            # A ROUTE THAT IS NOT AN ATTACHMENT SAYS NOTHING. Without this the
            # notifier would report on every response it was ever handed.
            before = len(lines)
            srv._note_attachment("/v1/messages", b"HTTP/1.1 200 OK")
            assert len(lines) == before, (
                f"it reported about a non-attachment route: {lines[-1]!r}")

            # AND SOMETHING MUST ASK. `deaf_bridges` was correct and unreached
            # for three releases; this is the same shape one file over.
            import inspect
            wired = inspect.getsource(pp.PinProxy._forward)
            assert "_note_attachment" in wired, (
                "nothing calls the attachment notifier, so it can only ever "
                "prove that the maths is right")
            relay = inspect.getsource(pp._relay_response)
            assert "on_status" in relay, (
                "`_relay_response` does not hand the status back, so the "
                "caller that knows the path can never learn the outcome")
        finally:
            pp._log_lifecycle = real_log

    def case_a_refused_rename_leaves_a_record(self, certdir):
        """`updateSessionTitle` PUTs the title and swallows the answer.

        The CLI's own call carries `validateStatus: (d) => d < 500`, so a 4xx
        raises nothing and leaves one debug line. The roster keeps showing the
        new name, so the only party who learns the rename did not land is the
        PEER reading the old label off a cross-session message — and by then a
        reply has already gone to the wrong session.

        The proxy is the only place that sees both the route and the status, so
        it is the only place the failure can stop being silent. Same shape as
        the attachment notifier one class up: on CHANGE, carrying the code,
        never raising.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._live_lock = threading.Lock()
            P = "/v1/code/sessions/cse_01AAAAAAAAAAAAAAAAAAAAAA"

            srv._note_rename("PUT", P, b"HTTP/1.1 403 Forbidden")
            assert lines, (
                "a refused rename left no record anywhere, which is the whole "
                "defect: the CLI swallows it and the roster still shows the "
                "new name")
            assert pp.RENAME_REPORT_FAIL in lines[-1], lines[-1]
            assert "403" in lines[-1], (
                "the failure does not carry its status, so a reader cannot "
                f"tell a refused owner from a vanished bridge: {lines[-1]!r}")

            before = len(lines)
            srv._note_rename("PUT", P, b"HTTP/1.1 403 Forbidden")
            assert len(lines) == before, (
                "it logged again with nothing changed; the CLI retries the "
                "title on reconnect, so one line per PUT buries the change")

            # AND BACK, or a session that recovers keeps reading as broken.
            srv._note_rename("PUT", P, b"HTTP/1.1 200 OK")
            assert pp.RENAME_REPORT_OK in lines[-1], lines[-1]

            # A GET ON THE SAME PATH SAYS NOTHING. The route is shared, so
            # keying on the path alone would report every failed poll as a
            # failed rename.
            before = len(lines)
            srv._note_rename("GET", P, b"HTTP/1.1 404 Not Found")
            assert len(lines) == before, (
                f"it reported a GET on the sessions route: {lines[-1]!r}")

            # AND THE COLLECTION ROUTE IS NOT A RENAME EITHER -- `POST
            # /v1/code/sessions` mints a bridge and its 4xx is a different bug.
            before = len(lines)
            srv._note_rename("PUT", "/v1/code/sessions", b"HTTP/1.1 400 Bad")
            assert len(lines) == before, (
                f"it reported about the collection route: {lines[-1]!r}")

            # NOR A SUB-RESOURCE. The prefix test alone passes this, so without
            # it a PUT under the bridge id reports as a failed rename.
            before = len(lines)
            srv._note_rename("PUT", P + "/worker/events", b"HTTP/1.1 404 No")
            assert len(lines) == before, (
                f"it reported a PUT under the bridge id: {lines[-1]!r}")

            # AND A QUERY STRING IS NOT A SEGMENT. Stripping it is what keeps
            # the rename itself from being filtered out as a sub-resource.
            srv._note_rename("PUT", P + "?x=1/2", b"HTTP/1.1 500 Err")
            assert pp.RENAME_REPORT_FAIL in lines[-1], lines[-1]

            # AND SOMETHING MUST ASK.
            import inspect
            wired = inspect.getsource(pp.PinProxy._forward)
            assert "_note_rename" in wired, (
                "nothing calls the rename notifier, so a refused rename stays "
                "exactly as silent as it was")
        finally:
            pp._log_lifecycle = real_log

    def case_a_409_on_a_worker_post_clears_the_bridge_from_deaf_state(
            self, certdir):
        """A bridge the server superseded is not the same as one gone deaf.

        Measured on a linux host after the 0.1.240 rollout (`daemon.log` +
        `trace.log` of one generation): four of six ids named in DEAF lines
        had ended with `<- HTTP/1.1 409 Conflict  POST
        .../worker/events/delivery` and `... 409 Conflict  POST
        .../worker/events`, then nothing more. They stayed in
        `_bridge_posts` for the full `_DEAF_WINDOW_S` and were reported at
        ages 54-244s, with a line whose claims ("messages reach the
        server", "only a NEW PROCESS clears it") are false for a bridge the
        server already refused every message from.
        `sweep_superseded_bridges` clears the same id eventually, but a full
        listing poll later than the 409 that already told us. The relay
        sees the worker POST's path and its response status at the same
        site (`_forward`'s `on_status`), so that is where this clears it.
        """
        import threading

        import cswap_pin.proxy as pp

        def _srv():
            s = pp.PinProxy.__new__(pp.PinProxy)
            s._live_lock = threading.Lock()
            s._stream_conns = set()
            s._open_conns = set()
            s._reset_bridge_traffic()
            s._stream_lost = {}
            return s

        WORKER = "/v1/code/sessions/cse_SUPERSEDED/worker/events/delivery"
        # A BRIDGE-ID-BEARING PATH, so this is a real test of the worker-
        # subtree guard rather than the "no bridge id at all" guard next to
        # it: a path with no trailing segment (bare "/sessions/<id>") never
        # matches `_BRIDGE_ID` either, and would pass this control even with
        # the worker-subtree check deleted.
        NON_WORKER = "/v1/code/sessions/cse_SUPERSEDED/rename"

        srv = _srv()
        srv._note_bridge_traffic(WORKER, now=100.0)
        # PAST THE DWELL, or the setup itself is shielded as a fresh loss.
        srv._stream_lost["cse_SUPERSEDED"] = 100.0 - pp._DEAF_STARTUP_GRACE_S
        assert srv.deaf_bridges(window=60.0, now=101.0) == [
            "cse_SUPERSEDED"], (
            "setup: a bridge that posted and holds no stream starts out "
            "deaf")

        srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
        assert srv.deaf_bridges(window=60.0, now=101.0) == [], (
            "a 409 to its own worker POST means the server already "
            "superseded this bridge; `deaf_bridges` must stop naming it")
        assert "cse_SUPERSEDED" not in srv._stream_lost, (
            "its stream-loss record must go with it, or a create retried "
            "under the same id inherits a loss that was never its own")

        # CONTROL: a 200 on the same route leaves the bridge exactly posted.
        srv = _srv()
        srv._note_bridge_traffic(WORKER, now=100.0)
        srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 200 OK")
        assert srv.deaf_bridges(window=60.0, now=101.0) == [
            "cse_SUPERSEDED"], (
            "a 200 must not touch the bridge's posting record")

        # CONTROL: a 409 on a route that is not a worker POST changes
        # nothing -- only the worker POST itself is authoritative that the
        # server rejected THIS bridge.
        srv = _srv()
        srv._note_bridge_traffic(WORKER, now=100.0)
        srv._note_bridge_superseded("POST", NON_WORKER, b"HTTP/1.1 409 Conflict")
        assert srv.deaf_bridges(window=60.0, now=101.0) == [
            "cse_SUPERSEDED"], (
            "a 409 on a non-worker route must not clear the bridge")

        # `_posting_now` is `_report_deaf_bridges`'s own denominator, and it
        # reads real wall time rather than an injected `now`.
        srv = _srv()
        srv._note_bridge_traffic(WORKER, now=time.monotonic())
        assert srv._posting_now() == 1
        srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
        assert srv._posting_now() == 0, (
            "the superseded bridge still counted toward the denominator "
            "`_report_deaf_bridges` divides by")

        # AND SOMETHING MUST WIRE IT: `_forward`'s `on_status` is the only
        # site that sees the worker POST's path and its response status
        # together. The exact call-site text, not just the name, so a
        # `(path, method, st)` argument swap goes red instead of passing a
        # grep that only checks the callee is mentioned somewhere.
        import inspect
        wired = inspect.getsource(pp.PinProxy._forward)
        assert "self._note_bridge_superseded(method, path, st)" in wired, (
            "nothing calls the notifier with (method, path, st), in that "
            "order, so a superseded bridge is still reported deaf until "
            "the window or a sweep clears it")

    def case_a_superseded_bridges_409_leaves_one_durable_line(self, certdir):
        """The takeover 409 is the only record of it anywhere in the fleet.

        `_note_bridge_superseded` evicts the id from `_bridge_posts` but logs
        nothing, so the one place that saw the server hand a bridge's worker
        subtree to a newer registration leaves no trace once `daemon.log`
        rotates. A durable line, once per bridge life, is the fix.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._reset_bridge_traffic()
            srv._stream_lost = {}

            WORKER = "/v1/code/sessions/cse_SUPERSEDED/worker/events"
            srv._note_bridge_traffic(WORKER, now=100.0)

            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == 1, (
                "a superseded worker's 409 is the only record of the "
                f"takeover, and it left {len(lines)}: {lines!r}")
            assert "cse_SUPERSEDED" in lines[-1], lines[-1]
            assert WORKER in lines[-1], lines[-1]
            assert "409" in lines[-1], lines[-1]
            assert "superseded" in lines[-1], lines[-1]

            # A SECOND 409 on the same already-evicted bridge must not log
            # again -- a stuck retry loop hammers the dead worker and would
            # otherwise bury the one line that mattered under its repeats.
            # The retry itself is a request, and `_handle_one_request` notes
            # every request's traffic BEFORE forwarding it, so the id is
            # back in `_bridge_posts` by the time the 409 arrives: exactly
            # what a real retry does, not a bare second call.
            srv._note_bridge_traffic(WORKER, now=100.5)
            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == 1, (
                "a second 409 for the same bridge logged again: " + repr(lines))

            REGISTER = "/v1/code/sessions/cse_SUPERSEDED/bridge"

            # A FAILED MINT must not start a new life: the guard clears
            # only on a CONFIRMED registration (a 2xx on the register
            # path), not on the bare request -- a mint-fail + worker-409
            # retry loop must not log once per retry either.
            srv._note_bridge_superseded(
                "POST", REGISTER, b"HTTP/1.1 500 Internal Server Error")
            before = len(lines)
            srv._note_bridge_traffic(WORKER, now=101.7)
            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == before, (
                "a failed mint (non-2xx) started a new life: " + repr(lines))

            # A RE-REGISTRATION is a new life ONLY once CONFIRMED (a 2xx
            # on the register path): the daemon assigns the session id to
            # another worker, which then also gets 409'd, and that IS a
            # second takeover worth its own line.
            before = len(lines)
            srv._note_bridge_superseded(
                "POST", REGISTER, b"HTTP/1.1 201 Created")
            assert len(lines) == before + 1, (
                "a 2xx re-registration did not leave its own line: "
                + repr(lines))
            srv._note_bridge_traffic(WORKER, now=102.5)
            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == before + 2, (
                "a 409 after a CONFIRMED re-registration of the same id "
                "is a new life and must log again: " + repr(lines))

            # A 409 ON A NON-WORKER PATH is not this bridge's takeover.
            # A FRESH id: `cse_SUPERSEDED` is already in
            # `_bridge_superseded_logged` by this point, so reusing it would
            # pass even with the `_WORKER_SUBTREE`/`_EVENT_STREAM` guard
            # deleted -- the once-per-life gate alone would still block it.
            before = len(lines)
            srv._note_bridge_superseded(
                "PUT", "/v1/code/sessions/cse_RENAMEONLY/rename",
                b"HTTP/1.1 409 Conflict")
            assert len(lines) == before, (
                "a 409 on a non-worker route logged as a takeover: "
                + repr(lines))
        finally:
            pp._log_lifecycle = real_log

    def case_a_registered_worker_leaves_one_line(self, certdir):
        """The other half of the same event: who WON the worker subtree.

        `_note_bridge_superseded` already records who LOST it on a 409; a
        2xx on the same register path, on the same status-line hook, is the
        registrant. No new hook, once per registration (each one is an
        event, so no once-per-life guard here).
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._reset_bridge_traffic()
            srv._stream_lost = {}

            REGISTER = "/v1/code/sessions/cse_NEWWORKER/bridge"
            srv._note_bridge_superseded(
                "POST", REGISTER, b"HTTP/1.1 201 Created")
            assert len(lines) == 1, (
                "a 2xx on the register POST left "
                f"{len(lines)}: {lines!r}")
            assert "cse_NEWWORKER" in lines[-1], lines[-1]
            assert "registered" in lines[-1], lines[-1]
            assert "201" in lines[-1], lines[-1]
            assert "POST" in lines[-1], lines[-1]
            assert REGISTER in lines[-1], lines[-1]

            # A 2xx ON A NON-REGISTER WORKER PATH is not a registration.
            WORKER = "/v1/code/sessions/cse_NEWWORKER/worker/events"
            before = len(lines)
            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 200 OK")
            assert len(lines) == before, (
                "a 2xx on a non-register worker path logged as a "
                "registration: " + repr(lines))

            # THE 409 CASES ARE UNCHANGED, still reached and still gated.
            srv._note_bridge_superseded(
                "POST", WORKER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == before + 1, (
                "a 409 stopped logging once the register branch was added: "
                + repr(lines))
        finally:
            pp._log_lifecycle = real_log

    def case_a_worker_register_2xx_is_also_a_registration(self, certdir):
        """The OTHER mint for an existing session: `POST .../worker/register`.

        `_BRIDGE_REGISTER` only matches the REPL's `/bridge` mint; a
        takeover through THIS pin can also land as a 2xx on
        `<worker subtree>/register`, and that is exactly the takeover
        class this round exists to record. Same f-string, same hook, and
        it clears the once-per-life guard the way the `/bridge` mint's
        request-path register branch already does.
        """
        import threading

        import cswap_pin.proxy as pp

        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            srv = pp.PinProxy.__new__(pp.PinProxy)
            srv._live_lock = threading.Lock()
            srv._stream_conns = set()
            srv._open_conns = set()
            srv._reset_bridge_traffic()
            srv._stream_lost = {}

            WORKER = "/v1/code/sessions/cse_TAKEOVER/worker/events"
            REGISTER = "/v1/code/sessions/cse_TAKEOVER/worker/register"

            # A PRIOR LIFE, already 409'd and logged once.
            srv._note_bridge_traffic(WORKER, now=100.0)
            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == 1, lines

            # THE REGISTRATION ITSELF: one line.
            srv._note_bridge_superseded("POST", REGISTER, b"HTTP/1.1 200 OK")
            assert len(lines) == 2, (
                "a 2xx on the worker/register POST left "
                f"{len(lines)}: {lines!r}")
            assert "cse_TAKEOVER" in lines[-1], lines[-1]
            assert "registered" in lines[-1], lines[-1]
            assert "200" in lines[-1], lines[-1]
            assert REGISTER in lines[-1], lines[-1]

            # THE GUARD IS CLEARED: a following 409 for the same id logs
            # again, as this new life's own takeover.
            srv._note_bridge_traffic(WORKER, now=101.0)
            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == 3, (
                "the register branch did not clear the once-per-life "
                "guard: " + repr(lines))
            assert "superseded" in lines[-1], lines[-1]

            # A 2xx ON A NON-REGISTER WORKER PATH is still not a
            # registration.
            before = len(lines)
            srv._note_bridge_superseded("POST", WORKER, b"HTTP/1.1 200 OK")
            assert len(lines) == before, (
                "a 2xx on a non-register worker path logged as a "
                "registration: " + repr(lines))

            # A 409 ON worker/register IS the losing registration,
            # unchanged: it is still `_WORKER_SUBTREE`, no new code for it.
            # A FRESH id, so the once-per-life guard from above cannot
            # gate this away.
            OTHER_REGISTER = "/v1/code/sessions/cse_OTHER/worker/register"
            srv._note_bridge_traffic(OTHER_REGISTER, now=102.0)
            before = len(lines)
            srv._note_bridge_superseded(
                "POST", OTHER_REGISTER, b"HTTP/1.1 409 Conflict")
            assert len(lines) == before + 1, (
                "a 409 on worker/register did not log as a takeover: "
                + repr(lines))
            assert OTHER_REGISTER in lines[-1], lines[-1]
            assert "superseded" in lines[-1], lines[-1]
        finally:
            pp._log_lifecycle = real_log

    def case_the_carry_is_reachable_without_a_daemon(self, certdir):
        """A switch must be able to carry pointers with no daemon running.

        The only trigger today is the daemon noticing `.claude.json` move, so
        the carry does not happen at all while the daemon is down -- and the
        sessions that miss it are refused Remote Control until it comes back.
        `cswap` is in the process that just wrote that file and can do it
        itself, but only if the carry is callable without a `PinProxy`.

        It already is, in fact: the method touches `self` nowhere. This pins
        that as a contract rather than an accident, because a later `self.`
        would break the caller silently -- an AttributeError inside a
        best-effort call is swallowed and the carry just stops happening.
        """
        import inspect

        import cswap_pin.proxy as pp

        assert callable(getattr(pp, "carry_live_pointers", None)), (
            "there is no module-level carry, so a switch cannot run one "
            "without constructing a daemon")

        src = inspect.getsource(pp.carry_live_pointers)
        assert "self" not in src, (
            "the module-level carry reaches for `self`, so the caller that "
            f"has no daemon cannot use it: {src[:200]!r}")

        # AND THE METHOD MUST STILL WORK, or every daemon-side caller breaks.
        m = inspect.getsource(pp.PinProxy.carry_live_pointers)
        assert "carry_live_pointers(" in m.split("def ", 1)[1], (
            "the method no longer delegates to the module-level carry, so "
            "the two can drift apart")

    def case_the_forget_call_carries_no_live_pointer(self):
        """The live carry runs only where the splice has just run.

        `carry_live_pointers` has no pin-org guard; its sibling
        `_carry_history_pointers` does. What stands in for one is that the
        splice writes the field this carry reads, immediately above it. The
        splice is guarded on `identity`, so a carry guarded only on
        `account_num` would fire on the no-identity call -- the one that
        FORGETS the pin -- and restamp every LIVE session onto whatever
        account happens to be signed in. Those sessions' bridges are not that
        account's, and Claude Code answers 500 on a bridge it cannot use.
        """
        import inspect

        import cswap_pin.proxy as pp

        src = inspect.getsource(pp.heal)
        between = src[src.index("_carry_history_pointers(certdir)"):
                      src.index("carry_live_pointers(")]
        assert "if identity:" in between, (
            "the live carry in `heal` is not guarded on `identity`, so the "
            "call that forgets the pin restamps live sessions onto whatever "
            f"account is signed in: {between!r}")

    def case_a_deaf_bridge_carries_how_long_it_has_been_deaf(self):
        """A duration read off two log lines measures the POLL, not the fleet.

        The deaf verdict is re-evaluated at most once per
        `_BRIDGE_SWEEP_COOLDOWN_S` (600s), so the gap between the line that
        names a deaf bridge and the line that clears it is quantised to that
        interval. Three "recovery times" were reported off that gap -- 12s,
        7min, 10min -- and the 10min one is exactly one cooldown, which is the
        interval and not a recovery.

        The pin already knows the exact instant: it HOLDS the stream, so the
        moment it drops one is local state and costs no request. Recording it
        turns the duration into a measurement instead of an artefact of how
        often we happen to look.
        """
        import cswap_pin.proxy as pp
        import inspect

        assert hasattr(pp.PinProxy, "deaf_for"), (
            "no way to ask how long a bridge has been without its stream, so "
            "every duration has to be inferred from log spacing")

        src = inspect.getsource(pp.PinProxy._forget_stream)
        assert "_stream_lost" in src, (
            "the loss instant is not recorded where the stream is dropped")

        # AND THE REPORT MUST CARRY IT, or the number exists and nobody reads
        # it -- the same shape as a detector nothing consults.
        # AND IT IS BOUNDED. A dict nothing prunes holds one entry per bridge
        # that ever lost a stream, for the life of the daemon -- the shape a
        # previous fix here had to remove when the same map pinned a socket
        # object per stream. It is dropped when the bridge gets one back.
        est = inspect.getsource(pp.PinProxy._note_bridge_traffic)
        assert "_stream_lost.pop(" in est, (
            "nothing clears the loss record when a stream comes back, so it "
            "grows for the life of the daemon")

        rep = inspect.getsource(pp.PinProxy._report_deaf_bridges)
        assert "deaf_for" in rep, (
            "the deaf report still states no duration, so a reader has only "
            "the log spacing to go on and will read the cooldown as recovery")

    def case_the_pin_signals_no_session_worker_at_all(self):
        """The pin does not decide when a user's session restarts.

        Two repairs here ended a session's worker: one keyed on a deaf bridge,
        one on a policy refusal cached in that process. Both are gone. The
        second looked defensible -- the verdict lives in memory, every external
        surface is closed, and a measured case came back in 12s with the
        conversation intact -- but the registry cannot tell a background
        session somebody is ATTACHED TO from one nobody is watching. `kind` has
        two values, `bg` and `interactive`, and every session a person works in
        through the agent view is `bg`. So "only a background session" was
        never the guard it read as, and the idle test means "between turns",
        which is exactly what a session looks like while its user reads.

        The cause is upstream of the symptom: `/api/claude_code/policy_limits`
        is a pinned route, so an answer fetched THROUGH the pin is correct. A
        wrong one can only be cached when that question left the machine
        without passing the pin. That window is where this is fixed.

        Guarding the absence: the two removals were a year apart in kind but
        one week apart in fact, and both were argued for from a real symptom.
        """
        import cswap_pin.proxy as pp
        import pathlib

        src = pathlib.Path(pp.__file__).read_text(encoding="utf-8")
        for banned in ("_signal_worker", "recycle_denied_sessions",
                       "recycle_deaf_sessions"):
            assert banned not in src, (
                f"{banned} is back: the pin must not end a session's worker. "
                "Fix what made the session wrong, and report what you cannot "
                "fix -- never restart somebody's session to clear it")

        # AND THE SIGNALS THAT REMAIN CANNOT REACH A SESSION. Checked on the
        # TARGET, not the signal number: an allowlist of constants has to grow
        # every time a holder learns a new one, and it drifted twice while
        # being written. The registry is the only way this daemon learns a
        # session's pid, so the invariant is that the two never meet in one
        # function. `os.kill(pid, 0)` is exempt because POSIX defines it as
        # sending nothing -- the liveness probe the registry readers need.
        import ast, re
        sessiony = re.compile(r"session|bridge|job|policy", re.I)

        def sends_a_signal(call):
            if len(call.args) < 2:
                return True
            sig = call.args[1]
            return not (isinstance(sig, ast.Constant) and sig.value == 0)

        def offenders(text):
            out = []
            for fn in ast.walk(ast.parse(text)):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not any(isinstance(n, ast.Call)
                           and isinstance(n.func, ast.Attribute)
                           and n.func.attr == "kill" and sends_a_signal(n)
                           for n in ast.walk(fn)):
                    continue
                names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
                names |= {n.attr for n in ast.walk(fn)
                          if isinstance(n, ast.Attribute)}
                hit = sorted(x for x in names if sessiony.search(x))
                if hit:
                    out.append((fn.name, hit))
            return out

        # THE CONTROL, in the same run. A guard whose pattern matches nothing
        # reports a clean file exactly like a guard that works, so re-derive
        # the shape that was removed and require this to see it.
        removed_shape = (
            "def _signal_worker(self, sid, sig):\n"
            "    for r in _live_session_records():\n"
            "        if r.get('sessionId') == sid:\n"
            "            os.kill(int(r['pid']), sig)\n")
        assert offenders(removed_shape), (
            "the guard is blind: it does not flag the very function that was "
            "removed, so its verdict on the live file means nothing")

        assert not offenders(src), (
            f"a signal is sent from a function that reads the session "
            f"registry: {offenders(src)}. The pin must not end a session's "
            "worker -- fix what made the session wrong, and report what you "
            "cannot fix")

    def case_the_pin_never_kills_a_session_to_cure_deafness(self):
        """A deaf bridge is REPORTED and never repaired by killing anything.

        The pin once grew `recycle_deaf_sessions`, which SIGTERMed the worker
        behind a bridge holding no inbound stream. It crash-looped two peer
        sessions before it was removed. Deafness is a real condition and the
        pin cannot cure it -- Claude Code does not rebuild the Remote Control
        receive channel after an EOF or a reset, so the only remedy is a new
        process and the REPL is what dispatches one. The log line saying "only
        a new process clears it" is addressed to that REPL, not to this daemon.

        Guarding the absence, because the detector and the actor look alike and
        this shape has been rebuilt from its own report before.
        """
        import cswap_pin.proxy as pp
        import pathlib

        src = pathlib.Path(pp.__file__).read_text(encoding="utf-8")
        for banned in ("recycle_deaf_sessions", "_RECYCLED_PREFIX",
                       "_recycled_recently", "_remember_recycle"):
            assert banned not in src, (
                f"{banned} is back: the pin must never kill a session to cure "
                "a deaf bridge -- report it and let the REPL re-home itself")
        assert hasattr(pp.PinProxy, "deaf_bridges"), (
            "the DETECTOR must stay -- removing the report is the opposite "
            "error, and it is what left a session on `rc failed` for hours")
    def case_a_bridge_archived_later_is_still_swept(self, certdir):
        """The superseded sweep fired on ONE event and missed half the cases.

        `_sweep_bridges_after_connect` runs only on `POST /v1/code/sessions`,
        and its comment claims an older bridge "becoming ambiguous happens
        here and nowhere else". Measured counter-example on this machine:

            keep     0.0h  active                'cswap_pin_artifacts'
            DELETE   0.3h  archived  connected   'cswap_pin_artifacts'

        Two ways a title becomes a coin flip, not one:
          1. a NEW bridge opens while an older one is connected  -> caught
          2. an OLDER bridge is ARCHIVED while still connected, AFTER the
             newer one already opened                            -> never

        The sweep requires `archived`, and archiving is a server-side event
        that happens later and that the pin never sees. So case 2 cannot be
        covered by the create event, however the comment reads.

        PRESENCE WAS THE TRIGGER THAT ALREADY EXISTED, chosen because it was
        believed to recur on the server's poll interval WITHOUT waking a quiet
        daemon -- the objection the create-only design was built on. It does
        not recur: a live trace of 2132 requests across 13 attached sessions
        caught ZERO presence posts and 26 worker posts in its first 45
        seconds. So worker traffic carries case 2, presence stays because it
        costs nothing, and the cooldown is what keeps either from listing on
        every post.
        """
        import ast

        import cswap_pin.proxy as pp

        srv = pp.PinProxy.__new__(pp.PinProxy)
        srv._last_bridge_sweep = 0.0
        calls = []
        srv._sweep_bridges_after_connect = lambda tok: calls.append(tok)

        PRESENCE = "/v1/code/sessions/cse_AAA/client/presence"
        CREATE = "/v1/code/sessions"

        # REACHABILITY FIRST. Presence is deliberately NOT a pinned route, so
        # a sweep call placed inside `if pinned:` can never see it — the
        # trigger, its cooldown and its timestamp are all dead and this test
        # would still pass, because it calls the predicate directly.
        assert pp.is_pinned_route(PRESENCE) is False, (
            "presence became a pinned route; the reasoning below needs "
            "rechecking")
        import inspect
        import textwrap
        body = inspect.getsource(pp.PinProxy._handle_one_request_inner)
        tree = ast.parse(textwrap.dedent(body))
        guarded = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            if not (isinstance(node.test, ast.Name) and node.test.id == "pinned"):
                continue
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Attribute)
                        and inner.func.attr == "_should_sweep_bridges"):
                    guarded = True
        assert not guarded, (
            "the sweep decision sits inside `if pinned:`, and presence is not "
            "a pinned route — so the second trigger can never fire")

        # The create event still sweeps, every time — unchanged behaviour.
        assert srv._should_sweep_bridges("POST", CREATE, now=100.0) is True
        assert srv._should_sweep_bridges("POST", CREATE, now=101.0) is True

        # Presence sweeps too, but at most once per cooldown.
        assert srv._should_sweep_bridges("POST", PRESENCE, now=1000.0) is True
        assert srv._should_sweep_bridges("POST", PRESENCE, now=1001.0) is False, (
            "presence swept on every post; with 13 attached sessions that is a "
            "server listing several times a second")
        assert srv._should_sweep_bridges(
            "POST", PRESENCE, now=1000.0 + pp._BRIDGE_SWEEP_COOLDOWN_S + 1) is True

        # WORKER TRAFFIC SWEEPS TOO, and it is the trigger that actually
        # arrives. Without it the verdict is only ever as fresh as the last
        # create, so a fleet that starts no session never re-asks at all.
        WORKER = "/v1/code/sessions/cse_AAA/worker/events"
        srv._last_bridge_sweep = None
        assert srv._should_sweep_bridges("POST", WORKER, now=2000.0) is True
        assert srv._should_sweep_bridges("POST", WORKER, now=2001.0) is False, (
            "worker posts arrive several times a second across the fleet; "
            "without the cooldown this lists the account on every one")
        assert srv._should_sweep_bridges(
            "POST", WORKER, now=2000.0 + pp._BRIDGE_SWEEP_COOLDOWN_S + 1) is True
        # The inbound stream is a GET held open for the session's life, so it
        # is never a trigger however well its path matches.
        assert srv._should_sweep_bridges(
            "GET", "/v1/code/sessions/cse_AAA/worker/events/stream",
            now=9e9) is False

        # THE CONTROL: an unrelated route must not sweep at all, or the
        # cooldown is the only thing standing between this and every request.
        assert srv._should_sweep_bridges("POST", "/v1/messages", now=9e9) is False
        assert srv._should_sweep_bridges("GET", CREATE, now=9e9) is False

    def case_presence_stops_at_a_path_boundary(self, certdir):
        """The boundary group was `(/|$|\\\\?)` inside a RAW string.

        That is an optional LITERAL BACKSLASH, and zero-or-one matches the
        empty string -- so the whole group was vacuous and the pattern
        accepted any suffix. `_PRESENCE` has two readers with opposite jobs
        (the never-swap rule and the sweep trigger), and a route classifier
        that does not stop at a path boundary is wrong for both.
        """
        import cswap_pin.proxy as pp

        base = "/v1/code/sessions/cse_AAA/client/presence"
        # The three real shapes, unchanged.
        assert pp._PRESENCE.search(base)
        assert pp._PRESENCE.search(base + "?x=1")
        assert pp._PRESENCE.search(base + "/sub")
        assert not pp._PRESENCE.search(base + "EVIL"), (
            "the boundary group still matches the empty string")
        # THE CONTROL: the sibling classifier written correctly, so a failure
        # above is this pattern and not the assertion style.
        assert pp._WORKER_SUBTREE.search("/v1/code/sessions/cse_AAA/worker")
        assert not pp._WORKER_SUBTREE.search(
            "/v1/code/sessions/cse_AAA/workerEVIL")

    def case_the_accept_probe_and_the_bind_probe_disagree(self, certdir):
        """`_port_answers` must answer about ACCEPTING, not about BOUND.

        The whole recovery keys on those two facts disagreeing, so a probe
        that conflates them makes the branch unreachable. Both directions,
        against real sockets:

            bound, not listening -> nobody accepts   -> False
            bound and listening  -> the kernel does  -> True

        The second is the control. A probe that always said False would pass
        the first alone and would then retire a HEALTHY handover's standby,
        opening the gap that standby exists to close.
        """
        import socket

        import cswap_pin.proxy as pp

        quiet = socket.socket()
        quiet.bind(("127.0.0.1", 0))
        try:
            assert pp._port_answers(quiet.getsockname()[1], timeout=0.5) is False
        finally:
            quiet.close()

        live = socket.socket()
        live.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        live.bind(("127.0.0.1", 0))
        live.listen(4)
        try:
            assert pp._port_answers(live.getsockname()[1], timeout=1.0) is True
        finally:
            live.close()

    def case_a_squatting_standby_is_retired_so_the_holder_can_bind(
            self, certdir, monkeypatch):
        """A stale standby holding the port and never accepting deadlocked a
        machine for 3.4 hours, and the recovery for it was gated behind the
        very bind it prevented.

        `_retire_stale_standbys` runs after a holder places its OWN standby,
        which requires already owning the port. A standby left by a holder
        that was KILLED rather than released owns it and sleeps: the backlog
        fills (129 queued, measured), every connect is refused, every new
        holder's bind is EADDRINUSE, and the holder refuses to move -- rightly,
        since live sessions have that port baked into their environment. 50
        retries, 63 sessions, ended by a person sending SIGHUP by hand.

        THE DISCRIMINATOR IS INJECTED HERE, ON PURPOSE. Reproducing the field
        shape needs a FULL listen backlog, and that is where the portability
        lies: macOS treats `listen(0)` as a floor, so connects still complete
        and the branch never runs -- CI went red on a fix that works. A socket
        bound WITHOUT listen is portable but useless, because SO_REUSEADDR
        lets the holder bind straight past it. So the sibling case above
        proves `_port_answers` tells the two apart against real sockets, and
        this one proves the holder ACTS on that answer.
        """
        import socket

        import cswap_pin.proxy as pp

        squat = socket.socket()
        squat.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squat.bind(("127.0.0.1", 0))
        squat.listen(4)
        port = squat.getsockname()[1]

        retired = []

        def _fake_retire(cd, keep_pid=None):
            retired.append((str(cd), keep_pid))
            squat.close()          # what a SIGHUP to the standby achieves
            return 1

        monkeypatch.setattr(pp, "_retire_stale_standbys", _fake_retire)
        monkeypatch.setattr(pp, "_port_answers", lambda *_a, **_k: False)
        monkeypatch.setattr(pp, "wanted_port", lambda _cd: port)
        monkeypatch.setattr(pp, "_HOLD_BIND_WAIT_S", 0.2)

        try:
            holder = pp.PortHolder(certdir, "1", "a@example.com")
        except OSError as exc:
            raise AssertionError(
                "the holder gave up on a port a squatting standby was sitting "
                f"on, which is the deadlock it can recover from: {exc}"
            ) from exc
        try:
            assert retired, (
                "the holder refused the port without ever asking whether one "
                "of OUR OWN standbys was squatting on it")
            assert holder.port == port, (
                f"the holder escaped to another port ({holder.port}) — every "
                f"session wired to {port} is stranded")
        finally:
            holder.stop()
            squat.close()

    def case_a_healthy_handover_standby_is_left_alone(self, certdir,
                                                      monkeypatch):
        """The other half, and the reason the escalation is not unconditional.

        During a handover the predecessor's standby holds the address open on
        purpose. It IS unbindable -- and it ANSWERS. Retiring it would open
        exactly the gap it exists to close, so the pair must be required, not
        either half.
        """
        import socket

        import cswap_pin.proxy as pp

        live = socket.socket()
        live.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        live.bind(("127.0.0.1", 0))
        live.listen(4)
        port = live.getsockname()[1]

        retired = []
        monkeypatch.setattr(
            pp, "_retire_stale_standbys",
            lambda cd, keep_pid=None: retired.append(cd) or 1)
        monkeypatch.setattr(pp, "_port_answers", lambda *_a, **_k: True)
        monkeypatch.setattr(pp, "wanted_port", lambda _cd: port)
        monkeypatch.setattr(pp, "_HOLD_BIND_WAIT_S", 0.2)

        try:
            try:
                pp.PortHolder(certdir, "1", "a@example.com")
            except OSError:
                pass          # refusing is correct here
            assert not retired, (
                "a standby that is ANSWERING was retired; during a handover "
                "that is the one holding the address open, and killing it "
                "opens the gap")
        finally:
            live.close()


    def case_the_armed_trace_can_see_the_tunnel(self, certdir):
        """An armed trace was blind to the one path that fails.

        `trace-to` arms `self._debug`, which only the MITM request path wrote.
        `_blind_tunnel` wrote to `_TRACE`, a module global opened once at
        import from `CSWAP_PIN_DEBUG` and unreachable afterwards. So a trace
        armed on a running daemon recorded every route Claude Code SENDS and
        nothing about the channel it RECEIVES on — which is the outage the
        comment at that very site describes.

        MEASURED WITH A CONTROL before the fix: a real CONNECT driven through
        a live pin produced ZERO lines in an armed trace. The zero was the
        instrument.
        """
        import cswap_pin.proxy as pp

        out = certdir / "armed-trace.log"
        (certdir / pp._TRACE_SWITCH_FILE).write_text(str(out))
        pp._TRACE_CACHE.clear()

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        proxy._tunnel_trace("CONNECT example:443 tunnelled")
        assert out.exists() and "CONNECT example:443" in out.read_text(), (
            "the tunnel path does not write to the armable trace, so an "
            "incident can only be traced by restarting the daemon — which "
            "ends the very connections being investigated")

        # AND ALL THREE TUNNEL SITES GO THROUGH IT, not just the one above.
        # Reaching them needs a real chain, so read it out of the source.
        import inspect

        src = inspect.getsource(pp.PinProxy._blind_tunnel)
        assert "_TRACE.write" not in src, (
            "a tunnel line still writes straight to the import-time global, "
            "so that line is invisible to a trace armed during an incident")
        assert src.count("self._tunnel_trace(") >= 3, (
            f"only {src.count('self._tunnel_trace(')} tunnel site(s) use the "
            "shared writer; the others are blind to an armed trace")

    def case_every_beat_keeps_the_channel_count(self, certdir):
        """The beat REWRITES the marker, so a beat that omits the channel
        count erases the reap protection.

        The first beat wrote the fifth line and the periodic one, 15 seconds
        later, wrote a four-line marker over it — so a daemon carrying a bridge
        looked like a daemon carrying nothing to the sweep that decides what to
        kill. The protection lasted one interval.

        MEASURED ON A LIVE MARKER while this was shipped: pid draining with 13
        replies owed, 13 live, and no fifth line.
        """
        import cswap_pin.proxy as pp

        pid = 918273
        pp.announce_draining(certdir, pid)
        pp.beat_draining(certdir, pid, owed=3, live=3, quiet=1.0, streams=7)
        assert pp.draining_streams(certdir, pid) == 7, (
            "the marker does not carry the channel count at all")

        # THE SECOND BEAT IS THE ONE THAT USED TO ERASE IT.
        pp.beat_draining(certdir, pid, owed=3, live=2, quiet=2.0, streams=7)
        assert pp.draining_streams(certdir, pid) == 7, (
            "a later beat dropped the channel count, so the reaper reads zero "
            "and takes the daemon carrying the bridge — the protection lasts "
            "one beat interval")

        # AND THE DRAIN'S OWN PERIODIC BEAT MUST PASS IT. Reaching that line
        # needs a live daemon mid-drain, so read it out of the source, which is
        # the convention this file uses for the exit paths.
        import inspect

        src = inspect.getsource(pp.PinProxy.await_inflight)
        beats = src.count("beat_draining(")
        passes = src.count("streams=")
        assert beats > 0 and passes == beats, (
            f"{beats} beat(s) in the drain but {passes} pass the channel "
            "count; the ones that do not erase it on their next write")

    def case_the_pump_can_say_what_the_process_is_carrying(self, certdir):
        """The reaper needs the PROCESS's tunnel count, and only the marker
        can carry it — the sweep runs somewhere else.

        A daemon whose only remaining job is a bridge WebSocket owes no reply,
        so every cost the reaper weighs scored it as the cheapest thing on the
        box and it was always the one taken. That is the reap no session can
        recover from by itself.

        THE COUNT IS PROCESS-WIDE, THE PROXY'S IS NOT. `_PUMP` drives every
        tunnel in the process; folding it into `live_stream_count` made one
        proxy report another's, measured on a single-process runner as 2 where
        1 was expected. The proxy counts its own subscriptions; the marker adds
        the pump's pairs, because the marker describes the process.
        """
        import socket

        import cswap_pin.proxy as pp
        from cswap_pin.proxy import _PUMP, PinProxy

        # A BASELINE OFF A SHARED GLOBAL IS NOT A BASELINE. `_PUMP` is a
        # module global and the macOS job runs single-process, so a pair
        # another case left behind can be torn down BETWEEN the two reads
        # below and the count drops out from under the assertion.
        # `reset_for_tests` exists for exactly this and had no caller
        # anywhere; the flake it was written to prevent reddened main once.
        _PUMP.reset_for_tests()
        a, b = socket.socketpair()
        try:
            before = _PUMP.live_pairs()
            assert before == 0, (
                "the reset left tunnels behind, so this case is measuring "
                f"another one's: {before}")
            _PUMP.add(a, b)
            assert _PUMP.live_pairs() == before + 1, (
                "the pump cannot say how many tunnels it drives, so the "
                "marker cannot tell the reaper this daemon is carrying one")
        finally:
            for s_ in (a, b):
                try:
                    s_.close()
                except OSError:
                    pass

        # AND THE PROXY'S OWN COUNT STAYS ITS OWN.
        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                         upstream=("127.0.0.1", 1))
        c, d = socket.socketpair()
        try:
            _PUMP.add(c, d)
            assert proxy.live_stream_count() == 0, (
                "a proxy with no subscriptions of its own reported the "
                "process's tunnels, so one proxy speaks for another")
        finally:
            for s_ in (c, d):
                try:
                    s_.close()
                except OSError:
                    pass

        # AND THE DRAIN MUST WAIT FOR THEM. A daemon whose tunnels are its
        # only remaining work owes nothing — `_mitm` hands a tunnel's debt back
        # at the 101 — so without this it leaves at once and the tunnels die
        # with the process. Measured on the fleet: pid 423760 owed nothing,
        # drained "clean" in 0.0s and took four open connections with it, while
        # pid 1452400 owed a stream, stayed, and kept fourteen channels.
        #
        # AND IT MUST END. `live_pairs()` alone has no exit — a wedged peer
        # keeps its entry for ever — so it is bounded on SILENCE, the same
        # discriminator the reply wait uses.
        import inspect

        src = inspect.getsource(pp.PinProxy.await_inflight)
        assert "while (_PUMP.live_pairs()" in src, (
            "the drain does not wait for live tunnels, so a recycle drops "
            "every Remote Control channel this daemon is pumping")
        i = src.index("while (_PUMP.live_pairs()")
        assert "_PUMP.quiet_for() <= _DRAINING_MARKER_TTL" in src[i:i + 200], (
            "the tunnel wait has no exit: a tunnel whose peer wedged holds "
            "this process open for ever, which is the never-ending drain the "
            "removed wall clock used to bound")
        assert 'budget == float("inf")' in src[:i], (
            "the tunnel wait is not confined to the uncapped arm. The signal "
            "arm has a supervisor counting to `_DRAIN_SECONDS + 2`, so waiting "
            "past it buys a harder kill; the held arm holds the port dark")

        # AND THE PUMP CAN BE ISOLATED, or this suite measures leftovers. The
        # macOS runner is single-process, so without a per-case reset one
        # case's tunnels are counted by the next one's proxy.
        assert hasattr(_PUMP, "reset_for_tests"), (
            "nothing can clear the shared pump between cases, so a leftover "
            "tunnel makes one case fail about another case's state")

        # AND SILENCE IS NOT REACHABLE FOR THE CHANNEL THIS PROTECTS.
        # Remote Control RECEIVES on a WebSocket tunnel and the server sends
        # keepalives on it, so `_last_move` keeps refreshing and `quiet_for()`
        # never climbs to the TTL. The wait's only exit is therefore closed by
        # construction for exactly the tunnel it exists to protect. Measured on
        # pmac 2026-08-31: `drained clean in 2240.2s`, holding the two bridges
        # of the greencard and canada_pr sessions, and unbounded in principle.
        assert "tunnel_deadline" not in src, (
            "a wall clock is back on the tunnel wait. A bridge inbound stream "
            "is never silent because the server keepalives it, and while this "
            "process holds that stream THE SESSION IS RECEIVING THROUGH IT. "
            "Releasing it on a clock turns a working channel into a deaf "
            "bridge, and Claude Code rebuilds the receive side after neither "
            "an EOF nor a reset. Unbounded is the correct behaviour here: the "
            "cost is one lingering process, and the alternative is a cut")

    def case_a_chatty_bridge_holds_the_drain_and_is_never_released(
            self, certdir):
        """A live Remote Control stream is served until it ends, on no clock.

        `quiet_for()` pins near zero while the peer keeps talking, so the only
        exit stays closed and this call keeps waiting. That is the channel
        working, not a hang: the session receives through this process for as
        long as it holds the stream. A drain that ran 2240s held two sessions'
        bridges and both were healthy throughout; deafness arrived when it
        ended, not while it lasted.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", 1),
        )
        old_pump = pp._PUMP
        _Chatty.released = []
        pp._PUMP = _Chatty("bridge")
        try:
            th = threading.Thread(target=proxy.await_inflight,
                                  args=(float("inf"),), daemon=True)
            th.start()
            th.join(timeout=3.0)
            still_waiting = th.is_alive()
        finally:
            pp._PUMP = old_pump
        assert still_waiting, (
            "the drain stopped waiting on a bridge whose peer is still "
            "talking — the only thing that ends this wait must be the stream "
            "ending, never a timer")
        assert "bridge" not in _Chatty.released, (
            "the drain RELEASED a live bridge tunnel. That is the cut this "
            "invariant exists to prevent: the peer sees EOF, the session goes "
            "deaf, and nothing rebuilds the receive side")

    def case_CONTROL_a_bulk_tunnel_is_not_cut_either(self, certdir):
        """THE OTHER KIND, held by the same rule.

        Every host that is not the upstream takes a blind CONNECT and lands in
        the same pump — git, pip, npm, the auto-updater. A transfer still
        moving bytes is real work, and the silence bound waits it out
        correctly; only the keepalived bridge can never satisfy that bound.
        A shipped clock cut a running `git clone` at 150s because a recycle
        happened to be draining. Both kinds are now held by silence alone.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", 1),
        )
        old_pump, old_cap = pp._PUMP, pp._TUNNEL_DRAIN_SECONDS
        _Chatty.released = []
        pp._PUMP = _Chatty("tunnel")        # a bulk transfer, not a bridge
        pp._TUNNEL_DRAIN_SECONDS = 0.0      # the deadline is already past
        try:
            t0 = time.monotonic()
            # It must NOT return on the clock. The bound that applies here is
            # silence, and this peer never goes silent, so the call is
            # expected to keep waiting -- which is what the old behaviour was
            # and what a bulk transfer needs.
            th = threading.Thread(target=proxy.await_inflight,
                                  args=(float("inf"),), daemon=True)
            th.start()
            th.join(timeout=3.0)
            still_waiting = th.is_alive()
            waited = time.monotonic() - t0
        finally:
            pp._PUMP, pp._TUNNEL_DRAIN_SECONDS = old_pump, old_cap
        assert still_waiting, (
            "the drain gave up on a bulk tunnel after %.1fs; a transfer still "
            "moving bytes is real work and only silence may end this wait"
            % waited)
        assert "bridge" not in _Chatty.released and not _Chatty.released, (
            "a non-bridge tunnel was released by the bridge deadline: %r"
            % (_Chatty.released,))

    def case_a_drain_does_not_cut_the_subscription(self, certdir):
        """The channel a session cannot reopen for itself must survive a recycle.

        A drain used to close every held-open `/worker/events/stream` on the
        grounds that it never completes, so waiting for it waits for ever. The
        premise behind the harm — that holding one stamps `Connection: close`
        on enough other replies to matter — did not survive measurement: the
        banner was observed with NOTHING draining, and a departing daemon has
        released its listener, so the only replies left are on keep-alives that
        migrate after one each.

        What the cut did buy was a hard disconnect of the bridge's inbound
        stream. A DRAINING DAEMON STILL SERVES WHAT IT ALREADY HOLDS — it gave
        up the listener, not its connections — so leaving the stream alone
        keeps the session working on the departing process for as long as it
        lasts. That is what shipped before 0.1.125 and it is what this guards.

        The cost is a process that lingers. That is the session still working,
        not a leak, and `live_stream_count` is how the drain line says so.
        """
        import socket
        import threading

        from cswap_pin.proxy import PinProxy, _EVENT_STREAM

        assert _EVENT_STREAM.search(
            "GET /v1/code/sessions/cse_x/worker/events/stream HTTP/1.1"), (
            "the one request that never completes is not recognised, so the "
            "drain line cannot say what is holding it")
        assert not _EVENT_STREAM.search(
            "POST /v1/code/sessions/cse_x/worker/events HTTP/1.1"), (
            "the ordinary event POST was taken for a subscription")

        proxy = PinProxy.__new__(PinProxy)
        proxy._live_lock = threading.Lock()
        proxy._stream_conns, proxy._open_conns = set(), set()
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        try:
            # A SUBSCRIPTION THAT ALREADY FINISHED, still remembered. Its
            # descriptor is gone and the NUMBER has been handed to something
            # else, so counting it names a connection that is not ours.
            c.close()
            d.close()
            proxy._stream_conns.add(c)
            proxy._stream_conns.add(a)
            proxy._open_conns.add(a)
            assert proxy.live_stream_count() == 1, (
                "the count is taken from the stream set alone, so it reports a "
                "connection whose descriptor has been reused")

            # AND THE PEER MUST NOT SEE EOF WHEN A REAL DRAIN RUNS. Asserting
            # on names — no `release_subscriptions`, no `_end_connection` —
            # only holds until somebody writes the cut under a third name.
            # This asks the property instead: run the drain, then read the far
            # end. A cut gives EOF; an intact stream gives a timeout.
            real = PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
            # THE FINAL CATCH-ALL IS A NO-OP IN PRODUCTION, so it is one here.
            # `_close_open_connections` shuts down every open connection as
            # the drain's last act, and for a MITM'd connection it reaches the
            # RAW socket that `wrap_socket` detached — `fileno()` is -1 and
            # the close does nothing. That no-op is load-bearing and its own
            # guard covers it. A plain socketpair is NOT detached, so leaving
            # the call in makes this case measure a cut that cannot happen on
            # the real object. The question here is the DELIBERATE cut.
            real._close_open_connections = lambda: None
            e, f = socket.socketpair()
            with real._live_lock:
                real._open_conns.add(e)
                real._stream_conns.add(e)
            try:
                real.await_inflight(0.0)
                f.settimeout(1.0)
                try:
                    got = f.recv(1)
                except (TimeoutError, OSError):
                    got = None            # still open — nothing cut it
                assert got is None, (
                    "the drain closed a held-open subscription. That is the "
                    "channel claude.ai pushes through, and the session cannot "
                    "reopen it for itself")
            finally:
                for s_ in (e, f):
                    try:
                        s_.close()
                    except OSError:
                        pass

            # AND NOTHING CLOSES IT. Reaching a real drain needs a live daemon,
            # so read it out of the source — the convention this file already
            # uses for the exit paths.
            import ast
            import inspect

            import cswap_pin.proxy as pp

            src = inspect.getsource(pp)
            assert "_end_connection" not in src, (
                "the apparatus that made the cut real is back. Closing the "
                "TLS object really does end the connection, and the one it "
                "ends is the bridge's inbound stream")
            tree = ast.parse(src)
            drains = [n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef)
                      and n.name == "await_inflight"]
            assert drains, "await_inflight moved; this guard is blind"
            closers = {c_.func.attr for d_ in drains for c_ in ast.walk(d_)
                       if isinstance(c_, ast.Call)
                       and isinstance(c_.func, ast.Attribute)}
            assert "release_subscriptions" not in closers, (
                "the drain cuts subscriptions again, so every recycle drops "
                "the channel claude.ai pushes through and the session stops "
                "receiving until it reconnects")

            # AND THE MARK IS FORGOTTEN WHEN THE REPLY THAT SET IT ENDS,
            # or the set grows for the life of the daemon and fills with
            # sockets whose descriptors have been reused. SCOPED TO `_mitm`
            # ITSELF (T1025): `_stream_conns` is only ever populated behind
            # `_mitm`'s own loop boundary (`_handle_one_request`), so this
            # check is about THAT boundary specifically -- a whole-module
            # search would read whichever call comes first in the file, not
            # the one this check is about. `_plain_relay` clears its own
            # owed-answer debt at its own loop boundary (finding 5) with a
            # different call, `_owe_answer(conn, False)` and never
            # `_note_reply_finished` (see proxy.py ~16213), a deliberate
            # difference this check does not cover.
            mitm_src = inspect.getsource(pp.PinProxy._mitm)
            paid = mitm_src.find("self._note_reply_finished(conn)")
            assert paid != -1, "the debt boundary moved; this guard is blind"
            # THE ACT, NOT THE SPELLING. The three sites that ended a stream
            # were `_stream_conns.discard` + `_stream_owner.pop`, one fact
            # written three times; they are `_forget_stream` now, which also
            # records WHEN so a duration stops being read off log spacing.
            # Pinning the old literal made this guard fail on that move while
            # the property it guards was intact.
            assert "self._forget_stream(conn)" in mitm_src[paid:paid + 700], (
                "the subscription mark outlives the reply that set it")
        finally:
            for s_ in (a, b, c, d):
                try:
                    s_.close()
                except OSError:
                    pass
    def case_a_successor_on_the_port_means_nobody_waits_for_us(self, certdir):
        """`handed_over` asks "did I hand over"; the budget needs "is anyone
        waiting for me to be gone". Those differ for a daemon superseded from
        OUTSIDE, and that daemon is the one that pays.

        Measured: a holder took the replace signal and spawned a successor,
        which served the same port from 01:44:13Z. The predecessor had
        announced no drain of its own, so `this_process_is_draining()` was
        False, the held arm fired, and its refcount teardown at 01:47:19Z cut
        13 mid-response replies on a 30s ceiling while the successor was three
        minutes into serving. The uncapped refcount arm below it is
        unreachable for a held daemon, so nothing else could have caught this.
        """
        import os
        import subprocess

        from cswap_pin.proxy import _superseded_on_the_port, write_daemon_state

        assert _superseded_on_the_port(certdir) is False, (
            "no record at all read as a successor")

        write_daemon_state(certdir, 40404, os.getpid(), "fp")
        assert _superseded_on_the_port(certdir) is False, (
            "the record naming US read as a successor — every teardown would "
            "take the uncapped ceiling with nothing behind the port")

        live = subprocess.Popen(["sleep", "30"])
        try:
            write_daemon_state(certdir, 40404, live.pid, "fp")
            assert _superseded_on_the_port(certdir) is True, (
                "a live successor on the record read as absent — the held arm "
                "fires and cuts whatever this daemon still owes")
        finally:
            live.kill()
            live.wait()

        write_daemon_state(certdir, 40404, live.pid, "fp")
        assert _superseded_on_the_port(certdir) is False, (
            "a reaped pid on the record read as a live successor — that is an "
            "uncapped drain with nothing serving the port")

        # AND THE TEARDOWN MUST ACTUALLY ASK IT. The predicate above is right
        # in isolation whether or not anything calls it, so the assertions so
        # far cannot fail on the bug they describe. Read out of the source
        # because `_teardown` is a closure inside `daemon_main` and reaching it
        # needs a live daemon, its sockets and its state file — a harness that
        # reconstructs those can be wrong in its own right.
        import ast
        import inspect

        import cswap_pin.proxy as pp

        asked = None
        for node in ast.walk(ast.parse(inspect.getsource(pp))):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "teardown_drain_budget"):
                for kw in node.keywords:
                    if kw.arg == "handed_over":
                        asked = {n.func.id for n in ast.walk(kw.value)
                                 if isinstance(n, ast.Call)
                                 and isinstance(n.func, ast.Name)}
        assert asked == {"this_process_is_draining", "_superseded_on_the_port"}, (
            "the teardown no longer asks both ways a daemon can owe nothing. "
            "Its own marker covers the handover it announced; a successor the "
            "holder started leaves nothing announced here at all, and the "
            "held arm then cuts every reply still in flight. Got: " + str(asked)
        )

    def case_each_exit_path_drains_on_the_ceiling_that_fits_it(self, certdir):
        """FOUR DRAINS, TWO SITUATIONS — and they were collapsed into one number.

        Measured 2026-08-18, all three hosts, with the phase split live:

            host-a  cut 16   (16 mid-response, 0 before headers)
            host-b   cut  3   ( 3 mid-response, 0 before headers)
            host-c   drained clean

        Zero "before headers" anywhere, so those are replies that had already
        begun streaming to a user and did not finish inside thirty seconds. The
        drain was working; the ceiling was wrong.

        THE TWO SITUATIONS ARE NOT INTERCHANGEABLE:

          successor already serving  the holder spawned it, or we handed the
                                     listening socket down by fd. This process
                                     accepts nothing and nobody is waiting on
                                     it, so waiting costs one idle process and
                                     nothing else -> `_HANDOVER_DRAIN_SECONDS`.

          holder respawns after us   the holder cannot start the successor
                                     until we are gone, so every second here is
                                     a second with nothing serving the port.
                                     Cutting is the lesser evil
                                     -> `_HELD_DRAIN_SECONDS`. TWO call sites
                                     share it: no holder pid to ask at all,
                                     and a holder that survived the ask but
                                     whose successor never published within
                                     the wait -- both leave the supervisor to
                                     start the next one the slow way.

        AND `_DRAIN_SECONDS` COULD NOT SIMPLY BE RAISED, which is why this is a
        third constant rather than a bigger one: it is also the supervisor's
        patience (`proc.wait(timeout=_DRAIN_SECONDS + 2)`, the SIGKILL
        escalation, the stop poll). Raising it makes every teardown wait ten
        minutes for a process that is not coming back.

        Read out of the source because the property IS the wiring. A behavioural
        test would have to run for ten minutes to tell 600 from 30, and the
        regression this guards is somebody tidying three constants into one.
        """
        import ast
        import inspect
        import cswap_pin.proxy as pp

        tree = ast.parse(inspect.getsource(pp))
        named = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "await_inflight"
                    and node.args
                    and isinstance(node.args[0], ast.Name)
                    # CONSTANTS ONLY. `stop()` forwards its own `drain`
                    # parameter through here, and a parameter says nothing
                    # about which ceiling an exit path chose.
                    and node.args[0].id.isupper()):
                named.append(node.args[0].id)

        assert named, (
            "no `await_inflight(<CONSTANT>)` call found at all — the scan is "
            "broken, and a broken scan passes every assertion below it")
        assert sorted(named) == [
            "_HANDOVER_DRAIN_SECONDS", "_HANDOVER_DRAIN_SECONDS",
            "_HELD_DRAIN_SECONDS", "_HELD_DRAIN_SECONDS",
        ], (
            "the exit paths no longer drain on the ceilings that fit them. Two "
            "hand over to a successor that is already serving (free to wait) "
            "and two exit so a holder can start the successor the slow way "
            "(every second is an unserved port). Got: " + ", ".join(sorted(named))
        )

        # AND THE NUMBERS THEMSELVES, or the names above are decoration.
        #
        # THE HANDOVER CEILING IS NOT A NUMBER ANY MORE, and no number can be
        # right: 1800 cuts a 31-minute reply, 3600 cuts a 61-minute one, and
        # this box runs subagent replies past an hour. Nothing waits on this
        # process — the successor is already serving — so a clock buys nothing
        # here and spends a reply every time it is wrong.
        assert pp._HANDOVER_DRAIN_SECONDS == float("inf"), (
            "the handover drain is capped by a clock again. A clock cannot "
            "tell a slow reply from a wedged one; `_owed_still_moving` can, "
            f"and it is what ends a healthy drain. Got "
            f"{pp._HANDOVER_DRAIN_SECONDS}")
        assert pp._HELD_DRAIN_SECONDS <= pp._DRAIN_SECONDS, (
            "the held ceiling holds the port dark, and the supervisor SIGKILLs "
            "at `_DRAIN_SECONDS + 2` — raising it past that trades a logged "
            "cut for an unlogged one")

        # AND THE MARKER TTL MUST NOT FOLLOW THE CEILING. It was
        # `_HANDOVER_DRAIN_SECONDS + 60`, which is now infinite — a marker
        # that never expires spares whatever pid inherits the number, forever.
        # Freshness comes from a beat instead, so this stays small.
        assert pp._DRAINING_MARKER_TTL < 600.0, (
            "the draining marker outlives its writer by "
            f"{pp._DRAINING_MARKER_TTL}s. A SIGKILLed drainer cannot unlink "
            "it, and pids are reused — that window is a real orphan wearing a "
            "dead process's badge")
        assert pp._DRAINING_BEAT_SECONDS * 3 < pp._DRAINING_MARKER_TTL, (
            "the beat is too slow for the TTL it refreshes: a drain that is "
            "alive and working would look abandoned between two beats")

    def case_the_blind_tunnel_gives_its_debt_back(self, certdir):
        """THE FOURTH UNREACHABLE ZERO, and it is the same connection as the first.

        `_blind_tunnel` never called `_owe_answer(conn, False)`. The accept path
        marks every connection OWED, so a blind tunnel stayed owed for its
        entire life and `inflight_requests()` could not reach zero on any
        machine that had ever connected Remote Control. Every drain then paid
        its full ceiling — exactly the behaviour the `_owed` set was introduced
        to end.

        AND THIS IS THE RC PATH. `_blind_tunnel`'s own docstring: "Remote
        Control receives over a WebSocket to the ingress host the /bridge
        response names — NOT api.anthropic.com — so it lands here, not in the
        MITM." The fix went to `_mitm`'s 101 handover, which is the path RC
        does not take.

        Measured on host-a 2026-08-18, three versions, one signature:
            0.1.93 departing  cut 14 / cut 16  after 30s
            0.1.94 departing  cut 14           after 30s
            0.1.96 departing  cut 16           after 30s

        DRIVEN THROUGH THE REAL FUNCTION, not by arranging the state it should
        produce. The sibling cases above model "a tunnel owes nothing" by simply
        not adding it to `_owed` — which asserts the conclusion and can never
        catch a path that fails to reach it. This one dials a real listener,
        lets `_blind_tunnel` send its own 200, and then asks the counter.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(128)
        target = "127.0.0.1:%d" % srv.getsockname()[1]
        client, conn = socket.socketpair()
        accepted = []
        try:
            # THE ACCEPT PATH'S OWN MARKING, reproduced exactly: open, and owed
            # from the moment it is accepted.
            with proxy._live_lock:
                proxy._open_conns.add(conn)
            proxy._owe_answer(conn, True)
            assert proxy.inflight_requests() == 1, "precondition: owed at accept"

            proxy._local.conn = conn
            proxy._local.release = lambda: None
            proxy._blind_tunnel(target, conn)
            accepted.append(srv.accept()[0])

            assert proxy.inflight_requests() == 0, (
                "the tunnel still owes an answer. Nobody is waiting on it — it "
                "is two sockets being copied into each other — so it holds "
                "every drain to its full ceiling, and this is the path Remote "
                "Control's WebSocket takes")
            assert proxy.live_client_count() == 1, (
                "and it is still an OPEN connection, which teardown must close")

            # AND THE DRAIN MUST SAY SO. This is the one state where the two
            # counters disagree — one socket open, nothing owed — so it is the
            # only place that can catch a message reporting open sockets as
            # cut requests. That conflation is what put "cut 14 in-flight
            # request(s)" in the log for fourteen sockets nobody was waiting on.
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                assert proxy.await_inflight(0.0) == 0, (
                    "a tunnel owes nobody an answer, so cutting it costs "
                    "nothing and must not be reported as a cut request")
            # Anchored for the same reason as the sibling case above: the
            # capped arm's announcement contains the word.
            assert not re.search(r"cut \d+ in-flight", err.getvalue()), \
                err.getvalue()
            assert "closed 1 idle connection(s)" in err.getvalue(), (
                "the tunnel WAS closed and the line must account for it, or "
                "the two counters go back to being one number: "
                + err.getvalue())
        finally:
            for s_ in accepted + [client, conn, srv]:
                try: s_.close()
                except OSError: pass

    def case_the_drain_line_measures_instead_of_quoting_its_budget(self, certdir):
        """"after 30s" was the ARGUMENT, printed whether or not it was spent.

            f"cut {cut} in-flight request(s) after {budget:.0f}s"

        `budget` is the ceiling passed in. A drain that broke out in 20ms
        printed the same "after 30s" as one that burned the whole thing, so the
        one field that says whether the wait was real could not be read — and a
        peer session correctly refused to conclude anything from it.

        Here the drain returns at once (nothing is owed) on a large budget, and
        the line must not claim the budget was spent.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        err = io.StringIO()
        try:
            # OPEN, OWING NOTHING, ON A LARGE BUDGET. The elapsed and the
            # budget must DIFFER or the assertion cannot tell them apart —
            # this case first drove `await_inflight(0.0)`, where `0.0` and
            # `0.0` are the same string, and the mutation that put the budget
            # back into the field passed it. A test whose two candidate values
            # are equal is not a test.
            with proxy._live_lock:
                proxy._open_conns.add(a)
            assert proxy.inflight_requests() == 0, "precondition: nothing owed"
            with contextlib.redirect_stderr(err):
                proxy.await_inflight(20.0)
            line = err.getvalue()
            assert "drained clean" in line, (
                "a departure that cost nothing must still say so — silence "
                "reads the same as a daemon that never drained: " + line)
            # NOT A FIXED VALUE. A slower box genuinely drains in 0.1s and
            # the line correctly says so, which turned this red on CI while
            # the code was right. What the case is for is that the elapsed
            # field is a MEASUREMENT and not the ceiling copied into it, so
            # bound it by the budget: the mutation this exists to catch puts
            # 20 there, and anything a real drain takes is far below it.
            waited = re.search(r"drained clean in ([\d.]+)s of a 20s budget",
                               line)
            assert waited, (
                "the drain line did not report an elapsed time at all: " + line)
            # A TENTH OF THE BUDGET, NOT THE BUDGET. Bounding it by 20 admits
            # a drain that burned 19 of its 20 seconds owing nothing, which is
            # a broken value wearing a passing test. One second is still ten
            # times the slowest real drain a loaded runner has produced.
            assert float(waited.group(1)) < 1.0, (
                "the line quotes its budget rather than what it waited: " + line)
            assert "20s budget" in line, (
                "and it must still name the ceiling it did not need: " + line)

            # AND WITH NO CEILING AT ALL it must say that, not print a float.
            # "of a infs budget" reads as a number nobody can act on, and this
            # is the one line a later session reads to decide whether a pin
            # departure cost somebody a reply.
            err2 = io.StringIO()
            with contextlib.redirect_stderr(err2):
                proxy.await_inflight(pp._HANDOVER_DRAIN_SECONDS)
            line2 = err2.getvalue()
            assert "inf" not in line2, (
                "the drain line printed a raw infinity: " + line2)
            assert "no wall-clock cap" in line2, (
                "an uncapped drain must name that it is uncapped — otherwise "
                "the log cannot tell it from one that had a budget and did "
                "not spend it: " + line2)
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_the_cut_says_whether_the_reply_had_started(self, certdir):
        """A CUT BEFORE HEADERS IS A RETRY; A CUT MID-RESPONSE IS A LOSS.

        The line said "a reply may have ended mid-stream" over both, so the
        number could not be used for the one thing it exists for: telling the
        user whether a recycle cost them an answer. A request cut before its
        headers went out has sent the client nothing — the SDK retries and it
        costs a round trip. One cut after has delivered part of an answer, and
        no retry repairs that.

        Measured on the sibling CCF proxy the same night, which already splits
        them: `cut 4 in-flight request(s) after 5s (4 mid-response, 0 before
        headers)`. Its counts were the only ones defensible as user-visible
        while ours reported sockets and hedged about the phase.

        BOTH DIRECTIONS IN ONE CASE, because either alone passes on a version
        that hardcodes the other: a constant "0 mid-response" survives the
        before-headers half, and a constant "0 before headers" survives the
        mid-response half.
        """
        import cswap_pin.proxy as pp

        for started, want in ((False, "0 mid-response, 1 before headers"),
                              (True, "1 mid-response, 0 before headers")):
            proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                                upstream=("127.0.0.1", 1))
            a, b = socket.socketpair()
            err = io.StringIO()
            try:
                with proxy._live_lock:
                    proxy._open_conns.add(a)
                proxy._owe_answer(a, True)
                if started:
                    proxy._note_response_started(a)
                assert proxy.inflight_requests() == 1, "precondition: owed"
                assert proxy.inflight_mid_response() == (1 if started else 0)
                with contextlib.redirect_stderr(err):
                    proxy.await_inflight(0.0)
                assert want in err.getvalue(), (
                    f"started={started}: the line does not say which kind of "
                    f"cut this was: {err.getvalue()}")
            finally:
                for s_ in (a, b):
                    try: s_.close()
                    except OSError: pass

    def case_the_relay_is_what_says_the_reply_started(self, certdir):
        """THE WIRING, not the method — and the mutation that proved it missing.

        The two cases around this one call `_note_response_started` themselves,
        so deleting the `on_headers()` call from the relay left them both GREEN.
        Measured: mutation "the relay never says the reply started" SURVIVED,
        which means nothing connected the marker to the only event that can set
        it. That is the same hole as a drain fix landing on the path Remote
        Control does not take — a correct function nobody calls.

        So this drives the real `_relay_response` over a real socket pair with
        a canned upstream response, and asks whether the callback fired.
        """
        from cswap_pin.proxy import _relay_response

        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        fired = []
        try:
            up_b.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
            up_b.shutdown(socket.SHUT_WR)
            _relay_response(up_a, cl_a, 0,
                            on_headers=lambda n, c: fired.append(n))
            assert fired, (
                "the relay wrote the response head to the client without "
                "saying so, so every cut is reported as retryable no matter "
                "how much of the answer had already been delivered")
            # AND THE CLIENT REALLY GOT IT — otherwise a relay that fires the
            # callback and sends nothing would pass.
            cl_a.shutdown(socket.SHUT_WR)
            got = cl_b.recv(4096)
            assert got.startswith(b"HTTP/1.1 200"), got[:60]
            assert got.endswith(b"hi"), got[-20:]
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

    def case_marking_a_response_started_cannot_rewind(self, certdir):
        """RE-OWING MUST NOT UNDO IT, and `_owe_answer` is called again mid-request.

        The accept path marks a connection owed, and `_handle_one_request`
        marks it owed AGAIN when the request line arrives — so a plain
        `self._owed[conn] = False` would reset a response already in flight to
        "before headers" and under-report exactly the cuts that matter.
        `setdefault` is what makes that impossible, and this is the case that
        says so.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            proxy._owe_answer(a, True)
            proxy._note_response_started(a)
            proxy._owe_answer(a, True)          # the second marking
            assert proxy.inflight_mid_response() == 1, (
                "re-marking an owed connection rewound a reply that had "
                "already started, so a real mid-response cut would be counted "
                "as a retryable one")
            # And paying the debt really does clear it, or the rewind guard
            # would be a leak instead.
            proxy._owe_answer(a, False)
            assert proxy.inflight_requests() == 0
            assert proxy.inflight_mid_response() == 0
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_a_request_in_flight_holds_the_drain(self, certdir):
        """THE OTHER HALF, and the one that must never regress to "fast".

        Counting requests is only right if a request actually holds the drain.
        Without this case, `await_inflight` could return immediately always and
        the case above would still pass — which is the same "verified where it
        cannot fail" shape as the drain line that reported a constant 0.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            # OWED AN ANSWER — what the accept path marks, and what a
            # streaming `/v1/messages` stays marked as for every second it
            # streams. This is the state a recycle must never walk away from.
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)
            assert proxy.inflight_requests() == 1
            started = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(1.0)
            waited = time.monotonic() - started
            assert waited >= 0.9, (
                f"returned after {waited:.2f}s with a request in flight — a "
                "streaming reply would be cut mid-response")
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass


class TestTunnelIsOpen:
    """`_tunnel_is_open` on its own, with nothing racing.

    The integration case above proves the FALLBACK happens; this proves the
    DETECTOR that is supposed to trigger it, and it can do so without a
    scheduler in the loop — a socket whose peer has already closed is EOF now,
    not in 0.35 s.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_peer_that_closed_reads_as_EOF(self):
        import cswap_pin.proxy as pp
        a, b = socket.socketpair()
        b.close()
        try:
            assert pp.PinProxy._tunnel_is_open(a) is None, (
                "a closed peer must read as EOF — this is the whole detector")
        finally:
            a.close()

    def case_a_live_idle_socket_reads_as_OPEN(self):
        """THE CONTROL. Without it, "closed reads as EOF" also passes on a
        detector that answers None for everything — which would send every
        healthy tunnel down the direct-dial path."""
        import cswap_pin.proxy as pp
        a, b = socket.socketpair()
        try:
            assert pp.PinProxy._tunnel_is_open(a) is a, (
                "an idle tunnel has nothing to read and that means OPEN")
        finally:
            a.close(); b.close()

    def case_a_byte_already_waiting_is_pushed_back(self):
        """It READS to test, so the byte it consumed has to reappear or the
        caller's stream is corrupted — the reason it returns a socket rather
        than a bool."""
        import cswap_pin.proxy as pp
        a, b = socket.socketpair()
        try:
            b.sendall(b"XY")
            out = pp.PinProxy._tunnel_is_open(a)
            assert out is not None and out is not a, "expected the wrapper"
            # READ UNTIL SATISFIED, not one recv. `_Prefixed` hands back the
            # single probed byte first and the socket's own data after it, so
            # a `recv(2) == b"XY"` expectation is the TEST being wrong about
            # stream semantics, not the wrapper losing anything. What the
            # contract actually promises is that no byte disappears.
            got = b""
            while len(got) < 2:
                chunk = out.recv(2 - len(got))
                assert chunk, "the stream ended early — a byte was swallowed"
                got += chunk
            assert got == b"XY", got
        finally:
            a.close(); b.close()


class TestOptimisticConnectIsDetected:
    """A CONNECT 200 means the chain ACCEPTED the request, not that it reached
    the host. privoxy answers optimistically and dials afterwards, closing the
    socket when that dial fails — measured on host-b against the Remote
    Control ingress: "200 Connection established" followed immediately by
    UNEXPECTED_EOF_WHILE_READING on the first TLS byte. Trusting the status
    made RC silently deaf: everything Claude Code SENDS kept going through the
    MITM path at 200 while the receive channel was a dead socket."""


    def _optimistic_chain(self):
        """Answers 200 to every CONNECT, then closes without connecting."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()          # the dial "failed" — EOF at once

        threading.Thread(target=serve, daemon=True).start()
        return srv

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_falls_back_when_the_200_tunnel_is_already_eof(
        self, certdir, tmp_path, monkeypatch
    ):
        """Since 2026-09-07 an optimistic-then-EOF chain is the same "every
        hop failed" case `_blind_tunnel` answers with 503 by default — a
        chain that ACCEPTED and died and a chain that never accepted at all
        both leave `up is None`, and a direct dial from a chained host is
        what reached the corporate TLS-inspecting proxy 49 times (see
        TestChainRediscovery). `CSWAP_PIN_ALLOW_DIRECT=1` restores the old
        re-dial and is the CONTROL below.
        """
        import cswap_pin.proxy as pp

        chain = self._optimistic_chain()

        peer = socket.socket()
        peer.bind(("127.0.0.1", 0))
        peer.listen(2)
        peer_port = peer.getsockname()[1]
        reached = threading.Event()

        def serve_peer():
            try:
                c, _ = peer.accept()
            except OSError:
                return
            reached.set()
            try:
                if c.recv(64):
                    c.sendall(b"PONG")
            finally:
                c.close()

        threading.Thread(target=serve_peer, daemon=True).start()

        monkeypatch.delenv("CSWAP_PIN_ALLOW_DIRECT", raising=False)
        log = tmp_path / "trace.log"
        prev = pp._TRACE
        pp._TRACE = open(log, "a")
        try:
            proxy = pp.PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: "PINTOKEN",
                upstream=("127.0.0.1", 1),
            )
            proxy._current_chain = lambda: ("127.0.0.1", chain.getsockname()[1])
            proxy.start()
            try:
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                raw.sendall(
                    f"CONNECT 127.0.0.1:{peer_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{peer_port}\r\n\r\n".encode()
                )
                resp = raw.recv(4096)
                raw.close()
                assert resp.split(b"\r\n")[0] == b"HTTP/1.1 503 Service Unavailable", (
                    f"a dead-tunnel chain must answer 503, never dial direct: "
                    f"{resp[:80]!r}"
                )
                assert not reached.is_set(), (
                    "an optimistic chain reached the host directly"
                )

                # CONTROL: the opt-in restores the old re-dial.
                monkeypatch.setenv("CSWAP_PIN_ALLOW_DIRECT", "1")
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                raw.sendall(
                    f"CONNECT 127.0.0.1:{peer_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{peer_port}\r\n\r\n".encode()
                )
                resp2 = b""
                while b"\r\n\r\n" not in resp2:
                    chunk = raw.recv(4096)
                    assert chunk, "CONTROL FAILED: proxy closed instead of re-dialling"
                    resp2 += chunk
                assert b"200" in resp2.split(b"\r\n")[0], resp2[:80]
                raw.sendall(b"PING")
                assert raw.recv(16) == b"PONG", (
                    "CONTROL FAILED: the tunnel was the chain's dead socket, "
                    "not the host"
                )
                raw.close()
            finally:
                proxy.stop()
                peer.close()
                chain.close()
            pp._TRACE.flush()
        finally:
            pp._TRACE.close()
            pp._TRACE = prev

        assert reached.is_set(), "CONTROL FAILED: the host was never dialled directly"
        # THE CONTRACT, NOT THE BRANCH THAT DELIVERED IT. This used to assert
        # `"already EOF" in log`, which names one internal path. Measured on
        # macOS CI 2026-08-18: the two behavioural assertions above BOTH passed
        # — the host was dialled directly and answered PONG, so the dead chain
        # was correctly not used — while the log read
        # `CONNECT … tunnelled (no pin: bearer never seen)`. The chain closes
        # immediately after its 200, so whether the proxy observes a FIN inside
        # `_tunnel_is_open`'s 0.35 s select or an RST earlier is a scheduling
        # question, and both answers are right.
        #
        # The detector itself is pinned deterministically instead, with no
        # sockets in flight, by `TestTunnelIsOpen` below. Asserting a log line
        # here bought nothing that case does not, and cost a red CI on a
        # correct build — which blocked a release.
        assert log.read_text().strip(), "the connection was not traced at all"


class TestTheTrustFileActuallyVerifies:
    """Every other check on the CA-trust contract inspects file CONTENT — does
    the bundle contain our CA, are its BEGIN/END markers balanced. Both are
    necessary and neither is evidence: they are pre-flight guards, and only a
    completed handshake proves the file yields a working trust path to the
    proxy. Measured on host-a against the live daemon: with the merged bundle,
    TLS OK, issuer "cswap pin-proxy CA"; with no extra CA,
    UNABLE_TO_VERIFY_LEAF_SIGNATURE. This is that, in-process."""


    def _handshake(self, proxy_port: int, cafile) -> str:
        """CONNECT through the proxy and complete TLS, trusting only cafile."""
        raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
        raw.sendall(
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
            b"Host: api.anthropic.com:443\r\n\r\n"
        )
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = raw.recv(4096)
            if not chunk:
                break
            resp += chunk
        assert b"200" in resp.split(b"\r\n")[0], resp[:80]
        ctx = ssl.create_default_context(cafile=str(cafile)) if cafile else (
            ssl.create_default_context()
        )
        try:
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            issuer = dict(x[0] for x in (tls.getpeercert() or {}).get("issuer", ()))
            tls.close()
            return issuer.get("commonName", "?")
        except ssl.SSLError as e:
            raw.close()
            return f"FAIL:{e.reason}"

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_named_trust_file_verifies_the_proxy(self, certdir, tmp_path, monkeypatch):
        import cswap_pin.proxy as pp

        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)

        proxy = pp.PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PINTOKEN",
            upstream=("127.0.0.1", 1),
        )
        proxy.start()
        try:
            ca = certdir / "ca.pem"
            # A merged bundle exactly as a launcher would build it: someone
            # else's root first, ours after.
            merged = home / pp.CA_TRUST_FILE
            merged.write_bytes(ca.read_bytes())
            chosen = pp._trust_file(ca, None)
            assert chosen == merged, "the contract's own selection did not pick it"

            # The point of the test: what NODE_EXTRA_CA_CERTS names must
            # actually verify the proxy, not merely mention it.
            assert self._handshake(proxy.port, chosen) == "cswap pin-proxy CA"
            # Control — without it the handshake must FAIL, or the assertion
            # above proves nothing.
            assert self._handshake(proxy.port, None).startswith("FAIL:")
        finally:
            proxy.stop()


class TestTheKillGateIdentifiesItsTarget:
    """`_pin_daemon_pids` decides who gets SIGTERM then SIGKILL.

    Every other test stubs it, so the matcher itself was never exercised —
    and it matched by plain substring over the whole `ps` line, which also
    selects anything that merely MENTIONS the module and the certdir: a
    shell whose command line quotes them, a wrapper, a grep.
    """


    def _pids(self, monkeypatch, lines, certdir):
        import subprocess as _sp

        from cswap_pin import proxy as pp

        class _R:
            stdout = "\n".join(lines)

        monkeypatch.setattr(_sp, "run", lambda *a, **k: _R())
        return pp._pin_daemon_pids(certdir)

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_certdir_must_be_the_last_argv_token(self, tmp_path, monkeypatch):
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        t = str(certdir.resolve())
        pids = self._pids(
            monkeypatch,
            [
                f" 111 python3 -m cswap_pin.proxy 1 a@b.c {t}",       # the daemon
                f" 222 /bin/zsh -c 'cswap_pin.proxy ... {t}' && ls",   # a shell
                f" 333 grep cswap_pin.proxy {t} /var/log/x",           # a grep
            ],
            certdir,
        )
        assert pids == [111], (
            f"the kill gate selected a process that only mentions the "
            f"daemon: {pids}"
        )

    def case_a_different_certdir_is_never_matched(self, tmp_path, monkeypatch):
        mine = tmp_path / "pin-proxy"; mine.mkdir()
        other = tmp_path / "other-proxy"; other.mkdir()
        pids = self._pids(
            monkeypatch,
            [f" 444 python3 -m cswap_pin.proxy 1 a@b.c {other.resolve()}"],
            mine,
        )
        assert pids == [], "a daemon for another backup dir was selected"


def test_mint_lock_bound_covers_the_real_in_lock_ceiling():
    """`_MINT_LOCK_BOUND_S` bounds a WAITER; the work the holder does inside
    the lock belongs to the HOST, not this module -- a cold keychain read,
    then (should the held token be expired) `consume_backup_grant`'s own
    file lock, the switcher's file lock, a keychain re-read and the refresh
    POST. Below their sum, a legitimate contended refresh gets cut off as
    if it were stalled."""
    import inspect

    from claude_swap import locking, macos_keychain, oauth
    from cswap_pin import proxy as pp

    keychain = macos_keychain._TIMEOUT
    filelock = inspect.signature(
        locking.FileLock.__init__).parameters["timeout"].default
    post = inspect.signature(
        oauth.try_refresh_oauth_credentials).parameters["timeout_s"].default

    ceiling = 2 * keychain + 2 * filelock + post
    assert pp._MINT_LOCK_BOUND_S >= ceiling, (
        f"_MINT_LOCK_BOUND_S={pp._MINT_LOCK_BOUND_S} is below the host's own "
        f"in-lock ceiling {ceiling} (keychain={keychain}, filelock={filelock}, "
        f"post={post})")


class TestFailOpenIsNotSilent:
    """The token swap fails OPEN by design — a pin that cannot resolve must
    never block work. The cost is that nothing marks it: requests keep
    succeeding, /health keeps answering, and the consequence surfaces days
    later as Remote Control sessions owned by the wrong account, which the
    server fixes at /bridge and never transfers. Measured: a daemon that could
    not reach its credential store served 13 of 13 pinned routes unswapped, and
    19 sessions had to be rebuilt by hand. Fail open, but say so."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _proxy(self, certdir, provider):
        from cswap_pin.proxy import PinProxy
        return PinProxy(certdir=certdir, pin_token_provider=provider,
                        upstream=("127.0.0.1", 1))

    def _drive_pinned_request(self, proxy):
        """Run one PINNED request through the real swap path.

        The fail-open warning lives in ``_handle_one_request``, so asserting on
        ``_warn_unpinnable()`` directly proves nothing about whether a request
        reaches the guard. Feeds a fake TLS socket instead: the relay fails
        (upstream is port 1, deliberately dead), which is fine — the swap
        decision, and the warning, happen before the relay.
        """
        class _FakeTLS:
            def __init__(self):
                self._in = (
                    b"POST /v1/code/sessions HTTP/1.1\r\n"
                    b"Host: api.anthropic.com\r\n"
                    b"Authorization: Bearer disk-bearer\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                self.sent = b""

            def recv(self, n):
                out, self._in = self._in[:n], self._in[n:]
                return out

            def sendall(self, b):
                self.sent += b

            def close(self):
                pass

        try:
            proxy._handle_one_request(_FakeTLS())
        except Exception:
            pass  # relay to the dead upstream fails; the swap already happened
        return None

    def case_a_deferred_refresh_does_not_condemn_the_daemon(self, tmp_path):
        """"Busy right now" is not "cannot pin".

        The gate answers ``consume-busy`` when another process holds the
        slot's consume lock — the usage collector polls on its own schedule
        and contends for exactly this slot. That is a race to retry, and the
        provider's own docstring says so.

        But the only other reading of a None token is "this daemon cannot
        pin", which ``_warn_unpinnable`` records into proxy.json as
        ``unpinnable: True`` — and ``_read_alive_port`` then refuses to reuse
        that daemon FOREVER. One lost race would condemn a healthy daemon and
        print macOS-keychain advice for a Linux lock contention.
        """
        import json

        from claude_swap.oauth import RefreshOutcome
        from cswap_pin import proxy as pp

        expired = json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt"}})

        class _Busy:
            backup_dir = tmp_path
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e): return expired
            def resolve_account(self, i): return ("2", "pin@example.com", "org")
            def consume_backup_grant(self, n, e, snap):
                return RefreshOutcome(None, "consume-busy")

        pp.save_pin(tmp_path, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Busy(), "2", "pin@example.com")

        assert provider() is None, "a busy gate yields no token, by design"
        assert provider.pin_is_noop() is True, (
            "a deferral was reported as a failure — the daemon gets marked "
            "unpinnable and is never reused again"
        )

    def case_a_real_unreadable_credential_IS_still_a_failure(self, tmp_path):
        """...and the deferral must not swallow the case the warning exists
        for. An unreadable store still has to condemn."""
        from cswap_pin import proxy as pp

        class _Unreadable:
            backup_dir = tmp_path
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e): return ""
            def resolve_account(self, i): return ("2", "pin@example.com", "org")

        pp.save_pin(tmp_path, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Unreadable(), "2", "pin@example.com")

        assert provider() is None
        assert provider.pin_is_noop() is False, (
            "an unreadable credential must still warn"
        )

    def case_warns_when_the_token_cannot_be_minted(self, certdir, monkeypatch):
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        self._proxy(certdir, lambda: None)._warn_unpinnable()
        err = buf.getvalue()
        assert "UNPINNED" in err
        assert "cswap pin" in err, "the message must name the fix"

    def case_the_spawned_daemon_has_somewhere_to_warn(self, certdir, monkeypatch):
        """The warning above is written to the daemon's stderr, and the daemon
        is spawned detached — so whether it reaches anyone is decided by
        spawn_daemon, not by the writer. Measured on all three machines: the
        daemon's fd 2 was /dev/null, meaning every fail-open was silent by
        construction while two tests above asserted the message "works" against
        a substituted stderr. A warning with no destination is the bug it
        exists to report."""
        import subprocess as _sp
        from cswap_pin import proxy as pp

        seen = {}

        class _FakePopen:
            def __init__(self, argv, **kw):
                seen.update(kw)
                seen["argv"] = argv

        monkeypatch.setattr(_sp, "Popen", _FakePopen)
        # Return a port on the first poll so spawn_daemon stops immediately —
        # we only care about how it tried to spawn, not about waiting out the
        # ~10s window for a daemon this test never starts.
        monkeypatch.setattr(pp, "_read_alive_port", lambda *a, **k: 4321)
        monkeypatch.setattr(pp, "read_daemon_state", lambda *a, **k: None)
        monkeypatch.setattr(pp, "_sweep_orphan_daemons", lambda *a, **k: None)
        pp._spawn_daemon("1", "a@b.c", certdir)

        assert seen["stderr"] is not _sp.DEVNULL, (
            "stderr=DEVNULL gives _warn_unpinnable nowhere to land"
        )
        log = pp.daemon_log_path(certdir)
        assert seen["stderr"].name == str(log), (
            f"expected the daemon's stderr on {log}, got {seen['stderr']!r}"
        )

    def case_the_warning_lands_in_that_log(self, certdir):
        """End to end through the real file object spawn_daemon opens: write
        the warning to it and read it back off disk. The two tests above pass a
        StringIO and so cannot see a destination that does not exist."""
        from cswap_pin import proxy as pp

        log = pp.daemon_log_path(certdir)
        handle = pp._open_daemon_log(certdir)
        try:
            p = self._proxy(certdir, lambda: None)
            with contextlib.redirect_stderr(handle):
                p._warn_unpinnable()
        finally:
            handle.close()
        body = log.read_text(encoding="utf-8")
        assert "UNPINNED" in body
        assert "cswap pin" in body

    def case_the_cap_rotates_rather_than_deleting(self, certdir):
        """THE INSTRUMENT MUST NOT BE DESTROYED BY THE EVENT IT DESCRIBES.

        `_open_daemon_log` runs at DAEMON START, and past the size cap it used
        to `unlink` the file. Daemon start is the instant a handover completes,
        so the INCOMING daemon was deleting the OUTGOING daemon's teardown
        record — the "drained, N" and "cut N in-flight request(s)" lines that
        exist to say whether a recycle cost anyone their reply.

        Measured 2026-08-18: three sessions took "API Error: Connection lost
        mid-response" during a two-stage recycle, and the log covering it had
        been unlinked 8 seconds in. A second question riding the same window —
        who emptied `.claude.json`'s env block — could not be settled either,
        by anyone, ever.

        An empty log reads as "the daemon had nothing to say", which is why
        this is worse than having no log at all.
        """
        from cswap_pin import proxy as pp

        log = pp.daemon_log_path(certdir)
        log.parent.mkdir(parents=True, exist_ok=True)
        marker = "THE-DEPARTING-DAEMONS-LAST-WORDS"
        log.write_text(marker + "x" * (pp._LOG_MAX_BYTES + 1), encoding="utf-8")

        handle = pp._open_daemon_log(certdir)
        try:
            assert log.stat().st_size < pp._LOG_MAX_BYTES, (
                "the cap has to hold, or the log grows without bound")
            kept = log.with_suffix(log.suffix + ".1")
            assert kept.is_file(), (
                "the previous generation was deleted, not rotated — the next "
                "recycle's evidence dies with it")
            assert marker in kept.read_text(encoding="utf-8", errors="replace"), (
                "the rotated file does not carry what the old daemon wrote")
        finally:
            handle.close()

        # A SECOND ROTATION IN THE SAME RECYCLE MUST NOT EAT THE FIRST. A
        # recycle is two-stage — measured 70 s apart — and each stage opens
        # the log. One generation meant stage two overwrote stage one's
        # teardown record, which is the very line the rotation exists to keep.
        log.write_text("STAGE-TWO" + "x" * (pp._LOG_MAX_BYTES + 1),
                       encoding="utf-8")
        handle = pp._open_daemon_log(certdir)
        try:
            older = log.with_suffix(log.suffix + ".2")
            assert older.is_file(), (
                "a second rotation kept only one generation, so the departing "
                "daemon's last words were overwritten by the next stage of "
                "the same recycle")
            assert marker in older.read_text(encoding="utf-8", errors="replace"), (
                "the older generation is not the one that carried the "
                "teardown record")
        finally:
            handle.close()

    def case_warns_only_once_per_daemon(self, certdir, monkeypatch):
        """A pinned session makes these calls continuously; a line each would
        bury the signal it exists to be."""
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        p = self._proxy(certdir, lambda: None)
        for _ in range(5):
            p._warn_unpinnable()
        assert buf.getvalue().count("UNPINNED") == 1

    def case_health_reports_whether_the_pin_can_apply(self, certdir):
        """A daemon being up is not the same as the pin working. The sweep
        needs the second fact, and only the daemon can answer it."""
        import json as _json, socket as _s
        for provider, expect in ((lambda: "TOK", True), (lambda: None, False)):
            p = self._proxy(certdir, provider)
            p.start()
            try:
                c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
                c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                body = buf.partition(b"\r\n\r\n")[2]
                while not body.endswith(b"}"):
                    d = c.recv(4096)
                    if not d:
                        break
                    body += d
                c.close()
                assert _json.loads(body)["can_pin"] is expect
            finally:
                p.stop()

    def case_a_noop_pin_does_not_warn(self, certdir, monkeypatch):
        """Nothing-to-swap must not fire the keychain warning.

        When the pinned account IS the active one the provider correctly
        returns no token: the live bearer already belongs to it. Warning there
        sends whoever reads the log after a macOS keychain fault that is not
        there. Measured on host-c after the 79a665a deploy: daemon.log
        carried "the pinned account token could not be read ... started
        outside the GUI session" while the keychain read was fine (rc=0, 509
        bytes), and it cost the reader ten minutes.

        Drives the real swap path rather than asserting on a method call, so
        it fails if the guard is put anywhere the request does not reach.
        """
        import io
        import sys as _sys

        def provider():
            return None
        provider.pin_is_noop = lambda: True

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        p = self._proxy(certdir, provider)
        # A pinned route with no token: the exact condition that warns.
        assert self._drive_pinned_request(p) is None
        assert "UNPINNED" not in buf.getvalue(), "warned when nothing was wrong"

    def case_an_unreadable_store_still_warns(self, certdir, monkeypatch):
        """The quieting must not swallow the case the warning exists for."""
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        # No pin_is_noop hook: "cannot read" is the default reading of None.
        p = self._proxy(certdir, lambda: None)
        assert self._drive_pinned_request(p) is None
        assert "UNPINNED" in buf.getvalue(), "went silent on a real fail-open"

    def case_a_foreign_verdict_does_not_mask_a_later_real_failure(
            self, certdir, monkeypatch):
        """I2: the once-per-daemon latch used to be set on a foreign call
        too -- `_warn_unpinnable` only skipped `mark_daemon_unpinnable` for
        it, not the latch above that -- so ONE foreign episode silenced the
        warning AND the record for every later, genuinely unreadable store
        on this daemon for the rest of its life. The splice-site guard must
        keep a foreign call from reaching `_warn_unpinnable` at all, so the
        latch stays open for the failure it exists to report."""
        import io
        import sys as _sys
        import threading

        def foreign_provider():
            return None

        foreign_provider._tls = threading.local()
        foreign_provider._tls.foreign = True

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        p = self._proxy(certdir, foreign_provider)

        assert self._drive_pinned_request(p) is None
        assert "UNPINNED" not in buf.getvalue(), (
            "a foreign bearer warned with the wrong (keychain) advice")
        assert getattr(p, "_warned_unpinnable", False) is False, (
            "a foreign episode consumed the once-per-daemon latch, which "
            "would silence a LATER real failure on the same daemon"
        )

        # The SAME daemon, now genuinely unable to read the store -- the
        # case the warning exists for.
        p._pin_token_provider = lambda: None
        assert self._drive_pinned_request(p) is None
        assert "UNPINNED" in buf.getvalue(), (
            "the earlier foreign episode masked this later, real failure"
        )

    def case_a_noop_pin_reports_can_pin_on_health(self, certdir):
        """/health must not call a pin broken on the machine where it is a no-op.

        can_pin is what a fleet sweep reads. Reporting false where there is
        deliberately nothing to swap is a false alarm in the machine-readable
        channel, which is worse than the log line because nobody is there to
        judge it.
        """
        import json as _json, socket as _s

        def provider():
            return None
        provider.pin_is_noop = lambda: True

        p = self._proxy(certdir, provider)
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            body = buf.partition(b"\r\n\r\n")[2]
            while not body.endswith(b"}"):
                d = c.recv(4096)
                if not d:
                    break
                body += d
            c.close()
            assert _json.loads(body)["can_pin"] is True, (
                "reported the pin as broken on a machine where it has nothing to do"
            )
        finally:
            p.stop()

    def case_a_raising_provider_reports_cannot_pin(self, certdir):
        """Health must never take the daemon down, whatever the store does."""
        import json as _json, socket as _s

        def boom():
            raise RuntimeError("keychain unavailable")

        p = self._proxy(certdir, boom)
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            body = buf.partition(b"\r\n\r\n")[2]
            while not body.endswith(b"}"):
                d = c.recv(4096)
                if not d:
                    break
                body += d
            c.close()
            assert _json.loads(body)["can_pin"] is False
        finally:
            p.stop()

    def _stalled_provider(self, certdir):
        """A REAL provider whose `refresh_lock` is held forever by a helper
        thread stuck exactly the way a stalled Keychain read is: never
        raises, never returns, and unkillable from here (measured: `security
        find-generic-password -w` still hung after 2d19h). The caller must
        `event.set()` in a `finally` so the thread does not outlive the test.
        """
        import json as _json
        import threading

        from cswap_pin import proxy as pp

        expired = _json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt"}})

        class _Stuck:
            backup_dir = certdir
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e): return expired
            def resolve_account(self, i): return ("2", "pin@example.com", "org")

        pp.save_pin(certdir, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Stuck(), "2", "pin@example.com")
        event = threading.Event()

        def _hold():
            with provider.refresh_lock:
                event.wait()  # never set within the test: stuck forever

        holder = threading.Thread(target=_hold, daemon=True)
        holder.start()
        while not provider.refresh_lock.locked():
            import time as _time
            _time.sleep(0.001)
        return provider, event

    def case_health_never_waits_on_a_stalled_mint(self, certdir):
        """/health must answer well inside a 5s probe even when the mint's
        refresh lock is genuinely stuck, and say so rather than reading as a
        dead daemon -- see `_mint_lock_busy`."""
        import json as _json
        import socket as _s
        import time as _time

        provider, event = self._stalled_provider(certdir)
        try:
            p = self._proxy(certdir, provider)
            p.start()
            try:
                c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
                c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                started = _time.monotonic()
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                body = buf.partition(b"\r\n\r\n")[2]
                while not body.endswith(b"}"):
                    d = c.recv(4096)
                    if not d:
                        break
                    body += d
                elapsed = _time.monotonic() - started
                c.close()
                assert elapsed < 1.0, (
                    f"/health waited {elapsed:.2f}s on a stalled mint")
                doc = _json.loads(body)
                assert doc["mint_stalled"] is True, doc
                assert doc["can_pin"] is True, (
                    "busy is unknown, not a failure — reporting it broken "
                    "is the false alarm `can_pin` exists to avoid")
            finally:
                p.stop()
        finally:
            event.set()

    def case_a_pinned_request_fails_fast_on_a_stalled_mint(self, certdir,
                                                            monkeypatch):
        """A pinned route must not queue behind a refresh lock a stalled
        credential store may never release. Measured: 104 requests held
        'before headers' with a live socket answering nobody."""
        import time as _time

        from cswap_pin import proxy as pp

        monkeypatch.setattr(pp, "_MINT_LOCK_BOUND_S", 0.1)
        provider, event = self._stalled_provider(certdir)
        try:
            proxy = pp.PinProxy(certdir=certdir, pin_token_provider=provider,
                                upstream=("127.0.0.1", 1))

            class _FakeTLS:
                def __init__(self):
                    self._in = (
                        b"POST /v1/code/sessions HTTP/1.1\r\n"
                        b"Host: api.anthropic.com\r\n"
                        b"Authorization: Bearer disk-bearer\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    self.sent = b""

                def recv(self, n):
                    out, self._in = self._in[:n], self._in[n:]
                    return out

                def sendall(self, b):
                    self.sent += b

                def close(self):
                    pass

            tls = _FakeTLS()
            started = _time.monotonic()
            proxy._handle_one_request(tls)
            elapsed = _time.monotonic() - started
            assert elapsed < 1.0, (
                f"the pinned request waited {elapsed:.2f}s on a stalled mint")
            assert tls.sent.startswith(b"HTTP/1.1 503"), tls.sent
        finally:
            event.set()

    def _cold_wedged_provider(self, certdir):
        """A REAL provider whose credential store hangs on the very FIRST
        read -- the COLD-CACHE case (`_cred_cache` starts empty on every
        daemon start), not the already-cached-then-stuck-refresh case
        `_stalled_provider` drives. Never raises, never returns."""
        from cswap_pin import proxy as pp

        class _Wedged:
            backup_dir = certdir
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e):
                event.wait()  # never set within the test: stuck forever
                return None
            def resolve_account(self, i): return ("2", "pin@example.com", "org")

        pp.save_pin(certdir, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Wedged(), "2", "pin@example.com")
        event = threading.Event()
        return provider, event

    def case_health_never_calls_the_provider_directly(self, certdir):
        """`_serve_health` must never call `provider()` itself: a FREE lock
        does not mean the provider is cheap to call, and with a cold, wedged
        store the /health-handling thread would become the unkillable holder
        (nobody bounds the HOLDER, only a waiter -- see `_MINT_LOCK_BOUND_S`).
        Built without `.start()` so nothing else can race to the lock first
        -- this isolates `_serve_health`'s own behaviour from the daemon-
        start warm thread."""
        import socket as _s
        import time as _time

        from cswap_pin import proxy as pp

        provider, event = self._cold_wedged_provider(certdir)
        try:
            proxy = pp.PinProxy(certdir=certdir, pin_token_provider=provider,
                                upstream=("127.0.0.1", 1))
            server, client = _s.socketpair()
            t = threading.Thread(target=proxy._serve_health, args=(server,),
                                 daemon=True)
            started = _time.monotonic()
            t.start()
            client.settimeout(2.0)
            buf = b""
            try:
                while b"\r\n\r\n" not in buf:
                    d = client.recv(4096)
                    if not d:
                        break
                    buf += d
            except OSError:
                pass
            elapsed = _time.monotonic() - started
            client.close()
            assert elapsed < 1.0, (
                f"/health waited {elapsed:.2f}s -- it called the provider "
                "directly instead of reading only what is cached")
        finally:
            event.set()

    def case_a_cold_read_is_bounded_by_the_mint_lock(self, certdir, monkeypatch):
        """The COLD credential read used to run OUTSIDE `refresh_lock` --
        unbounded, and invisible to `_mint_lock_busy` -- so a wedged store on
        a fresh daemon (every handover, recycle and heal successor starts
        cold) blocked `/health` and every pinned request right along with it,
        forever. The FIRST caller becomes the holder and gets stuck inside
        the read; a SECOND caller must not queue behind it past the bound."""
        import time as _time

        from cswap_pin import proxy as pp

        monkeypatch.setattr(pp, "_MINT_LOCK_BOUND_S", 0.3)
        provider, event = self._cold_wedged_provider(certdir)
        holder = None
        try:
            assert pp._mint_lock_busy(provider) is None, (
                "the lock reads busy before anything has tried to mint")

            holder = threading.Thread(target=provider, daemon=True)
            holder.start()
            deadline = _time.monotonic() + 2.0
            while (pp._mint_lock_busy(provider) is None
                   and _time.monotonic() < deadline):
                _time.sleep(0.01)
            assert pp._mint_lock_busy(provider) is not None, (
                "a cold read in progress did not show up as the lock being "
                "held -- it used to run outside `refresh_lock` entirely")

            started = _time.monotonic()
            result = provider()
            elapsed = _time.monotonic() - started
            assert result is None
            assert elapsed < 1.0, (
                f"a waiter behind a cold read waited {elapsed:.2f}s")
            assert provider.mint_stalled() is True
        finally:
            event.set()
            if holder is not None:
                holder.join(timeout=2.0)

    def case_health_and_a_pinned_request_survive_a_cold_wedged_store(
            self, certdir, monkeypatch):
        """End to end: a fresh daemon's cold cache read is exactly the store
        access `/health` and a pinned request must never wait on unbounded."""
        import json as _json
        import socket as _s
        import time as _time

        from cswap_pin import proxy as pp

        monkeypatch.setattr(pp, "_MINT_LOCK_BOUND_S", 0.3)
        provider, event = self._cold_wedged_provider(certdir)
        try:
            p = self._proxy(certdir, provider)
            p.start()
            try:
                # Let the daemon-start warm engage the store before probing,
                # so this measures the bound, not a startup race.
                deadline = _time.monotonic() + 2.0
                while (pp._mint_lock_busy(p._pin_token_provider) is None
                       and _time.monotonic() < deadline):
                    _time.sleep(0.01)
                assert pp._mint_lock_busy(p._pin_token_provider) is not None, (
                    "the daemon-start warm never touched the store")

                c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
                c.settimeout(2.0)
                c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                started = _time.monotonic()
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                body = buf.partition(b"\r\n\r\n")[2]
                while not body.endswith(b"}"):
                    d = c.recv(4096)
                    if not d:
                        break
                    body += d
                elapsed = _time.monotonic() - started
                c.close()
                assert elapsed < 1.0, (
                    f"/health waited {elapsed:.2f}s on a cold, wedged store")
                doc = _json.loads(body)
                assert doc["mint_stalled"] is True, doc

                class _FakeTLS:
                    def __init__(self):
                        self._in = (
                            b"POST /v1/code/sessions HTTP/1.1\r\n"
                            b"Host: api.anthropic.com\r\n"
                            b"Authorization: Bearer disk-bearer\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        self.sent = b""
                    def recv(self, n):
                        out, self._in = self._in[:n], self._in[n:]
                        return out
                    def sendall(self, b):
                        self.sent += b
                    def close(self):
                        pass

                tls = _FakeTLS()
                started = _time.monotonic()
                p._handle_one_request(tls)
                elapsed = _time.monotonic() - started
                assert elapsed < 1.0, (
                    f"the pinned request waited {elapsed:.2f}s on a cold, "
                    "wedged store")
                assert tls.sent.startswith(b"HTTP/1.1 503"), tls.sent
            finally:
                p.stop()
        finally:
            event.set()

    def case_a_slow_cold_read_does_not_wedge_the_daemon(self, certdir):
        """`_serving_can_pin` probes `/health` up to `_PIN_PROBE_ATTEMPTS`
        times at `timeout` seconds each; the unlocked cold read used to pay
        its own cost on EVERY probe (measured: 2.5s hid behind all three), so
        a healthy but merely slow store read wedged and recycled a daemon
        that was fine. Driven here as `/health` itself must answer it --
        `_serving_can_pin`'s own wedge-vs-busy classification of that answer
        is `TestAWedgeIsNotTrustedForever`'s (test_proxy.py), and a real
        socket read past this daemon's response RSTs in this sandbox for
        ANY provider, healthy or not -- reproduced on baseline fb874da with
        an immediate `lambda: "TOK"` -- so this reads the safe way every
        other case in this class already does, not through that probe."""
        import json as _json
        import socket as _s
        import time as _time

        from cswap_pin import proxy as pp

        live = _json.dumps({"claudeAiOauth": {
            "accessToken": "TOK", "expiresAt": 4102444800000,
            "refreshToken": "rt"}})

        class _Slow:
            backup_dir = certdir
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e):
                _time.sleep(2.5)
                return live
            def resolve_account(self, i): return ("2", "pin@example.com", "org")

        pp.save_pin(certdir, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Slow(), "2", "pin@example.com")
        p = self._proxy(certdir, provider)
        p.start()
        try:
            # Let the daemon-start warm engage the store before probing, so
            # this measures the read's own cost, not a startup race against
            # the warm thread.
            deadline = _time.monotonic() + 2.0
            while (pp._mint_lock_busy(p._pin_token_provider) is None
                   and _time.monotonic() < deadline):
                _time.sleep(0.01)
            assert pp._mint_lock_busy(p._pin_token_provider) is not None, (
                "the daemon-start warm never touched the store")

            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.settimeout(1.0)
            c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            started = _time.monotonic()
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            body = buf.partition(b"\r\n\r\n")[2]
            while not body.endswith(b"}"):
                d = c.recv(4096)
                if not d:
                    break
                body += d
            elapsed = _time.monotonic() - started
            c.close()
            assert elapsed < 1.0, (
                f"/health waited {elapsed:.2f}s behind a healthy 2.5s cold "
                "read -- the same cost `_serving_can_pin` used to pay on "
                "every one of its probes")
            doc = _json.loads(body)
            assert doc["can_pin"] is True, (
                f"a healthy daemon with a 2.5s cold read was called a wedge: "
                f"{doc}")
        finally:
            p.stop()

    def case_mint_stalled_does_not_leak_across_threads(self, certdir,
                                                        monkeypatch):
        """`_stalled` used to be one flag shared by every request thread:
        cleared on entry by whoever calls `provider()` next, and read by
        whichever thread asks -- so a stall THIS thread caused could read as
        cleared by an unrelated caller, or an unrelated caller's stall could
        read as this thread's own."""
        import json as _json

        from cswap_pin import proxy as pp

        monkeypatch.setattr(pp, "_MINT_LOCK_BOUND_S", 0.05)

        expired = _json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt"}})

        class _Switcher:
            def current_account_number(self):
                # Thread "B" IS the pinned account already: a no-op, no lock.
                return "2" if threading.current_thread().name == "B" else "1"
            def read_account_credentials(self, n, e): return expired
            def resolve_account(self, i): return ("2", "pin@example.com", "org")

        pp.save_pin(certdir, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Switcher(), "2",
                                              "pin@example.com")
        event = threading.Event()

        def _hold():
            with provider.refresh_lock:
                event.wait()

        holder = threading.Thread(target=_hold, daemon=True)
        holder.start()
        while not provider.refresh_lock.locked():
            time.sleep(0.001)

        try:
            result = {}
            a_stalled = threading.Event()
            b_done = threading.Event()

            def _a():
                provider()  # cold, contends for the held lock, times out
                a_stalled.set()
                # Let B run its own call+check to completion BEFORE this
                # thread reads its own verdict -- the interleaving that
                # exposed a shared flag.
                b_done.wait(timeout=5)
                result["a"] = provider.mint_stalled()

            def _b():
                a_stalled.wait(timeout=5)
                provider()  # no-op: pin IS the live login, no lock touched
                result["b"] = provider.mint_stalled()
                b_done.set()

            ta = threading.Thread(target=_a, name="A")
            tb = threading.Thread(target=_b, name="B")
            ta.start()
            tb.start()
            ta.join(timeout=6)
            tb.join(timeout=6)

            assert result.get("b") is False, (
                "thread B's own call read a stall it never caused")
            assert result.get("a") is True, (
                "thread A's own stall was cleared by an unrelated thread's "
                f"call -- `_stalled` is shared, not per-call: {result}")
        finally:
            event.set()
            holder.join(timeout=2.0)

    def case_a_refresh_updates_the_cache_can_pin_stays_true(
            self, certdir, monkeypatch):
        """`provider()` wrote the pre-refresh (expired) credential into
        `_cred_cache` and never wrote the rotated one back, so
        `can_pin_cached()` -- and therefore `/health`'s `can_pin` -- kept
        reading a permanently-expired cache after every successful mint.
        Drives a REAL refresh through a switcher whose gate persists the
        rotated credential the way the host's does, then checks the CACHED
        read, not `provider()` again -- `can_pin_cached()` must never touch
        the store."""
        import json as _json
        import socket as _s

        from claude_swap.oauth import RefreshOutcome
        from cswap_pin import proxy as pp

        # R11: the suite must never dial api.anthropic.com. The mint-time
        # identity probe verifies the rotated token as the pin's own.
        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})

        expired = _json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt"}})
        rotated = _json.dumps({"claudeAiOauth": {
            "accessToken": "new", "expiresAt": 4102444800000,
            "refreshToken": "rt2"}})

        class _Switcher:
            backup_dir = certdir
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e): return expired
            def resolve_account(self, i): return ("2", "pin@example.com", "org")
            def consume_backup_grant(self, n, e, snap):
                # The gate persists internally, the way the host's does; the
                # mock only has to hand back what it rotated to.
                return RefreshOutcome(rotated, None)

        pp.save_pin(certdir, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Switcher(), "2",
                                              "pin@example.com")

        assert provider() == "new", "the refresh did not hand back the rotated token"
        assert provider.can_pin_cached() is True, (
            "the cache still held the expired blob after a successful refresh")

        p = self._proxy(certdir, provider)
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            body = buf.partition(b"\r\n\r\n")[2]
            while not body.endswith(b"}"):
                d = c.recv(4096)
                if not d:
                    break
                body += d
            c.close()
            doc = _json.loads(body)
            assert doc["can_pin"] is True, doc
            assert doc["mint_stalled"] is False, doc
        finally:
            p.stop()


class TestTheRequestPathNeverOpensTheTraceFile:
    """The shared trace handle used to be opened FROM the request thread.

    Measured on a live daemon: 342 `_serve_client` threads sharing one
    identical stack, all parked in the SAME `open(path, "a", ...)` call while
    a stalled filesystem let the accept loop and the trace's own already-open
    writer keep working. `self._debug` is ONE handle every request thread
    shares; re-arming the trace (or crossing its cap) used to null it and
    every thread then raced into `open(2)` at once.

    `PinProxy._trace_tick` (off `_title_sweep_loop`'s beat, never the request
    path) is now the only place that opens, rotates or re-targets it;
    `_write_capped_line` on the request path only ever writes to whatever is
    already open, or drops the line.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _proxy(self, certdir, provider=None):
        from cswap_pin.proxy import PinProxy
        return PinProxy(
            certdir=certdir,
            pin_token_provider=provider or (lambda: None),
            upstream=("127.0.0.1", 1),
        )

    class _FakeTLS:
        """One GET on an unpinned route — reaches the trace append without
        touching any bearer-swap machinery (`/v1/messages` is explicitly
        never pinned, and a non-POST never triggers the bridge sweep)."""

        def __init__(self):
            self._in = (
                b"GET /v1/messages HTTP/1.1\r\n"
                b"Host: api.anthropic.com\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            self.sent = b""

        def recv(self, n):
            out, self._in = self._in[:n], self._in[n:]
            return out

        def sendall(self, b):
            self.sent += b

        def close(self):
            pass

    def _drive_one(self, proxy):
        try:
            proxy._handle_one_request(self._FakeTLS())
        except Exception:
            pass  # the relay to the dead upstream (127.0.0.1:1) fails; unrelated

    def _arm(self, certdir):
        import cswap_pin.proxy as pp
        trace = certdir / "armed-trace.log"
        (certdir / pp._TRACE_SWITCH_FILE).write_text(str(trace))
        pp._TRACE_CACHE.clear()
        return trace

    def case_a_request_answers_within_2s_even_when_open_would_block(
            self, certdir, monkeypatch):
        """RED without the fix: the trace is armed, `self._debug` is unopened
        (the ordinary state right after an arm, or after the tick drops it at
        the cap), and `open()` on that path blocks forever. The old code
        opened it FROM this thread; the new code must never call it, so the
        request has to answer regardless of what `open()` on that path does.
        """
        import builtins

        trace = self._arm(certdir)
        never = threading.Event()
        real_open = builtins.open

        def _blocking_open(path, *a, **kw):
            if str(path) == str(trace):
                never.wait()  # never set: this IS the parked open(2)
            return real_open(path, *a, **kw)

        monkeypatch.setattr(builtins, "open", _blocking_open)

        proxy = self._proxy(certdir)
        proxy._debug = None

        t = threading.Thread(target=self._drive_one, args=(proxy,), daemon=True)
        t.start()
        t.join(2.0)
        assert not t.is_alive(), (
            "the request thread is still parked after 2s — the trace append "
            "called open(2) on the request path")

    def case_the_tick_opens_the_handle_and_requests_then_write_their_line(
            self, certdir):
        """Control: once `_trace_tick` has run, a request DOES write."""
        trace = self._arm(certdir)
        proxy = self._proxy(certdir)
        assert proxy._debug is None, "nothing has opened it yet"

        proxy._trace_tick()
        assert proxy._debug is not None, "the tick did not open the handle"

        self._drive_one(proxy)
        body = trace.read_text()
        assert "GET /v1/messages" in body, (
            f"the request did not reach the handle the tick opened: {body!r}")

    def case_at_the_cap_the_request_nulls_and_the_tick_rotates(
            self, certdir, monkeypatch):
        """The write side notices the cap and drops the reference — never
        closes it, never reopens it — and the NEXT tick is what rotates.

        Also covers the tick's OTHER trigger: a handle that crossed the cap
        without any request thread ever writing past it (so nothing nulled
        it) still gets rotated, because the tick checks the cap itself too.
        """
        import cswap_pin.proxy as pp

        trace = self._arm(certdir)
        monkeypatch.setattr(pp, "_TRACE_MAX_BYTES", 200)

        proxy = self._proxy(certdir)
        proxy._trace_tick()
        assert proxy._debug is not None

        crossed = False
        for _ in range(50):
            self._drive_one(proxy)
            if proxy._debug is None:
                crossed = True
                break
        assert crossed, "50 requests never crossed a 200-byte cap"
        rotated = trace.with_suffix(trace.suffix + ".1")
        assert not rotated.exists(), (
            "the request thread rotated the file itself — it must only drop "
            "the handle and leave rotation to the tick")

        proxy._trace_tick()
        assert proxy._debug is not None, "the tick did not reopen after the cap"
        assert rotated.exists(), "the tick did not rotate the over-cap file"

        # AND REQUESTS KEEP ANSWERING THROUGH ALL OF IT.
        for _ in range(5):
            self._drive_one(proxy)
        assert trace.exists()

        # THE TICK'S OWN CAP CHECK, independent of a write ever nulling the
        # handle first: hand it a handle that is already over cap. Retick
        # first so we hold a known-fresh handle rather than one the loop
        # above may already have nulled.
        proxy._trace_tick()
        handle = proxy._debug
        assert handle is not None
        handle.write("x" * 300 + "\n")
        assert not handle.closed
        proxy._trace_tick()
        assert proxy._debug is not handle, (
            "the tick kept serving an over-cap handle nobody nulled")

    def case_an_open_failure_on_the_tick_warns_once_and_never_raises(
            self, certdir, monkeypatch):
        """`_append_capped`'s own contract: "a trace that cannot be written is
        a diagnostic that is missing, not a proxy that stops relaying" —
        `_reopen_trace` holds to it, and does not spam a warning every 0.5s
        tick either."""
        import builtins
        import io
        import sys as _sys

        trace = self._arm(certdir)
        real_open = builtins.open

        def _raising_open(path, *a, **kw):
            if str(path) == str(trace):
                raise OSError("no space left on device")
            return real_open(path, *a, **kw)

        monkeypatch.setattr(builtins, "open", _raising_open)
        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)

        proxy = self._proxy(certdir)
        proxy._trace_tick()
        assert proxy._debug is None, "an open() that raised left a handle"
        proxy._trace_tick()
        assert proxy._debug is None

        self._drive_one(proxy)  # must not raise into the request

        warnings = buf.getvalue().count("could not be")
        assert warnings == 1, (
            f"expected exactly one warning across two failing ticks, got "
            f"{warnings}: {buf.getvalue()!r}")

    def case_a_write_that_races_a_close_does_not_reach_the_request(self):
        """`_write_capped_line`'s own null-safety, direct: a handle another
        thread let go of and closed between the caller's ``is not None``
        check and this call raises ValueError on ``write``, not OSError —
        the same race `_append_capped` already guards against."""
        import cswap_pin.proxy as pp

        class _ClosedUnderUs:
            closed = False

            def write(self, _):
                raise ValueError("I/O operation on closed file")

            def tell(self):
                return 0

        assert pp._write_capped_line(_ClosedUnderUs(), "x\n") is None, (
            "a handle that went away mid-write raised out of the trace and "
            "into the relay")


class TestTogglingThePinMidSessionActuallyWorks:
    """THE requirement, both halves: no restart, and the pin APPLIES.

    A session's HTTPS_PROXY is fixed at exec, so anything the daemon keys off
    that variable is unchangeable for a running session. The gate did key off
    it, so turning the pin on 407'd every session that predated the credential
    (measured: 313 processes, including the one that ran `cswap pin`).

    Softening that to "serve them unpinned" fixes the 407 and fails the
    feature: `cswap pin 1` would leave the sessions the user is looking at on
    the active account. Both halves have to hold at once —

        claude.ai side (RC / artifacts) -> PINNED account
        CLI side       (inference)      -> ACTIVE account

    — for a session that never carried a credential, across the toggle.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_rc_swaps_and_inference_does_not_for_an_uncredentialed_session(
        self, certdir
    ):
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            assert _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions", bearer="disk-token",
            ) == 200
            assert upstream.seen_auth == "Bearer PIN-TOKEN", (
                "the pin did not apply to a session that predates it — "
                "`cswap pin` silently did nothing for the sessions in front "
                "of the user"
            )

            assert _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/messages", bearer="disk-token",
            ) == 200
            assert upstream.seen_auth == "Bearer disk-token", (
                "inference was billed to the pinned account"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def case_clearing_returns_rc_to_the_active_account(self, certdir):
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        token = {"v": "PIN-TOKEN"}
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: token["v"],
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            _request_through_proxy(proxy.port, certdir / "ca.pem",
                                   "/v1/code/sessions", bearer="disk-token")
            assert upstream.seen_auth == "Bearer PIN-TOKEN"

            # `cswap pin --clear`: the record goes, so the provider yields
            # nothing and the route falls back to the request's own bearer.
            token["v"] = None
            assert _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions", bearer="disk-token",
            ) == 200
            assert upstream.seen_auth == "Bearer disk-token", (
                "clearing the pin left RC on the pinned account"
            )
        finally:
            proxy.stop()
            upstream.stop()


class TestAMisroutedSwapCannotKillASession:
    """A 401/403/404 caused by OUR swap must never reach the client.

    Those three are terminal in Claude Code: SSETransport treats them as
    permanent (M7y = new Set([401,403,404])), sets state="closed", and never
    reconnects — so ONE misrouted request ends Remote Control for the life of
    the process. Measured: a /worker-swap experiment produced 26 such
    responses and severed the inbound channel of four sessions that were still
    running hours later with bridgeSessionId gone.

    That makes the route predicate a single point of PERMANENT failure, and no
    amount of care in it removes the risk — a route we have not seen yet can
    always be classified wrong. Retrying without the swap turns "wrong about
    this route" into "this request went out unpinned", which is the failure
    the module is already built to tolerate.
    """
    def test_all(self, request, tmp_path_factory):
        run_cases(
            self,
            request,
            tmp_path_factory,
            # this class wants the CA one level down, in `pin-proxy/`
            extra={"certdir": lambda t: _make_certdir(_mkdir(t / "pin-proxy"))},
        )

    def case_a_403_on_a_swapped_route_is_retried_unswapped(self, certdir):
        """The upstream refuses the pinned bearer; the client must still get a
        real answer, carrying its OWN bearer."""
        from cswap_pin.proxy import PinProxy

        seen = []

        class Upstream(_FakeUpstream):
            def handle(self, auth):  # pragma: no cover - shape only
                seen.append(auth)

        upstream = _FakeUpstream(certdir, reject_bearer="PIN-TOKEN")
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions", bearer="disk-token",
            )
            assert status != 403, (
                "a swap the upstream refused reached the client — that is "
                "terminal in SSETransport and ends Remote Control permanently"
            )
            assert upstream.seen_auth == "Bearer disk-token", (
                "the retry did not fall back to the request's own bearer"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def case_an_artifact_route_never_falls_back_to_the_active_account(
            self, certdir, monkeypatch):
        """T1592: on `/api/frame/` and `/api/oauth/files/` the take-back must
        never resend as the ACTIVE account. Measured on lmd42 2026-09-29
        04:36:09Z: `GET /api/frame/frames/external` went out swapped to the
        pinned slot, got 403, found no newer token and was resent with the
        session's own bearer, so an artifact request left as another account
        (rc-gate row 13). The pinned account's own answer goes to the client.

        Each row is a refused pinned request on an artifact route, with no
        rotation (`dead`) and with a rotation that is refused too (`rotated`,
        so the refetch retry still runs). Nothing but a pin bearer may reach
        the upstream, the client gets the 403, and the log says `relayed as
        the pin`, never `fell-back`. THE CONTROL is a pinned route that is
        not an artifact, on the same proxy: it still falls back to the
        session's own bearer (4e8fcd3: a 401/403/404 is terminal to the
        client).

        T1596: a 401 twin of each row. Claude Code reads a 401 as ITS OWN
        credential failing (a relayed 401 kills subagents), so the pin's
        refusal reaches the client as a 403 and the unarmed third send does
        not happen."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})
        pp.save_pin(certdir, "pin@example.com", "org")
        rows = [
            ("dead", 403, "/api/frame/frames/external", lambda n: "dead-token",
             ["Bearer dead-token"] * 2, ["relayed as the pin"]),
            ("rotated", 403, "/api/oauth/files/abc/content",
             lambda n: "stale-token" if n == 1 else "fresh-token",
             ["Bearer stale-token", "Bearer fresh-token", "Bearer fresh-token"],
             ["retried-fresh", "relayed as the pin"]),
            ("dead-401", 401, "/api/frame/frames/external",
             lambda n: "dead-token", ["Bearer dead-token"],
             ["relayed as the pin as 403"]),
            ("rotated-401", 401, "/api/oauth/files/abc/content",
             lambda n: "stale-token" if n == 1 else "fresh-token",
             ["Bearer stale-token", "Bearer fresh-token"],
             ["retried-fresh", "relayed as the pin as 403"]),
        ]
        for (name, code, path, token_for_read, expect_auths,
             expect_outcomes) in rows:
            provider = pp.make_pin_token_provider(
                _refetch_switcher(certdir, token_for_read), "2",
                "pin@example.com")
            upstream = _FakeUpstream(
                certdir, reject_status=code,
                reject_bearer={"dead-token", "stale-token", "fresh-token"})
            proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                             upstream=("127.0.0.1", upstream.port))
            lines = []
            real_log = pp._log_lifecycle
            pp._log_lifecycle = lines.append
            proxy.start()
            try:
                status = _request_through_proxy(
                    proxy.port, certdir / "ca.pem", path, bearer="disk-token")
                assert status == 403, (
                    f"{name}: the pinned account's own refusal must reach "
                    f"the client: {status}")
                assert upstream.auths_seen == expect_auths, (
                    f"{name}: only the pinned bearer may reach the upstream "
                    f"on an artifact route: {upstream.auths_seen}")
                assert [ln for ln in lines if ln.startswith("swap refused")
                        ] == [f"swap refused ({code}) on POST {path}: {o}"
                              for o in expect_outcomes], f"{name}: {lines}"
                # THE CONTROL: not an artifact route, so it still falls back.
                upstream.auths_seen.clear()
                status = _request_through_proxy(
                    proxy.port, certdir / "ca.pem", "/api/oauth/validate",
                    bearer="disk-token")
                assert status == 200 and upstream.auths_seen[-1] == (
                    "Bearer disk-token"), (
                    f"{name}: a non-artifact pinned route must still fall "
                    f"back: {status} {upstream.auths_seen}")
                assert (f"swap refused ({code}) on POST /api/oauth/validate: "
                        "fell-back") in lines, f"{name}: {lines}"
            finally:
                proxy.stop()
                upstream.stop()
                pp._log_lifecycle = real_log

    def case_an_absolute_form_artifact_route_never_falls_back_to_the_active_account(
            self, certdir, monkeypatch):
        """T1592: the absolute-form twin of the MITM case above. A refused
        pinned request on an artifact route (`/api/frame/...`) is relayed as
        the pin's own 403 after the refetch retry, and no request carrying
        the session's own bearer reaches the hop. T1596: a 401 there is
        answered to the client as a 403 (Claude Code reads a 401 as its own
        credential failing). THE CONTROL, on the same proxy:
        `/api/oauth/validate` still falls back."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})
        pp.save_pin(certdir, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(
            _refetch_switcher(
                certdir,
                lambda n: "stale-token" if n == 1 else "fresh-token"),
            "2", "pin@example.com")
        chain = _RecordingChain(
            lambda req: (b"HTTP/1.1 %d X\r\nContent-Length: 0\r\n\r\n"
                         % (401 if b"/api/oauth/files/" in req else 403)
                         if (b"Bearer stale-token" in req
                             or b"Bearer fresh-token" in req) else
                         b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                             rediscover_chain=True)
            proxy.start()

            def _send(path):
                c = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                try:
                    c.sendall(
                        f"GET https://api.anthropic.com{path} HTTP/1.1\r\n"
                        f"Host: api.anthropic.com\r\n"
                        f"Authorization: Bearer disk-token\r\n\r\n"
                        .encode("latin1"))
                    return c.recv(256)
                finally:
                    c.close()

            got = _send("/api/frame/frames/external")
            assert got.startswith(b"HTTP/1.1 403"), (
                f"the pinned account's own refusal must reach the client: "
                f"{got[:60]!r}")
            assert not any(b"disk-token" in r for r in chain.seen), (
                "an artifact request went out as the session's own account: "
                f"{chain.seen!r}")
            assert [ln for ln in lines if ln.startswith("swap refused")] == [
                "swap refused (403) on GET /api/frame/frames/external: "
                "retried-fresh",
                "swap refused (403) on GET /api/frame/frames/external: "
                "relayed as the pin",
            ], lines
            # T1596: the pin's 401 (chain answers 401 on the files route)
            # reaches the client as a 403, sent from here, not as a third send.
            sent = len(chain.seen)
            got = _send("/api/oauth/files/abc/content")
            assert got.startswith(b"HTTP/1.1 403"), (
                f"a 401 on an artifact route must not reach the client: "
                f"{got[:60]!r}")
            assert len(chain.seen) == sent + 1 and not any(
                b"disk-token" in r for r in chain.seen), chain.seen
            assert ("swap refused (401) on GET /api/oauth/files/abc/content: "
                    "relayed as the pin as 403") in lines, lines
            # THE CONTROL: not an artifact route, so it still falls back.
            got = _send("/api/oauth/validate")
            assert got.startswith(b"HTTP/1.1 200"), got[:60]
            assert b"Bearer disk-token" in chain.seen[-1]
            assert ("swap refused (403) on GET /api/oauth/validate: "
                    "fell-back") in lines, lines
        finally:
            if proxy:
                proxy.stop()
            chain.stop()
            pp._log_lifecycle = real_log

    def case_a_missing_authorization_header_is_not_falsely_retried_fresh(
            self, certdir, monkeypatch):
        """T1193: a pinned request that arrives with NO `Authorization`
        header has nothing to substitute, so it must never be armed for a
        take-back in the first place -- the same guard the absolute-form
        path already applies before ever calling in (`unswapped` is armed
        only when an Authorization header exists). `swapped` used to be
        set unconditionally once a token was minted, so a request with no
        Authorization header was sent, refused, and RE-SENT byte-identical
        by the take-back -- twice on the wire for one arrival, and a
        `swap refused ... fell-back` line logged for a request that was
        never actually swapped (rc-gate row 13 counts that line as an
        artifact FAIL)."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})

        pp.save_pin(certdir, "pin@example.com", "org")
        switcher = _refetch_switcher(certdir, lambda n: "pin-token")
        provider = pp.make_pin_token_provider(switcher, "2", "pin@example.com")

        upstream = _FakeUpstream(
            certdir, reject_missing_auth=True, reject_status=401)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=provider,
            upstream=("127.0.0.1", upstream.port),
        )
        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        proxy.start()
        try:
            # NOT `/v1/code/sessions` -- every POST there unconditionally
            # triggers `_should_sweep_bridges`' own upstream call, which
            # would land on this SAME fake upstream and contaminate
            # `auths_seen` on a timing that races this request. Every
            # other case in this class uses this route for the same
            # reason.
            # A genuine 401 IS the right answer here: there is nothing to
            # swap, so the upstream's own refusal is the only honest
            # answer -- and it must be reached with exactly ONE request,
            # never a take-back re-sending the same bytes.
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/api/frame/deploy/direct",
            )
            assert status == 401, f"expected the upstream's own refusal: {status}"
            assert len(upstream.auths_seen) == 1, (
                "a request with no Authorization header was never actually "
                f"swapped, so it must reach the upstream exactly once, not "
                f"be re-sent by a take-back: {upstream.auths_seen}"
            )
            swap_lines = [ln for ln in lines if ln.startswith("swap refused")]
            assert not swap_lines, (
                f"nothing was swapped, so there is nothing to take back and "
                f"no 'swap refused' line to log: {lines}"
            )
            assert getattr(proxy, "_warned_unpinnable", False) is False, (
                "a resolved token with no Authorization header to rewrite "
                "fell into the fail-open branch and warned UNPINNED, though "
                "the pin itself resolved fine"
            )
        finally:
            proxy.stop()
            upstream.stop()
            pp._log_lifecycle = real_log

    def case_a_swap_refused_line_is_keyed_on_three_segments_under_api_oauth(
            self, certdir):
        """T1193: `/api/oauth/files/<id>/content` (an rc-gate row 13
        artifact route) used to share its two-segment family
        (`/api/oauth`) with `/api/oauth/validate` and `/api/oauth/profile`
        -- a files fall-back inside a validate fall-back's own cooldown
        folded into the validate line's "; N more", and the gate could
        read PASS off a suppressed line naming a different route than the
        one it was counting. Three requests, one cooldown: files (its own
        family), validate (its own family, absolute-form with a `?query`),
        then validate again with a DIFFERENT query -- same family, so it
        must fold rather than print its own line, which is only true if
        the query is stripped BEFORE the family is computed, not carried
        into it (the absolute-form `rel.split("?", 1)[0]` this exercises).
        Red against all three reverts if any is undone: outcome-alone
        (files and validate would share one line), two segments (both
        collapse to `/api/oauth`, same result), or a dropped query strip
        (the second validate would print its own line instead of
        folding).

        T1592: an artifact route no longer falls back at all, so the files
        request of the first version is now `/api/oauth/file_upload` (the
        write half of that pair, pinned and not an artifact route): the
        same three-segment split, the same three reverts."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        def _reject_pin_token(req_bytes):
            head = req_bytes.split(b"\r\n\r\n", 1)[0]
            auth = None
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"authorization:"):
                    auth = line.split(b":", 1)[1].strip()
            if auth == b"Bearer PINTOKEN":
                return (b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                        b"Connection: close\r\n\r\n")
            return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

        chain = _RecordingChain(_reject_pin_token)
        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir,
                             pin_token_provider=lambda: "PINTOKEN",
                             rediscover_chain=True)
            proxy.start()

            def _send(path):
                c = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                try:
                    c.sendall(
                        f"POST https://api.anthropic.com{path} HTTP/1.1\r\n"
                        f"Host: api.anthropic.com\r\n"
                        f"Authorization: Bearer disk-token\r\n"
                        f"Content-Length: 0\r\n\r\n".encode("latin1"))
                    c.settimeout(10)
                    got = b""
                    while b"\r\n\r\n" not in got:
                        d = c.recv(4096)
                        if not d:
                            break
                        got += d
                    return got
                finally:
                    c.close()

            resp_upload = _send("/api/oauth/file_upload?sig=abc")
            resp_validate = _send("/api/oauth/validate")
            resp_validate2 = _send("/api/oauth/validate?x=2")
            for name, got in (("upload", resp_upload),
                              ("validate", resp_validate),
                              ("validate2", resp_validate2)):
                assert got.startswith(b"HTTP/1.1 200"), f"{name}: {got[:60]!r}"

            swap_lines = [ln for ln in lines if ln.startswith("swap refused")]
            assert swap_lines == [
                "swap refused (401) on POST /api/oauth/file_upload: "
                "fell-back",
                "swap refused (401) on POST /api/oauth/validate: fell-back",
            ], (
                f"an upload fall-back must not share a line with a validate "
                f"fall-back, and a second validate fall-back (even with a "
                f"different query) must fold into the first instead of "
                f"printing its own line: {lines}"
            )
        finally:
            if proxy:
                proxy.stop()
            chain.stop()
            pp._log_lifecycle = real_log

    def case_the_refetch_takes_every_shape_the_real_provider_can_answer(
            self, certdir, monkeypatch):
        """T1155 pass 3: the swap-refused retry, THROUGH THE REAL
        `make_pin_token_provider` (T1155 I2) -- a bare callable's own
        call counter goes green even when a retry calls `provider()`
        AGAIN instead of forcing a genuine store re-read, because the
        real provider's fast path returns the SAME cached, unexpired
        token on every call (`_live_token` only checks `expiresAt`).
        Only a switcher whose disk read genuinely runs proves any of
        these branches rather than their absence.

        One table, one runner -- the six rows differed only in the
        switcher's per-read tokens, the rejected bearer(s), and which
        assertions apply:

          a: a rotation refused once, then accepted on the fresh read
             (`retried-fresh`).
          CONTROL: the same dead token twice -- eviction buys nothing,
             no second swapped attempt (`fell-back`, no retried-fresh).
          b: the fresh retry is ALSO refused (T1155 m3) -- a missing
             branch here let `_AuthRejected` escape as `keep` and drop
             the connection instead of falling back unswapped.
          c: an empty re-read (T1155 pass 3 (b)) must not blind
             `provider` when a live credential is already cached.
          d: a re-read landing on a FOREIGN account (T1155 pass 3 (d))
             must not be spliced in -- the same `_identity_ok` gate
             every other cold-path read runs.
          e: a re-read that RAISES (a locked Keychain) must still fall
             back rather than drop the connection.

        Sent to `/api/oauth/validate`, a pinned route that is NOT an
        artifact route: `/api/frame/` and `/api/oauth/files/` relay the
        pin's own refusal and never fall back (T1592).
        """
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        def _default_profile(token):
            return {"emailAddress": "pin@example.com"}

        foreign_profiles = {
            "pin-token": {"emailAddress": "pin@example.com"},
            "foreign-token": {"accountUuid": "foreign-uuid",
                              "emailAddress": "someone-else@example.com"},
        }

        def _raises_on_second_read(n):
            if n == 1:
                return "stale-token"
            raise OSError("Keychain locked")

        rows = [
            dict(name="a: stale token retried with a fresh one",
                 token_for_read=lambda n: "stale-token" if n == 1 else "fresh-token",
                 reject_bearer="stale-token", reject_status=401,
                 status_ok=lambda s: s == 200,
                 expect_auths=["Bearer stale-token", "Bearer fresh-token"],
                 expect_reads=2,
                 expect_swap_lines=[
                     "swap refused (401) on POST /api/oauth/validate: "
                     "retried-fresh"]),
            dict(name="CONTROL: the same dead token still falls back",
                 token_for_read=lambda n: "dead-token",
                 reject_bearer="dead-token", reject_status=403,
                 status_ok=lambda s: s != 403,
                 expect_auths=["Bearer dead-token", "Bearer disk-token"],
                 expect_reads=2,
                 expect_swap_lines=[
                     "swap refused (403) on POST /api/oauth/validate: "
                     "fell-back"]),
            dict(name="b: a fresh retry that is also refused falls back unswapped",
                 token_for_read=lambda n: "stale-token" if n == 1 else "also-stale-token",
                 reject_bearer={"stale-token", "also-stale-token"}, reject_status=401,
                 status_ok=lambda s: s == 200,
                 expect_auths=["Bearer stale-token", "Bearer also-stale-token",
                               "Bearer disk-token"],
                 expect_swap_lines=[
                     "swap refused (401) on POST /api/oauth/validate: "
                     "retried-fresh",
                     "swap refused (401) on POST /api/oauth/validate: "
                     "fell-back"]),
            dict(name="c: an empty re-read falls back without emptying the cache",
                 token_for_read=lambda n: "stale-token" if n == 1 else "",
                 reject_bearer="stale-token", reject_status=401,
                 status_ok=lambda s: s == 200,
                 expect_auths=["Bearer stale-token", "Bearer disk-token"],
                 expect_reads=2, expect_can_pin_cached=True,
                 expect_blind_reason=""),
            dict(name="d: a foreign re-read is not spliced in",
                 token_for_read=lambda n: "pin-token" if n == 1 else "foreign-token",
                 reject_bearer="pin-token", reject_status=401,
                 status_ok=lambda s: s == 200,
                 expect_auths=["Bearer pin-token", "Bearer disk-token"],
                 expect_reads=2, profile_for=foreign_profiles.__getitem__),
            dict(name="e: a raising re-read still falls back unswapped",
                 token_for_read=_raises_on_second_read,
                 reject_bearer="stale-token", reject_status=401,
                 status_ok=lambda s: s == 200,
                 expect_auths=["Bearer stale-token", "Bearer disk-token"],
                 expect_reads=2),
        ]

        for row in rows:
            monkeypatch.setattr(
                pp, "pin_profile_for", row.get("profile_for", _default_profile))
            pp.save_pin(certdir, "pin@example.com", "org")
            switcher = _refetch_switcher(certdir, row["token_for_read"])
            provider = pp.make_pin_token_provider(switcher, "2", "pin@example.com")

            upstream = _FakeUpstream(
                certdir, reject_bearer=row["reject_bearer"],
                reject_status=row["reject_status"])
            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=provider,
                upstream=("127.0.0.1", upstream.port),
            )
            lines = []
            real_log = pp._log_lifecycle
            pp._log_lifecycle = lines.append
            proxy.start()
            try:
                status = _request_through_proxy(
                    proxy.port, certdir / "ca.pem",
                    "/api/oauth/validate", bearer="disk-token",
                )
                assert row["status_ok"](status), f"{row['name']}: got {status}"
                assert upstream.auths_seen == row["expect_auths"], (
                    f"{row['name']}: {upstream.auths_seen}")
                if row.get("expect_reads") is not None:
                    assert switcher.reads == row["expect_reads"], (
                        f"{row['name']}: {switcher.reads} reads")
                if row.get("expect_swap_lines") is not None:
                    # Filtered, not an exact-list compare of `lines`:
                    # `proxy.start()` logs its own startup lines too.
                    swap_lines = [ln for ln in lines
                                 if ln.startswith("swap refused")]
                    assert swap_lines == row["expect_swap_lines"], (
                        f"{row['name']}: {lines}")
                if row.get("expect_can_pin_cached") is not None:
                    assert (provider.can_pin_cached()
                           is row["expect_can_pin_cached"]), (
                        f"{row['name']}: can_pin_cached mismatch")
                if row.get("expect_blind_reason") is not None:
                    # AN EMPTY RE-READ MUST NOT BLIND `provider` when a
                    # live credential is already cached -- `can_pin_cached`
                    # alone does not prove that: it is set from the cache,
                    # never from `blind_reason`, so a docstring's claim
                    # about blinding needs its own assertion.
                    assert provider.blind_reason == row["expect_blind_reason"], (
                        f"{row['name']}: blind_reason={provider.blind_reason!r}")
            finally:
                proxy.stop()
                upstream.stop()
                pp._log_lifecycle = real_log

    def case_a_later_rotation_is_refetched_even_after_an_unchanged_read(
            self, certdir, monkeypatch):
        """T1155 pass 3: `_refetch_memo` used to remember "X was refused,
        nothing new" and skip the NEXT re-read for the identical bearer --
        which is exactly the shape of a real rotation landing between two
        DIFFERENT refused requests, not the polled-404 case the memo
        existed for. Deleting the memo must not cost a genuine later
        rotation its retry."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})

        pp.save_pin(certdir, "pin@example.com", "org")
        # 1: the cold warm-up swap. 2: the FIRST refusal's re-read,
        # unchanged -- the store has not rotated yet. 3: the SECOND
        # refusal's re-read, now rotated.
        switcher = _refetch_switcher(
            certdir, lambda n: "token-A" if n <= 2 else "token-B")
        provider = pp.make_pin_token_provider(switcher, "2", "pin@example.com")

        upstream = _FakeUpstream(
            certdir, reject_bearer="token-A", reject_status=401)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=provider,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status1 = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/api/oauth/validate", bearer="disk-token",
            )
            assert status1 == 200, (
                f"the first (unrotated) refusal must still fall back "
                f"cleanly: got {status1}")
            status2 = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/api/oauth/validate", bearer="disk-token",
            )
            assert status2 == 200, (
                "a rotation landing between two refused requests must "
                f"still be retried: got {status2}")
            assert switcher.reads == 3, (
                "the second refusal must force its own genuine re-read, "
                f"not be blocked by a memo of the first: {switcher.reads} reads"
            )
            assert upstream.auths_seen == [
                "Bearer token-A", "Bearer disk-token",
                "Bearer token-A", "Bearer token-B",
            ], (
                "expected the first request's swap-then-fallback, then the "
                f"second request's swap and its rotated retry: "
                f"{upstream.auths_seen}"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def case_a_swapped_upgrade_refused_401_is_retried_fresh_and_still_gets_101(
            self, certdir, monkeypatch):
        """T1155: the gap. `/api/frame/sync` (artifact sync, the RC comment
        watch/wake route) is a pinned route reached as a WebSocket upgrade.
        `_relay_upgrade` used to relay a 401/403/404 straight to the client
        -- terminal in SSETransport, same as the HTTP path above -- with no
        refetch and no retry. A stale cached pinned token refused must get
        the SAME treatment as the HTTP path: refetch once
        (`_refetch_swap_token`), retry swapped, and the client sees only
        the eventual 101."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})
        pp.save_pin(certdir, "pin@example.com", "org")
        switcher = _refetch_switcher(
            certdir, lambda n: "stale-token" if n == 1 else "fresh-token")
        provider = pp.make_pin_token_provider(switcher, "2", "pin@example.com")

        up = _WebSocketAuthUpstream(certdir, reject_bearer="stale-token",
                                    reject_status=401)
        proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                         upstream=("127.0.0.1", up.port))
        proxy.start()
        try:
            status, tls = _upgrade_via_proxy(
                proxy.port, certdir / "ca.pem", "/api/frame/sync",
                bearer="disk-token")
            assert b"101" in status, (
                "a refused swap on an upgrade must be retried fresh, not "
                f"handed to the client as-is: {status!r}")
            tls.sendall(b"PING")
            assert tls.recv(4096) == b"PONG"
            tls.close()
        finally:
            proxy.stop()
            up.stop()
        assert up.auths_seen == ["Bearer stale-token", "Bearer fresh-token"], (
            up.auths_seen)

    def case_a_dead_pinned_token_on_an_artifact_upgrade_answers_403_not_401(
            self, certdir, monkeypatch):
        """T1596: `/api/frame/sync` is an artifact route, so a dead pinned
        token is never taken back to the active account, and the client must
        not see the 401 either: Claude Code reads a 401 as its own
        credential failing. It gets a 403, after ONE upstream attempt."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})
        pp.save_pin(certdir, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(
            _refetch_switcher(certdir, lambda n: "dead-token"), "2",
            "pin@example.com")
        up = _WebSocketAuthUpstream(certdir, reject_bearer="dead-token",
                                    reject_status=401)
        proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                         upstream=("127.0.0.1", up.port))
        proxy.start()
        try:
            status, tls = _upgrade_via_proxy(
                proxy.port, certdir / "ca.pem", "/api/frame/sync",
                bearer="disk-token")
            tls.close()
        finally:
            proxy.stop()
            up.stop()
        assert b"403" in status, status
        assert up.auths_seen == ["Bearer dead-token"], up.auths_seen

    def case_a_dead_pinned_token_on_an_upgrade_falls_back_unswapped(
            self, certdir, monkeypatch):
        """Control: the pinned account is really dead (every read answers
        the same refused token), not a stale cache. One retry, then the
        same disk-bearer fallback the HTTP path takes, and one `swap
        refused ... fell-back` log line -- never a client-visible
        401/403/404."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})
        pp.save_pin(certdir, "pin@example.com", "org")
        switcher = _refetch_switcher(certdir, lambda n: "dead-token")
        provider = pp.make_pin_token_provider(switcher, "2", "pin@example.com")

        up = _WebSocketAuthUpstream(certdir, reject_bearer="dead-token",
                                    reject_status=403)
        proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                         upstream=("127.0.0.1", up.port))
        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        proxy.start()
        try:
            status, tls = _upgrade_via_proxy(
                proxy.port, certdir / "ca.pem", "/api/oauth/validate",
                bearer="disk-token")
            assert b"101" in status, (
                f"the unswapped fallback must still complete the upgrade: "
                f"{status!r}")
            tls.close()
            assert up.auths_seen == ["Bearer dead-token", "Bearer disk-token"], (
                up.auths_seen)
            swap_lines = [ln for ln in lines if ln.startswith("swap refused")]
            assert swap_lines == [
                "swap refused (403) on GET /api/oauth/validate: fell-back"
            ], lines
        finally:
            proxy.stop()
            up.stop()
            pp._log_lifecycle = real_log

    def case_a_non_swapped_upgrade_refused_is_relayed_untouched(self, certdir):
        """Control: a route `is_pinned_route` never swaps (the `/worker`
        subtree keeps its own session JWT, per that function's docstring)
        must see NO refetch and NO retry on refusal -- the refused response
        is the client's, verbatim, after exactly one upstream attempt."""
        from cswap_pin.proxy import PinProxy

        up = _WebSocketAuthUpstream(certdir, reject_bearer="disk-token",
                                    reject_status=403)
        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: "PINTOKEN",
                         upstream=("127.0.0.1", up.port))
        proxy.start()
        try:
            status, tls = _upgrade_via_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions/cse_x/worker/events/stream",
                bearer="disk-token")
            assert b"403" in status, (
                f"a non-swapped route's own refusal must reach the client "
                f"untouched: {status!r}")
            tls.close()
        finally:
            proxy.stop()
            up.stop()
        assert up.auths_seen == ["Bearer disk-token"], (
            f"a non-pinned route must never retry on refusal: {up.auths_seen}")


class TestThePolicyQuestionIsNeverAnsweredAsAnotherAccount:
    """CC 2.1.286 TEARS DOWN EVERY CONNECTED REMOTE CONTROL BRIDGE when its
    org-policy verdict turns to an explicit `allow_remote_control` deny, and a
    FAILED fetch of `/api/claude_code/policy_limits` keeps CC on its cached
    verdict or the document on disk, so a request this daemon cannot answer as
    the pin must not be answered as the ACTIVE account: that account's org may
    deny. A failed or deferred mint, and a pinned token that is still refused
    after the refetch, answer a local 503 on this ONE route. A pin that is
    cleared, or that IS the live login, has nothing to swap and keeps relaying
    on the session's own bearer."""

    POLICY = "/api/claude_code/policy_limits"
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _provider(self, certdir, monkeypatch, token=lambda n: "",
                  pinned=True, active="1", busy=False):
        """A REAL provider over a store whose n-th read answers `token(n)`
        ("" is an unreadable credential, "expired" an expired one).
        `pinned=False` is a CLEARED pin; `active="2"` makes the pinned slot
        the live login; `busy` makes the refresh gate answer `consume-busy`
        (a deferral)."""
        import cswap_pin.proxy as pp

        monkeypatch.setattr(
            pp, "pin_profile_for",
            lambda token: {"emailAddress": "pin@example.com"})
        reads = []

        class _Sw:
            backup_dir = certdir

            def current_account_number(self):
                return active

            def _get_sequence_data(self):
                return {"activeAccountNumber": active}

            def read_account_credentials(self, n, e):
                reads.append(n)
                t = token(len(reads))
                if not t:
                    return ""
                return json.dumps({"claudeAiOauth": {
                    "accessToken": t, "refreshToken": "rt",
                    "expiresAt": 1 if t == "expired" else 4102444800000}})

            def resolve_account(self, i):
                return ("2", "pin@example.com", "org")

        if busy:
            from claude_swap.oauth import RefreshOutcome
            _Sw.consume_backup_grant = lambda self, n, e, snap: \
                RefreshOutcome(None, "consume-busy")
        if pinned:
            pp.save_pin(certdir, "pin@example.com", "org")
        return pp.make_pin_token_provider(_Sw(), "2", "pin@example.com")

    def _ask(self, certdir, provider, path=None, lines=None,
             reject=("pin-token",), reject_status=403):
        """One GET of `path` (the policy route by default) with the session's
        own bearer through a real daemon; `(status, bearers the upstream
        saw)`. `lines` collects the lifecycle log."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir, reject_bearer=set(reject),
                                 reject_status=reject_status)
        proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                         upstream=("127.0.0.1", upstream.port))
        real_log = pp._log_lifecycle
        if lines is not None:
            pp._log_lifecycle = lines.append
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", path or self.POLICY,
                bearer="session-bearer", method="GET", body=None)
            return status, list(upstream.auths_seen)
        finally:
            proxy.stop()
            upstream.stop()
            pp._log_lifecycle = real_log

    def case_a_failed_mint_answers_503_in_every_form_of_the_route(
            self, certdir, monkeypatch):
        """Nothing may leave on the session's bearer, bare, with a query, or
        with a trailing slash (`is_pinned_route`'s own normalisation). THE
        CONTROL, same daemon state: another pinned route still falls open."""
        for path in (self.POLICY, self.POLICY + "?x=1", self.POLICY + "/"):
            lines = []
            status, seen = self._ask(
                certdir, self._provider(certdir, monkeypatch), path, lines)
            assert status == 503 and seen == [], (
                f"{path}: a failed mint was relayed as the active account: "
                f"{status} {seen}")
            assert any(f"GET {path} refused (503)" in ln
                       and "org-policy" in ln for ln in lines), lines
        status, seen = self._ask(
            certdir, self._provider(certdir, monkeypatch),
            "/api/oauth/validate")
        assert status == 200 and seen == ["Bearer session-bearer"], (
            f"another route must still fail open: {status} {seen}")

    def case_a_deferred_mint_answers_503(self, certdir, monkeypatch):
        """`consume-busy` (another process holds the slot) yields no token
        and `pin_is_noop()` reads True, but the answer would still be the
        ACTIVE account's verdict on a pin that is neither cleared nor the
        live login."""
        provider = self._provider(
            certdir, monkeypatch, lambda n: "expired", busy=True)
        status, seen = self._ask(certdir, provider)
        assert provider.pin_is_noop() is True  # the deferral was real
        assert status == 503 and seen == [], (status, seen)

    def case_a_cleared_pin_and_the_live_login_still_relay(
            self, certdir, monkeypatch):
        """Nothing to swap, so the session's own bearer IS the right one."""
        for name, kw in (("cleared", {"pinned": False}),
                         ("live login", {"active": "2"})):
            status, seen = self._ask(
                certdir, self._provider(certdir, monkeypatch, **kw))
            assert status == 200 and seen == ["Bearer session-bearer"], (
                f"{name}: {status} {seen}")

    def case_a_minted_token_still_swaps(self, certdir, monkeypatch):
        """THE CONTROL: the pin answers as the pin."""
        status, seen = self._ask(
            certdir,
            self._provider(certdir, monkeypatch, lambda n: "pin-token"),
            reject=())
        assert status == 200 and seen == ["Bearer pin-token"], (status, seen)

    def case_a_pin_token_still_refused_after_the_refetch_answers_503(
            self, certdir, monkeypatch):
        """The take-back must not resend the policy question as the active
        account: `dead` (no rotation) and `rotated` (a refetch that is
        refused too). THE CONTROL, same daemon: another pinned route still
        resends on the session's own bearer and logs `fell-back`."""
        for name, token, expect in (
                ("dead", lambda n: "pin-token", ["Bearer pin-token"]),
                ("rotated", lambda n: "pin-token" if n == 1 else "fresh",
                 ["Bearer pin-token", "Bearer fresh"])):
            provider = self._provider(certdir, monkeypatch, token)
            lines = []
            status, seen = self._ask(
                certdir, provider, lines=lines, reject=("pin-token", "fresh"))
            assert status == 503 and seen == expect, (
                f"{name}: the refused pin token was resent as another "
                f"account: {status} {seen}")
            assert any(f"GET {self.POLICY} refused (503)" in ln
                       for ln in lines), (name, lines)
            assert not any("fell-back" in ln and "policy_limits" in ln
                           for ln in lines), (name, lines)
            # ONCE: the refusal is one event, and the take-back used to log it
            # twice (`swap refused ... not resent` and `refused (503)`).
            assert len([ln for ln in lines if "policy_limits" in ln
                        and "retried-fresh" not in ln]) == 1, (name, lines)
            lines.clear()
            status, seen = self._ask(
                certdir, provider, "/api/oauth/validate", lines,
                reject=("pin-token", "fresh"))
            assert status == 200 and seen[-1] == "Bearer session-bearer", (
                name, status, seen)
            assert ("swap refused (403) on GET /api/oauth/validate: "
                    "fell-back") in lines, (name, lines)

    def _ask_absolute(self, certdir, provider, path=None, lines=None,
                      reject=("pin-token",)):
        """The absolute-form twin of `_ask` (`claude remote-control`'s own
        form): one GET of `path` with the session's own bearer through a real
        daemon and a recording hop that refuses every bearer in `reject`;
        `(the reply's first bytes, the requests the hop saw)`."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: (b"HTTP/1.1 403 X\r\nContent-Length: 0\r\n\r\n"
                         if any(f"Bearer {b}".encode() in req for b in reject)
                         else b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        real_log = pp._log_lifecycle
        if lines is not None:
            pp._log_lifecycle = lines.append
        proxy = None
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=provider,
                             rediscover_chain=True)
            proxy.start()
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    f"GET https://api.anthropic.com{path or self.POLICY} "
                    "HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    "Authorization: Bearer session-bearer\r\n\r\n"
                    .encode("latin1"))
                got = c.recv(256)
            finally:
                c.close()
            return got, list(chain.seen)
        finally:
            if proxy:
                proxy.stop()
            chain.stop()
            pp._log_lifecycle = real_log

    def case_an_absolute_form_failed_or_deferred_mint_answers_503(
            self, certdir, monkeypatch):
        """The MITM rule, on the path `claude remote-control` uses: nothing
        may leave on the session's bearer, bare, with a query or with a
        trailing slash, for a failed mint or a deferred one. THE CONTROL,
        same daemon state: another pinned route still falls open."""
        for path in (self.POLICY, self.POLICY + "?x=1", self.POLICY + "/"):
            lines = []
            got, seen = self._ask_absolute(
                certdir, self._provider(certdir, monkeypatch), path, lines)
            assert got.startswith(b"HTTP/1.1 503") and seen == [], (
                f"{path}: a failed mint was relayed as the active account: "
                f"{got[:40]!r} {seen}")
            assert any(f"GET {path} refused (503)" in ln
                       and "org-policy" in ln for ln in lines), lines
        got, seen = self._ask_absolute(
            certdir, self._provider(certdir, monkeypatch, lambda n: "expired",
                                    busy=True))
        assert got.startswith(b"HTTP/1.1 503") and seen == [], (
            f"a deferred mint was relayed: {got[:40]!r} {seen}")
        got, seen = self._ask_absolute(
            certdir, self._provider(certdir, monkeypatch),
            "/api/oauth/validate")
        assert got.startswith(b"HTTP/1.1 200") and len(seen) == 1 \
            and b"Bearer session-bearer" in seen[0], (
            f"another route must still fail open: {got[:40]!r} {seen}")

    def case_an_absolute_form_pin_token_refused_answers_503_without_a_resend(
            self, certdir, monkeypatch):
        """The take-back's last send is the session's own bearer, which
        answers the policy question as the ACTIVE account: `dead` (no
        rotation) and `rotated` (a refetch refused too). Only pin bearers
        may reach the hop and the refusal is one log line. THE CONTROL, same
        daemon: another pinned route still resends and logs `fell-back`."""
        for name, token, expect in (
                ("dead", lambda n: "pin-token", [b"Bearer pin-token"]),
                ("rotated", lambda n: "pin-token" if n == 1 else "fresh",
                 [b"Bearer pin-token", b"Bearer fresh"])):
            provider = self._provider(certdir, monkeypatch, token)
            lines = []
            got, seen = self._ask_absolute(
                certdir, provider, lines=lines, reject=("pin-token", "fresh"))
            assert got.startswith(b"HTTP/1.1 503"), (name, got[:40])
            assert len(seen) == len(expect) and all(
                e in r for e, r in zip(expect, seen)) and not any(
                b"session-bearer" in r for r in seen), (
                f"{name}: the refused pin token was resent as another "
                f"account: {seen}")
            assert len([ln for ln in lines if "policy_limits" in ln
                        and "retried-fresh" not in ln]) == 1, (name, lines)
            lines.clear()
            got, seen = self._ask_absolute(
                certdir, provider, "/api/oauth/validate", lines,
                reject=("pin-token", "fresh"))
            assert got.startswith(b"HTTP/1.1 200") and (
                b"Bearer session-bearer" in seen[-1]), (name, got[:40], seen)
            assert ("swap refused (403) on GET /api/oauth/validate: "
                    "fell-back") in lines, (name, lines)

    def case_an_absolute_form_cleared_pin_and_live_login_still_relay(
            self, certdir, monkeypatch):
        """THE CONTROL: nothing to swap, so the session's own bearer is the
        right one on this path too."""
        for name, kw in (("cleared", {"pinned": False}),
                         ("live login", {"active": "2"})):
            got, seen = self._ask_absolute(
                certdir, self._provider(certdir, monkeypatch, **kw))
            assert got.startswith(b"HTTP/1.1 200") and len(seen) == 1 \
                and b"Bearer session-bearer" in seen[0], (name, got[:40], seen)

    def case_a_policy_503_does_not_silence_a_following_blind_mint_line(
            self, certdir):
        """`_refuse_stalled_mint`'s line is rate-limited, and the blind-mint
        one it writes for a bridge create is load-bearing (a respawning
        worker would otherwise log one per respawn). An hourly policy 503
        burst shares none of that budget: its own slot, still limited."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import PinProxy

        class Tls:
            def sendall(self, _b):
                pass

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        lines = []
        real_log = pp._log_lifecycle
        pp._log_lifecycle = lines.append
        try:
            proxy._refuse_stalled_mint(Tls(), "GET", self.POLICY, "policy")
            proxy._refuse_stalled_mint(
                Tls(), "POST", "/v1/environments/bridge", "blind")
            proxy._refuse_stalled_mint(Tls(), "GET", self.POLICY, "policy")
            proxy._refuse_stalled_mint(
                Tls(), "POST", "/v1/environments/bridge", "blind")
        finally:
            pp._log_lifecycle = real_log
        assert lines == [
            f"GET {self.POLICY} refused (503): policy",
            "POST /v1/environments/bridge refused (503): blind"], lines


class TestEverySmallCaseHolder:
    """Every small case-holder in this file, as ONE pytest test.

    Each holder is run SEPARATELY (its own instance, its own helpers)
    rather than merged by inheritance: three of these classes define a
    `_ca` / `_cfg` / `_ours` helper with different meanings, and a
    shared MRO would have handed every case just one of them.
    A failure still names the class its case came from.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(
            [
                TestStreamingRelay(),
                TestChunkedRequestBodiesReachUpstream(),
                TestTheChainsCredentialIsSent(),
                TestLoopbackChainTrust(),
                TestLongPollSurvives(),
                TestAbsoluteFormPassthrough(),
                TestHealthEndpoint(),
                TestKeepAlive(),
                TestWebSocketUpgrade(),
                TestBlindTunnelIsTraced(),
                TestBlindTunnelFallsBackWhenChainRefuses(),
                TestOptimisticConnectIsDetected(),
                TestTheTrustFileActuallyVerifies(),
                TestTheKillGateIdentifiesItsTarget(),
                ],
            request,
            tmp_path_factory,
        )


class TestAHandoverMidDrainDropsTheClock:
    """The budget is chosen once, and a handover can arrive after it.

    A signal drain takes the CAPPED arm because the port would otherwise go
    dark. If a successor then takes the port while that drain is running, the
    reason is gone -- nothing waits on this process and it accepts nothing.
    It is one idle process finishing replies it already owes, which is the
    exact condition `_HANDOVER_DRAIN_SECONDS` was made infinite for.

    Measured: a TERM armed the 30s arm; twenty seconds later this process's own
    watchdog handed over with the successor already serving; at thirty seconds
    the clock from BEFORE the handover cut 13 mid-response replies.

    `teardown_drain_budget(handed_over=...)` means to prevent this and cannot:
    `_HELD_DRAIN_SECONDS` IS `_DRAIN_SECONDS`, so all four combinations of its
    arguments return 30.0 -- measured. The fact has to be re-read where it can
    change mid-wait, which is here.
    """

    def _drain(self, tmp_path, monkeypatch, *, superseded, moving_for=3):
        import cswap_pin.proxy as pp
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        seen = {"n": 0}

        def moving(_started):
            seen["n"] += 1
            return seen["n"] <= moving_for

        monkeypatch.setattr(proxy, "_owed_still_moving", moving)
        monkeypatch.setattr(pp, "_superseded_on_the_port",
                            lambda _c: superseded)
        monkeypatch.setattr(pp.time, "sleep", lambda _s: None)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            proxy.await_inflight(5.0)
        return err.getvalue()

    def test_a_successor_taking_the_port_drops_the_wall_clock(
            self, tmp_path, monkeypatch):
        out = self._drain(tmp_path, monkeypatch, superseded=True)
        assert "dropping the wall clock" in out, out

    def test_CONTROL_no_successor_means_the_clock_still_binds(
            self, tmp_path, monkeypatch):
        """What keeps the case above from being "always uncapped". With
        nothing serving the port, hurrying is correct and the cap stays."""
        out = self._drain(tmp_path, monkeypatch, superseded=False)
        assert "dropping the wall clock" not in out, out

    def test_CONTROL_the_promotion_happens_at_most_once(
            self, tmp_path, monkeypatch):
        """The check runs every pass of a loop that can spin thousands of
        times. Announcing on each would bury the drain's own lines in the one
        file a person reads to find out why a daemon died."""
        out = self._drain(tmp_path, monkeypatch, superseded=True,
                          moving_for=25)
        assert out.count("dropping the wall clock") == 1, out


class TestARequestThatArrivesMidDrainIsNotBornStale:
    """A new request on an OPEN connection is aged from its own debt.

    `release_listener` sheds ARRIVALS, not requests. A keep-alive connection
    that is already open can begin a fresh request while the drain runs, and
    `_owed` carries 0.0 for it until the first response byte goes out. Aged
    from the drain's start, such a request reads as however long the drain has
    been running and is cut on its first evaluation -- so the longer a daemon
    politely waits for everyone else, the more certainly it kills whoever
    arrives last.

    Observed on a live host as `cut 1 in-flight request(s) after 2569.8s of no
    wall-clock cap (0 mid-response, 1 before headers; delivered 0/0/0 B;
    content-free 0/0/0 s)`. The two zeros are what identify it: no response
    byte ever went out, and the debt was seconds old, not 2569.
    """

    @staticmethod
    def _proxy(tmp_path):
        import cswap_pin.proxy as pp
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        return pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                           upstream=("127.0.0.1", 1))

    def test_a_request_that_began_seconds_ago_is_still_moving(self, tmp_path):
        import cswap_pin.proxy as pp
        proxy = self._proxy(tmp_path)
        now, started = pp.time.monotonic(), pp.time.monotonic() - 3000.0
        # Owed, no response byte yet, and the debt is one second old.
        proxy._owed["c"] = 0.0
        proxy._content_at["c"] = now - 1.0
        assert proxy._owed_still_moving(started) is True

    def test_CONTROL_an_upstream_that_never_answers_still_ages_out(
            self, tmp_path):
        """The property the fix must not spend. A request whose OWN debt is
        older than the stall window is still released, so a wedged upstream
        cannot hold the daemon open for ever."""
        import cswap_pin.proxy as pp
        proxy = self._proxy(tmp_path)
        now, started = pp.time.monotonic(), pp.time.monotonic() - 3000.0
        proxy._owed["c"] = 0.0
        proxy._content_at["c"] = now - (pp._DRAIN_STALL_SECONDS + 10.0)
        assert proxy._owed_still_moving(started) is False

    def test_CONTROL_a_stale_mid_response_reply_still_ages_out(self, tmp_path):
        """The other half of the predicate is untouched: once a response has
        started, `_owed` carries the last-byte stamp and that is what binds."""
        import cswap_pin.proxy as pp
        proxy = self._proxy(tmp_path)
        now, started = pp.time.monotonic(), pp.time.monotonic() - 3000.0
        proxy._owed["c"] = now - (pp._DRAIN_STALL_SECONDS + 10.0)
        proxy._content_at["c"] = now - 1.0   # fresh seed must not rescue it
        assert proxy._owed_still_moving(started) is False


class TestABeatIsNeverReadHalfWritten:
    """A short marker and an old marker must not read the same.

    `draining_bridges` reports "cannot be asked" for a marker with fewer than
    six lines, and that verdict is reserved for a predecessor from a release
    predating the held-bridge record. A non-atomic beat -- which fires every
    few seconds for the whole life of a drain -- puts the CURRENT release into
    that state for the width of one write, and the successor then refuses to
    say whether any bridge is deaf.
    """

    def test_a_concurrent_reader_never_sees_a_short_marker(self, tmp_path):
        import os
        import threading

        import cswap_pin.proxy as pp

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        pid = os.getpid()
        # SEEDED THROUGH THE REAL WRITERS. `beat_draining` reads line 0 (the
        # drain's start) out of the existing marker, so a beat with no
        # `announce_draining` before it writes NOTHING -- and an absent marker
        # also reports False, which is a different and correct answer this
        # case must not accidentally assert on.
        done = pp.announce_draining(certdir, pid)   # returns a release callable
        pp.beat_draining(certdir, pid, owed=1, live=0, quiet=0.0,
                         streams=1, bridges={"cse_seed"})
        assert pp.draining_bridges(certdir, pid)[1] is True, "seed beat unreadable"

        stop, short = threading.Event(), []

        def beat():
            n = 0
            while not stop.is_set():
                pp.beat_draining(certdir, pid, owed=1, live=0, quiet=0.0,
                                 streams=1, bridges={f"cse_{n % 4}"})
                n += 1

        t = threading.Thread(target=beat, daemon=True)
        t.start()
        try:
            for _ in range(6000):
                if pp.draining_bridges(certdir, pid)[1] is not True:
                    short.append(1)
                    break
        finally:
            stop.set()
            t.join(timeout=5.0)
            done()
        assert not short, (
            "a reader saw a marker with no held-bridge line while a beat was "
            "in flight — that is the verdict reserved for an old release")


class TestAMarkerIsAnswerableTheMomentItExists:
    """`announce_draining` must not leave a file only line 0 long.

    The announce deliberately precedes `_spawn_daemon`, which BLOCKS waiting
    for the successor to publish -- so the process that reads the marker
    during that window is the successor being spawned, every handover.
    `draining_bridges` takes `body[5]`, and on a one-line file that is an
    IndexError reported as "cannot be asked": the verdict reserved for a
    release predating the held-bridge record. A current daemon then accuses
    its own predecessor of being ancient and refuses to say whether any
    bridge is deaf.
    """

    @staticmethod
    def _proxy(tmp_path):
        import cswap_pin.proxy as pp
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        return pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                           upstream=("127.0.0.1", 1)), certdir

    def test_the_successor_can_ask_immediately(self, tmp_path):
        import os

        import cswap_pin.proxy as pp

        proxy, certdir = self._proxy(tmp_path)
        pid = os.getpid()
        done = pp.announce_draining(certdir, pid, server=proxy)
        try:
            _ids, said = pp.draining_bridges(certdir, pid)
            assert said is True, (
                "a marker written by announce is unanswerable, so the "
                "successor spawned during the announce->beat window reads "
                "this daemon as predating the held-bridge record")
        finally:
            done()

    def test_CONTROL_without_the_server_it_is_still_bare(self, tmp_path):
        """What keeps the case above from passing for any reason at all. A
        caller with nothing to ask still writes the one-line marker, and this
        is the shape that produced the false 'predates the record' verdict."""
        import os

        import cswap_pin.proxy as pp

        _proxy, certdir = self._proxy(tmp_path)
        pid = os.getpid()
        done = pp.announce_draining(certdir, pid)
        try:
            assert pp.draining_bridges(certdir, pid)[1] is False
        finally:
            done()


class TestASpuriousStream404DoesNotEndTheSession:
    """A 404 on the RC event stream that the pin can see is not true.

    MEASURED 2026-08-25 on a live host. `GET .../worker/events/stream` came
    back 404 for four sessions whose other worker routes were answering 200
    seconds either side of it, one of them a `PUT /worker` on the same id
    right after. Three of the thirteen carried no `from_sequence_num` at all,
    so it is not a resume point ageing out, and the retried request was
    byte-identical to the one that had just been answered 200.

    The client cannot tell. 404 is in its permanent set, so it sends
    `end_session` to the child and the person reconnects by hand. 503 is not:
    `validateStatus: f<500` keeps it away from the flag-setter and the retry
    predicate takes `>= 500`.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    @staticmethod
    def _relay(path, status, prime=None, age=0.0):
        """Drive the REAL relay and return what the client actually received.

        `prime` is a route to answer 200 on first, which is the only way the
        pin learns a session is alive -- there is no probe and no extra
        request, just traffic already crossing this hop.
        """
        import socket as _s
        from cswap_pin import proxy as pp

        with pp._worker_alive_lock:
            pp._worker_alive.clear()
        if prime is not None:
            pp._note_worker_status(prime, b"HTTP/1.1 200 OK")
            if age:
                with pp._worker_alive_lock:
                    for k in pp._worker_alive:
                        pp._worker_alive[k] -= age

        up_a, up_b = _s.socketpair()
        cl_a, cl_b = _s.socketpair()
        try:
            up_b.sendall(b"HTTP/1.1 " + status +
                         b"\r\nContent-Length: 2\r\n\r\nno")
            up_b.shutdown(_s.SHUT_WR)
            pp._relay_response(up_a, cl_a, 0, method="GET", path=path)
            cl_a.shutdown(_s.SHUT_WR)
            return cl_b.recv(4096)
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

    SID = "cse_013L9dri6ged52FB83rBYvb8"
    STREAM = f"/v1/code/sessions/{SID}/worker/events/stream?from_sequence_num=1249"
    BEAT = f"/v1/code/sessions/{SID}/worker/heartbeat"

    def case_a_live_session_keeps_its_stream(self):
        got = self._relay(self.STREAM, b"404 Not Found", prime=self.BEAT)
        assert got.startswith(b"HTTP/1.1 503"), (
            "the pin saw this session's heartbeat answered 200 and then let a "
            "404 through on its stream, which is the one status the client "
            f"treats as permanent — it ends the session. got {got[:40]!r}")

    def case_a_404_during_a_hop_failure_is_relayed_as_503(self):
        """The transport-outage case: no liveness evidence, because the hop is
        down. That absence is why the guard must fire, not why it must not."""
        from cswap_pin import proxy as pp
        pp._hop_trouble_at = 0.0
        pp._note_hop_trouble(b"HTTP/1.1 502 Bad Gateway")
        try:
            got = self._relay(self.STREAM, b"404 Not Found", prime=None)
        finally:
            pp._hop_trouble_at = 0.0
        assert got.startswith(b"HTTP/1.1 503"), (
            "this hop had just returned a 502, so the 404 is not a verdict — "
            f"relaying it ends the session permanently. got {got[:40]!r}")

    def case_a_foreign_hosts_502_does_not_arm_hop_trouble(self, certdir):
        """T1025 finding 4: `_note_hop_trouble` ran on every
        `_relay_response` call, including the plain absolute-form path's
        foreign-host requests. A foreign host's own 502 then poisoned the
        NEXT stream 404 on api.anthropic.com, masking a real session loss
        as a transport hiccup on a hop the pin's own upstream never
        touched.

        END TO END, through the real plain-relay call site
        (`note_hop=host == UPSTREAM_HOST and secure` in
        `_plain_relay_request`) -- a direct `_relay_response(note_hop=False)`
        call stays green even with that argument reverted to unconditional
        `True`, and caught nothing."""
        from cswap_pin import proxy as pp
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        chain = _RecordingChain(
            lambda req: b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        proxy = None
        pp._hop_trouble_at = 0.0
        try:
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             rediscover_chain=True)
            proxy.start()

            def ask(url, host):
                c = socket.create_connection(("127.0.0.1", proxy.port),
                                             timeout=10)
                try:
                    c.sendall(
                        f"GET {url} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                    c.settimeout(10)
                    try:
                        c.recv(256)
                    except OSError:
                        pass
                finally:
                    c.close()

            ask("https://example.com/", "example.com")
            assert pp._hop_trouble_at == 0.0, (
                "a foreign host's 502 armed hop trouble for the pin's own "
                "upstream")

            # THE CONTROL, through the same end-to-end path: the pin's own
            # upstream's 502 must still arm it.
            ask("https://api.anthropic.com/", "api.anthropic.com")
            assert pp._hop_trouble_at != 0.0, (
                "the pin's own upstream's 502 did not arm hop trouble")
        finally:
            pp._hop_trouble_at = 0.0
            if proxy:
                proxy.stop()
            chain.stop()

    def case_the_pins_own_upstreams_502_still_arms_hop_trouble(self):
        """THE CONTROL: narrowing `_note_hop_trouble` to the pin's own
        upstream must not also blind it to a REAL hop failure there."""
        from cswap_pin import proxy as pp
        pp._hop_trouble_at = 0.0
        try:
            self._relay("/", b"502 Bad Gateway", prime=None)
            assert pp._hop_trouble_at != 0.0, (
                "the pin's own upstream's 502 did not arm hop trouble")
            got = self._relay(self.STREAM, b"404 Not Found", prime=None)
            assert got.startswith(b"HTTP/1.1 503"), (
                f"the real hop failure was not honoured. got {got[:40]!r}")
        finally:
            pp._hop_trouble_at = 0.0

    def case_a_404_off_the_stream_route_is_untouched_during_trouble(self):
        """THE SCOPE CONTROL. `_hop_recently_failed` knows nothing about paths,
        so without the route test every 404 on the machine becomes a 503."""
        from cswap_pin import proxy as pp
        pp._hop_trouble_at = 0.0
        pp._note_hop_trouble(b"HTTP/1.1 502 Bad Gateway")
        try:
            got = self._relay("/v1/messages", b"404 Not Found", prime=None)
        finally:
            pp._hop_trouble_at = 0.0
        assert got.startswith(b"HTTP/1.1 404"), (
            f"only the RC stream route is protected. got {got[:40]!r}")

    def case_a_session_the_pin_cannot_vouch_for_is_left_alone(self):
        # THE CONTROL. Without it every case above passes on a relay that
        # rewrites every 404 it ever sees, and a session the server really has
        # lost would retry forever instead of ending cleanly.
        got = self._relay(self.STREAM, b"404 Not Found", prime=None)
        assert got.startswith(b"HTTP/1.1 404"), (
            "with no evidence the session is alive the 404 must go through "
            f"untouched, so the client can end cleanly. got {got[:40]!r}")

    def case_evidence_expires(self):
        from cswap_pin import proxy as pp
        got = self._relay(self.STREAM, b"404 Not Found", prime=self.BEAT,
                          age=pp._STREAM_LIVE_SECONDS + 1.0)
        assert got.startswith(b"HTTP/1.1 404"), (
            "a session that stopped answering minutes ago is not evidence of "
            f"anything; the 404 must go through. got {got[:40]!r}")

    def case_only_the_stream_is_rewritten(self):
        # A 404 on a NON-stream worker route is a real answer about a real
        # request and belongs to whoever asked. Rewriting it would hide it.
        got = self._relay(self.BEAT, b"404 Not Found", prime=self.BEAT)
        assert got.startswith(b"HTTP/1.1 404"), (
            "only the event stream turns a 404 into a dead session; every "
            f"other route's 404 is its own answer. got {got[:40]!r}")

    def case_a_real_200_is_untouched(self):
        got = self._relay(self.STREAM, b"200 OK", prime=self.BEAT)
        assert got.startswith(b"HTTP/1.1 200"), got[:40]


class TestA429OnMessagesBecomesA401OnceCswapHasWalledTheAccount:
    """A 429 on /v1/messages sleeps the client for the WHOLE reset window of
    the account it walled; a credential swap underneath that sleep does not
    shorten it, because CC only re-reads the credential file when it rebuilds
    its client, and a rate limit is not one of the triggers that rebuild
    watches — 401/403, a stale socket, or an mTLS reload are. Measured live
    at 45m44s beside an account with 4h of headroom. See
    `_switch_off_walled_account`.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    RESET_HEADER = b"anthropic-ratelimit-unified-reset: 9999999999"
    RESET_HEADER_2 = b"anthropic-ratelimit-unified-reset: 8888888888"
    RETRY_AFTER = b"retry-after: 3600"
    UNIFIED_STATUS = b"anthropic-ratelimit-unified-status: allowed_warning"
    SHOULD_RETRY = b"x-should-retry: true"
    LIVE = "live-account-token"
    HEADROOM = {"five_hour": {"pct": 10.0}, "seven_day": {"pct": 20.0}}
    NO_HEADROOM = {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 20.0}}

    @staticmethod
    def _wire(monkeypatch, switched, raises_once=None, needs_login=False,
              validated=True, before=None, live_token=None, usage=None,
              snap=None, live_num="1", entry_walled=False,
              record_usage_headers=None, fleet=None, disabled=None,
              reason="candidates-exhausted"):
        """Stub claude_swap's switcher so no real account store is touched.

        ``validated=None`` omits the key entirely (an older cswap that never
        probed the landing credential, or a probe that never ran). ``before``
        runs at the top of `switch()`, for a case that needs to block or fail
        inside it.

        ``live_token`` is the access token the credential store hands back for
        the account cswap has ACTIVE; ``None`` (the default every case that
        predates the bearer test gets) makes the store unreadable, which is
        also what a real host with a broken store gives, or a CALLABLE when a
        case needs it to change between relays (a same-account token
        rotation, unlike `live_num`'s account switch). ``usage`` is the
        live slot's decision-grade usage value — ``None`` for "no reading",
        a sentinel string, or a window dict. ``snap`` collects each
        ``usage_entries_by_account`` ``fetch=`` argument. ``live_num`` is what
        `current_account_number()` answers, or a CALLABLE when a case needs it
        to change between relays; ``None`` is an UNMANAGED live login, which
        cswap refuses to evaluate the usage of. ``entry_walled`` sets the live
        slot's usage entry's own ``.walled`` — cswap's persisted wall, read by
        `_live_account_headroom` before ``usage`` is even asked for its
        decision value. ``record_usage_headers``, when given, is attached to
        the fake switcher for `_note_usage_headers`'s own rows; omitted (the
        default) makes the fake switcher one WITHOUT the method, which is
        what an older cswap gives.

        The returned list holds the ``models=`` basis of each `switch()` call,
        so `len(calls)` still counts calls AND a case can assert WHICH windows
        the ranking was told to weigh. The pin's whole responsibility here is
        that basis; what the host then decides is the host's.

        ``fleet``, when given, is a ``{account_num: usage_dict}`` map merged
        into what ``usage_entries_by_account`` returns, and switches on
        ``is_account_disabled`` plus a fake ``poll_policy`` — the two symbols
        `_fleet_earliest_provable_reset` needs and an older host lacks.
        Omitted (the default) leaves the fake exactly as it was before this
        parameter existed, which is what keeps every case that does not pass
        it exercising the plain strip. A ``fleet`` usage dict may carry
        ``_reset_ts`` directly (the fake ``poll_policy.limiting_reset_ts``
        reads that key rather than parsing an ISO string). ``disabled``
        names which of ``fleet``'s accounts ``is_account_disabled`` answers
        True for. ``reason`` overrides the default ``switched=False``
        reason string."""
        from cswap_pin import proxy as pp

        calls = []
        state = {"raised": False}

        # NO `**_`: the fake's signature IS the contract. Swallowing an
        # unknown kwarg would keep every case green while each real host
        # raised TypeError into the relay's except and silently stopped
        # converting any wall at all.
        def _switch(strategy=None, json_output=False, models=None,
                    current_at_limit=False):
            calls.append(models)
            if before is not None:
                before()
            if raises_once is not None and not state["raised"]:
                state["raised"] = True
                raise raises_once
            result = {"switched": switched, "needsLogin": needs_login,
                      "reason": None if switched else reason}
            if validated is not None:
                result["validated"] = validated
            return result

        def _read_credentials():
            lt = live_token() if callable(live_token) else live_token
            if lt is None:
                raise OSError("credential store unreadable")
            return json.dumps({"claudeAiOauth": {"accessToken": lt}})

        def _usage_entries_by_account(fetch=None):
            if snap is not None:
                snap.append(fetch)
            # Decoy rows with full headroom: a read that takes any row but
            # the live slot answers "there is headroom" on a fleet where only
            # the walled account is live.
            entries = {
                # Without a row here `[None]` raises KeyError into the
                # helper's own `except` and the unmanaged-login case passes
                # whatever the code does.
                None: types.SimpleNamespace(
                    decision_value=lambda models=(): {
                        "five_hour": {"pct": 0.0}, "seven_day": {"pct": 0.0}}),
                "2": types.SimpleNamespace(
                    decision_value=lambda models=(): {
                        "five_hour": {"pct": 0.0}, "seven_day": {"pct": 0.0}}),
                "1": types.SimpleNamespace(
                    decision_value=lambda models=(): usage,
                    walled=entry_walled),
            }
            for num, fusage in (fleet or {}).items():
                entries[num] = types.SimpleNamespace(
                    decision_value=(lambda u: (lambda models=(): u))(fusage),
                    walled=False)
            return entries

        _attrs = dict(
            switch=_switch,
            _read_credentials=_read_credentials,
            current_account_number=(
                live_num if callable(live_num) else lambda: live_num),
            usage_entries_by_account=_usage_entries_by_account,
        )
        if record_usage_headers is not None:
            _attrs["record_usage_headers"] = record_usage_headers
        if fleet is not None:
            _attrs["is_account_disabled"] = (
                lambda num: num in (disabled or ()))
        fake_module = type("M", (), {
            "ClaudeAccountSwitcher": staticmethod(
                lambda: types.SimpleNamespace(**_attrs)),
        })()
        fake_poll_policy = type("PP", (), {
            "limiting_reset_ts": staticmethod(
                lambda u, models=(): (
                    u.get("_reset_ts") if isinstance(u, dict) else None)),
        })()

        def _require(name):
            if name == "poll_policy" and fleet is not None:
                return fake_poll_policy
            return fake_module

        monkeypatch.setattr(pp, "require", _require)
        pp._walled_switch_seen.clear()
        pp._walled_slots.clear()
        pp._walled_switch_seen_by_session.clear()
        pp._walled_headroom_seen.clear()
        pp._fleet_exhausted_until = 0.0
        # THE `_note_usage_headers` THROTTLES are memos of the SAME shape
        # and outlive this case exactly like the three above: cases run
        # alphabetically (`run_cases`'s `sorted(dir(cls))`), so a case that
        # stamps `self.LIVE` leaves an entry in here for whichever case
        # with that same bearer or slot sorts next, throttling it before it
        # ever reaches the code it means to exercise. `_usage_header_seen`
        # is keyed on the live SLOT; `_usage_header_spawn_seen` is the
        # pre-spawn gate, keyed on the bearer.
        pp._usage_header_seen.clear()
        pp._usage_header_spawn_seen.clear()
        return calls

    @classmethod
    def _relay(cls, path="/v1/messages", reset=None, status=b"429 Too Many Requests",
               auth="", session="", extra_headers=b""):
        import socket as _s
        from cswap_pin import proxy as pp
        up_a, up_b = _s.socketpair()
        cl_a, cl_b = _s.socketpair()
        try:
            head = b"HTTP/1.1 " + status + b"\r\n"
            if reset is not False:  # False omits the header entirely
                head += (reset or cls.RESET_HEADER) + b"\r\n"
            head += (cls.RETRY_AFTER + b"\r\n" + cls.UNIFIED_STATUS + b"\r\n"
                     + cls.SHOULD_RETRY + b"\r\n" + extra_headers
                     + b"Content-Length: 2\r\n\r\nno")
            up_b.sendall(head)
            up_b.shutdown(_s.SHUT_WR)
            pp._relay_response(up_a, cl_a, 0, method="POST", path=path,
                               auth=auth, session=session)
            cl_a.shutdown(_s.SHUT_WR)
            return cl_b.recv(4096)
        finally:
            for x in (up_a, up_b, cl_a, cl_b):
                try: x.close()
                except OSError: pass

    def case_a_successful_switch_rewrites_429_to_401(self, monkeypatch):
        self._wire(monkeypatch, switched=True)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 401"), got[:40]

    def case_a_401_carries_no_rate_limit_header(self, monkeypatch):
        """`retry-after` above 60s throws `api_request_retry_after_too_long`
        and kills the client's turn outright; the whole
        `anthropic-ratelimit-*` family (unified-status included) is
        meaningless, or misleading, on an auth response; `x-should-retry:
        true` would have the SDK retry internally on the same client,
        defeating the whole point of the 401 silently."""
        self._wire(monkeypatch, switched=True)
        got = self._relay()
        assert b"retry-after" not in got.lower(), got[:80]
        assert self.RESET_HEADER not in got, got[:80]
        assert self.UNIFIED_STATUS not in got, got[:80]
        assert self.SHOULD_RETRY not in got, got[:80]

    def case_no_headroom_anywhere_relays_the_429_with_rate_limit_headers_stripped(
        self, monkeypatch,
    ):
        """A relayed wall the pin could not convert must not carry a reset
        the client would sleep the whole window for — nor a header it would
        render as a false 'resets in ~Ns' into its own transcript.
        `x-should-retry` is stripped too: a bare `false` would stop the
        retry this fix depends on, and absent or `true` both fall back to
        the client's own default retry on a 429, so stripping costs
        nothing and removes the one case that would regress."""
        calls = self._wire(monkeypatch, switched=False)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert self.RESET_HEADER not in got, got[:80]
        assert self.UNIFIED_STATUS not in got, got[:80]
        assert self.RETRY_AFTER not in got, got[:80]
        assert self.SHOULD_RETRY not in got, got[:80]
        assert len(calls) == 1, len(calls)

    # --- the fleet-exhausted fact (T1465) -----------------------------

    def case_the_negative_lifecycle_line_carries_the_switch_reason(
        self, monkeypatch,
    ):
        """`switched=False` alone conflates a fleet that is merely
        exhausted with a switch that actually failed; the log line must
        say which."""
        from cswap_pin import proxy as pp
        lines = []
        self._wire(monkeypatch, switched=False)
        monkeypatch.setattr(pp, "_log_lifecycle", lines.append)
        self._relay()
        assert any("reason=candidates-exhausted" in l for l in lines), lines

    def case_an_exhausted_fleet_relays_its_own_reset_instead_of_the_walls(
        self, monkeypatch,
    ):
        """A provable fleet-wide reset must reach the client instead of the
        strip alone — and never later than the fleet value, since this
        wall's OWN reset can belong to a frozen bearer on another account
        entirely."""
        now = time.time()
        earliest = now + 120
        self._wire(
            monkeypatch, switched=False,
            fleet={"6": {"five_hour": {"pct": 100.0},
                         "seven_day": {"pct": 0.0}, "_reset_ts": earliest}},
        )
        upstream_reset = int(now) + 86400 * 3
        got = self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {upstream_reset}"
            .encode())
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert b"anthropic-ratelimit-unified-status: rejected" in got, got
        assert (f"anthropic-ratelimit-unified-reset: {int(earliest)}"
                .encode() in got), got
        assert (f"anthropic-ratelimit-unified-reset: {upstream_reset}"
                .encode() not in got), got
        assert (b"anthropic-ratelimit-unified-representative-claim: "
                b"five_hour" in got), got
        assert self.RETRY_AFTER not in got, got
        assert self.SHOULD_RETRY not in got, got
        assert self.UNIFIED_STATUS not in got, got

    def case_an_all_provable_fleet_reset_relays_uncapped_even_days_out(
        self, monkeypatch,
    ):
        """Every blocked slot proving its own reset means the fleet's real
        worst case IS that far out — capping it would wake an interactive
        client early into a wall that has not lifted. No cap applies when
        every blocked slot is provable, however far its reset is."""
        days_out = time.time() + 86400 * 5
        self._wire(
            monkeypatch, switched=False,
            fleet={"6": {"five_hour": {"pct": 100.0},
                         "seven_day": {"pct": 0.0}, "_reset_ts": days_out}},
        )
        got = self._relay()
        assert (f"anthropic-ratelimit-unified-reset: {int(days_out)}"
                .encode() in got), got

    def case_a_not_all_provable_fleet_reset_announces_the_bounded_minimum(
        self, monkeypatch,
    ):
        """One blocked slot proves a far reset; another proves none at all
        — that second slot could beat the far one at any moment, so the
        far reset cannot be relayed unbounded. Announced instead as
        `min(earliest, decision time + _EXHAUSTED_RESET_CAP_S)`, mirroring
        `_earliest_recovery`'s own "announce the earliest provable moment
        and keep a bounded re-check rather than sleeping toward a reset
        that peer may beat"."""
        from cswap_pin import proxy as pp
        far = time.time() + 86400 * 3
        self._wire(
            monkeypatch, switched=False,
            fleet={
                "6": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                      "_reset_ts": far},
                "7": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                      "_reset_ts": None},
            },
        )
        before = time.time()
        got = self._relay()
        after = time.time()
        m = re.search(rb"anthropic-ratelimit-unified-reset: (\d+)", got)
        assert m, got
        relayed = int(m.group(1))
        assert relayed < far, relayed
        assert before + pp._EXHAUSTED_RESET_CAP_S - 1 <= relayed, relayed
        assert relayed <= after + pp._EXHAUSTED_RESET_CAP_S + 1, relayed

    def case_a_live_walls_own_clear_bounds_a_fleet_blocked_on_a_scoped_window(
        self, monkeypatch,
    ):
        """A live-token 429's own reset can clear soon while
        `_fleet_earliest_provable_reset`'s `("all",)` basis reads the SAME
        slot as blocked for days on an unrelated per-model weekly window —
        and every other enabled slot proves an equally far reset, so the
        naive fleet earliest is days out too. The relay bounds the fleet
        value by THIS 429's own reset header, so the live wall's near
        clear time is what gets announced, never the far scoped-window
        one."""
        now = time.time()
        days_out = now + 86400 * 5
        live_reset = int(now) + 3600
        blocked_days_out = {
            "five_hour": {"pct": 0.0}, "seven_day": {"pct": 0.0},
            "scoped": [{"name": "opus", "pct": 100.0}], "_reset_ts": days_out,
        }
        self._wire(
            monkeypatch, switched=False, live_token=self.LIVE,
            usage=blocked_days_out, fleet={"6": blocked_days_out},
        )
        got = self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {live_reset}".encode(),
            auth="Bearer " + self.LIVE,
        )
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert (f"anthropic-ratelimit-unified-reset: {live_reset}".encode()
                in got), got
        assert (f"anthropic-ratelimit-unified-reset: {int(days_out)}"
                .encode() not in got), got

    def case_a_frozen_bearers_far_own_reset_never_beats_a_nearer_fleet_value(
        self, monkeypatch,
    ):
        """A frozen bearer's own reset header can be days out while the
        fleet itself proves a nearer reset through some other slot. Both
        are upper bounds on when this client is served again, so the
        minimum — the nearer fleet value — is what gets relayed; the far
        bearer reset never reaches the client.

        The live slot is KNOWN WALLED (`entry_walled=True`, cswap's own
        persisted wall) so the bearer branch falls through to `switch()`
        instead of converting this to a 401 — exercising the actual
        frozen-bearer path (proxy.py's `token != live` branch) rather than
        skipping it via an unreadable credential store."""
        now = time.time()
        fleet_reset = int(now) + 3600
        days_out = now + 86400 * 5
        self._wire(
            monkeypatch, switched=False, live_token=self.LIVE,
            entry_walled=True,
            fleet={"6": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                         "_reset_ts": fleet_reset}},
        )
        got = self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {int(days_out)}"
            .encode(),
            auth="Bearer stale-account-token",
        )
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert (f"anthropic-ratelimit-unified-reset: {fleet_reset}".encode()
                in got), got
        assert (f"anthropic-ratelimit-unified-reset: {int(days_out)}"
                .encode() not in got), got

    def case_a_frozen_bearers_nearer_own_reset_bounds_a_far_fleet_value(
        self, monkeypatch,
    ):
        """A frozen bearer's own reset header can be nearer than the
        fleet's provable worst case — the minimum, the bearer's own nearer
        reset, is what gets relayed.

        The live slot is KNOWN WALLED (`entry_walled=True`, cswap's own
        persisted wall) so the bearer branch falls through to `switch()`
        instead of converting this to a 401 — exercising the actual
        frozen-bearer path (proxy.py's `token != live` branch) rather than
        skipping it via an unreadable credential store."""
        now = time.time()
        own_reset = int(now) + 1800
        days_out = now + 86400 * 5
        self._wire(
            monkeypatch, switched=False, live_token=self.LIVE,
            entry_walled=True,
            fleet={"6": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                         "_reset_ts": days_out}},
        )
        got = self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {own_reset}".encode(),
            auth="Bearer stale-account-token",
        )
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert (f"anthropic-ratelimit-unified-reset: {own_reset}".encode()
                in got), got
        assert (f"anthropic-ratelimit-unified-reset: {int(days_out)}"
                .encode() not in got), got

    def case_an_unknown_live_wall_leaves_the_fleet_value_unbounded(
        self, monkeypatch,
    ):
        """THE CONTROL: a default reset header far past the fleet's own
        provable value must not engage the minimum — the announced value
        stays the fleet's own provable worst case."""
        days_out = time.time() + 86400 * 5
        self._wire(
            monkeypatch, switched=False,
            fleet={"6": {"five_hour": {"pct": 0.0}, "seven_day": {"pct": 0.0},
                         "scoped": [{"name": "opus", "pct": 100.0}],
                         "_reset_ts": days_out}},
        )
        got = self._relay()
        assert (f"anthropic-ratelimit-unified-reset: {int(days_out)}"
                .encode() in got), got

    def case_a_debounced_repeat_relays_its_own_wall_not_a_later_walls(
        self, monkeypatch,
    ):
        """CONTAMINATION, fails on f7ebfbd. Wall W1 (live-token, own reset
        now+3600) is decided against a fleet blocked days out — f7ebfbd's
        module-wide `_fleet_exhausted_until` bounds itself to W1's own wall
        at that moment, by design. A second live-token wall W2 on the SAME
        slot then lands with its own reset days out and gets decided too —
        overwriting `_walled_slots[slot]` and, on f7ebfbd, re-bounding the
        SAME module-wide fact to W2's far value. W1 then reappears inside
        its own debounce window: the debounced repeat never recomputes the
        fact, so it relays whatever the fact holds NOW — W2's far value on
        f7ebfbd, not W1's own near one. The fix bounds at relay time, from
        each request's own reset header, so a wall never leaks another
        wall's bound into a debounced repeat of itself."""
        now = time.time()
        w1_reset = int(now) + 3600
        days_out = now + 86400 * 5
        self._wire(
            monkeypatch, switched=False, live_token=self.LIVE,
            fleet={"6": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                         "_reset_ts": days_out}},
        )
        first = self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {w1_reset}".encode(),
            auth="Bearer " + self.LIVE,
        )
        assert (f"anthropic-ratelimit-unified-reset: {w1_reset}".encode()
                in first), first
        self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {int(days_out)}"
            .encode(),
            auth="Bearer " + self.LIVE,
        )
        repeat = self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {w1_reset}".encode(),
            auth="Bearer " + self.LIVE,
        )
        assert (f"anthropic-ratelimit-unified-reset: {w1_reset}".encode()
                in repeat), repeat
        assert (f"anthropic-ratelimit-unified-reset: {int(days_out)}"
                .encode() not in repeat), repeat

    def case_an_unparseable_own_reset_leaves_the_fleet_value_alone(
        self, monkeypatch,
    ):
        """This 429's own reset header can fail to parse as a number —
        nothing to bound with, so the fleet's own provable value is
        relayed exactly as decided."""
        fleet_reset = time.time() + 3600
        self._wire(
            monkeypatch, switched=False,
            fleet={"6": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                         "_reset_ts": fleet_reset}},
        )
        got = self._relay(
            reset=b"anthropic-ratelimit-unified-reset: not-a-number")
        assert (f"anthropic-ratelimit-unified-reset: {int(fleet_reset)}"
                .encode() in got), got

    def case_a_past_own_reset_bounds_the_fleet_value_at_the_cap(
        self, monkeypatch,
    ):
        """This 429's own reset header can already be past — the SAME
        case `_fleet_earliest_provable_reset` treats as unprovable,
        because that account could recover at any moment. Relayed instead
        as `min(fleet value, now + _EXHAUSTED_RESET_CAP_S)`, the same
        bounded re-check the not-all-provable case gets, rather than the
        bare far fleet value: a client sleeping to it would ignore that
        this very request's own account may already be clear."""
        from cswap_pin import proxy as pp
        now = time.time()
        days_out = now + 86400 * 5
        self._wire(
            monkeypatch, switched=False,
            fleet={"6": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                         "_reset_ts": days_out}},
        )
        before = time.time()
        got = self._relay(
            reset=f"anthropic-ratelimit-unified-reset: {int(now) - 100}"
            .encode())
        after = time.time()
        m = re.search(rb"anthropic-ratelimit-unified-reset: (\d+)", got)
        assert m, got
        relayed = int(m.group(1))
        assert relayed < int(days_out), relayed
        assert before + pp._EXHAUSTED_RESET_CAP_S - 1 <= relayed, relayed
        assert relayed <= after + pp._EXHAUSTED_RESET_CAP_S + 1, relayed

    def case_a_disabled_slot_is_never_the_fleets_earliest(self, monkeypatch):
        """A slot the user disabled is never a `switch()` candidate, so its
        earlier reset must not be the one announced. Both resets stay under
        `_EXHAUSTED_RESET_CAP_S` so the cap cannot be the reason either
        value wins — see the separate cap case for that."""
        now = time.time()
        self._wire(
            monkeypatch, switched=False,
            fleet={
                "3": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                      "_reset_ts": now + 50},
                "5": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 0.0},
                      "_reset_ts": now + 200},
            },
            disabled={"3"},
        )
        got = self._relay()
        assert (f"anthropic-ratelimit-unified-reset: {int(now + 200)}"
                .encode() in got), got
        assert (f"anthropic-ratelimit-unified-reset: {int(now + 50)}"
                .encode() not in got), got

    def case_no_provable_fleet_reset_is_not_announced(self, monkeypatch):
        """No blocked slot can prove a reset at all — it could recover any
        moment — so nothing is announced, and the plain strip stands."""
        self._wire(
            monkeypatch, switched=False,
            fleet={"6": {"five_hour": {"pct": 100.0},
                         "seven_day": {"pct": 0.0}, "_reset_ts": None}},
        )
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert b"anthropic-ratelimit-unified-status: rejected" not in got, got
        assert self.RESET_HEADER not in got, got[:80]

    def case_a_host_without_the_fleet_symbols_is_not_announced(
        self, monkeypatch,
    ):
        """An older claude-swap with no `is_account_disabled` / no
        `poll_policy` — the shape every case above `fleet=` gets by
        omitting it — must not raise into the relay; it just cannot prove
        anything, so the plain strip stands."""
        calls = self._wire(monkeypatch, switched=False)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert b"anthropic-ratelimit-unified-status: rejected" not in got, got
        assert len(calls) == 1, calls

    def case_the_fleet_fact_does_not_leak_across_a_different_reason(
        self, monkeypatch,
    ):
        """A stale exhausted verdict from an earlier wall must not survive
        into THIS decision when its own `switch()` reports a different
        reason — the memo has to clear, not just fail to refresh."""
        from cswap_pin import proxy as pp
        self._wire(monkeypatch, switched=False, reason="some-other-reason")
        pp._fleet_exhausted_until = time.time() + 500
        got = self._relay()
        assert b"anthropic-ratelimit-unified-status: rejected" not in got, got
        assert pp._fleet_exhausted_until == 0.0, pp._fleet_exhausted_until

    def case_the_fleet_fact_clears_on_a_landed_switch(self, monkeypatch):
        """A switch that actually lands says the fleet is not exhausted —
        even when a stale exhausted verdict from an earlier wall is still
        sitting in the fact."""
        from cswap_pin import proxy as pp
        self._wire(monkeypatch, switched=True)
        pp._fleet_exhausted_until = time.time() + 500
        self._relay()
        assert pp._fleet_exhausted_until == 0.0, pp._fleet_exhausted_until

    def case_the_fleet_fact_clears_when_switch_raises(self, monkeypatch):
        """A raising `switch()` proves nothing about the fleet — a stale
        exhausted verdict from an earlier wall must not survive it."""
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_WALLED_SWITCH_RAISE_TTL", 0.0)
        self._wire(monkeypatch, switched=True, raises_once=OSError("locked"))
        pp._fleet_exhausted_until = time.time() + 500
        self._relay()
        assert pp._fleet_exhausted_until == 0.0, pp._fleet_exhausted_until

    def case_the_fleet_fact_clears_on_a_stale_bearer_conversion(
        self, monkeypatch,
    ):
        """The stale-bearer 401 branch never calls `switch()` — it judged
        the LIVE slot able to take a retry, so a stale exhausted verdict
        from an earlier wall must not survive it either."""
        from cswap_pin import proxy as pp
        self._wire(monkeypatch, switched=False,
                   live_token=self.LIVE, usage=self.HEADROOM)
        pp._fleet_exhausted_until = time.time() + 500
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert pp._fleet_exhausted_until == 0.0, pp._fleet_exhausted_until

    def case_a_debounced_repeat_of_an_exhausted_wall_still_carries_the_headers(
        self, monkeypatch,
    ):
        """A debounced repeat never recomputes the fleet fact — it must
        read whatever the first decision on this wall wrote, not the
        strip alone."""
        now = time.time()
        calls = self._wire(
            monkeypatch, switched=False,
            fleet={"6": {"five_hour": {"pct": 100.0},
                         "seven_day": {"pct": 0.0}, "_reset_ts": now + 500}},
        )
        first = self._relay()
        second = self._relay()
        assert b"anthropic-ratelimit-unified-status: rejected" in first, first
        assert (b"anthropic-ratelimit-unified-status: rejected"
                in second), second
        assert len(calls) == 1, (
            f"the repeat must be a debounce, not a fresh switch(): {calls}")

    def case_a_raising_switch_releases_the_slot_for_a_retry(self, monkeypatch):
        """A transient failure (this daemon's own config lock held
        elsewhere, or an older claude-swap with no such symbol) must not
        burn the wall's only attempt forever — once its short memo expiry
        has passed."""
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_WALLED_SWITCH_RAISE_TTL", 0.0)
        calls = self._wire(monkeypatch, switched=True, raises_once=OSError("locked"))
        first = self._relay()
        assert first.startswith(b"HTTP/1.1 429"), first[:40]
        second = self._relay()
        assert second.startswith(b"HTTP/1.1 401"), second[:40]
        assert len(calls) == 2, len(calls)

    def case_a_raise_is_remembered_briefly_so_a_storm_does_not_serialize(
        self, monkeypatch,
    ):
        """The raise path used to record nothing, so a storm on one wall
        serialized N real `switch()` calls — each blocking the lock for the
        full config-lock timeout — instead of one. A raise must debounce
        like any other outcome, for its own short expiry."""
        def _always_raises():
            raise OSError("locked")

        calls = self._wire(monkeypatch, switched=True, before=_always_raises)

        for _ in range(10):
            got = self._relay()
            assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, len(calls)

    def case_needs_login_is_not_a_usable_switch(self, monkeypatch):
        """switched=True with needsLogin=True means the credential is gone,
        not moved to a usable one — a 401 here dies on auth instead of
        surviving a wait it could have survived."""
        self._wire(monkeypatch, switched=True, needs_login=True)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 429"), got[:40]

    def case_an_absent_reset_header_is_never_walled(self, monkeypatch):
        """No header is no evidence of an account-level unified wall (an
        edge/gateway 429, or an org/key-scoped limit `switch()` cannot
        fix) — must not switch, and must not debounce future header-less
        429s against one shared empty key."""
        calls = self._wire(monkeypatch, switched=True)
        got = self._relay(reset=False)
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert not calls, len(calls)

    def case_a_non_429_on_messages_is_never_touched(self, monkeypatch):
        calls = self._wire(monkeypatch, switched=True)
        got = self._relay(status=b"200 OK")
        assert got.startswith(b"HTTP/1.1 200"), got[:40]
        assert not calls, len(calls)

    # --- _note_usage_headers, the T1138 producer half ---------------------

    _5H_HEADER = b"anthropic-ratelimit-unified-5h-utilization: 0.42\r\n"

    @staticmethod
    def _run_usage_thread_synchronously(monkeypatch):
        """`_note_usage_headers` starts a daemon thread; racing a test
        against it would be flaky, so this runs `fn` inline instead."""
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_spawn_usage_header_recorder",
                            lambda fn: fn())

    def case_a_200_feeds_its_5h_headers_to_the_usage_store(self, monkeypatch):
        """T1138: free evidence off a live reply lands on the SWAPPED
        slot's own number, not the account the client believes it is on."""
        self._run_usage_thread_synchronously(monkeypatch)
        recorded = []
        self._wire(monkeypatch, switched=True, live_token=self.LIVE,
                   live_num="7",
                   record_usage_headers=lambda num, headers:
                       recorded.append((num, headers)))
        self._relay(status=b"200 OK", reset=False, auth="Bearer " + self.LIVE,
                    extra_headers=self._5H_HEADER)
        assert len(recorded) == 1, recorded
        num, headers = recorded[0]
        assert num == "7", recorded
        assert headers["anthropic-ratelimit-unified-5h-utilization"] == "0.42", (
            recorded)

    def case_no_5h_header_never_calls_record(self, monkeypatch):
        self._run_usage_thread_synchronously(monkeypatch)
        recorded = []
        self._wire(monkeypatch, switched=True, live_token=self.LIVE,
                   record_usage_headers=lambda *a: recorded.append(a))
        self._relay(status=b"200 OK", reset=False, auth="Bearer " + self.LIVE)
        assert not recorded, recorded

    def case_many_200s_inside_30s_spawn_one_thread(self, monkeypatch):
        """T1178: moving the throttle inside `_run` left NOTHING in front
        of `_spawn_usage_header_recorder` -- every 200 carrying the 5h
        header spawned its own thread, each building two
        `ClaudeAccountSwitcher()`s before the in-thread check ever ran.
        Counting spawns through the seam itself, without ever running
        `fn`, isolates the pre-spawn gate from the in-thread per-slot
        throttle the case below covers."""
        from cswap_pin import proxy as pp
        spawns = []
        monkeypatch.setattr(pp, "_spawn_usage_header_recorder", spawns.append)
        self._wire(monkeypatch, switched=True, live_token=self.LIVE)
        for _ in range(5):
            self._relay(status=b"200 OK", reset=False,
                        auth="Bearer " + self.LIVE,
                        extra_headers=self._5H_HEADER)
        assert len(spawns) == 1, (
            f"many 200s inside the throttle window must spawn one thread, "
            f"not one per reply: {len(spawns)}")

    def case_a_second_reply_inside_30s_is_throttled_a_later_one_is_not(
        self, monkeypatch,
    ):
        from cswap_pin import proxy as pp
        self._run_usage_thread_synchronously(monkeypatch)
        recorded = []
        self._wire(monkeypatch, switched=True, live_token=self.LIVE,
                   record_usage_headers=lambda *a: recorded.append(a))
        pp._usage_header_seen.clear()
        for _ in range(2):
            self._relay(status=b"200 OK", reset=False,
                        auth="Bearer " + self.LIVE,
                        extra_headers=self._5H_HEADER)
        assert len(recorded) == 1, (
            f"a reply inside the throttle window must not record again: "
            f"{recorded}")
        # Age the one entry past the throttle instead of sleeping for it.
        # Keyed on the live SLOT ("1", `_wire`'s default), not the bearer.
        pp._usage_header_seen["1"] -= pp._USAGE_HEADER_THROTTLE_S + 1
        # ... and the PRE-SPAWN gate, keyed on the bearer every relay above
        # used -- unaged, it would swallow the third call before `_run`
        # ever saw the slot entry aged above.
        pp._usage_header_spawn_seen[self.LIVE] -= (
            pp._USAGE_HEADER_THROTTLE_S + 1)
        self._relay(status=b"200 OK", reset=False, auth="Bearer " + self.LIVE,
                    extra_headers=self._5H_HEADER)
        assert len(recorded) == 2, (
            f"a reply after the throttle expires must record: {recorded}")

    def case_a_delayed_thread_still_dates_its_slot_memo_from_its_spawn(
        self, monkeypatch,
    ):
        """THE DEFECT (T1213): `_run` used to stamp `_usage_header_seen`
        with its OWN, later `time.monotonic()` read instead of the spawn
        gate's `now` -- so a thread that resolves after a scheduling delay
        lands inside the OLD slot window. A second reply spawned exactly
        30s after the FIRST one (which the pre-spawn gate must allow) then
        found the slot memo still fresh and recorded nothing, stretching
        two records that should be 30s apart to ~60s on a busy
        single-token loop. Dating both memos from the SAME spawn-time
        `now` fixes it."""
        import time as _time
        from cswap_pin import proxy as pp
        captured = []
        monkeypatch.setattr(pp, "_spawn_usage_header_recorder", captured.append)
        recorded = []
        self._wire(monkeypatch, switched=True, live_token=self.LIVE,
                   record_usage_headers=lambda *a: recorded.append(a))
        clock = {"t": 0.0}
        monkeypatch.setattr(_time, "monotonic", lambda: clock["t"])

        self._relay(status=b"200 OK", reset=False, auth="Bearer " + self.LIVE,
                    extra_headers=self._5H_HEADER)
        assert len(captured) == 1, captured
        # This thread does not get scheduled until 5s later.
        clock["t"] = 5.0
        captured.pop(0)()
        assert len(recorded) == 1, recorded

        # A second reply, 30s after the FIRST SPAWN -- the pre-spawn gate
        # (keyed on spawn time) must allow it.
        clock["t"] = 30.0
        self._relay(status=b"200 OK", reset=False, auth="Bearer " + self.LIVE,
                    extra_headers=self._5H_HEADER)
        assert len(captured) == 1, captured
        captured.pop(0)()
        assert len(recorded) == 2, (
            f"two replies 30s apart on one slot must each record, not be "
            f"throttled by a slot memo dated from the first thread's late "
            f"run time: {recorded}")

    def case_two_tokens_of_the_same_slot_inside_30s_is_one_record(
        self, monkeypatch,
    ):
        """THE DEFECT: keyed on the bearer, a token ROTATION on the same
        account — the ordinary shape of a refreshed access token — was a
        fresh key, so two different tokens of ONE slot each earned their own
        record inside the window `record_usage_headers` means to collapse to
        one. Keyed on the slot instead, a second reply from a rotated token
        on the SAME live slot inside the TTL is the debounced repeat."""
        from cswap_pin import proxy as pp
        self._run_usage_thread_synchronously(monkeypatch)
        recorded = []
        # A real client always presents whatever is currently live, so the
        # rotation moves BOTH the store's own answer and the request's own
        # bearer together — only the slot ("1", `_wire`'s default) stays put.
        tokens = iter([self.LIVE, self.LIVE + "-rotated"])
        self._wire(monkeypatch, switched=True, live_token=lambda: next(tokens),
                   record_usage_headers=lambda *a: recorded.append(a))
        pp._usage_header_seen.clear()
        self._relay(status=b"200 OK", reset=False, auth="Bearer " + self.LIVE,
                    extra_headers=self._5H_HEADER)
        self._relay(status=b"200 OK", reset=False,
                    auth="Bearer " + self.LIVE + "-rotated",
                    extra_headers=self._5H_HEADER)
        assert len(recorded) == 1, (
            f"two tokens of the same slot inside the TTL must be one "
            f"record, not one per token: {recorded}")

    def case_a_stale_token_never_calls_record(self, monkeypatch):
        """The request's own token must equal the LIVE one, or a stale
        session's headers would land on the healthy slot it is not
        talking to."""
        self._run_usage_thread_synchronously(monkeypatch)
        recorded = []
        self._wire(monkeypatch, switched=True, live_token=self.LIVE,
                   record_usage_headers=lambda *a: recorded.append(a))
        self._relay(status=b"200 OK", reset=False,
                    auth="Bearer stale-account-token",
                    extra_headers=self._5H_HEADER)
        assert not recorded, recorded

    def case_a_switcher_without_the_method_raises_nothing(self, monkeypatch):
        """`_wire`'s default fake switcher has no `record_usage_headers` —
        an older cswap, still installable as a peer.

        THE HTTP STATUS ALONE CANNOT SEE THIS: `_run`'s own `except`
        swallows an `AttributeError` from calling a method that is not
        there and only logs it, so a reply that never even reaches `_run`
        (the response head is already sent) reads 200 either way. The
        assertion that actually exercises the `hasattr` guard is that
        nothing was logged as a raise."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        self._run_usage_thread_synchronously(monkeypatch)
        self._wire(monkeypatch, switched=True, live_token=self.LIVE)
        got = self._relay(status=b"200 OK", reset=False,
                          auth="Bearer " + self.LIVE,
                          extra_headers=self._5H_HEADER)
        assert got.startswith(b"HTTP/1.1 200"), got[:40]
        assert not any("usage-header record raised" in m for m in logged), (
            f"the missing method must be a no-op, not a caught exception: "
            f"{logged}")

    def case_a_thread_spawn_failure_does_not_abort_the_reply(self, monkeypatch):
        """`_spawn_usage_header_recorder` is a bare `Thread.start()`, which
        can raise `RuntimeError` under thread exhaustion — a statistic that
        must never cost the reply it is riding on, exactly like `on_status`
        just above it in `_relay_response`. Unguarded, this raise would
        propagate out of `_note_usage_headers` and abort the response BEFORE
        its head is sent."""
        from cswap_pin import proxy as pp

        def _raise(fn):
            raise RuntimeError("can't start new thread")

        monkeypatch.setattr(pp, "_spawn_usage_header_recorder", _raise)
        self._wire(monkeypatch, switched=True, live_token=self.LIVE)
        got = self._relay(status=b"200 OK", reset=False,
                          auth="Bearer " + self.LIVE,
                          extra_headers=self._5H_HEADER)
        assert got.startswith(b"HTTP/1.1 200"), (
            f"a thread-spawn failure must not cost the reply: {got[:40]!r}")

    def case_the_switch_outcome_is_logged_both_ways(self, monkeypatch):
        """`_TRACE` is off on a daemon that is already serving, which is
        every daemon this runs on — `_log_lifecycle` (daemon.log) is the
        only record that survives, on success AND on a no-headroom no-op."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        self._wire(monkeypatch, switched=True)
        self._relay()
        assert logged, "a successful switch went unlogged"
        logged.clear()
        self._wire(monkeypatch, switched=False)
        self._relay(reset=self.RESET_HEADER_2)
        assert logged, "a no-headroom switch attempt went unlogged"

    def case_an_absent_reset_header_is_also_logged(self, monkeypatch):
        """Without this, a daemon declining every header-less 429 produces a
        daemon.log identical to one this release never reached — "verify
        what is serving, not what is installed" needs a line to read."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        self._wire(monkeypatch, switched=True)
        self._relay(reset=False)
        assert logged, "a header-less 429 decline went unlogged"

    def case_an_absent_reset_header_log_carries_the_retry_after(self, monkeypatch):
        """A header-less 429's own sleep is capped at 6h client-side and
        unguarded against a throw — instrumentation only, no behaviour keyed
        on it, but unmeasurable unless the value is on the line."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        self._wire(monkeypatch, switched=True)
        self._relay(reset=False)
        assert any(b"3600" in m.encode() for m in logged), logged

    def case_the_debounce_hit_is_logged_with_the_reset_epoch(self, monkeypatch):
        """This branch was invisible in daemon.log before the fix, which is
        why a repeat wall could only be reconstructed from the CC bundle;
        the new `session_limit_watch` monitor reads this line."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        self._wire(monkeypatch, switched=True)
        self._relay()
        logged.clear()
        self._relay()
        assert any(b"9999999999" in m.encode() for m in logged), logged

    def case_a_second_429_on_the_same_wall_still_gets_the_401(self, monkeypatch):
        """A retry that reused the stale bearer, or a second concurrent
        connection on the same wall, must not re-attempt the switch — that
        would either churn accounts or dogpile the cross-process locks ten
        at once. But the account for THIS wall is already switched off, so
        the client must still see the 401, not the wall 429 relayed
        verbatim — a debounced switch is not a debounced conversion."""
        calls = self._wire(monkeypatch, switched=True)
        first = self._relay()
        assert first.startswith(b"HTTP/1.1 401"), first[:40]
        second = self._relay()
        assert second.startswith(b"HTTP/1.1 401"), second[:40]
        assert len(calls) == 1, len(calls)

    def case_a_debounced_failed_switch_still_relays_the_429(self, monkeypatch):
        """The deque slot is claimed whether or not the switch succeeded —
        it also has to stop a storm of retries on a wall with no headroom
        anywhere. A debounce hit must only forge a 401 for a wall this
        daemon actually switched off; one that never succeeded must keep
        relaying the 429, headers stripped, on every repeat, not just the
        first."""
        calls = self._wire(monkeypatch, switched=False)
        first = self._relay()
        assert first.startswith(b"HTTP/1.1 429"), first[:40]
        second = self._relay()
        assert second.startswith(b"HTTP/1.1 429"), second[:40]
        assert self.RESET_HEADER not in second, second[:80]
        assert len(calls) == 1, len(calls)

    def case_a_settled_negative_expires_so_the_next_429_re_attempts(
        self, monkeypatch,
    ):
        """THE 28-LINE DEFECT, 2026-09-09 03:22:07Z-03:23:48Z.

        `switched=False` was recorded with `retry_at=None`, and the read
        treats None as NEVER RETRY — so one "nowhere to land" answer silenced
        the wall for its whole window and every later 429 was relayed raw.
        A raise already got `_WALLED_SWITCH_RAISE_TTL`; `switched=False` is
        exactly as transient (it means nowhere to land YET) and must expire
        the same way. The case next door, on the unpatched TTL, is the
        control that the debounce still holds inside it."""
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_WALLED_SWITCH_RAISE_TTL", 0.0)
        calls = self._wire(monkeypatch, switched=False)
        first = self._relay()
        assert first.startswith(b"HTTP/1.1 429"), first[:40]
        second = self._relay()
        assert second.startswith(b"HTTP/1.1 429"), second[:40]
        assert len(calls) == 2, (
            "a settled negative must expire like a raise does, or the wall's "
            f"one attempt is spent forever: {len(calls)}")

    def case_a_settled_conversion_never_expires(self, monkeypatch):
        """ONLY A NEGATIVE EXPIRES. The account for this wall really is
        switched off, so re-running `switch()` on a later repeat would churn
        accounts for nothing — and `current_at_limit=True` would then pin the
        HEALTHY account it just landed on to 0.0."""
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_WALLED_SWITCH_RAISE_TTL", 0.0)
        calls = self._wire(monkeypatch, switched=True)
        for _ in range(3):
            got = self._relay()
            assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert len(calls) == 1, (
            "a wall this daemon already converted is settled forever: "
            f"{len(calls)}")

    def case_a_stale_bearer_converts_without_switching(self, monkeypatch):
        """THE HALF THAT RELEASES THE SESSION, 2026-09-09 03:25:25Z.

        A third writer (a hand `cswap switch`, or the engine) moved the host
        to a healthy account 97s after the last 429. A 429 never rebuilds
        Claude Code's client, so its next retry re-sent the FROZEN bearer of
        the walled account and walled again — while `switch()` would answer
        `switched=False` forever, because `current_at_limit=True` pins the
        CURRENTLY ACTIVE account (by then the healthy one) to 0.0 and nothing
        beats it.

        So the precondition is not "did I just switch?" but "is the client's
        bearer still the live account?". When the host has already moved, the
        401 IS the whole fix. `switched=False` is wired deliberately: the 401
        here cannot have come from a switch."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, (
            "the host has already moved off the walled account, so a 401 "
            f"alone fixes it and no switch is needed: {calls}")

    def case_a_bearer_that_is_still_the_live_account_switches_as_before(
        self, monkeypatch,
    ):
        """THE CONTROL. Without it the case above passes on a relay that
        answers 401 to every wall it sees. A bearer that IS the live account
        is the ordinary wall: nothing has moved underneath the client, so a
        401 would rebuild it straight back onto the account that just walled
        and only `switch()` can help."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        got = self._relay(auth="Bearer " + self.LIVE)
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, (
            "the client is on the account that walled; the switch is the "
            f"only path and must still be attempted: {len(calls)}")
        # AND THE SCHEME IS CASE-INSENSITIVE. Without this the `.lower()` in
        # the prefix strip is never executed by any case.
        lower = self._relay(reset=self.RESET_HEADER_2,
                            auth="bearer " + self.LIVE)
        assert lower.startswith(b"HTTP/1.1 429"), lower[:40]

    def case_a_stale_bearer_onto_a_full_live_account_is_relayed(
        self, monkeypatch,
    ):
        """A 401 THAT FIRES WHEN THE RETRY CANNOT LAND KILLS EVERY SUBAGENT
        (2026-09-07, three leads on `authentication_failed`, a reason absent
        from Claude Code's partial-result set). The bearer being stale says
        the client would rebuild; it says nothing about whether what it
        rebuilds onto can serve. A relayed 429 costs a sleep the owner can
        Esc; this must fall through to `switch()` and look for somewhere
        better instead of forging the 401."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.NO_HEADROOM)
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, (
            "no headroom on the live account is not a verdict to answer 401 "
            f"on; the switch still owes an attempt: {len(calls)}")

    def case_an_unknown_headroom_reading_converts_when_not_known_walled(
        self, monkeypatch,
    ):
        """INVERTED (T1178): `decision_value` returns None for "no reading
        recent enough to act on" — a property of the CACHE, not evidence
        the account is walled. Failing closed on it forged the "nowhere to
        land" 429 whenever the cache was merely cold, with a perfectly
        healthy account sitting live — the OTHER direction of the
        2026-09-07 opus Critical this reversal is safe against, because
        `walled` (below) still fails closed on the wall this daemon or
        cswap actually knows about."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=None)
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, (
            f"an unknown reading on an account not known walled must "
            f"convert without ever reaching switch(): {calls}")

    def case_an_unknown_headroom_on_a_slot_this_daemon_walled_relays_the_429(
        self, monkeypatch,
    ):
        """THE FIRST CONTROL. Unknown headroom converts only when the live
        account is not KNOWN walled — `_walled_slots` is this daemon's own
        record of a wall it saw directly on this slot, and a cold cache
        must not override it."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=None)
        from cswap_pin import proxy as pp
        pp._walled_slots["1"] = time.time() + 3600
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, (
            f"a slot this daemon already knows is walled must not convert "
            f"on an unknown reading: {calls}")

    def case_an_unknown_headroom_on_cswaps_own_persisted_wall_relays_the_429(
        self, monkeypatch,
    ):
        """THE SECOND CONTROL. `_live_account_headroom` reads `0.0`, not
        `None`, off `entry.walled` — cswap's OWN persisted wall on the live
        slot — so this is a KNOWN wall too, even though `_walled_slots`
        (this daemon's own memory) never saw it."""
        calls = self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                           usage=self.HEADROOM, entry_walled=True)
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, (
            f"cswap's own persisted wall must not be overridden by an "
            f"otherwise-good reading: {calls}")

    def case_the_headroom_read_refetches_rather_than_trusting_the_cache(
        self, monkeypatch,
    ):
        """`fetch=set()` forbids every fetch, so `decision_value` is None on
        any account nobody polled inside `STALE_OK_S` (300s) — and a wall is
        exactly when nobody has. `switch()` itself refetches; so must this,
        or the conversion is unavailable at the only moment it is needed."""
        snap = []
        self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                   usage=self.HEADROOM, snap=snap)
        self._relay(auth="Bearer stale-account-token")
        assert snap == [{"1"}], (
            "the read must name the live slot: `fetch=None` reserves with "
            "`respect_plans=True`, so a row that is stale but not yet "
            "poll-due is NOT refetched and the reading can describe the "
            "account as it was before it walled — and it sweeps every managed "
            f"account over the network to do it: {snap}")

    def case_a_request_with_no_bearer_never_converts(self, monkeypatch):
        """NOTHING KILLED THE `token and` GUARD. Every case that predates the
        bearer test sends no `Authorization`, but also has an unreadable
        store, so `live` is falsy and the comparison is never reached — drop
        `token and` and they all still pass. A request the pin forwarded
        without a bearer (an `x-api-key` client) would then have its wall
        converted on the strength of an OAuth account's headroom that has
        nothing to do with it: the fail-open shape this round exists to end."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        got = self._relay(auth="")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, len(calls)

    def case_an_unmanaged_live_login_never_converts(self, monkeypatch):
        """`current_account_number()` answers None for a live login cswap does
        not own — deliberately, with no fallback to the recorded
        `activeAccountNumber`, so nobody evaluates the wrong account's usage.
        There is then no live account to read headroom for."""
        calls = self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                           usage=self.HEADROOM, live_num=None)
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, len(calls)

    def case_an_unreadable_live_account_never_converts(self, monkeypatch):
        """The identity half fails closed too: with no answer to "which
        account is live" there is no evidence the bearer is stale, and a
        difference against nothing is not a difference."""
        calls = self._wire(monkeypatch, switched=False, usage=self.HEADROOM)
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, len(calls)

    def case_a_bearer_conversion_is_not_a_standing_401(self, monkeypatch):
        """THE 401 LOOP WITH NO SLEEP, and it is this path's own to prevent.

        A SECOND 429 CARRYING THE SAME RESET IS PROOF THE CONVERSION DID NOT
        LAND: the epoch is per (account, window), so a client that really
        rebuilt onto another account cannot re-earn it. Recording the bearer
        path's answer as a settled TRUE made the memo re-answer 401 to that
        proof forever, without re-reading the bearer or the headroom — and a
        same-account token ROTATION reaches it (bearer != live, account
        unchanged and still walled), giving 401 -> 429 -> 401 with no sleep
        until the retry loop exhausts into `authentication_failed`.

        So the wall converts at most once per `_WALLED_SWITCH_RAISE_TTL` out
        of this path; every 429 in between relays, which is a sleep the client
        survives. Not once and never again -- the entry expires like any other
        negative, so a straggler still on the old bearer is not starved."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        first = self._relay(auth="Bearer stale-account-token")
        assert first.startswith(b"HTTP/1.1 401"), first[:40]
        for n in (2, 3):
            again = self._relay(auth="Bearer stale-account-token")
            assert again.startswith(b"HTTP/1.1 429"), (
                f"relay {n} of the same wall on the same bearer: the client "
                f"did not move, so a second 401 only spends its retries "
                f"faster: {again[:40]!r}")
        assert not calls, (
            f"no repeat may reach `switch()` inside the debounce: {calls}")

    def case_n_sessions_on_the_same_wall_each_get_their_own_401(
        self, monkeypatch,
    ):
        """T1178: the bearer branch used to write its verdict into the SAME
        `(reset, slot)` memo `switch()` uses, so the first stale session to
        convert silenced every OTHER stale session's 429 on that wall until
        the TTL passed -- N sessions took N * 30s to all recover. Keyed on
        `(reset, slot, session)` instead, each session's OWN stale bearer
        converts independently."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        for sid in ("cse_a", "cse_b", "cse_c"):
            got = self._relay(auth="Bearer stale-account-token", session=sid)
            assert got.startswith(b"HTTP/1.1 401"), (sid, got[:40])
        assert not calls, (
            f"no session's bearer conversion may reach switch(): {calls}")

    def case_n_sessions_on_the_same_wall_share_one_headroom_read(
        self, monkeypatch,
    ):
        """THE DEFECT (T1213): keying the 401 per session (above) is right,
        but each of the N sessions then also asked `_live_account_headroom`
        on its own -- N usage fetches under `_walled_switch_lock` where the
        old SHARED memo used to pay for one. A short (reset, slot) verdict
        cache lets the N sessions still each get their own 401 while the
        underlying reading is asked for once."""
        snap = []
        self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                   usage=self.HEADROOM, snap=snap)
        for sid in ("cse_a", "cse_b", "cse_c"):
            got = self._relay(auth="Bearer stale-account-token", session=sid)
            assert got.startswith(b"HTTP/1.1 401"), (sid, got[:40])
        assert len(snap) == 1, (
            f"N stale sessions on one wall must share one headroom read, "
            f"not pay their own: {snap}")

    def case_one_session_gets_one_401_per_ttl_even_as_its_token_rotates(
        self, monkeypatch,
    ):
        """THE 78bd597 LOOP STAYS CLOSED, per session now instead of per
        wall: a second 429 carrying the same reset from the SAME session --
        even with a rotated token, since a retry mints a fresh one -- is
        still proof the conversion did not land, and must not repeat the
        401 that would spend the client's retries with no sleep."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        first = self._relay(auth="Bearer stale-account-token",
                            session="cse_rotating")
        assert first.startswith(b"HTTP/1.1 401"), first[:40]
        for n in (2, 3):
            again = self._relay(auth=f"Bearer rotated-token-{n}",
                                session="cse_rotating")
            assert again.startswith(b"HTTP/1.1 429"), (
                f"relay {n}: the same session must not get a second 401 "
                f"inside the TTL: {again[:40]!r}")
        assert not calls, (
            f"no repeat from this session may reach switch(): {calls}")

    def case_a_sessions_expired_memo_converts_again(self, monkeypatch):
        """THE OTHER HALF OF THE TTL: the case above is the control that the
        debounce holds INSIDE the window; nothing covered the per-session
        memo actually EXPIRING, the way `_walled_switch_seen`'s own negative
        does (`case_a_settled_negative_expires_so_the_next_429_re_attempts`).
        Without the prune in `_switch_off_walled_account`'s bearer branch,
        this session's one 401 would be its last forever, on a wall whose
        window can run for hours."""
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_WALLED_SWITCH_RAISE_TTL", 0.0)
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        first = self._relay(auth="Bearer stale-account-token",
                            session="cse_expiring")
        assert first.startswith(b"HTTP/1.1 401"), first[:40]
        second = self._relay(auth="Bearer stale-account-token",
                             session="cse_expiring")
        assert second.startswith(b"HTTP/1.1 401"), (
            "a session's own stale-bearer memo must expire like any other "
            f"negative, or one 401 is this session's last on the whole "
            f"wall: {second[:40]!r}")
        assert not calls, (
            f"no repeat from this session may reach switch(): {calls}")

    def case_a_reading_missing_a_base_window_converts(self, monkeypatch):
        """INVERTED (T1178): `oauth.relevant_windows` appends 5h and 7d only
        when each is present, so this reading is UNKNOWN (not "90% full") —
        `account_headroom` never even runs on it, `_live_account_headroom`
        returns `None`, and `None` now converts when the account is not
        known walled, same as any other unknown reading."""
        calls = self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                           usage={"five_hour": {"pct": 10.0}})
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, calls

    def case_a_scoped_only_reading_converts(self, monkeypatch):
        """INVERTED (T1178): with no 5h/7d measured at all this reading is
        UNKNOWN too, by the same rule as the case above — `oauth.py` writes
        `five_hour`/`seven_day` conditionally, so this shape is permitted by
        the host, and an unknown reading on an account not known walled
        converts."""
        calls = self._wire(
            monkeypatch, switched=False, live_token=self.LIVE,
            usage={"scoped": [{"name": "Fable", "pct": 10.0}]})
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, calls

    def case_an_over_limit_reading_fails_closed(self, monkeypatch):
        """A window past 100% gives a NEGATIVE headroom. `> 0` is the test,
        not `is not None`, and not `>= 0`."""
        calls = self._wire(
            monkeypatch, switched=False, live_token=self.LIVE,
            usage={"five_hour": {"pct": 120.0}, "seven_day": {"pct": 20.0}})
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, len(calls)

    def case_a_sentinel_reading_converts(self, monkeypatch):
        """INVERTED (T1178): `decision_value` returns a SENTINEL STRING as
        well as a dict or None — a rate-limited row says so that way. Not a
        dict, so not a number, so UNKNOWN rather than "no headroom" — and an
        unknown reading on an account not known walled converts."""
        calls = self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                           usage="rate_limited")
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, calls

    def case_only_a_bearer_scheme_carries_a_bearer(self, monkeypatch):
        """Stripping `bearer ` and treating whatever is left as the token
        makes EVERY other scheme's whole value a token that can never equal
        the live one — so `Basic <b64>` converts unconditionally. Not a shape
        Claude Code sends on `/v1/messages`, which is exactly why it would
        have sat here unnoticed."""
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        got = self._relay(auth="Basic dXNlcjpwYXNz")
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, len(calls)

    def case_the_bearer_paths_own_negative_expires(self, monkeypatch):
        """m1: NOTHING ASSERTED THAT THIS PATH'S ENTRY EXPIRES. Writing
        `(False, None)` instead of going through `_remember_walled_switch`
        left all 38 cases green, so "at most once per TTL" was enforced by
        nobody. The case next door pins the debounce INSIDE the TTL; this one
        pins that the TTL ends. A straggler still holding the old bearer must
        get another chance to be told to rebuild."""
        from cswap_pin import proxy as pp
        monkeypatch.setattr(pp, "_WALLED_SWITCH_RAISE_TTL", 0.0)
        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        for n in (1, 2):
            got = self._relay(auth="Bearer stale-account-token")
            assert got.startswith(b"HTTP/1.1 401"), (
                f"relay {n}: the bearer path's negative must expire like "
                f"every other one: {got[:40]!r}")
        assert not calls, calls

    def case_a_hairline_headroom_converts_and_the_rebuild_closes_it(
        self, monkeypatch,
    ):
        """I1: THE (0, 1) BAND WAS UNASSERTED. `account_headroom` is
        `100 - max(pct)`, so a live account at 99.9% scores 0.1 and this
        branch answers 401; the full-account case pins exactly 100.0, which
        says nothing about the band below it.

        It converts, and that is deliberate: 0.1% is not "at limit", the
        retry lands, and what bounds the danger is not the size of the number
        but the REBUILD. Once the client is on the live account its bearer
        equals the live token, so this path cannot fire again -- a second 401
        needs a bearer that is still stale. That is the mechanism, asserted
        rather than argued."""
        calls = self._wire(
            monkeypatch, switched=False, live_token=self.LIVE,
            usage={"five_hour": {"pct": 99.9}, "seven_day": {"pct": 20.0}})
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, calls
        # The client rebuilt: its bearer IS the live account now.
        after = self._relay(reset=self.RESET_HEADER_2,
                            auth="Bearer " + self.LIVE)
        assert after.startswith(b"HTTP/1.1 429"), (
            "once the client is on the live account this path is closed, so "
            f"no 401 can repeat and the retry loop cannot exhaust: {after[:40]!r}")
        # AND IT REACHED THE SWITCH. `switched=False` makes 429 the answer from
        # the switch path too, so the status alone also passes if the function
        # returned False at the top (a RESET_HEADER_2 that stopped parsing).
        # This pins that the BEARER branch is what was skipped.
        assert len(calls) == 1, (
            f"the second wall never reached switch(), so the 429 above does "
            f"not show the bearer branch was closed: {calls}")

    def case_a_hairline_headroom_is_logged_as_itself(self, monkeypatch):
        """I1: `{headroom:.0f}` printed "0% headroom; relaying a 401" for the
        very band the branch was taken on, so the only post-hoc evidence
        contradicted the decision it recorded. This round's own event took two
        analyzers to read out of daemon.log; a line that lies costs a third."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                   usage={"five_hour": {"pct": 99.9}, "seven_day": {"pct": 20.0}})
        self._relay(auth="Bearer stale-account-token")
        line = next(m for m in logged if "no longer the live account" in m)
        assert "0.1% headroom" in line, (
            f"the headroom that decided the branch must be readable: {line!r}")
        assert "0% headroom" not in line, line

    def case_two_accounts_sharing_a_reset_epoch_decide_separately(
        self, monkeypatch,
    ):
        """I2: A UNIFIED-RESET EPOCH IS A CLOCK BOUNDARY, NOT AN IDENTITY.
        This round's own wall was `1788925200` = 03:40:00Z exactly, so two
        accounts hitting their window at the same boundary carry the SAME
        reset. Keyed on the epoch alone, the first client's settled TRUE
        answers 401 for the second account's wall with no bearer test and no
        headroom test -- an account that never earned it.

        The exposure is this branch's own doing: a settled negative used to
        close the key forever, and now expires every TTL, so `switch()` gets
        an attempt per TTL across the whole window to mint that permanent
        TRUE. The key is `(reset, slot)`; the slot does not rotate per retry,
        so a same-account token rotation still debounces."""
        slots = iter(["1", "2"])   # one slot read per relay
        calls = self._wire(monkeypatch, switched=True, live_token=self.LIVE,
                           usage=self.HEADROOM,
                           live_num=lambda: next(slots, "2"))
        first = self._relay(auth="Bearer " + self.LIVE)
        assert first.startswith(b"HTTP/1.1 401"), first[:40]
        # Slot 2's own wall, same epoch, and it has never been switched off.
        second = self._relay(auth="Bearer " + self.LIVE)
        assert second.startswith(b"HTTP/1.1 401"), second[:40]
        assert len(calls) == 2, (
            "the second account's wall must be decided on its own evidence, "
            f"not inherited from a conversion the first account earned: {calls}")

    # --- the model sweep -------------------------------------------------
    # tests/models/at_limit_conversion.pict enumerates the decision's inputs;
    # `pict` expands it to the pairwise set beside it. The cases above each
    # carry a NAMED rationale for one combination; this one walks every row of
    # the model so a combination nobody imagined cannot go missing quietly.

    HEADROOM_USAGE = {
        "Ample": {"five_hour": {"pct": 10.0}, "seven_day": {"pct": 20.0}},
        "Hairline": {"five_hour": {"pct": 99.9}, "seven_day": {"pct": 20.0}},
        "Exhausted": {"five_hour": {"pct": 100.0}, "seven_day": {"pct": 20.0}},
        "OverLimit": {"five_hour": {"pct": 120.0}, "seven_day": {"pct": 20.0}},
        "NoReading": None,
        "Sentinel": "rate_limited",
        "MissingBaseWindow": {"five_hour": {"pct": 10.0}},
        "ScopedOnly": {"scoped": [{"name": "Fable", "pct": 10.0}]},
    }
    SWITCH_WIRING = {
        "LandedValidated": dict(switched=True, validated=True),
        "LandedUnvalidated": dict(switched=True, validated=None),
        "NoCandidate": dict(switched=False),
        "NeedsLogin": dict(switched=True, needs_login=True),
        "Raised": dict(switched=True),
    }

    @classmethod
    def _model_rows(cls):
        """Rows of the committed expansion, checked against the model itself.

        A PARAMETER ADDED WITHOUT RE-RUNNING `pict` leaves the sweep passing on
        the stale set while it reports full model coverage -- the model's own
        "an unrun gate reads like a passed one", one level up. The header row
        is the cheap witness: it is exactly the model's parameter names, in
        order."""
        from pathlib import Path
        models = Path(__file__).parent / "models"
        tsv = (models / "at_limit_conversion.tsv").read_text().splitlines()
        head = tsv[0].split("\t")
        declared = [
            ln.split(":", 1)[0].strip()
            for ln in (models / "at_limit_conversion.pict").read_text().splitlines()
            if ln and not ln.lstrip().startswith(("#", "IF")) and ":" in ln
        ]
        assert declared == head, (
            "at_limit_conversion.tsv is not the expansion of the current "
            f"model -- re-run `pict`. model={declared} tsv={head}")
        return [dict(zip(head, line.split("\t"))) for line in tsv[1:] if line]

    @staticmethod
    def _model_expects(row):
        """The SPEC, read off the model -- never a second copy of the code.

        A wall 429 becomes a 401 when, and only when, one of two things is
        true: an earlier call for this same (wall, account) already converted
        it, or the client's bearer is no longer the live account AND that
        account is not KNOWN to be walled (T1178: an UNKNOWN reading now
        converts too, same as a good one -- every row here has an empty
        `_walled_slots` and `entry.walled=False`, since neither is a
        parameter of this model; the two known-walled controls live as their
        own named cases instead of a ninth `Headroom` value). Only a
        MEASURED non-positive headroom (Exhausted, OverLimit) still relays.
        """
        if row["ResetHeader"] == "Absent":
            return False, 0
        if row["MemoEntry"] == "SettledConversion":
            return True, 0
        if row["MemoEntry"] == "LiveNegative":
            return False, 0
        stale_bearer = (row["Authorization"] == "BearerStale"
                        and row["LiveToken"] == "Readable"
                        and row["LiveSlot"] == "Managed")
        if stale_bearer and row["Headroom"] not in ("Exhausted", "OverLimit"):
            return True, 0
        return row["Switch"] == "LandedValidated", 1

    def case_every_row_of_the_pict_model(self, monkeypatch):
        """One row per pairwise combination, expected outcome derived from the
        model's rules rather than from the implementation."""
        from cswap_pin import proxy as pp

        rows = self._model_rows()
        assert len(rows) > 40, f"the expanded model looks truncated: {len(rows)}"
        failures = []
        for i, row in enumerate(rows):
            def _raise():
                raise OSError("locked")

            slot = "1" if row["LiveSlot"] == "Managed" else None
            calls = self._wire(
                monkeypatch,
                live_token=self.LIVE if row["LiveToken"] == "Readable" else None,
                usage=self.HEADROOM_USAGE[row["Headroom"]],
                live_num=slot,
                before=_raise if row["Switch"] == "Raised" else None,
                **self.SWITCH_WIRING[row["Switch"]])
            key = (b"9999999999", slot)
            # `decided_at` in the past: this fixture's `ClaudeAccountSwitcher`
            # has no `.switch` class attribute (`_wire`'s lambda returns an
            # instance, not a class), so `_switch_takes_exclude` always reads
            # False here and the re-decide gate this fix adds never opens —
            # the model's own rows carry no case for it.
            decided_at = time.monotonic() - 1.0
            if row["MemoEntry"] == "SettledConversion":
                pp._walled_switch_seen[key] = (True, None, decided_at)
            elif row["MemoEntry"] == "LiveNegative":
                pp._walled_switch_seen[key] = (
                    False, time.monotonic() + 1e6, decided_at)
            elif row["MemoEntry"] == "ExpiredNegative":
                pp._walled_switch_seen[key] = (
                    False, time.monotonic() - 1.0, decided_at)
            auth = {"BearerStale": "Bearer stale-account-token",
                    "BearerIsLive": "Bearer " + self.LIVE,
                    "NonBearerScheme": "Basic dXNlcjpwYXNz",
                    "NoHeader": ""}[row["Authorization"]]
            got = self._relay(
                reset=False if row["ResetHeader"] == "Absent" else None,
                auth=auth)
            want_401, want_calls = self._model_expects(row)
            saw_401 = got.startswith(b"HTTP/1.1 401")
            if saw_401 != want_401 or len(calls) != want_calls:
                failures.append(
                    f"row {i + 1} {row} -> 401={saw_401} calls={len(calls)}, "
                    f"model says 401={want_401} calls={want_calls}")
                continue
            # Every wall this decision reaches (ResetHeader=Present, 401 or
            # relayed) must lose its rate-limit family either way; an
            # edge/gateway 429 (ResetHeader=Absent) is outside this decision
            # and must pass every header through unchanged.
            if row["ResetHeader"] == "Present":
                if (self.RESET_HEADER in got or self.RETRY_AFTER in got
                        or self.UNIFIED_STATUS in got
                        or self.SHOULD_RETRY in got):
                    failures.append(
                        f"row {i + 1} {row} -> rate-limit headers survived "
                        f"(401={saw_401})")
            elif self.RETRY_AFTER not in got or self.SHOULD_RETRY not in got:
                failures.append(
                    f"row {i + 1} {row} -> an edge/gateway 429 lost a header "
                    "this decision never touches")
        assert not failures, (
            f"{len(failures)} of {len(rows)} model rows disagree with the "
            "implementation:\n" + "\n".join(failures[:6]))

    def case_the_live_slot_is_read_outside_the_wall_lock(self, monkeypatch):
        """`_live_login_identity`'s own docstring: "`ask_server=False` for a
        caller inside the locks". `current_account_number()` takes the DEFAULT
        `ask_server=True`, so reading it under `_walled_switch_lock` puts a
        server round trip inside the one lock every waiter in a wall storm
        blocks on -- ten concurrent 429s on one wall is measured, and the
        debounced repeats (28 in the 2026-09-09 event) would each pay it in
        series. The key needs the slot; nothing needs it read under the lock."""
        from cswap_pin import proxy as pp
        under_lock = []

        def _slot():
            free = pp._walled_switch_lock.acquire(blocking=False)
            if free:
                pp._walled_switch_lock.release()
            under_lock.append(not free)
            return "1"

        self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                   usage=self.HEADROOM, live_num=_slot)
        self._relay(auth="Bearer stale-account-token")
        assert under_lock and not any(under_lock), (
            "the live slot was resolved while `_walled_switch_lock` was held: "
            f"{under_lock}")

    def case_the_bearer_conversion_is_logged(self, monkeypatch):
        """`_TRACE` is off on a serving daemon, so daemon.log is the only
        record — and every count in the 2026-09-09 analysis came from
        `/usr/bin/grep -aFc` over these lines. A branch with no line of its
        own is unmeasurable after the fact."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        self._wire(monkeypatch, switched=False,
                   live_token=self.LIVE, usage=self.HEADROOM)
        self._relay(auth="Bearer stale-account-token")
        assert sum("no longer the live account" in m for m in logged) == 1, logged

    def case_a_switch_without_a_validated_landing_relays_the_429_with_headers_stripped(
        self, monkeypatch,
    ):
        """`switch()` landed a credential but never probed it live (an older
        cswap on the host, or a probe that did not run) — no `validated`
        key at all. A 401 here would rebuild CC onto a credential nobody
        confirmed is alive, which is worse than the wall it replaces."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        calls = self._wire(monkeypatch, switched=True, validated=None)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert self.RESET_HEADER not in got, got[:80]
        assert self.RETRY_AFTER not in got, got[:80]
        assert sum(
            "did not validate the landing credential (validated absent), "
            "relaying the 429 with headers stripped" in m for m in logged
        ) == 1, logged
        second = self._relay()
        assert second.startswith(b"HTTP/1.1 429"), second[:40]
        assert self.RESET_HEADER not in second, second[:80]
        assert len(calls) == 1, len(calls)

    def case_a_switch_with_validated_false_relays_the_429_with_headers_stripped(
        self, monkeypatch,
    ):
        """Same as the missing-key case, spelled the other way: `switch()`
        ran the probe and it came back dead."""
        from cswap_pin import proxy as pp
        logged = []
        monkeypatch.setattr(pp, "_log_lifecycle", logged.append)
        calls = self._wire(monkeypatch, switched=True, validated=False)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert self.RESET_HEADER not in got, got[:80]
        assert self.RETRY_AFTER not in got, got[:80]
        assert sum(
            "did not validate the landing credential (validated False), "
            "relaying the 429 with headers stripped" in m for m in logged
        ) == 1, logged
        second = self._relay()
        assert second.startswith(b"HTTP/1.1 429"), second[:40]
        assert len(calls) == 1, len(calls)

    def case_two_concurrent_429s_on_the_same_wall_wait_for_the_switch(
        self, monkeypatch,
    ):
        """Ten concurrent 429s on one wall (measured), each its own MITM
        thread: a debounce that claims the wall's slot and releases the
        lock BEFORE `switch()` returns lets a second thread read
        seen-and-not-yet-ok and relay the 429 verbatim while the first
        thread's switch is still landing. The lock must stay held across
        `switch()` so every waiter reads the one settled answer."""
        entered = threading.Event()
        release = threading.Event()

        def _block():
            entered.set()
            assert release.wait(timeout=5), "release never set — test bug"

        calls = self._wire(monkeypatch, switched=True, before=_block)

        results = {}

        def _run(key):
            results[key] = self._relay()

        t1 = threading.Thread(target=_run, args=("a",))
        t1.start()
        assert entered.wait(timeout=5), "switch() never started"

        t2 = threading.Thread(target=_run, args=("b",))
        t2.start()
        # t2 has had time to reach the debounce check (or run past it, on
        # the broken shape) while switch() is still blocked on `release`.
        time.sleep(0.2)
        # On the broken shape (lock released before `switch()` returns) t2
        # has already written its 429 by now, before switch() ever settles.
        assert "b" not in results, results
        release.set()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert results["a"].startswith(b"HTTP/1.1 401"), results["a"][:40]
        assert results["b"].startswith(b"HTTP/1.1 401"), results["b"][:40]
        assert len(calls) == 1, len(calls)

    def case_two_concurrent_429s_on_the_same_wall_wait_for_the_switch_with_the_gate_open(
        self, monkeypatch,
    ):
        """THE STORM BOUND WITH THE RE-DECIDE GATE ABLE TO OPEN. The case
        above runs on `_wire`, where `_switch_takes_exclude()` reads False,
        so it never exercises the `redecide` branch at all — nothing there
        proves the storm still collapses into one `switch()` call once a
        host CAN take `exclude`. Thread b reads its own slot (`seen_at`)
        while thread a's `switch()` is still blocked, so that read predates
        `decided_at` by construction: `seen_at >= decided_at` must read
        False for it, same as the case above, one `switch()` call for both
        429s."""
        entered = threading.Event()
        release = threading.Event()

        def _block():
            entered.set()
            assert release.wait(timeout=5), "release never set — test bug"

        calls = self._wire_exclude_capable(monkeypatch, switched=True,
                                            before=_block)

        results = {}

        def _run(key):
            results[key] = self._relay()

        t1 = threading.Thread(target=_run, args=("a",))
        t1.start()
        assert entered.wait(timeout=5), "switch() never started"

        t2 = threading.Thread(target=_run, args=("b",))
        t2.start()
        time.sleep(0.2)
        assert "b" not in results, results
        release.set()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert results["a"].startswith(b"HTTP/1.1 401"), results["a"][:40]
        assert results["b"].startswith(b"HTTP/1.1 401"), results["b"][:40]
        assert len(calls) == 1, len(calls)

    def case_a_different_wall_switches_again(self, monkeypatch):
        """The debounce keys on the WALL's own reset value, not on a time
        window or the account identity: a different wall must switch again
        even seconds later, and a wall already seen must never re-switch no
        matter how long it persists — but its already-converted 401 is what
        every later repeat of it sees."""
        calls = self._wire(monkeypatch, switched=True)
        first = self._relay(reset=self.RESET_HEADER)
        assert first.startswith(b"HTTP/1.1 401"), first[:40]
        second = self._relay(reset=self.RESET_HEADER_2)
        assert second.startswith(b"HTTP/1.1 401"), second[:40]
        assert len(calls) == 2, len(calls)
        third = self._relay(reset=self.RESET_HEADER)
        assert third.startswith(b"HTTP/1.1 401"), third[:40]
        assert len(calls) == 2, len(calls)

    def case_a_429_off_messages_is_never_touched(self, monkeypatch):
        calls = self._wire(monkeypatch, switched=True)
        got = self._relay(path="/v1/other")
        assert got.startswith(b"HTTP/1.1 429"), got
        assert not calls, "the switch must only ever be tried for /v1/messages"

    def case_a_wall_with_nowhere_to_land_is_relayed_not_converted(
        self, monkeypatch, certdir,
    ):
        """THE EVENT, 2026-09-07 ~18:1xZ, through the real MITM.

        Account-2 walled, the failover moved to Account-4, Account-4 was Fable
        100%. The ranking never saw that window — `switch_off_at_limit_account`
        weighs 5h/7d only — so the switch landed, the pin answered 401, Claude
        Code rebuilt onto Account-4, walled again, and the retry loop exhausted
        into `authentication_failed`. That reason is not in Claude Code's
        partial-result set {rate_limit, overloaded, server_error}, so three
        fable team leads lost their context outright instead of sleeping
        (req_011Cepk7iQtQCjPtKjVxCxna and two siblings in the same minute).

        THE ASSERTION THAT DISCRIMINATES IS THE BASIS, not the status: with no
        candidate the pin relays a 429 either way. `models=("all",)` folds
        EVERY scoped weekly window the account reports into the comparison
        (`oauth.relevant_windows`, the `all` sentinel), which is the one thing
        that makes a full Fable window able to stop the conversion. What the
        host then decides on that basis is the host's.

        End to end rather than straight into `_relay_response`, because the
        request and the response are handled in different methods and a wiring
        that never reaches the relay is invisible from the cases next door."""
        from cswap_pin.proxy import PinProxy

        calls = self._wire(monkeypatch, switched=False)
        upstream = _FakeUpstream(certdir, reply=(
            b"HTTP/1.1 429 Too Many Requests\r\n" + self.RESET_HEADER
            + b"\r\n" + self.RETRY_AFTER + b"\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n"))
        proxy = PinProxy(certdir=certdir,
                         pin_token_provider=lambda: "PIN-TOKEN",
                         upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages",
                bearer="disk-token",
                body=json.dumps({"model": "claude-fable-5-1", "max_tokens": 4}),
            )
        finally:
            proxy.stop()
            upstream.stop()
        assert calls == [("all",)], (
            "the ranking was not told to weigh the per-model weekly windows, "
            "so a target full on the model this request needs is invisible to "
            f"it and the wall becomes a 401 with nowhere to land: {calls}")
        assert status == 429, status

    def case_the_bearer_reaches_the_relay_through_the_real_mitm(
        self, monkeypatch, certdir,
    ):
        """THE WIRING, end to end. The request and the response are handled in
        different methods, so the bearer has to be carried from `_forward` to
        `_relay_response` — and a conversion that works when the unit case
        hands `auth=` in directly, while the daemon passes nothing, is a fleet
        that never converts and a unit suite that never says so.

        `disk-token` is the client's bearer; the store answers with a
        different live account that has headroom, and `switched=False` means
        the 401 cannot have come from a switch."""
        from cswap_pin.proxy import PinProxy

        calls = self._wire(monkeypatch, switched=False,
                           live_token=self.LIVE, usage=self.HEADROOM)
        upstream = _FakeUpstream(certdir, reply=(
            b"HTTP/1.1 429 Too Many Requests\r\n" + self.RESET_HEADER
            + b"\r\n" + self.RETRY_AFTER + b"\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n"))
        proxy = PinProxy(certdir=certdir,
                         pin_token_provider=lambda: "PIN-TOKEN",
                         upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages",
                bearer="disk-token",
                body=json.dumps({"model": "claude-fable-5-1", "max_tokens": 4}),
            )
        finally:
            proxy.stop()
            upstream.stop()
        assert not calls, (
            f"no switch was needed; the host had already moved: {calls}")
        assert status == 401, (
            "the client's bearer never reached the relay, so the daemon "
            f"relayed the wall the host had already left: {status}")

    def case_the_session_id_reaches_the_relay_through_the_real_mitm(
        self, monkeypatch, certdir,
    ):
        """THE OTHER HALF OF THE SAME WIRING: `x-claude-code-session-id`
        travels `_forward` -> `_relay_response` exactly like the bearer
        above, and nothing covered it. If the header is not threaded, both
        sessions fall back to the shared `(reset, slot)` memo: the first
        stale-bearer 429 converts and records a negative under that shared
        key, and the second session's 429 on the same wall is then a
        DEBOUNCED REPEAT of that negative — a raw 429, not its own 401. With
        the header threaded each session gets its own per-session memo, so
        both convert."""
        from cswap_pin.proxy import PinProxy

        self._wire(monkeypatch, switched=False,
                   live_token=self.LIVE, usage=self.HEADROOM)
        upstream = _FakeUpstream(certdir, reply=(
            b"HTTP/1.1 429 Too Many Requests\r\n" + self.RESET_HEADER
            + b"\r\n" + self.RETRY_AFTER + b"\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n"))
        proxy = PinProxy(certdir=certdir,
                         pin_token_provider=lambda: "PIN-TOKEN",
                         upstream=("127.0.0.1", upstream.port))
        proxy.start()
        try:
            body = json.dumps({"model": "claude-fable-5-1", "max_tokens": 4})
            first = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages",
                bearer="disk-token", body=body,
                extra_headers={"x-claude-code-session-id": "session-a"},
            )
            second = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages",
                bearer="disk-token", body=body,
                extra_headers={"x-claude-code-session-id": "session-b"},
            )
        finally:
            proxy.stop()
            upstream.stop()
        assert first == 401, (
            "the first session's stale bearer never reached the relay: "
            f"{first}")
        assert second == 401, (
            "the session id never reached the relay, so the second "
            "session's own stale-bearer 429 was debounced against the "
            f"first session's shared-key negative instead of its own "
            f"per-session memo: {second}")

    # --- a walled slot going live again inside its own wall (T1111) -------

    @staticmethod
    def _wire_exclude_capable(monkeypatch, switched, exclude_param=True,
                               validated=True, live_token=None, live_num="1",
                               before=None):
        """`ClaudeAccountSwitcher` as a real CLASS carrying `switch` as an
        ordinary method, so `_switch_takes_exclude`'s
        `inspect.signature(...ClaudeAccountSwitcher.switch)` can actually see
        whether `exclude` is in it. `_wire`'s lambda returns an INSTANCE, so
        `ClaudeAccountSwitcher.switch` there has no `.switch` attribute at
        all and `_switch_takes_exclude` reads False on the AttributeError —
        which is what keeps every case above this one immune to the
        re-decide gate regardless of timing. This wiring is what exercises
        it. ``before``, as in `_wire`, runs at the top of `switch()`, for a
        case that needs to block inside it."""
        from cswap_pin import proxy as pp
        calls = []

        def _read_credentials(self):
            if live_token is None:
                raise OSError("credential store unreadable")
            return json.dumps({"claudeAiOauth": {"accessToken": live_token}})

        def _current_account_number(self):
            return live_num() if callable(live_num) else live_num

        if exclude_param:
            def _switch(self, strategy=None, json_output=False, models=None,
                        current_at_limit=False, exclude=None):
                calls.append(exclude)
                if before is not None:
                    before()
                return {"switched": switched, "needsLogin": False,
                        "validated": validated,
                        "reason": None if switched else "candidates-exhausted"}
        else:
            def _switch(self, strategy=None, json_output=False, models=None,
                        current_at_limit=False):
                calls.append(None)
                if before is not None:
                    before()
                return {"switched": switched, "needsLogin": False,
                        "validated": validated,
                        "reason": None if switched else "candidates-exhausted"}

        fake_switcher = type("FakeSwitcher", (), {
            "_read_credentials": _read_credentials,
            "current_account_number": _current_account_number,
            "switch": _switch,
        })
        fake_module = type("M", (), {"ClaudeAccountSwitcher": fake_switcher})()
        monkeypatch.setattr(pp, "require", lambda n: fake_module)
        pp._walled_switch_seen.clear()
        pp._walled_slots.clear()
        pp._walled_switch_seen_by_session.clear()
        pp._walled_headroom_seen.clear()
        return calls

    def case_a_walled_slot_live_again_re_decides_when_the_host_can_exclude_it(
        self, monkeypatch,
    ):
        """THE DEFECT: a settled TRUE was permanent, so once cswap moved BACK
        onto the walled slot inside its own wall the pin kept relaying a
        debounced 401 forever — measured 1055 times across 23 minutes on
        2026-09-23 (wall reset unexpired, slot live again). A request whose
        own slot read happened AFTER the verdict, and still names the walled
        slot, is what tells this apart from a storm waiter (whose read
        predates the verdict by construction): only that request re-decides,
        and only when the host can be told to skip the slot it would
        otherwise land right back on."""
        from cswap_pin import proxy as pp
        calls = self._wire_exclude_capable(monkeypatch, switched=True,
                                            live_num="6")
        pp._walled_switch_seen[(b"9999999999", "6")] = (
            True, None, time.monotonic() - 1.0)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert len(calls) == 1, (
            "the walled slot is live again; a fresh switch() attempt was "
            f"owed, not a bare debounce: {calls}")

    def case_a_storm_waiter_reading_before_the_verdict_still_just_debounces(
        self, monkeypatch,
    ):
        """THE CONTROL for the case above. Without the `seen_at < decided_at`
        gate every debounced repeat would re-attempt `switch()` — exactly
        the ten-at-once storm `case_two_concurrent_429s_on_the_same_wall_
        wait_for_the_switch` exists to collapse into one call. Seeding
        `decided_at` far in the future stands in for a read that truly
        predates the verdict, deterministically and without a sleep."""
        from cswap_pin import proxy as pp
        calls = self._wire_exclude_capable(monkeypatch, switched=True,
                                            live_num="6")
        pp._walled_switch_seen[(b"9999999999", "6")] = (
            True, None, time.monotonic() + 1e6)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, (
            f"a storm waiter must not re-attempt the switch: {calls}")

    def case_a_host_that_cannot_exclude_keeps_the_bare_debounce(
        self, monkeypatch,
    ):
        """THE OTHER CONTROL. Without `exclude` a re-decide could ping-pong
        between two walled slots, one consume per client retry — so on a
        host whose `switch()` predates the kwarg (every host until a
        separate cswap task ships it) the pin must keep debouncing exactly
        as it did before this fix, even though the slot read postdates the
        verdict."""
        from cswap_pin import proxy as pp
        calls = self._wire_exclude_capable(monkeypatch, switched=True,
                                            exclude_param=False, live_num="6")
        pp._walled_switch_seen[(b"9999999999", "6")] = (
            True, None, time.monotonic() - 1.0)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, (
            "a host without `exclude` must not re-attempt the switch: "
            f"{calls}")

    def case_switch_excludes_a_slot_still_inside_its_own_wall(
        self, monkeypatch,
    ):
        """THE SECOND CAUSE: the pin's own switch-off can land right back on
        a slot it already knows is walled, because cswap's `switch()`
        cannot be told to skip one — until a separate cswap task adds
        `exclude`. `_walled_slots` is what feeds it: a fresh 429 on a
        different slot, with no memo entry of its own, still must not switch
        onto a slot this daemon already recorded a live, unexpired wall
        for."""
        from cswap_pin import proxy as pp
        calls = self._wire_exclude_capable(
            monkeypatch, switched=False, live_token=self.LIVE, live_num="4")
        pp._walled_slots["6"] = time.time() + 3600
        got = self._relay(auth="Bearer " + self.LIVE)
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert self.RESET_HEADER not in got, got[:80]
        assert len(calls) == 1, calls
        assert "6" in calls[0], (
            f"the still-walled slot must be excluded from the switch: {calls}")

    def case_an_expired_walled_slot_is_not_excluded(self, monkeypatch):
        """THE CONTROL. `_walled_slots` is a decaying set, not a log: once
        the slot's own wall has passed, keeping it excluded forever would
        refuse a perfectly healthy account for no reason."""
        from cswap_pin import proxy as pp
        calls = self._wire_exclude_capable(
            monkeypatch, switched=False, live_token=self.LIVE, live_num="4")
        pp._walled_slots["6"] = time.time() - 10
        got = self._relay(auth="Bearer " + self.LIVE)
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert len(calls) == 1, calls
        assert "6" not in calls[0], (
            f"an expired wall must not exclude its slot forever: {calls}")

    def case_a_bearer_branch_conversion_records_no_walled_slot(
        self, monkeypatch,
    ):
        """The bearer branch answers for a credential nobody has confirmed
        is still walled — its reset belongs to whichever account the
        client's frozen bearer names, not to the slot cswap has live now.
        Recording it into `_walled_slots` would make a future switch avoid a
        slot on no evidence at all."""
        from cswap_pin import proxy as pp
        self._wire(monkeypatch, switched=False,
                   live_token=self.LIVE, usage=self.HEADROOM)
        got = self._relay(auth="Bearer stale-account-token")
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not pp._walled_slots, pp._walled_slots

    def case_an_unmanaged_slot_never_redecides_on_a_settled_true(
        self, monkeypatch,
    ):
        """THE OTHER GAP `redecide` left open: `_live_account_slot` answers
        `None` on an unmanaged or failed read, so every 429 seen while the
        host is unmanaged keys on `(reset, None)` — not just the one
        request that first decided it. Without `slot is not None` in
        `redecide`, a settled TRUE on that key re-decides on every later
        look (`seen_at >= decided_at` is true for all of them, not just a
        storm waiter's), calling `switch()` again on every repeat instead
        of holding the debounce."""
        from cswap_pin import proxy as pp
        calls = self._wire_exclude_capable(monkeypatch, switched=True,
                                            live_num=None)
        pp._walled_switch_seen[(b"9999999999", None)] = (
            True, None, time.monotonic() - 1.0)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 401"), got[:40]
        assert not calls, (
            f"an unmanaged slot read must not re-attempt the switch: {calls}")

    def case_switch_off_records_the_walled_slot_from_a_real_relay(
        self, monkeypatch,
    ):
        """THE RECORDING, COVERED. Every case above this one SEEDS
        `_walled_slots` by hand, so deleting the two lines that write it
        (`_walled_slots[slot] = float(reset)`, in
        `_switch_off_walled_account`) leaves the whole suite green. Drive
        it from two real relays instead: a 429 on slot "6" carrying slot
        6's own live bearer must record the wall against "6" — then cswap
        moves the live slot to "4" and a DIFFERENT wall's 429, carrying
        slot 4's own bearer, must exclude "6" from that switch() call."""
        from cswap_pin import proxy as pp
        state = {"live_num": "6", "live_token": "token-6"}
        calls = []

        def _read_credentials(self):
            return json.dumps(
                {"claudeAiOauth": {"accessToken": state["live_token"]}})

        def _current_account_number(self):
            return state["live_num"]

        def _switch(self, strategy=None, json_output=False, models=None,
                    current_at_limit=False, exclude=None):
            calls.append(exclude)
            return {"switched": False, "needsLogin": False,
                    "validated": True, "reason": "candidates-exhausted"}

        fake_switcher = type("FakeSwitcher", (), {
            "_read_credentials": _read_credentials,
            "current_account_number": _current_account_number,
            "switch": _switch,
        })
        fake_module = type("M", (), {"ClaudeAccountSwitcher": fake_switcher})()
        monkeypatch.setattr(pp, "require", lambda n: fake_module)
        pp._walled_switch_seen.clear()
        pp._walled_slots.clear()
        pp._walled_switch_seen_by_session.clear()
        pp._walled_headroom_seen.clear()

        first = self._relay(reset=self.RESET_HEADER, auth="Bearer token-6")
        assert first.startswith(b"HTTP/1.1 429"), first[:40]

        state["live_num"] = "4"
        state["live_token"] = "token-4"
        second = self._relay(reset=self.RESET_HEADER_2, auth="Bearer token-4")
        assert second.startswith(b"HTTP/1.1 429"), second[:40]
        assert len(calls) == 2, calls
        assert "6" in calls[1], (
            f"slot 6's wall was recorded but not excluded: {calls}")

    def case_a_redecide_that_finds_no_candidate_relays_the_429_and_expires(
        self, monkeypatch,
    ):
        """THE RE-DECIDE'S OWN FAILURE PATH. The walled slot is live again,
        so a fresh `switch()` is owed — but this time nothing else is
        switchable. That answers exactly as a first-time miss would: the
        429 relays with its headers stripped, not the settled 401, and the
        verdict OVERWRITES the settled TRUE with an EXPIRING negative on
        the same key, not a permanent one."""
        from cswap_pin import proxy as pp
        calls = self._wire_exclude_capable(monkeypatch, switched=False,
                                            live_num="6")
        pp._walled_switch_seen[(b"9999999999", "6")] = (
            True, None, time.monotonic() - 1.0)
        got = self._relay()
        assert got.startswith(b"HTTP/1.1 429"), got[:40]
        assert self.RESET_HEADER not in got, got[:80]
        assert len(calls) == 1, calls
        ok, retry_at, decided_at = pp._walled_switch_seen[(b"9999999999", "6")]
        assert ok is False, pp._walled_switch_seen
        assert retry_at is not None, (
            "a redecide miss must expire, not go permanent: "
            f"{pp._walled_switch_seen}")

    def case_a_shared_negative_caps_on_the_live_walls_clock_not_the_stale_bearers(
        self, monkeypatch,
    ):
        """THE DEFECT (T1213 pass 2, I1): while the live slot is KNOWN walled
        (`_walled_slots`), a stale-bearer 429 skips the per-session headroom
        branch (`not walled` is False) and falls through to the ordinary
        `switch()` attempt, which writes its failure into the SHARED
        `(reset, slot)` memo. That 429's own `reset` belongs to the STALE
        account, not the live one -- its wall can clear long after the live
        slot's own does, so capping the negative on it (instead of on
        `_walled_slots[slot]`, the live slot's own clear time) lets the
        debounce outlive the LIVE wall by up to the stale account's wait
        instead of ending when the live wall does."""
        from cswap_pin import proxy as pp
        import time as _time
        BASE = 2_000_000_000.0
        LIVE_CLEAR = BASE + 2.0
        STALE_RESET = int(BASE) + 100  # the STALE account's own wall
        reset_header = (b"anthropic-ratelimit-unified-reset: "
                         + str(STALE_RESET).encode())
        clock = {"mono": 0.0, "wall": BASE}
        monkeypatch.setattr(_time, "monotonic", lambda: clock["mono"])
        monkeypatch.setattr(_time, "time", lambda: clock["wall"])
        calls = self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                           usage=self.HEADROOM)
        pp._walled_slots["1"] = LIVE_CLEAR

        first = self._relay(reset=reset_header,
                            auth="Bearer stale-account-token")
        assert first.startswith(b"HTTP/1.1 429"), first[:40]
        assert len(calls) == 1, calls

        # Still inside the LIVE wall (it clears at +2s): the debounce must
        # hold, and switch() must not run again for this same wall.
        clock["mono"] = 1.0
        clock["wall"] = BASE + 1.0
        second = self._relay(reset=reset_header,
                             auth="Bearer stale-account-token")
        assert second.startswith(b"HTTP/1.1 429"), second[:40]
        assert len(calls) == 1, (
            f"the debounce must hold while the LIVE wall still stands: "
            f"{calls}")

        # The LIVE wall has now cleared (+2s); the stale account's own wall
        # (STALE_RESET, +100s) has not -- and must not matter.
        clock["mono"] = 2.5
        clock["wall"] = BASE + 2.5
        third = self._relay(reset=reset_header,
                            auth="Bearer stale-account-token")
        assert third.startswith(b"HTTP/1.1 401"), (
            f"the live wall cleared 0.5s ago; the next stale-bearer 429 "
            f"must convert at once, not wait out a debounce capped on the "
            f"stale account's unrelated, later, wall: {third[:40]!r}")
        assert len(calls) == 1, calls

    def case_a_cap_already_past_does_not_reopen_switch_for_a_concurrent_429(
        self, monkeypatch,
    ):
        """I2: on the live token's own 429 (`auth` is `self.LIVE`, not a
        stale bearer) -- a non-walled path that never receives a cap -- a
        reset at or before `time.time()` (clock skew, or a wall whose own
        header already lagged) must not zero out the negative's expiry --
        that let every OTHER concurrent 429 on the same wall, queued behind
        `_walled_switch_lock`, find it already expired and re-run
        `switch()` for itself. A cap taken from this reset would have expired
        long before a second, genuinely concurrent 429 gets its turn on the
        lock: 0.5s later, far longer than a cap already past allows but nowhere near main's 30s
        TTL, is what a queued waiter's lock handoff actually costs. That
        later waiter must still find the debounce standing and call
        `switch()` once between them, not once each."""
        from cswap_pin import proxy as pp
        import time as _time
        BASE = 2_000_000_000.0
        PAST_RESET = int(BASE) - 5  # already expired when this 429 arrives
        reset_header = (b"anthropic-ratelimit-unified-reset: "
                         + str(PAST_RESET).encode())
        clock = {"mono": 0.0, "wall": BASE}
        monkeypatch.setattr(_time, "monotonic", lambda: clock["mono"])
        monkeypatch.setattr(_time, "time", lambda: clock["wall"])
        calls = self._wire(monkeypatch, switched=False, live_token=self.LIVE,
                           usage=self.HEADROOM)

        first = self._relay(reset=reset_header, auth=f"Bearer {self.LIVE}")
        assert first.startswith(b"HTTP/1.1 429"), first[:40]
        assert len(calls) == 1, calls

        # 0.5s later, not the same instant: long past any 1ms floor, the
        # shape of a queued waiter's actual lock handoff.
        clock["mono"] = 0.5
        clock["wall"] = BASE + 0.5
        second = self._relay(reset=reset_header, auth=f"Bearer {self.LIVE}")
        assert second.startswith(b"HTTP/1.1 429"), second[:40]
        assert len(calls) == 1, (
            f"a reset already in the past zeroed the debounce and let a "
            f"second concurrent 429 call switch() again: {calls}")


class TestTheEvidenceSurvivesAHandover:
    """THE DEFECT THE IN-MEMORY MAP HAD, and it is not a tuning problem.

    A long-held stream stays with the DEPARTING daemon for the whole drain
    while its session's heartbeats move to the successor. So the process
    holding the doomed connection is structurally unable to see that its
    session is alive, for as long as the drain lasts -- measured at 2110s.
    An in-memory map answers "no evidence" for exactly the population this
    guard exists for. Measured live: a stream 404 on a session whose
    heartbeats were 41s old, declined, mid-drain.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    SID = "cse_handover0000000000000"
    STREAM = f"/v1/code/sessions/{SID}/worker/events/stream"
    BEAT = f"/v1/code/sessions/{SID}/worker/heartbeat"

    @staticmethod
    def _cold():
        """A daemon that has just started. Each case gets a FRESH certdir but
        `_worker_alive` is module state, so without this a sibling case's entry
        trips the write throttle and the file is never written in the new dir."""
        from cswap_pin import proxy as pp
        with pp._worker_alive_lock:
            pp._worker_alive.clear()

    @staticmethod
    def _relay(path, status, certdir):
        import socket as _s
        from cswap_pin import proxy as pp
        up_a, up_b = _s.socketpair(); cl_a, cl_b = _s.socketpair()
        try:
            up_b.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: 2\r\n\r\nno")
            up_b.shutdown(_s.SHUT_WR)
            pp._relay_response(up_a, cl_a, 0, method="GET", path=path,
                               certdir=certdir)
            cl_a.shutdown(_s.SHUT_WR)
            return cl_b.recv(4096)
        finally:
            for x in (up_a, up_b, cl_a, cl_b):
                try: x.close()
                except OSError: pass

    def case_a_successors_heartbeat_reaches_the_departing_daemon(self, certdir):
        """THE WHOLE POINT. One 'process' records the 2xx; a SECOND, with an
        empty map, must still see it. Clearing `_worker_alive` between the two
        is exactly what a fresh daemon starts with."""
        from cswap_pin import proxy as pp
        self._cold()
        pp._note_worker_status(self.BEAT, b"HTTP/1.1 200 OK", certdir)
        with pp._worker_alive_lock:
            pp._worker_alive.clear()          # the OTHER daemon's memory
        got = self._relay(self.STREAM, b"404 Not Found", certdir)
        assert got.startswith(b"HTTP/1.1 503"), (
            "a daemon that did not personally see the heartbeat let the 404 "
            f"through — this is the live wmac case. got {got[:40]!r}")

    def case_CONTROL_no_shared_record_still_declines(self, certdir):
        """Without this, a relay that rewrote every 404 would pass above."""
        from cswap_pin import proxy as pp
        with pp._worker_alive_lock:
            pp._worker_alive.clear()
        got = self._relay(self.STREAM, b"404 Not Found", certdir)
        assert got.startswith(b"HTTP/1.1 404"), got[:40]

    def case_CONTROL_a_stale_shared_record_declines(self, certdir):
        """The file must expire like the map did, or a session that died an
        hour ago keeps its stream alive forever."""
        import json
        from cswap_pin import proxy as pp
        self._cold()
        pp._note_worker_status(self.BEAT, b"HTTP/1.1 200 OK", certdir)
        with pp._worker_alive_lock:
            pp._worker_alive.clear()
        f = pp._alive_path(certdir)
        f.write_text(json.dumps(
            {self.SID: __import__("time").time() - pp._STREAM_LIVE_SECONDS - 30}))
        got = self._relay(self.STREAM, b"404 Not Found", certdir)
        assert got.startswith(b"HTTP/1.1 404"), got[:40]

    def case_the_record_is_wall_clock_not_monotonic(self, certdir):
        """monotonic is not comparable across processes, and two of them read
        this file. A monotonic stamp would read as ~55 years in the past on a
        freshly booted host and expire instantly."""
        import json, os, time as _t
        from cswap_pin import proxy as pp
        self._cold()
        pp._note_worker_status(self.BEAT, b"HTTP/1.1 200 OK", certdir)
        # THE KEY CARRIES THE WRITER'S PID -- see `_worker_alive_age`.
        v = json.loads(pp._alive_path(certdir).read_text())[
            f"{self.SID}@{os.getpid()}"]
        assert abs(v - _t.time()) < 60, (
            f"stamp {v} is not wall clock; monotonic would be ~{_t.monotonic():.0f}")

    def case_a_corrupt_file_is_not_evidence(self, certdir):
        from cswap_pin import proxy as pp
        with pp._worker_alive_lock:
            pp._worker_alive.clear()
        pp._alive_path(certdir).write_text("{not json")
        got = self._relay(self.STREAM, b"404 Not Found", certdir)
        assert got.startswith(b"HTTP/1.1 404"), got[:40]

    def case_a_second_daemons_write_does_not_erase_the_first(self, certdir):
        """Both processes write this file. A plain overwrite would drop the
        other's sessions, which is a self-inflicted version of the bug."""
        import json, os
        from cswap_pin import proxy as pp
        other = "cse_theotherdaemons000000"
        self._cold()
        pp._note_worker_status(
            f"/v1/code/sessions/{other}/worker/heartbeat", b"HTTP/1.1 200 OK", certdir)
        with pp._worker_alive_lock:
            pp._worker_alive.clear()
        pp._note_worker_status(self.BEAT, b"HTTP/1.1 200 OK", certdir)
        got = json.loads(pp._alive_path(certdir).read_text())
        # THE KEY CARRIES THE WRITER'S PID -- see `_worker_alive_age`. Both
        # writes came from this same test process, so both carry it.
        pid = os.getpid()
        assert f"{other}@{pid}" in got and f"{self.SID}@{pid}" in got, sorted(got)

    def case_an_old_shape_reader_sees_a_new_writers_fresh_stamp(self, certdir):
        """During a rollout handover, a draining OLD daemon still running the
        DEPLOYED release reads `_alive_load(certdir).get(sid)` -- a bare key,
        never `sid@pid`. Writing ONLY the pid-suffixed key leaves that reader
        blind to a successor's traffic for the whole drain, and after
        `_STREAM_LIVE_SECONDS` a spurious 404 passes through and ends the
        session. The bare key has to be there too."""
        import time as _t
        from cswap_pin import proxy as pp
        self._cold()
        pp._note_worker_status(self.BEAT, b"HTTP/1.1 200 OK", certdir)
        bare = pp._alive_load(certdir).get(self.SID)
        assert isinstance(bare, (int, float)), (
            "no bare `sid` key -- an old-shape reader's `.get(sid)` sees "
            f"nothing: {pp._alive_load(certdir)!r}")
        assert abs(bare - _t.time()) < 60, f"stale bare stamp: {bare}"

    def case_a_fresh_bare_key_from_an_older_writer_still_spares_the_404(
            self, certdir):
        """The `k == sid` branch in `_stream_404_is_spurious`, untested until
        now: an OLDER release's daemon writes only the bare key, and a
        session mid-handover depends on the NEW reader still counting it."""
        import json
        import time as _t
        from cswap_pin import proxy as pp
        with pp._worker_alive_lock:
            pp._worker_alive.clear()
        pp._alive_path(certdir).write_text(json.dumps({self.SID: _t.time()}))
        got = self._relay(self.STREAM, b"404 Not Found", certdir)
        assert got.startswith(b"HTTP/1.1 503"), (
            "a bare `sid` key from an older-release writer did not spare "
            f"the 404: got {got[:40]!r}")


class TestADrainHandsStreamsOverInsteadOfOutlivingThem:
    """THE DRAIN PROTECTED NOTHING AND COST EVERYTHING.

    An SSE stream owes an answer for its whole life, so `await_inflight` waits
    on one for ever. Measured: 3316.7s of waiting that closed one idle
    connection and owed nobody an answer, while every session on the host sat
    in the window where a spurious 404 ends it.

    The successor already holds the listener, so a released client reconnects
    at once -- `handleStreamEnd` backs off 1s and carries `from_sequence_num`.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    @staticmethod
    def _server(certdir):
        from cswap_pin.proxy import PinProxy
        return PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                        upstream=("127.0.0.1", 1))

    @staticmethod
    def _conn():
        import socket as _s
        return _s.socketpair()

    def _register(self, srv, age):
        """A stream connection whose last CONTENT was `age` seconds ago."""
        import time as _t
        a, b = self._conn()
        with srv._live_lock:
            srv._open_conns.add(a)
            srv._stream_conns.add(a)
            srv._content_at[a] = _t.monotonic() - age
        return a, b

    def case_a_content_free_stream_is_handed_over(self, certdir):
        from cswap_pin import proxy as pp
        srv = self._server(certdir)
        a, b = self._register(srv, pp._CLIENT_LIVENESS_SECONDS + 5)
        assert srv.release_idle_streams() == 1
        # AND THE CLIENT REALLY SAW EOF -- a count alone would pass on a
        # method that returned 1 and shut nothing down.
        assert b.recv(16) == b"", "the client did not get a clean EOF"

    def case_CONTROL_a_stream_still_delivering_is_left_alone(self, certdir):
        """The half that makes this a handover and not a cut. Without it,
        releasing every stream unconditionally passes the case above."""
        from cswap_pin import proxy as pp
        srv = self._server(certdir)
        a, b = self._register(srv, 1.0)          # content one second ago
        assert srv.release_idle_streams() == 0
        b.send(b"x")                              # still a live socket
        assert a.recv(1) == b"x"

    def case_the_threshold_is_the_CLIENTS_OWN(self, certdir):
        """45s is `dn` in the 2.1.245 bundle, the liveness timeout the client
        re-arms on every frame. If this drifts from what the client does, we
        are cutting streams it would have kept."""
        from cswap_pin import proxy as pp
        assert pp._CLIENT_LIVENESS_SECONDS == 45.0

    def case_a_NON_stream_connection_is_never_touched(self, certdir):
        import time as _t
        srv = self._server(certdir)
        a, b = self._conn()
        with srv._live_lock:
            srv._open_conns.add(a)               # open, but not a stream
            srv._content_at[a] = _t.monotonic() - 600
        assert srv.release_idle_streams() == 0

    def case_a_stream_with_NO_content_stamp_is_left_alone(self, certdir):
        """An entry with no stamp is one we have never seen deliver. Defaulting
        it to `now` keeps it; defaulting to 0 would release every fresh stream
        on the first drain."""
        import socket as _s
        srv = self._server(certdir)
        a, b = self._conn()
        with srv._live_lock:
            srv._open_conns.add(a)
            srv._stream_conns.add(a)             # no _content_at entry
        assert srv.release_idle_streams() == 0


def _handshake(ctx, port, host="api.anthropic.com"):
    """One TLS handshake to a loopback server, `host` being the name checked.
    Raises ssl.SSLCertVerificationError when `ctx` does not trust what it
    serves."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        ctx.wrap_socket(raw, server_hostname=host).close()


def _pin_dir():
    """The directory `_verifying_context()` derives (conftest redirects the
    store it lives under to the case's tmp_path)."""
    from claude_swap.switcher import ClaudeAccountSwitcher

    return _mkdir(ClaudeAccountSwitcher().backup_dir / "pin-proxy")


class TestTheVerifyingContextTrustsTheHop:
    """The daemon's own profile and policy fetches go out through the pin and
    through whatever re-signing hop is recorded behind it. A third-party hop's
    CA is recorded in upstream.json and carries no keyUsage."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    @staticmethod
    def _hop_signed_dir(tmp_path):
        """A directory holding a leaf signed by a CA with NO keyUsage (the pin's
        own `ensure_ca` always adds one, so it cannot make this)."""
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from cswap_pin.proxy import _make_leaf

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hop CA")])
        now = dt.datetime.now(dt.timezone.utc)
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - dt.timedelta(days=1))
              .not_valid_after(now + dt.timedelta(days=30))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                             critical=True)
              .sign(key, hashes.SHA256()))
        with pytest.raises(x509.ExtensionNotFound):
            ca.extensions.get_extension_for_class(x509.KeyUsage)
        leaf, leaf_key = _make_leaf("api.anthropic.com", ca, key)
        signer = tmp_path / "hop"
        signer.mkdir()
        (signer / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (signer / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (signer / "leaf.key").write_bytes(leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        return signer

    def case_the_recorded_hop_ca_is_trusted_even_with_the_host_helper(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin import proxy

        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        # The affected box HAS the host's helper, and it trusts roots plus the
        # pin's own CA only: the context that failed.
        monkeypatch.setattr(proxy.oauth, "_pin_aware_ssl_context",
                            ssl.create_default_context, raising=False)
        signer = self._hop_signed_dir(tmp_path)
        upstream = _FakeUpstream(signer)
        try:
            # CONTROL: nothing recorded, so the hop's leaf must be refused.
            with pytest.raises(ssl.SSLCertVerificationError):
                _handshake(proxy._verifying_context(), upstream.port)
            proxy.write_upstream_hint(
                _pin_dir(), "http://127.0.0.1:1", str(signer / "ca.pem"))
            _handshake(proxy._verifying_context(), upstream.port)
        finally:
            upstream.stop()

    def case_a_leaf_the_pins_own_ca_signed_verifies_alone(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin import proxy

        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        pin_dir = _pin_dir()
        ensure_ca(pin_dir, "api.anthropic.com")
        assert not (pin_dir / "ca-bundle.pem").exists()
        assert proxy.read_upstream_ca(pin_dir) is None
        upstream = _FakeUpstream(pin_dir)
        try:
            _handshake(proxy._verifying_context(), upstream.port)
        finally:
            upstream.stop()

    def case_strict_verification_is_off(self, monkeypatch):
        from cswap_pin import proxy

        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        real = ssl.create_default_context

        def strict_like_3_13(*a, **kw):
            ctx = real(*a, **kw)
            ctx.verify_flags |= ssl.VERIFY_X509_STRICT
            return ctx

        monkeypatch.setattr(ssl, "create_default_context", strict_like_3_13)
        assert not proxy._verifying_context().verify_flags & ssl.VERIFY_X509_STRICT

# ---------------------------------------------------------------------------
# Inference follows the active account for hosts that bring their own login
# (Claude Desktop's Code tab). Opt-in via `<certdir>/inference-follows`.
# ---------------------------------------------------------------------------

_DESKTOP_UA = "claude-cli/2.1.281 (external, claude-desktop)"
_CLI_UA = "claude-cli/2.1.281 (external, cli)"


def _follow_proxy(certdir, upstream, token=("ACTIVE", None), pin="PIN-TOKEN"):
    import time as _time

    from cswap_pin.proxy import PinProxy, _ActiveTokenCache

    tok, exp = token
    if exp is None:
        exp = _time.time() + 3600
    proxy = PinProxy(
        certdir=certdir,
        pin_token_provider=lambda: pin,
        upstream=("127.0.0.1", upstream.port),
    )
    proxy._inference_tokens = _ActiveTokenCache(reader=lambda: (tok, exp))
    return proxy


class TestInferenceFollows:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_ua_entrypoint_parses_claude_cli_only(self):
        from cswap_pin.proxy import ua_entrypoint

        assert ua_entrypoint(_DESKTOP_UA) == "claude-desktop"
        assert ua_entrypoint(_CLI_UA) == "cli"
        assert ua_entrypoint(
            "claude-cli/2.1.281 (external, sdk-ts, agent-sdk/0.9)") == "sdk-ts"
        # The session-route UA carries no entrypoint; nor does anything else.
        assert ua_entrypoint("claude-code/2.1.281") is None
        assert ua_entrypoint("claude-swap/1.0") is None
        assert ua_entrypoint("") is None

    def case_route_needs_inference_path_and_listed_entrypoint(self):
        from cswap_pin.proxy import is_inference_follow_route as f

        on = frozenset({"claude-desktop"})
        assert f("/v1/messages?beta=true", _DESKTOP_UA, on)
        assert f("/v1/messages/count_tokens", _DESKTOP_UA, on)
        assert not f("/v1/messages", _CLI_UA, on)
        assert not f("/v1/messages", _DESKTOP_UA, frozenset())
        assert not f("/api/oauth/usage", _DESKTOP_UA, on)
        assert not f("/v1/code/sessions", _DESKTOP_UA, on)
        assert not f("/v1/messages/batches", _DESKTOP_UA, on)

    def case_switch_file_env_and_comments(self, certdir, monkeypatch):
        from cswap_pin import proxy as pp

        monkeypatch.delenv("CSWAP_PIN_INFERENCE_FOLLOWS", raising=False)
        pp._INFERENCE_CACHE.clear()
        assert pp.inference_follow_entrypoints(certdir) == frozenset()
        (certdir / "inference-follows").write_text(
            "# on 2026-09-27\nclaude-desktop  # the Code tab\n\n")
        pp._INFERENCE_CACHE.clear()
        assert pp.inference_follow_entrypoints(certdir) == {"claude-desktop"}
        monkeypatch.setenv("CSWAP_PIN_INFERENCE_FOLLOWS", "")
        assert pp.inference_follow_entrypoints(certdir) == frozenset()

    def case_desktop_inference_gets_active_bearer(self, certdir, monkeypatch):
        monkeypatch.delenv("CSWAP_PIN_INFERENCE_FOLLOWS", raising=False)
        (certdir / "inference-follows").write_text("claude-desktop\n")
        upstream = _FakeUpstream(certdir)
        proxy = _follow_proxy(certdir, upstream)
        proxy.start()
        try:
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages?beta=true",
                                        bearer="HOST-TOKEN", ua=_DESKTOP_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer ACTIVE"
            # The CLI already reads the active account; it is left alone.
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages", bearer="CLI-TOKEN",
                                        ua=_CLI_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer CLI-TOKEN"
            # Ownership routes keep the PIN, whoever asks.
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/code/sessions",
                                        bearer="HOST-TOKEN", ua=_DESKTOP_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer PIN-TOKEN"
            proxy._inference_stats.flush()
            stats = json.loads(proxy._inference_stats._path.read_text())
            assert stats["swapped"] == 1
            assert stats["entrypoints"] == ["claude-desktop"]
            assert stats["lastSwapAt"]
        finally:
            proxy.stop()
            upstream.stop()

    def case_off_without_the_switch(self, certdir, monkeypatch):
        monkeypatch.delenv("CSWAP_PIN_INFERENCE_FOLLOWS", raising=False)
        upstream = _FakeUpstream(certdir)
        proxy = _follow_proxy(certdir, upstream)
        proxy.start()
        try:
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages", bearer="HOST-TOKEN",
                                        ua=_DESKTOP_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer HOST-TOKEN"
        finally:
            proxy.stop()
            upstream.stop()

    def case_refused_swap_is_resent_on_host_bearer(self, certdir, monkeypatch):
        monkeypatch.delenv("CSWAP_PIN_INFERENCE_FOLLOWS", raising=False)
        (certdir / "inference-follows").write_text("claude-desktop\n")
        upstream = _FakeUpstream(certdir, reject_bearer="ACTIVE")
        proxy = _follow_proxy(certdir, upstream)
        proxy.start()
        try:
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages", bearer="HOST-TOKEN",
                                        ua=_DESKTOP_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer HOST-TOKEN"
            proxy._inference_stats.flush()
            stats = json.loads(proxy._inference_stats._path.read_text())
            assert stats["retriedUnswapped"] == 1
            assert stats["lastRetryAt"]
        finally:
            proxy.stop()
            upstream.stop()

    def case_expiring_or_same_token_passes_through(self, certdir, monkeypatch):
        import time as _time

        monkeypatch.delenv("CSWAP_PIN_INFERENCE_FOLLOWS", raising=False)
        (certdir / "inference-follows").write_text("claude-desktop\n")
        upstream = _FakeUpstream(certdir)
        proxy = _follow_proxy(certdir, upstream,
                              token=("ACTIVE", _time.time() + 10))
        proxy.start()
        try:
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages", bearer="HOST-TOKEN",
                                        ua=_DESKTOP_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer HOST-TOKEN"
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages", bearer="ACTIVE",
                                        ua=_DESKTOP_UA)
            proxy._inference_stats.flush()
            stats = json.loads(proxy._inference_stats._path.read_text())
            assert stats["swapped"] == 0
            assert stats["passthrough"]["expiring"] == 2
        finally:
            proxy.stop()
            upstream.stop()

    def case_token_cache_reads_once_per_ttl_and_never_blocks(self):
        import threading as _th
        import time as _time

        from cswap_pin.proxy import _ActiveTokenCache

        calls = []

        def reader():
            calls.append(1)
            return "T", _time.time() + 3600

        c = _ActiveTokenCache(reader=reader, ttl=60)
        assert c.get() == ("T", "ok")
        assert c.get() == ("T", "ok")
        assert len(calls) == 1
        c.invalidate()
        assert c.get() == ("T", "ok")
        assert len(calls) == 2
        # A reader that hangs holds the lock; everyone else gets the cached
        # token (still good) instead of queueing behind it.
        gate = _th.Event()

        def slow():
            gate.wait(5)
            return "T2", _time.time() + 3600

        c._reader = slow
        c.invalidate()
        t = _th.Thread(target=c.get)
        t.start()
        _time.sleep(0.1)
        assert c.get() == ("T", "ok")
        gate.set()
        t.join(5)
        assert c.get() == ("T2", "ok")
        empty = _ActiveTokenCache(reader=lambda: (None, None))
        assert empty.get() == (None, "no-token")


def _design_proxy(certdir, upstream, token=("DESIGN", None), pin="PIN-TOKEN"):
    import time as _time

    from cswap_pin.proxy import PinProxy, _ActiveTokenCache

    tok, exp = token
    if exp is None:
        exp = _time.time() + 3600
    proxy = PinProxy(
        certdir=certdir,
        pin_token_provider=lambda: pin,
        upstream=("127.0.0.1", upstream.port),
    )
    proxy._design_tokens = _ActiveTokenCache(reader=lambda: (tok, exp))
    return proxy


class TestDesignGrant:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_route_is_design_mcp_or_omelette(self):
        from cswap_pin.proxy import is_design_route as f, is_pinned_route

        assert f("/v1/design/mcp")
        assert f("/v1/design/consent?x=1")
        assert f("/v1/design/grants")
        assert f("/anthropic.omelette.api.v1alpha.OmeletteService/GetProject")
        assert not f("/v1/designs")
        assert not f("/v1/messages")
        assert not f("/api/frame/deploy")
        # Design routes are a third category: never pinned, never inference.
        assert not is_pinned_route("/v1/design/mcp")

    def case_foreign_bearer_gets_the_design_grant(self, certdir):
        upstream = _FakeUpstream(certdir)
        proxy = _design_proxy(certdir, upstream)
        proxy.start()
        try:
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/design/mcp",
                                        bearer="placeholder", ua=_CLI_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer DESIGN"
            st = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/anthropic.omelette.api.v1alpha.OmeletteService/GetProject",
                bearer="HOST-TOKEN", ua=_DESKTOP_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer DESIGN"
            # Claude Code's own client already sends the grant: untouched.
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/design/mcp", bearer="DESIGN",
                                        ua=_CLI_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer DESIGN"
            # Inference and ownership routes are not design routes.
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages", bearer="CLI-TOKEN",
                                        ua=_CLI_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer CLI-TOKEN"
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/api/frame/frames",
                                        bearer="placeholder", ua=_CLI_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer PIN-TOKEN"
            proxy._inference_stats.flush()
            stats = json.loads(proxy._inference_stats._path.read_text())
            assert stats["designSwapped"] == 2
            assert stats["designPassthrough"]["same-token"] == 1
            assert stats["lastDesignSwapAt"]
            assert stats["swapped"] == 0
        finally:
            proxy.stop()
            upstream.stop()

    def case_no_grant_passes_through(self, certdir):
        upstream = _FakeUpstream(certdir)
        proxy = _design_proxy(certdir, upstream, token=(None, None))
        proxy.start()
        try:
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/design/mcp",
                                        bearer="HOST-TOKEN", ua=_CLI_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer HOST-TOKEN"
            proxy._inference_stats.flush()
            stats = json.loads(proxy._inference_stats._path.read_text())
            assert stats["designSwapped"] == 0
            assert stats["designPassthrough"]["no-token"] == 1
        finally:
            proxy.stop()
            upstream.stop()

    def case_refused_grant_is_resent_on_the_callers_bearer(self, certdir):
        upstream = _FakeUpstream(certdir, reject_bearer="DESIGN")
        proxy = _design_proxy(certdir, upstream)
        proxy.start()
        try:
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/design/consent",
                                        bearer="HOST-TOKEN", ua=_CLI_UA)
            assert st == 200
            assert upstream.seen_auth == "Bearer HOST-TOKEN"
            proxy._inference_stats.flush()
            stats = json.loads(proxy._inference_stats._path.read_text())
            assert stats["designRetriedUnswapped"] == 1
            assert stats["lastDesignRetryAt"]
        finally:
            proxy.stop()
            upstream.stop()


# ---------------------------------------------------------------------------
# Rate-limit headers off inference replies, filed per bearer fingerprint in
# `<certdir>/ratelimits.json` — cswap's usage source for setup-token slots.
# ---------------------------------------------------------------------------

_RL_HEADERS = (
    b"anthropic-ratelimit-unified-5h-utilization: 0.23\r\n"
    b"anthropic-ratelimit-unified-5h-reset: 1791090600\r\n"
    b"anthropic-ratelimit-unified-7d-utilization: 0.77\r\n"
    b"anthropic-ratelimit-unified-7d-reset: 1791306000\r\n"
    b"anthropic-ratelimit-unified-status: allowed_warning\r\n"
)


class TestRateLimitLedger:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_parse_keeps_only_unified_headers(self):
        from cswap_pin.proxy import parse_ratelimit_headers as parse

        r = parse(b"HTTP/1.1 429 Too Many Requests", [
            b"Content-Type: application/json",
            b"anthropic-ratelimit-unified-5h-utilization: 1.0",
            b"Anthropic-Ratelimit-Unified-Status: rejected",
        ])
        assert r["status"] == 429
        assert r["headers"] == {"5h-utilization": "1.0", "status": "rejected"}
        assert parse(b"HTTP/1.1 200 OK", [b"Content-Length: 2"]) is None

    def case_inference_reply_is_filed_under_the_sent_bearer(
            self, certdir, monkeypatch):
        from cswap_pin.proxy import RATELIMIT_FILE, bearer_fingerprint

        monkeypatch.delenv("CSWAP_PIN_INFERENCE_FOLLOWS", raising=False)
        (certdir / "inference-follows").write_text("claude-desktop\n")
        upstream = _FakeUpstream(certdir, extra_headers=_RL_HEADERS)
        proxy = _follow_proxy(certdir, upstream)
        proxy.start()
        try:
            # Desktop's request is re-billed: the reading belongs to ACTIVE,
            # the bearer that went out, not the host's own.
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages?beta=true",
                                        bearer="HOST-TOKEN", ua=_DESKTOP_UA)
            assert st == 200
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/v1/messages", bearer="CLI-TOKEN",
                                        ua=_CLI_UA)
            assert st == 200
            # Not an inference route: nothing filed, whatever it carries.
            st = _request_through_proxy(proxy.port, certdir / "ca.pem",
                                        "/api/oauth/usage", bearer="OTHER",
                                        ua=_CLI_UA)
            assert st == 200
            proxy._ratelimits.flush()
            raw = (certdir / RATELIMIT_FILE).read_text()
            tokens = json.loads(raw)["tokens"]
            assert set(tokens) == {bearer_fingerprint("ACTIVE"),
                                   bearer_fingerprint("CLI-TOKEN")}
            r = tokens[bearer_fingerprint("ACTIVE")]
            assert r["status"] == 200
            assert r["headers"]["7d-utilization"] == "0.77"
            assert "ACTIVE" not in raw
        finally:
            proxy.stop()
            upstream.stop()

    def case_flush_merges_newest_per_bearer(self, certdir):
        import time as _time

        from cswap_pin.proxy import (RATELIMIT_FILE, _RateLimitLedger,
                                     bearer_fingerprint)

        now = _time.time()
        (certdir / RATELIMIT_FILE).write_text(json.dumps({"version": 1, "tokens": {
            "keep": {"at": now - 10, "status": 200, "headers": {"x": "old"}},
            "stale": {"at": now - 30 * 24 * 3600, "status": 200, "headers": {}},
        }}))
        ledger = _RateLimitLedger(certdir)
        ledger.note("TOK", b"HTTP/1.1 200 OK",
                    [b"anthropic-ratelimit-unified-status: allowed"])
        ledger.flush()
        tokens = json.loads((certdir / RATELIMIT_FILE).read_text())["tokens"]
        assert set(tokens) == {"keep", bearer_fingerprint("TOK")}
