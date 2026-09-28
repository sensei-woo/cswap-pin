"""No test may touch the real machine's Claude config. Enforced, not asked.

MEASURED BREAKAGE, and it was live rather than theoretical. Running this suite
on a developer's own box rewired that box's `~/.claude.json` to port 52000 — a
value that exists only as a fixture in `test_recycles_stale_fingerprint`:

    monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 52000)
    got, ca = pin_proxy.ensure_proxy(self._Sw(tmp_path))

That test patched `_spawn_daemon` and `_kill_daemon` but not the config PATH,
and `ensure_proxy` ends in `wire_global_config(port, ca)`, which resolves the
path from `claude_swap.paths` — the real `~/.claude.json`. So every run pointed
the machine's sessions at a port nothing had ever served. Measured afterwards:
`CSWAP_PIN_PORT = 52000`, connect refused, while the actual daemon served
36301. Any session started in that window could not reach the API at all.

WHY A CONFTEST AND NOT A FIX IN THAT TEST. This is the third instance in one
evening of a test reaching outside its fixture — a `GIT_DIR` inherited into a
hook fixture that rewrote the real repository's `main`, port-36301 literals
that described a LIVE daemon while claiming a dead one, and now this. Patching
each one as it is found leaves the next one to be discovered by damage. The
class of bug is "a test forgot to redirect something", so the guard belongs
where forgetting is impossible.

`autouse` means a test cannot opt out by omission. A test that genuinely wants
to exercise config writing gets a real file — under `tmp_path`, where pytest
throws it away.
"""

import json
import re
import pathlib
import sys
import warnings

import pytest


@pytest.fixture(autouse=True)
def _never_touch_the_real_claude_config(tmp_path, monkeypatch):
    _redirect_everything_to(tmp_path, monkeypatch)


@pytest.fixture(autouse=True)
def _pin_profile_never_dials_out(monkeypatch):
    """No test may reach api.anthropic.com. `make_pin_token_provider`'s
    mint-time identity check calls `pin_profile_for` on every fresh mint, so
    any case that mints a real token now makes that call unless it stubs
    one -- and most do not need to, they are testing something else. Default
    to the same "could not ask" answer a real network failure produces (the
    provider's own fail-open, no crash, no wait); a case that DOES want to
    assert identity behaviour overrides this with its own
    `monkeypatch.setattr(pin_proxy, "pin_profile_for", ...)`, layered on top
    and winning for that test.
    """
    from cswap_pin import proxy as _p

    monkeypatch.setattr(_p, "pin_profile_for", lambda token: None)


@pytest.fixture(autouse=True)
def _no_daemon_thread_outlives_its_test():
    """A daemon thread that outlives its test runs against the NEXT test.

    The title-sweep loop calls `_carry_on_login_change`, which logs through
    the module-level `_log_lifecycle` -- the same name a later test
    monkeypatches to a list. A loop left running by one test then appends
    its own first-look line into another test's recorder, and that test
    fails with a message about an identity it never used. Measured on CI:
    the control case that asserts silence received "(? -> A)" from a thread
    it did not own, on the slow runner only. Name the leaker instead.
    """
    import threading
    import time

    def sweeps():
        return {t for t in threading.enumerate()
                if getattr(getattr(t, "_target", None), "__name__", "") == "_title_sweep_loop"}

    before = sweeps()
    yield
    deadline = time.monotonic() + 2.0
    while sweeps() - before and time.monotonic() < deadline:
        time.sleep(0.05)
    leaked = sweeps() - before
    assert not leaked, (
        "this test left a daemon's title-sweep thread running "
        f"({len(leaked)}); stop() every PinProxy it started, or its beat "
        "pollutes the next test's module-level stubs")


@pytest.fixture(autouse=True)
def _close_sockets_the_test_left_open():
    """Close every socket a test opened, so its accept loop ends with it.

    A LEAKED ACCEPT THREAD IS WHAT KILLS AN XDIST WORKER. It outlives its
    case, reaches the real `os._exit` inside `_watch_own_code`, and the
    process vanishes with no traceback — `tests/leakwatch.py` names the
    signature. Fixing the helpers one at a time MOVES the crash instead of
    ending it: measured, deselecting the biggest single leaker left 3 of 3
    `-n 2` runs still short of the full 227.

    A Python thread cannot be killed, so closing its socket is the only
    lever — `accept()` raises OSError and the loop returns. Sweeping here
    rather than at each helper also covers the ones nobody has written yet.

    `fileno() < 3` is left alone: stdio is not a test's to close, and the
    xdist channel rides pipes rather than sockets.
    """
    import socket
    import weakref

    opened: list = []
    real_init = socket.socket.__init__

    def _init(self, *a, **kw):
        real_init(self, *a, **kw)
        try:
            opened.append(weakref.ref(self))
        except TypeError:      # not weak-referenceable; nothing to sweep
            pass

    socket.socket.__init__ = _init
    try:
        yield
    finally:
        socket.socket.__init__ = real_init
        for ref in opened:
            sock = ref()
            if sock is None:
                continue
            try:
                if sock.fileno() < 3:
                    continue
                # LISTENERS ONLY. A blocked `accept()` is the whole target,
                # and `_PUMP` is a module-level singleton whose own wakeup
                # pair and tunnel sockets are created inside whichever test
                # first touches it — closing those breaks the pump for every
                # later test, which is what `live_pairs() == 0` was.
                if not sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                    continue
                # SHUTDOWN BEFORE CLOSE. A `close()` from another thread does
                # NOT wake a thread already blocked in `accept()` on Linux —
                # the fd goes away and the blocked call keeps waiting. The
                # shutdown is what makes it return.
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
            except OSError:
                pass


def _redirect_everything_to(tmp_path, monkeypatch):
    """Point every config-path lookup at this test's own tmp_path."""
    cfg = tmp_path / "conftest-claude.json"
    if not cfg.exists():
        cfg.write_text(json.dumps({}), encoding="utf-8")

    try:
        import claude_swap.paths as paths
    except Exception:  # noqa: BLE001
        # The host is not importable here (packaging tests block it on
        # purpose). Nothing can resolve a real path either, so there is
        # nothing to redirect.
        return

    for name in ("get_global_config_path", "get_default_global_config_path"):
        if hasattr(paths, name):
            monkeypatch.setattr(paths, name, lambda cfg=cfg: cfg)

    # AND THE CONFIG HOME, which is a different question with the same answer.
    # The first version of this guard redirected only the two config-PATH
    # lookups, and `publish_ca` uses `get_claude_config_home` — so the suite
    # went on writing a test-generated CA into the real
    # `~/.claude/ca-trust.d/cswap-pin.pem`, replacing the one the live daemon
    # actually signs with. Caught by the shared ca-trust suite ("every
    # published component CA is in the bundle: missing cswap-pin.pem"), not by
    # anything here — which is the argument for redirecting the whole home
    # rather than enumerating the accessors someone might add next.
    home = tmp_path / "claude-home"
    home.mkdir(exist_ok=True)
    if hasattr(paths, "get_claude_config_home"):
        monkeypatch.setattr(paths, "get_claude_config_home", lambda home=home: home)

    # AND THROUGH THE ENVIRONMENT, because a monkeypatched attribute does not
    # cross a process boundary. `get_claude_config_home` reads CLAUDE_CONFIG_DIR
    # first, so setting it redirects the CHILDREN this suite spawns — the
    # daemons, the packaging probes, the oracle's node — none of which inherit
    # a patched module object.
    #
    # That gap was not theoretical. After the in-process redirect was added and
    # the real `~/.claude/ca-trust.d/cswap-pin.pem` restored, the file was
    # overwritten AGAIN by a test-minted CA — and the published CA then could
    # not verify the leaf the live daemon serves:
    #
    #     openssl verify -CAfile ca-trust.d/cswap-pin.pem  pin-proxy/leaf.pem
    #       error 20: unable to get local issuer certificate
    #     openssl verify -CAfile pin-proxy/ca.pem          pin-proxy/leaf.pem
    #       OK
    #
    # Every session on the box was handed a bundle carrying a CA that signs
    # nothing it talks to. An env var is the only redirect a child obeys.
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))

    # AND THE ACCOUNT STORE, which is a THIRD question the config redirects
    # above do not answer. Everything so far points at the CONFIG
    # (`.claude.json`, `~/.claude/`). The credentials and the roster live
    # somewhere else entirely — `~/.local/share/claude-swap/` — reached
    # through `get_backup_root`, and nothing here redirected it.
    #
    # This was found during a live incident on host-a: the real
    # `sequence.json` was overwritten with test fixture accounts
    # (`a@example.com`, `b@example.com`) plus matching 88-byte `.creds-*.enc`
    # files. That damage was NOT traced to this suite — no test here builds a
    # real switcher, so nothing reaches `switcher.backup_dir` today. But that
    # is a property of the tests, not a guard, and it is exactly the shape
    # every other hole in this file had before it fired. The roster syncs by
    # WHOLE-FILE COPY with newest-wins, so a store corrupted on one machine is
    # one sync away from overwriting both Macs.
    #
    # Three redirects because `get_backup_root` can be reached three ways:
    # the function itself (in-process callers), `XDG_DATA_HOME` (the children
    # this suite spawns, which do not inherit a patched module object), and
    # `Path.home()` (its fallback when XDG is unset, and anything that
    # computes the path itself).
    # AND THE PIN'S OWN ENV, which a pinned developer's session inherits at
    # BOOT. Claude Code applies `.claude.json`'s env block into process.env,
    # so every test run from inside a pinned session started with
    # `CSWAP_PIN_PORT` naming the LIVE daemon's port. Nothing read it until
    # the daemon started honouring a configured port — and then four unrelated
    # tests went red, each trying to bind the developer's real 36301 and
    # logging "configured port 36301 is not available". The suite was reading
    # a value from outside its own fixture, exactly like the config paths
    # above; it just had no consumer yet.
    # AND THE OFF SWITCH, for the opposite reason: it does not break tests, it
    # makes them PASS VACUOUSLY. `CSWAP_PIN_SELF_HEAL=off` disables the
    # holder's respawn and the code watchdog, so a developer who exported it
    # while debugging turns every test of those paths green without running
    # them. A peer session hit exactly this from the other side — its fixture
    # forced the switch off, and once the switch genuinely worked, three
    # watcher cases turned out never to have exercised the enabled path: "they
    # passed because the bug existed".
    # The list is not hand-maintained: `test_the_developers_environment_
    # cannot_change_what_the_suite_measures` reads proxy.py for every name it
    # takes from the environment and fails if one is missing here. It found
    # the last four — including the two hand-down variables, where a stale
    # value from a developer's shell would make a test adopt a descriptor
    # that is not the one under test.
    for name in ("CSWAP_PIN_PORT", "CSWAP_PIN_WIRED", "CSWAP_PIN_FIFO",
                 "CSWAP_PIN_REFCOUNT_FD", "CSWAP_PIN_SELF_HEAL",
                 "CSWAP_PIN_DEBUG", "CSWAP_PIN_SHAPE", "CSWAP_PIN_SLOW_MS",
                 "CSWAP_PIN_INFERENCE_FOLLOWS",
                 "CSWAP_PIN_LISTEN_FD", "CSWAP_PIN_LISTEN_FROM",
                 # Set BY a case that wants it, never inherited: a developer
                 # who exported it would make every holder in the suite die
                 # with its launcher, which is the production failure the
                 # opt-in exists to prevent.
                 "CSWAP_PIN_EXIT_WITH_PARENT",
                 "CSWAP_PIN_ALLOW_DIRECT",
                 # The standby's hand-down source. Same hazard as the two
                 # LISTEN vars above: a stale value from a shell makes a test
                 # adopt a descriptor that is not the one under test.
                 "CSWAP_PIN_STANDBY_FROM"):
        monkeypatch.delenv(name, raising=False)

    store = tmp_path / "data-home"
    store.mkdir(exist_ok=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(store))
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path / "fake-home")
    (tmp_path / "fake-home").mkdir(exist_ok=True)
    if hasattr(paths, "get_backup_root"):
        monkeypatch.setattr(
            paths, "get_backup_root", lambda store=store: store / "claude-swap"
        )

    # The seam re-imports these INSIDE functions (`from claude_swap.paths
    # import ...`), which reads the attribute at call time — so patching the
    # module attribute above is enough for those. But any module that bound
    # the name at import time keeps its own reference, and patching the source
    # module would not reach it. Catch those too.
    import sys

    for mod in list(sys.modules.values()):
        if mod is None or mod is paths:
            continue
        origin = getattr(mod, "__name__", "")
        if not (origin.startswith("claude_swap") or origin.startswith("cswap_pin")):
            continue
        for name in ("get_global_config_path", "get_default_global_config_path"):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name, lambda cfg=cfg: cfg, raising=False)
        if hasattr(mod, "get_claude_config_home"):
            monkeypatch.setattr(
                mod, "get_claude_config_home", lambda home=home: home, raising=False
            )
        if hasattr(mod, "get_backup_root"):
            monkeypatch.setattr(
                mod,
                "get_backup_root",
                lambda store=store: store / "claude-swap",
                raising=False,
            )


# --- one CA for the whole session -------------------------------------------
# `ensure_ca` generates an RSA key pair, which costs ~90 ms. Measured: 158 of
# the suite's tests call it, so the suite spent ~14 s — 18% of its runtime —
# re-deriving a key whose VALUE no test asserts on. The tests that care about
# CA CONTENT (the consistency checks, the trust-bundle merge) build their own
# and are unaffected; everything else just needs A valid CA to exist.
#
# So: build one, and have `ensure_ca` copy it when the target has none. The
# copy is what keeps the function's contract intact — callers still get four
# files in their own directory, and the idempotent-reuse path is untouched.
@pytest.fixture(autouse=True)
def _shared_ca(monkeypatch, tmp_path_factory):
    """Serve one pre-built CA to the FIRST cert dir each test asks for.

    `ensure_ca` mints two RSA-2048 keys — ~70 ms — and the suite calls it in
    most of its tests. Nothing asserts on a key's VALUE; what matters is that
    a CA signs its leaf, which a copy satisfies.

    THE FIRST DIR ONLY, per test. A test that builds a SECOND cert dir is
    almost always constructing a DIFFERENT CA on purpose ("a leaf signed by
    another CA of the same name", "a bundle without ours"), and handing those
    the same files makes the assertion vacuous. Measured: serving every dir
    broke three such tests.

    Only for the default host, too: a test naming another host needs a leaf
    with that SAN.
    """
    import shutil

    from cswap_pin import proxy as _p

    cache = tmp_path_factory.getbasetemp() / "_ca-cache"
    real = _p.ensure_ca
    if not (cache / "ca.pem").exists():
        cache.mkdir(parents=True, exist_ok=True)
        real(cache, "api.anthropic.com")

    served: list = []

    def fast_ensure_ca(ca_dir, host):
        d = pathlib.Path(ca_dir)
        # A SECOND cert dir gets the cache too, UNLESS its path says the test
        # wants a distinct CA. Restricting it to the first dir left 88 calls
        # generating (5.5 s); the tests that genuinely need two DIFFERENT CAs
        # name them, and `_other_ca` has its own cache.
        wants_distinct = any(
            w in str(d).lower()
            for w in ("other", "corp", "foreign", "sibling", "another", "second")
        )
        if (
            host == "api.anthropic.com"
            and not wants_distinct
            and not (d / "ca.pem").exists()
        ):
            served.append(str(d))
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            for f in ("ca.pem", "ca.key", "leaf.pem", "leaf.key"):
                shutil.copy2(cache / f, d / f)
            # AND SKIP THE RE-VERIFICATION. `ensure_ca` re-parses all four
            # files and checks the CA actually signed the leaf — 50 ms, and
            # correct for a real run. These four were verified once when the
            # cache was built and copied byte-for-byte, so re-deriving that
            # per test was 6.3 s of the suite. Tests that CARE about
            # consistency build their own pair and are unaffected.
            return _p.CertBundle(
                ca_path=d / "ca.pem",
                leaf_path=d / "leaf.pem",
                leaf_key_path=d / "leaf.key",
            )
        return real(d, host)

    monkeypatch.setattr(_p, "ensure_ca", fast_ensure_ca)
    # AND EVERY MODULE THAT IMPORTED THE NAME. `from cswap_pin.proxy import
    # ensure_ca` binds it into that module's namespace, so patching only the
    # source leaves those call sites on the real one.
    for mod in list(sys.modules.values()):
        if mod is None or mod is _p:
            continue
        if getattr(mod, "__name__", "").startswith(("test_", "tests.")):
            if getattr(mod, "ensure_ca", None) is real:
                monkeypatch.setattr(mod, "ensure_ca", fast_ensure_ca, raising=False)


@pytest.fixture(scope="session", autouse=True)
def _occupy_the_daemon_port():
    """Hold ``127.0.0.1:36301`` for the whole run so no case can be handed it.

    `bind(0)` draws from the ephemeral range, and on linux that range
    (32768-60999) CONTAINS the 36301 several classes use as the daemon's port;
    macOS's (49152-65535) does not. `test_proxy.py::_dead_port` already
    documents the consequence: a draw that collides makes `_wired_port() ==
    port` true, the claim check short-circuits to "already wired" and never
    reaches the repair. Roughly once in 28k draws, ubuntu only — which is
    exactly the one-job-red split seen twice in CI, run 33290951823
    (`TestTheDaemonRepairsItsOwnWiring`, `assert [] == [36301]`) and run
    34171357878 (`TestTheDaemonWatchesItsOwnCode`, `assert 36301 != 36301`).

    Occupying the port deletes the draw. This is also why the box the suite is
    developed on has never seen it: a live pin already holds 36301 there. The
    fixture reproduces that condition deliberately.

    ALREADY HELD IS THE SUCCESS CASE. A bind that fails means something else
    occupies the port, which achieves the identical goal, so the error is
    swallowed and only a socket we opened is ever closed. No `SO_REUSEADDR` or
    `SO_REUSEPORT` — exclusive occupation is the entire point.

    `test_meta.py::test_the_daemon_port_is_occupied_for_the_whole_run` is what
    stops this going quiet: a fixture that silently stops binding looks exactly
    like one that works, because the flake it prevents is ~2 in 173 runs.
    """
    import socket

    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 36301))
        s.listen(1)
    except OSError:
        s.close()
        yield
        return
    try:
        yield
    finally:
        s.close()


@pytest.fixture(scope="session")
def _session_ca(tmp_path_factory):
    """ONE CA for the whole run, built once and copied by everything that
    only needs *a* valid CA. Two RSA-2048 keys cost ~70 ms and the suite asked
    for one in most of its tests."""
    from cswap_pin import proxy as _p

    d = tmp_path_factory.mktemp("session-ca")
    _p.ensure_ca(d, "api.anthropic.com")
    return d


@pytest.fixture(autouse=True)
def _short_hop_budgets(monkeypatch):
    """Adjust the egress-hop budgets for tests: shrink three, raise the
    connect budget.

    A hop that accepts and never answers costs `_HOP_REPLY_BUDGET_S` (6 s) per
    dial, and several tests point the walk at exactly that shape on purpose.
    The PRODUCT budget has to be generous — it covers a real proxy's outbound
    round trip — but a test dialling 127.0.0.1 needs none of it, and the
    budget was the runtime rather than the thing under test.
    """
    from cswap_pin import proxy as _p

    # THE CONNECT BUDGET IS RAISED ABOVE PRODUCTION, NOT SHRUNK, and
    # deliberately: 10s here vs. 2.0s (`_HOP_CONNECT_BUDGET_S` in proxy.py),
    # five times over. Every dial here is to 127.0.0.1, which is refused or
    # connected at once (a census found 180 runtime `_dial_chain` calls
    # across test_proxy.py and test_proxy_server.py, none of which waits on
    # its connect timeout), so only a stalled handshake ever reads this
    # budget -- and 0.3s turned exactly that stall, on a loaded runner, into
    # a false `egress REFUSED` in
    # case_the_absolute_form_hold_releases_at_the_status_line. 10s matches
    # what T1076/PR #31 gave `_probe_next_hop` for the same class of
    # macOS-runner stall.
    monkeypatch.setattr(_p, "_HOP_CONNECT_BUDGET_S", 10, raising=False)
    monkeypatch.setattr(_p, "_HOP_REPLY_BUDGET_S", 0.3, raising=False)
    # AND THE HEAL GRACE. The production value waits out a hop that is
    # restarting (~1s, measured); a test whose hop is deliberately dead pays it
    # in full for nothing. Measured: the suite went 5s -> 96s the moment the
    # grace landed. Shrunk rather than zeroed, so the retry LOOP still runs —
    # a zero would skip the behaviour instead of shortening it.
    monkeypatch.setattr(_p, "_CHAIN_HEAL_GRACE_S", 0.3, raising=False)
    monkeypatch.setattr(_p, "_CHAIN_HEAL_POLL_S", 0.05, raising=False)


@pytest.fixture(autouse=True)
def _creator_pid_by_bridge_starts_empty(monkeypatch):
    """Reset the sweep's in-process `bridge -> creator pid` record before
    every test.

    A few cases stamp real pids into it directly (bypassing the job-record
    read) to exercise the in-process fallback in `_dead_creator_bridge_ids`.
    Without a reset that dict is the real module global, so a stamp one
    case leaves behind is still there for the next one to read -- order-
    fragile, since only distinct bridge ids across cases hide it today.
    """
    from cswap_pin import proxy as _p

    monkeypatch.setattr(_p, "_creator_pid_by_bridge", {}, raising=False)


_STANDBY_ARG = "--standby"


def signal_if_still_ours(pid: int, certdir, sig: int) -> bool:
    """Signal ``pid`` only while it is still a pin process for ``certdir``.

    A PID FROM A FILE IS A NUMBER, NOT A PROCESS. `read_daemon_state` records
    the daemon that was serving; by the time a test signals it, that daemon
    may have been replaced and its pid handed to somebody else. This suite
    already paid for that once — "signalling a bare number once killed a
    pytest-xdist worker" — and the guard it grew (`Popen.returncode is None`)
    only covers children we own, not pids we read.

    PORTABLE ON PURPOSE. Every existing ownership check here reads /proc, so
    it silently passes on macOS and the hazard is unguarded on exactly the
    platform where it fires: pid space is small there and reuse is fast, which
    is why CI went red on macos-latest and stayed green on ubuntu once the
    standby put a third process in every lineage and doubled the pid churn.

    Returns whether the signal was sent.
    """
    import os
    import subprocess as _sp

    # BOTH SPELLINGS OF THE SAME DIRECTORY. On macOS `mkdtemp()` returns
    # /var/folders/... while `resolve()` returns /private/var/folders/... —
    # same directory, different string, because /var is a symlink. A child is
    # spawned with the argv form and this compared the resolved form, so the
    # `endswith` gate was NEVER true and the sweep reaped nothing on macOS
    # whatever ps returned. Linux has no /private prefix; the two are equal
    # there and the bug is invisible.
    #
    # Measured on a mac: mkdtemp /var/folders/l5/.../T/tmpuuwqddva
    #                   resolve /private/var/folders/l5/.../T/tmpuuwqddva
    _cd = pathlib.Path(certdir)
    targets = {str(_cd), str(_cd.resolve())}
    try:
        # `-ww`, NOT bare `-o command=`. ps honours COLUMNS and pytest sets it
        # to 80, so the certdir this predicate matches on was CUT OFF mid-path
        # and every check refused. Measured:
        #   cmd='... -m cswap_pin.proxy 1 a@b.c /tmp/pytest-of-j.'
        # A width-dependent predicate fails toward "not ours", which is the
        # safe direction here and the silent direction everywhere else.
        cmd = _sp.run(["ps", "-ww", "-o", "command=", "-p", str(pid)],
                      capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, _sp.SubprocessError):
        return False
    if ("cswap_pin.proxy" not in cmd
            or not any(cmd.rstrip().endswith(" " + t) for t in targets)):
        return False
    try:
        os.kill(pid, sig)
    except OSError:
        return False
    return True


def _reap_pin_processes(certdir, timeout: float = 20.0) -> None:
    """Kill every pin process serving ``certdir``, PARENTS FIRST, and WAIT.

    Two things make this less obvious than it looks, both measured here:

      - PARENTS FIRST. A holder's whole job is to replace a daemon that dies,
        so killing children first MULTIPLIES them. A handover test that TERM'd
        only the recorded daemon pid accumulated 7 orphans across a few suite
        runs; a peer session stalled its machine with 53.
      - WAIT, and re-sweep. A holder answering SIGTERM drains its daemon
        first, so the child is still alive when this returns — and a test that
        returns before its processes are gone leaves them for the next run to
        find. Re-sending until the set is empty also catches a daemon the
        holder respawned in the window before it saw the signal.

    Matched on the certdir being the LAST argv token, which is how the product
    identifies its own daemons — so a test certdir can never select the live
    pin, whose certdir is the real backup dir. The match is "equal to, or
    under, this path": passing a crashed run's ROOT here (rather than one
    certdir) reaps everything under it, since that root's own certdir is
    gone from the CURRENT run's target set (a fresh ``tmp_path`` every time).
    """
    import os
    import subprocess
    import time

    # BOTH SPELLINGS OF THE SAME DIRECTORY. On macOS `mkdtemp()` returns
    # /var/folders/... while `resolve()` returns /private/var/folders/... —
    # same directory, different string, because /var is a symlink. A child is
    # spawned with the argv form and this compared the resolved form, so the
    # `endswith` gate was NEVER true and the sweep reaped nothing on macOS
    # whatever ps returned. Linux has no /private prefix; the two are equal
    # there and the bug is invisible.
    #
    # Measured on a mac: mkdtemp /var/folders/l5/.../T/tmpuuwqddva
    #                   resolve /private/var/folders/l5/.../T/tmpuuwqddva
    _cd = pathlib.Path(certdir)
    targets = {str(_cd), str(_cd.resolve())}

    def _mine():
        try:
            # `-ww` OR THIS SWEEP REAPS NOTHING. ps truncates to COLUMNS,
            # pytest sets it to 80, and the certdir gate below matches on
            # the LAST argv token — so every line came back cut off
            # mid-path and `_mine()` returned an empty list. On Linux
            # PDEATHSIG hides it by taking children down with their
            # holder; on macOS nothing does, so a lineage leaked per case
            # until the worker could not shut down and execnet SIGINT'd
            # it — `node down: keyboard-interrupt`, macOS red, ubuntu
            # green, traced to execnet's own `_terminate_execution`.
            out = subprocess.run(["ps", "-ww", "-eo", "pid=,command="],
                                 capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return [], []
        standbys, holders, daemons = [], [], []
        for line in out.splitlines():
            pid_s, _, cmd = line.strip().partition(" ")
            if "cswap_pin.proxy" not in cmd:
                continue
            tail = cmd.rstrip().rpartition(" ")[2]
            if not any(tail == t or tail.startswith(t + "/") for t in targets):
                continue
            try:
                pid = int(pid_s)
            except ValueError:
                continue
            if pid == os.getpid():
                continue
            if _STANDBY_ARG in cmd:
                standbys.append(pid)
            elif "--hold-port" in cmd:
                holders.append(pid)
            else:
                daemons.append(pid)
        return standbys, holders, daemons

    deadline = time.monotonic() + timeout
    while True:
        standbys, holders, daemons = _mine()
        if not standbys and not holders and not daemons:
            return
        # RELEASE THE STANDBY FIRST, and by SIGHUP. It is the same rule as
        # "parents first", one layer out: the standby is the last thing that
        # can put the port back, so killing what it watches before telling it
        # to let go makes it ARM and rebuild the lineage this sweep just
        # removed. And it must be SIGHUP — the standby ignores SIGTERM on
        # purpose, because TERM is what a supervisor sends and that is when a
        # live session needs the address most. Reaching it with 15 would take
        # the full timeout and a SIGKILL, after a resurrection or two.
        for pid in standbys:
            try:
                os.kill(pid, 1)
            except OSError:
                pass
        for pid in holders + daemons:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        if time.monotonic() >= deadline:
            # Last resort, still parents first, standby ahead of them: a
            # SIGKILLed holder cannot release anything on its way out.
            for pid in standbys + holders + daemons:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
            return
        time.sleep(0.2)


def _root_owner_alive(root) -> bool:
    """Whether ``root`` is CLAIMED by a session this sweep must not touch.

    Every numbered root pytest makes for a session (``.../pytest-of-<user>/
    pytest-N``) carries a ``.lock`` file stamped with that session's own pid
    (`_pytest.pathlib.create_cleanup_lock`), held for the session's whole
    life and unlinked only on a clean exit. Reading that pid and asking the
    kernel whether it still exists is a measurement, not an age guess — a
    crashed run leaves the lock behind with a pid that is already gone, and a
    live sibling run's lock names a pid that answers.

    NO LOCK, NO CLAIM — and an unreadable claim must fail toward LEAVING THE
    PROCESS ALONE, so a root with no ``.lock``, or one this can't parse,
    reads as owned (True) rather than dead. This matters under xdist: a
    worker's own root is ``<pytest-N>/popen-gwK``, and its sibling
    ``popen-gw*`` roots (the OTHER workers of the same run) carry no
    ``.lock`` at all — reading that as "dead" would make one worker reap the
    other three's live daemons mid-run. A crashed run's root still HAS its
    lock, naming a pid that's gone (the lock is `atexit`-removed, which
    `os._exit` skips) — that case still returns False and is still reaped.

    Liveness is read inline with ``os.kill(pid, 0)`` rather than via
    ``cswap_pin.proxy._pid_alive`` — this file already calls ``os.kill``
    directly elsewhere, and importing the product here would move that
    import from collection into this hook, which has no exception guard: a
    missing host would then abort the whole session (`INTERNALERROR`, zero
    tests) instead of failing at collection, which is the documented
    signature for that case.

    A pid the kernel rejects as absent (``ProcessLookupError``) is dead:
    sweepable. ``PermissionError`` (EPERM) means the pid EXISTS, owned by
    someone else — the opposite of ``_pid_alive``'s reading, which returns
    False on EPERM; correct for the product deciding whether IT can signal a
    pid, wrong for a reaper deciding whether to touch one. Anything else this
    can raise (a malformed or oversized pid: ``OverflowError``,
    ``ValueError``) is not a usable claim either way, so it also reads as
    owned.
    """
    import os

    lock = pathlib.Path(root) / ".lock"
    try:
        pid = int(lock.read_text().strip())
    except (OSError, ValueError):
        return True
    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except Exception:
        return True
    return True


def pytest_sessionstart(session) -> None:
    """Reap a crashed run's pin daemons before this run spawns any of its own.

    `_reap_pin_processes` only ever matched one exact certdir, which is
    always the CURRENT run's — a run that died before its `finally` (a
    leaked daemon thread reaching `os._exit`, or a SIGKILL) leaves its
    daemons for nobody, because the next run's fresh `tmp_path` can never
    equal the dead run's.

    NEVER SWEEP A SIBLING THAT IS STILL RUNNING. Two suites can share one
    `/tmp/pytest-of-<user>` prefix, and a sweep that reaps every root under
    it regardless of ownership is a fleet-wide `pkill` wearing a guard's
    clothes — so only a root whose OWNER has already exited is touched
    (`_root_owner_alive`), which itself fails toward "owned" on anything it
    can't read.
    """
    # ponytail: two ceilings from that same "fail toward owned" rule, both
    # acceptable: (1) under xdist (this project's default, `-n 4`) each
    # WORKER's own sweep is a no-op — its siblings are unlocked `popen-gw*`
    # dirs — but the CONTROLLER process also loads this file and sweeps the
    # real basetemp parent, so the feature still runs, through the
    # controller; (2) this only sees roots `iterdir()` can still find, and
    # pytest prunes all but the last three at every CLEAN exit — a daemon
    # under an already-pruned root is invisible. Next crash is always
    # covered (swept before pytest gets to prune it); upgrade path if either
    # bites: track daemon pids outside the tmp tree.
    own_root = session.config._tmp_path_factory.getbasetemp()
    prefix = own_root.parent
    for sibling in prefix.iterdir():
        if sibling == own_root or not sibling.is_dir():
            continue
        if _root_owner_alive(sibling):
            continue
        _reap_pin_processes(sibling, timeout=5.0)


def pytest_sessionfinish(session) -> None:
    """Sweep whatever THIS run's own root leaves behind; nothing else owns it."""
    own_root = session.config._tmp_path_factory.getbasetemp()
    _reap_pin_processes(own_root, timeout=5.0)


# --- the provenance stamp every lifecycle line carries -----------------------
# Two proxies on this fleet write drain lines, so a line that does not name
# its writer has no provenance. Two tests assert that.
#
# THE EXPECTATION DEPENDS ON THE ENVIRONMENT, and accepting both spellings
# unconditionally was wrong. `_derive_version` reads the INSTALLED
# distribution's metadata and falls back to `0+unknown` only when there is no
# distribution -- so which one is CORRECT is decided by whether one is
# installed, and a test that accepts either checks nothing:
#
#   uv run ...        (README, ci.yml, publish.yml)   -> a real semver
#   PYTHONPATH=src    (ambient interpreter)           -> 0+unknown
#
# Nothing else in this repo asserts the version's VALUE. `test_packaging`
# asserts the MECHANISM (that `__version__` is not a literal) and
# publish.yml prints it without asserting, so this is the only place a
# regression in the pipeline would be caught -- and it would be caught on
# CI, where a distribution IS installed and `0+unknown` would mean a wheel
# about to ship with versionless provenance. A PyPI version cannot be
# re-uploaded.
#
# The lookup here is deliberately INDEPENDENT of `_derive_version`, so this
# cannot certify itself: a broken `_derive_version` still fails the assert.
try:  # pragma: no cover - one branch per environment, both are real
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _dist_version

    _PIN_VER = re.escape(_dist_version("cswap-pin"))
except PackageNotFoundError:
    _PIN_VER = re.escape("0+unknown")

PIN_STAMP = r"\] cswap-pin/" + _PIN_VER + r" pid=\d+ "

# --- one pytest test per class, N cases inside -------------------------------
# The suite's cases are cheap (54 ms each, measured) and its per-case pytest
# overhead is not the cost — but 332 collected items is more surface than the
# behaviour warrants, and each one re-pays the autouse fixtures. `run_cases`
# runs every `case_*` method of a class inside ONE pytest test, giving each its
# own tmp_path and its own monkeypatch so a case cannot leak into the next.
#
# WHAT THIS MUST NOT LOSE, and does not:
#  - INDEPENDENCE. Each case gets a fresh MonkeyPatch (undone in a finally) and
#    a fresh tmp_path subdir, so state a case installs dies with it. That is
#    the property pytest's own per-test teardown was providing.
#  - EVERY FAILURE, not the first. A raising case is recorded and the run
#    continues; the driver fails at the end naming ALL of them. Stopping at the
#    first would hide the rest behind one fix — strictly worse than what the
#    separate tests reported.
#  - THE FAILING CASE'S NAME AND TRACEBACK. Both are in the message, so a
#    failure still points at one method in one file.
#  - A SKIP IS NOT AN EARLY EXIT. `pytest.skip()` raises `Skipped`, which
#    derives from `BaseException`, not `Exception` -- so it is caught on its
#    own, separately, and the loop CONTINUES: every later case still runs,
#    and a failure among them still gets raised. Only when every case in the
#    run skipped does this itself skip, naming each one; a mix of skips and a
#    clean pass surfaces the skips as a warning rather than going quiet.
def run_cases(instance, request, tmp_path_factory, extra=None):
    """Run every `case_*` method of `instance`, isolated, reporting all failures.

    `instance` may be a LIST of holders — several small classes sharing one
    pytest test. They are run separately (own instance, own helpers) rather
    than merged by inheritance, because three of this suite's classes define a
    `_ca` / `_cfg` / `_ours` helper with DIFFERENT meanings and a shared MRO
    would have handed every case just one of them.

    A case takes the fixtures it names in its signature, resolved from `extra`
    plus the per-case `tmp_path` / `monkeypatch` this builds. Anything else it
    asks for is fetched from pytest itself via `request.getfixturevalue`.
    """
    import traceback

    from _pytest.monkeypatch import MonkeyPatch

    holders = instance if isinstance(instance, (list, tuple)) else [instance]
    work = []
    for holder in holders:
        cls = type(holder)
        for n in sorted(dir(cls)):
            if n.startswith("case_") and callable(getattr(holder, n)):
                work.append((holder, f"{cls.__name__}::{n}", getattr(holder, n)))
    module_factories = getattr(
        sys.modules[type(holders[0]).__module__], "case_fixtures", {}
    )
    failures = []
    skipped = []
    for i, (instance, name, method) in enumerate(work):
        wants = [
            a
            for a in method.__code__.co_varnames[: method.__code__.co_argcount]
            if a != "self"
        ]
        mp = MonkeyPatch()
        # A per-case dir, not the shared one: two cases writing `pin-proxy/`
        # under one tmp_path would see each other's files.
        case_tmp = tmp_path_factory.mktemp(f"c{i}")
        # THE HOP-TROUBLE STAMP, BEFORE TOO. The `finally` below only clears
        # it AFTER a case, so a plain test outside this loop that pokes it
        # directly and never restores it -- no `finally` of its own -- is
        # still hot when THIS case starts, and the after-reset clears it only
        # once this case has already run under the polluted value.
        import cswap_pin.proxy as _pp

        with _pp._hop_trouble_lock:
            _pp._hop_trouble_at = 0.0
        try:
            # The autouse guards ran once for the DRIVER's tmp_path. Re-point
            # them at this case's dir, or a case's config writes land in the
            # dir a sibling case is asserting about.
            _redirect_everything_to(case_tmp, mp)
            pool = {"tmp_path": case_tmp, "monkeypatch": mp}
            # A FIXTURE A CASE CAN WRITE INTO IS BUILT PER CASE, not once for
            # the driver. Measured: sharing one `certdir` across a class let a
            # case's `upstream.json` be read by the next one, which then
            # asserted about a chain it had never recorded. A test module names
            # those in `case_fixtures`; everything else still comes from pytest,
            # where a read-only or session-scoped value is correct to share.
            for fname, factory in {**module_factories, **(extra or {})}.items():
                pool[fname] = factory(case_tmp) if callable(factory) else factory
            args = [
                pool[a] if a in pool else request.getfixturevalue(a) for a in wants
            ]
            method(*args)
        except pytest.skip.Exception as exc:
            # `Skipped` DERIVES FROM `BaseException`, NOT `Exception` -- the
            # `except Exception` below never caught it, so a `pytest.skip()`
            # inside any case ended this loop right here: every later case
            # never ran, and any failure already in `failures` was never
            # raised, because the raw `Skipped` propagated out of this
            # function on the spot instead. Recorded and CONTINUED instead,
            # the same as a real failure two lines down.
            skipped.append(f"{name}: {exc}")
        except (pytest.fail.Exception, Exception):  # noqa: BLE001
            # `Failed` -- what `pytest.fail()` raises -- derives from
            # `BaseException`, not `Exception`, the same as `Skipped` above,
            # so a plain `except Exception` never caught it either: a case
            # that calls `pytest.fail()` directly ended the loop right here,
            # the same way a `pytest.skip()` used to. Named in the tuple
            # explicitly and collected, do not stop the run. `pytest.fail.
            # Exception` (`Failed`) also catches `XFailed`, which subclasses
            # it -- no case calls `pytest.xfail()` today, but one that did
            # would be recorded here as a failure, not a skip.
            failures.append(f"--- {name} ---\n{traceback.format_exc()}")
        finally:
            mp.undo()
            # A MODULE GLOBAL IS OUTSIDE MONKEYPATCH'S REACH, and this one
            # decides how the relay frames replies. `this_process_is_draining`
            # matches the marker BASENAME — the pid — so a drain announced
            # under one case's certdir answers yes for every later case in this
            # worker, and the relay then marks their keep-alive replies
            # `Connection: close`.
            import cswap_pin.proxy as _pp

            with _pp._DRAINING_LOCK:
                _pp._DRAINING_DEPTH.clear()
            # AND THE SHARED PUMP. `_PUMP` is a module global driving every
            # tunnel in the process, so in a single-process run (macOS, which
            # sets WORKERS=0) one case's leftover pairs are visible to the
            # next. Measured on that runner: a proxy reported ANOTHER case's
            # tunnels in its own count, and a drain waited out the marker TTL
            # on a tunnel it did not own — two failures that read as
            # production defects and were neither.
            _pp._PUMP.reset_for_tests()
            # AND THE HOP-TROUBLE STAMP. `_note_hop_trouble` fires on any
            # real 5xx a case relays through `_relay_response(note_hop=True)`
            # -- most of them about something else entirely -- and
            # `_report_deaf_bridges` now reads it over a 300s WALL-CLOCK
            # window (`_DEAF_WINDOW_S`), so one case's incidental 502 blinded
            # every deaf-report case for the next several minutes of real
            # test time. Same shape as `_DRAINING_DEPTH` above.
            with _pp._hop_trouble_lock:
                _pp._hop_trouble_at = 0.0
    if failures:
        raise AssertionError(
            f"{len(failures)} of {len(work)} cases failed:\n\n" + "\n".join(failures)
        )
    if skipped and len(skipped) == len(work):
        # EVERY CASE SKIPPED. A pass here would read as "nothing to check",
        # which is not what happened -- pytest's own `skip` is the honest
        # report, naming every case so this reads nothing like the old bug's
        # single, unlabelled `Skipped` escaping on the first case alone.
        pytest.skip(f"all {len(work)} cases skipped:\n" + "\n".join(skipped))
    if skipped:
        # SOME SKIPPED, NONE FAILED: a real pass, not a failure -- but a
        # skip silent enough to need no trace is exactly how this bug went
        # unnoticed. `warnings.warn` is what pytest surfaces without turning
        # a legitimate pass into one.
        warnings.warn(
            f"{len(skipped)} of {len(work)} cases skipped:\n" + "\n".join(skipped)
        )
