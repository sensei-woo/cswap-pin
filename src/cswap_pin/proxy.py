"""Account-pin proxy.

A local MITM forward proxy that swaps the ``Authorization`` bearer to a pinned
account's token on the Remote-Control and Artifact routes, so those operations
stay on one account while inference follows whatever cswap has swapped onto
disk. Everything else (inference at ``/v1/messages``, OAuth, telemetry, …) is
relayed untouched, and non-anthropic hosts are blind-tunnelled.

The daemon lifecycle here — fixed port across respawns, FIFO refcount, config
fingerprint, idle teardown — follows the one used by local cache proxies ("the cache proxy"
in the comments below), whose forward-proxy mode solves the same shape of
problem in front of Claude Code. Nothing in this module requires it: a
comment naming a peer implementation cites where a decision came from,
not a dependency.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as _dt
import glob
import itertools
import json
import os
import warnings
import re
import selectors
import select
import signal
import socket
import stat
import sys
import ssl
import threading
import time
from dataclasses import dataclass
from typing import NamedTuple
from pathlib import Path
import urllib.request
from urllib.parse import quote, unquote, urlsplit

from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cswap_pin._host import require

oauth = require("oauth")


class _Chain(NamedTuple):
    """The egress proxy to CONNECT through.

    A ``(host, port)`` NamedTuple so every existing comparison, unpack and
    ``chain[0]`` keeps working, carrying the two things a bare pair threw
    away: the credential the URL supplied, and whether the hop itself is
    TLS. Dropping those sent an unauthenticated cleartext CONNECT to
    authenticated and https:// corporate proxies — 407, or a plaintext dial
    into a TLS port — which breaks ALL pinned traffic in those environments.

    ``socket.create_connection`` takes exactly a 2-tuple, so call sites pass
    ``chain.address`` rather than the chain itself.
    """

    host: str
    port: int
    auth: str | None = None   # value for Proxy-Authorization, already encoded
    tls: bool = False         # the hop to the proxy is itself TLS

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port

    def connect_headers(self) -> str:
        return f"Proxy-Authorization: {self.auth}\r\n" if self.auth else ""


def parse_upstream_proxy(value: str | None) -> _Chain | None:
    """Parse the proxy that was on ``HTTPS_PROXY`` before we displaced it.

    Returns the chain to CONNECT through (a corporate proxy, another local
    MITM, …), or ``None`` when there was none — in which case the proxy dials
    the upstream directly. A bare ``host:port`` (no scheme) is accepted; the
    default port follows the scheme (443 for https, else 80) rather than
    always being 80, which pointed every https:// proxy at the wrong port.
    """
    if not value:
        return None
    split = urlsplit(value if "://" in value else f"//{value}")
    host = split.hostname
    if not host:
        return None
    tls = split.scheme == "https"
    auth = None
    if split.username:
        # userinfo is percent-encoded in a URL; the header carries the
        # decoded bytes.
        raw = f"{unquote(split.username)}:{unquote(split.password or '')}"
        auth = "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return _Chain(host, split.port or (443 if tls else 80), auth, tls)


def _read_upstream(certdir: Path, key: str) -> str | None:
    """One field out of the upstream record, or None when it is absent."""
    try:
        raw = json.loads((Path(certdir) / _UPSTREAM_FILE).read_text())
    except (OSError, ValueError):
        return None
    return (raw.get(key) or None) if isinstance(raw, dict) else None


def read_upstream_hint(certdir: Path) -> tuple[str, int] | None:
    """The egress proxy the LAST launch was using, as recorded on disk.

    The daemon outlives the launch that spawned it, and a session's own
    ``HTTPS_PROXY`` is fixed at exec — so the daemon cannot ask "what should I
    chain through now?" of anything but this file. Every launch re-stamps it
    (``ensure_proxy``), so an egress proxy that moved ports or came up after the daemon
    is picked up on the next connection rather than bypassed for the daemon's
    whole life.

    Returns ``None`` when the file is absent or records "no proxy" — the same
    thing a direct dial means.
    """
    return parse_upstream_proxy(_read_upstream(certdir, "proxy"))


def _probe_next_hop(value: str | None, timeout: float = 1.0) -> str | None:
    """The proxy the recorded hop is ITSELF chaining to, asked of that hop.

    A local cache proxy reports its own upstream on ``/health`` while it is
    alive, and that is the only moment the answer can be trusted — so this is
    called at hint-writing time (a launch), never from the relay. Returns None
    whenever the hop does not answer or does not name one: a hop that cannot be
    confirmed NOW must not be recorded, because a stale next hop costs a dial
    before the walk reaches the no-chain decision.

    Loopback only. The next hop matters for a chain of local proxies; asking a
    remote corporate proxy for a /health it does not serve would spend the
    timeout on every launch.
    """
    import http.client

    hop = parse_upstream_proxy(value)
    if hop is None or hop.host not in _LOOPBACK or hop.tls:
        return None
    try:
        conn = http.client.HTTPConnection(hop.host, hop.port, timeout=timeout)
        try:
            conn.request("GET", "/health")
            body = json.loads(conn.getresponse().read())
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — an absent probe is "no next hop"
        return None
    if not isinstance(body, dict):
        return None
    nxt = body.get("https_proxy") or body.get("HTTPS_PROXY")
    if not isinstance(nxt, str) or not nxt:
        return None
    parsed = parse_upstream_proxy(nxt)
    # A hop naming ITSELF would make the walk retry the address that just
    # failed, which is a loop rather than a fallback.
    if parsed is None or parsed.address == hop.address:
        return None
    return nxt


def _chain_hops(certdir: Path) -> list[_Chain]:
    """Every recorded hop, outermost LAST — the order to try them in.

    The relay dials the first and falls through to the next when a hop is not
    usable. A single-hop record (nothing behind it was confirmed) yields one
    entry, which is what every caller did before the chain was recorded.
    """
    hops = []
    for value in (_read_upstream(certdir, "proxy"), _read_upstream(certdir, "next")):
        hop = parse_upstream_proxy(value)
        if hop is not None and hop not in hops:
            hops.append(hop)
    return hops


def write_upstream_hint(
    certdir: Path, value: str | None, ca: str | None = None,
    next_hop: str | None = None,
) -> None:
    """Record the egress proxy for the daemon to chain through (see above).

    ``ca`` records the CA that proxy signs with, so a later launch that cannot
    see it (a plain shell, where a launcher's CA only exists at exec time) can
    still merge it.

    A ``value`` of None means "this launch could not see a proxy", which is NOT
    the same as "there is no proxy": `cswap pin` normally runs in an ordinary
    shell, while the launcher sets HTTPS_PROXY only in the environment it execs
    Claude Code with. Recording that as "none" would drop a live upstream —
    measured: a re-pin from a plain shell blanked a recorded proxy and the daemon
    started bypassing it. So a previously recorded proxy is kept unless a
    launch positively reports a different one.
    """
    path = Path(certdir) / _UPSTREAM_FILE
    tmp = path.with_suffix(".tmp")
    keep_ca = read_upstream_ca(certdir) if ca is None else ca
    # THE CHAIN, NOT ONE HOP. A recorded hop that dies must fall through to the
    # hop behind it; falling through to a direct dial is not "no proxy" on a
    # machine whose direct route is a TLS-inspecting corporate proxy.
    #
    # A PROBE THAT COULD NOT ASK IS NOT AN ANSWER OF "NONE".
    # ``_probe_next_hop`` returns None both when the hop reports no upstream
    # AND when the hop is not answering — and the second case is exactly when
    # the chain is about to be needed. Writing "" there erased the outer hop at
    # the moment the inner one died, leaving a single-hop chain that falls
    # straight to a direct dial. Keep what a previous launch confirmed; only a
    # launch that positively reports a different hop replaces it.
    keep_next = next_hop or _read_upstream(certdir, "next") or ""
    if value:
        keep_proxy = value
    else:
        # KEEP THE RAW STRING. Rebuilding the URL from the parsed pair threw
        # away the two fields _Chain exists to carry: the credential and the
        # https scheme. And this is the NORMAL path — `cswap pin` from a plain
        # shell reports no proxy, and ensure_proxy re-stamps on every launch —
        # so an authenticated or TLS corporate proxy survived exactly until the
        # next re-pin, then every pinned request 407'd.
        keep_proxy = _read_upstream(certdir, "proxy") or ""
    try:
        tmp.write_text(json.dumps(
            {"proxy": keep_proxy, "ca": keep_ca or "", "next": keep_next}
        ))
        tmp.replace(path)
    except OSError:
        pass


def read_upstream_ca(certdir: Path) -> str | None:
    """The CA of the egress proxy, as last recorded. See above."""
    return _read_upstream(certdir, "ca")


_WIRE_KEYS = ("HTTPS_PROXY", "https_proxy", "NODE_EXTRA_CA_CERTS")
_WIRE_MARK = "_cswapPinWiredKeys"

# Environment variables that REPLACE a TLS trust store rather than adding to
# it. The pin writes none of them and removes any it finds — see the note in
# `wire_global_config` for why a subsumption gate was not enough.
#
# NODE_EXTRA_CA_CERTS is deliberately absent: node ADDS it to its built-in
# roots, so it can never narrow trust, and the pin does need it.
_REPLACE_CLASS_CA_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")

# -- where the receipt lives -------------------------------------------------
#
# The `env` block stays in `.claude.json` — Claude Code reads it there at boot,
# so that file IS the interface and nothing about it can move. The RECEIPT
# (which keys are ours, and what they displaced) is bookkeeping only cswap
# reads, and it belongs with cswap's other state: `.claude.json` is the user's
# file, and `_cswapPinWiredKeys` / `_cswapPinWiredKeysSaved` are two opaque
# keys a human editing it can only trip over.
#
# READ BOTH, WRITE NEW — no cutover. An OLDER cswap-pin, or an older
# claude-swap, still reads and writes the config key; both keep working
# because every reader here consults the sidecar first and falls back to the
# config. The config keys are REMOVED on the next write by a new pin, so a
# box converges by being used rather than by a migration step.


def _ledger_path(config_path: Path) -> Path:
    """The sidecar receipt for ``config_path``, under the account store.

    KEYED BY CONFIG PATH, because there are two configs: `~/.claude.json` and
    the `CLAUDE_CONFIG_DIR` copy a session terminal uses. One sidecar for both
    would let the second wiring's receipt overwrite the first's, and unwiring
    would restore the wrong displaced values into the wrong file — strictly
    worse than the config key it replaces, which at least travelled WITH its
    own config.
    """
    import hashlib

    from cswap_pin._host import require

    root = Path(require("paths").get_backup_root())
    key = hashlib.sha256(str(config_path).encode("utf-8")).hexdigest()[:16]
    return root / "pin-wiring" / f"{key}.json"


def _own_version() -> str:
    """The version of the package doing the writing, or "" if unknowable.

    ponytail: version string, not a content hash. `daemon_fingerprint` would
    also catch an editable checkout whose version never moves, but it reads
    every module in the package, and the reader of this field runs from an rc
    hook before every launch. Upgrade to the fingerprint if a dev install ever
    needs the rewrite too.
    """
    try:
        from cswap_pin import __version__
        return str(__version__ or "")
    except Exception:  # noqa: BLE001 — a missing version must not block a wire
        return ""


def rewire_if_version_changed(certdir: "Path | str") -> bool:
    """Re-apply the config wiring once, after the pin package changed.

    THE GAP THIS CLOSES, measured on host-a. `cswap-pin` went 0.1.86 ->
    0.1.87 on all three machines, the daemon recycled onto the new code, and
    `.claude.json` kept the FIVE keys the old version wrote — the new
    `SSL_CERT_FILE` never appeared. `cswap pin --ensure`, the rc hook that
    runs before every launch, does not refresh a LIVE wiring: it heals a
    broken daemon and clears DEAD configs, and a config whose port answers is
    neither. So the key waited for the next full session launch while the
    deploy looked finished. It was reported as deployed.

    WHY NOT JUST REWIRE EVERY LAUNCH. `--ensure` promises never-fails,
    silent, and CHEAP WHEN IDLE, and a read-modify-write under the config lock
    is exactly what that contract keeps off the launch path — the same lock a
    routine credential refresh holds, measured at 9.5s once. So the receipt
    names its writer and this compares two strings: one small read on a
    settled machine, one rewrite per upgrade.

    Never raises: the caller is a launch hook.
    """
    try:
        certdir = Path(certdir)
        get_global_config_path = require("paths").get_global_config_path
        cfg = get_global_config_path()
        try:
            raw = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — unreadable config: nothing to refresh
            raw = {}
        led = _read_ledger(cfg, raw)
        if not led.get(_WIRE_MARK):
            # Not wired by us. An unwired machine must not pay for this.
            return False
        if led.get("writtenBy") == _own_version():
            return False
        # THE RECORDED PORT, not a probe. `--ensure` has already healed a dead
        # daemon and cleared dead configs by the time this runs, so a port
        # here that is not serving is a state those steps own; adding another
        # socket probe would put a second timeout on the launch path.
        state = read_daemon_state(certdir)
        port = (state or {}).get("port")
        if not port:
            return False
        # SAME PORT ONLY. A block naming a DIFFERENT port is a repair, and the
        # repair belongs to `heal` — which reports what it fixed, and whose
        # caller renders that verdict. Rewriting it here first left heal with
        # nothing to correct and turned its True into a False: the config was
        # right and the message said nothing had been wrong. Caught by
        # `case_wired_to_the_WRONG_port_is_corrected`, not by reasoning.
        #
        # So this stays what it is for: a wiring that is already correct
        # except that an older version of this package wrote it.
        if str((raw.get("env") or {}).get("CSWAP_PIN_PORT") or "") != str(port):
            return False
        return bool(wire_global_config(int(port), certdir / "ca.pem"))
    except Exception:  # noqa: BLE001 — a launch must never fail on the pin
        return False


def _read_ledger(config_path: Path, raw: dict) -> dict:
    """The receipt for ``config_path``: sidecar first, config as fallback.

    A sidecar that EXISTS and says "not wired" is an answer, not a miss — an
    unwire writes exactly that. Falling through to the config there would
    resurrect a receipt the unwire deliberately emptied.
    """
    try:
        side = json.loads(_ledger_path(config_path).read_text(encoding="utf-8"))
        if isinstance(side, dict) and _WIRE_MARK in side:
            return side
    except Exception:  # noqa: BLE001 — absent/unreadable: fall back
        pass
    return raw if isinstance(raw, dict) else {}


def _write_ledger(config_path: Path, ledger: dict) -> bool:
    """Record the receipt beside cswap's other state. True when it landed.

    NEVER RAISES, but the answer is now load-bearing rather than advisory. It
    used to be best-effort on the reasoning that a lost receipt "degrades to
    the pre-existing behaviour — `--clear` still finds the wiring through the
    config keys an older pin left". That is false where it matters: the caller
    POPS those keys in the same write, so a failure here leaves the proxy vars
    in `.claude.json` with the receipt in NEITHER location, and nothing can
    remove them.

    So the caller writes this FIRST and abandons the config write when it
    fails. A receipt with no wiring is a no-op; a wiring with no receipt is an
    outage that needs a hand edit.
    """
    tmp = None
    try:
        path = _ledger_path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(ledger, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return True
    except Exception:  # noqa: BLE001 — see the docstring
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass
        return False


def _merged_ca(ca_path: Path, existing: str | None) -> Path:
    """Our CA plus whatever the session already trusted, in one file.

    ``NODE_EXTRA_CA_CERTS`` names a single file, so writing ours over an
    existing value silently drops that trust. When another CA is in play — the
    upstream cache proxy's, a corporate MITM's — hosts IT re-signs stop
    verifying, which is how a pinned session ends up unable to reach the
    updater. Merge instead; fall back to ours alone if the merge cannot be
    written.
    """
    ca_path = Path(ca_path)
    other = (
        existing
        or os.environ.get("NODE_EXTRA_CA_CERTS")
        # A launcher's CA exists only in the environment it execs Claude Code
        # with, which `cswap pin` never sees. Fall back to what a launch
        # recorded (see write_upstream_hint).
        or read_upstream_ca(ca_path.parent)
    )
    bundle = ca_path.parent / "ca-bundle.pem"
    if not other or Path(other) == ca_path:
        return ca_path
    # THE THIRD DOOR. `_publish_ca` refuses an empty `ours` and so does
    # `_trust_file`'s salvage arm; this one gated on mtime and never on
    # content, then concatenated `ca_path.read_bytes()` regardless. An empty
    # ca.pem satisfies every one of those conditions. Returning `ca_path` is
    # the same fallback every other error here takes.
    if Path(other) == bundle and (
        not _read_or_empty(ca_path).strip()
        or _carries(_read_or_empty(bundle), ca_path)
    ):
        # Already the merged file (a launch inside a pinned session inherits it
        # from our own env block). Returning ca_path here would UN-merge it and
        # lose the upstream proxy's CA on every later session.
        #
        # GATED ON CONTENT, not on the path alone. Falling through rebuilds it
        # from the live `ca.pem`, which is what the mtime check below would
        # have done had it been reached.
        #
        # EXCEPT WHEN WE HAVE NO CA AT ALL. An empty `ca.pem` means there is no
        # proxy of ours to verify, so "the bundle does not carry our CA" is
        # vacuously true and is not a reason to throw the bundle away — the
        # alternative wires an EMPTY file and costs the session every upstream
        # root for nothing. That is the case 0.1.21 fixed (0.1.20 wired 0 CAs
        # where 0.1.19 wired 2); a first pass at this guard un-fixed it, caught
        # by that release's own test.
        #
        # AHEAD OF THE EMPTY-CA GUARD, deliberately. 0.1.20 put the guard first
        # and made this case strictly worse than 0.1.19: an empty ca.pem in a
        # nested launch returned ca.pem and wired ZERO CAs, while the good
        # bundle sat on disk untouched. Returning a merge we did not build from
        # the empty file costs nothing and keeps every upstream root.
        return bundle
    try:
        if not ca_path.read_bytes().strip():
            return ca_path
    except OSError:
        return ca_path
    other_path = Path(other)
    # Rebuild only when an input is newer than the output — the inputs are
    # immutable per launch, so the steady state is two stats instead of
    # rewriting the bundle on every launch (the same trade a sibling proxy's
    # ensure makes).
    #
    # AND ON CONTENT, for the same reason the un-merge branch above needed it.
    # mtime answers "did an input change since we built this", which is not
    # "does this still carry our CA". A regenerated CA leaves a bundle that is
    # NEWER than both inputs — the salvage arm writes the same filename in the
    # same launch — so the freshness test passes while the file carries the
    # retired CA.
    try:
        if (
            not bundle.exists()
            or not _carries(_read_or_empty(bundle), ca_path)
            or ca_path.stat().st_mtime_ns > bundle.stat().st_mtime_ns
            or other_path.stat().st_mtime_ns > bundle.stat().st_mtime_ns
        ):
            _write_bundle_atomically(
                bundle,
                _drop_unreadable_blocks(
                    _join_pem(ca_path.read_bytes(), other_path.read_bytes())
                ),
            )
    except OSError:
        return ca_path
    return bundle


def _read_or_empty(path: Path) -> bytes:
    """The file's bytes, or empty when it cannot be read.

    An absent or unreadable bundle is "carries nothing", not an error: the
    caller's next move is to rebuild it either way.
    """
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _carries(body: bytes, ca_path: Path) -> bool:
    """Is the certificate at ``ca_path`` one of the blocks in ``body``?

    A DER comparison, not a subject-name one: `_make_ca` gives every cswap-pin
    CA the identical subject `CN=cswap pin-proxy CA`, so a name check would
    accept a RETIRED CA of our own — the exact case this is written to catch.

    Goes through `_load_cert` at both sites (``want`` and each block), not a
    raw `x509.load_pem_x509_certificate`. A bare load treats
    `CryptographyDeprecationWarning` as a parse failure under any ambient
    warnings-as-errors filter, same as the bug `_load_cert`'s guard exists to
    fix — `_make_ca` never mints a zero-serial CA (it uses
    `x509.random_serial_number()`, which per RFC 5280 is never 0), but
    ``ca_path`` can name a CA a DIFFERENT MITM published into the shared trust
    dir, and that one is not ours to constrain.
    """
    want_cert = _load_cert(_read_or_empty(ca_path))
    if want_cert is None:  # no CA to look for: nothing carries it
        return False
    want = want_cert.public_bytes(serialization.Encoding.DER)
    for label, _head, _end, block in _pem_blocks(body):
        if label != b"CERTIFICATE":
            continue
        cert = _load_cert(block)
        if cert is None:  # a block no loader reads is not a match
            continue
        if cert.public_bytes(serialization.Encoding.DER) == want:
            return True
    return False


_LOAD_CERT_LOCK = threading.Lock()


def _load_cert(block: bytes):
    """Parse a CERTIFICATE block, or None when no loader could read it.

    WARNINGS ARE NOT PARSE FAILURES, and a bare `except Exception` cannot tell
    them apart: `CryptographyDeprecationWarning` subclasses `UserWarning` ->
    `Warning` -> `Exception`, so any ambient filter that promotes warnings to
    errors turns a LOADABLE certificate into a dropped one. Measured on this
    box's real 125-block ambient store:

        default filter   125 source -> 125 kept
        python -W error  125 source -> 119 kept

    The six are zero-serial roots (Starfield Services Root G2 among them, the
    anchor for Amazon-fronted endpoints), and openssl and python `ssl` both
    accept every one. Counts on the other two machines: 8 and 11.

    Nothing promotes the warning today. The reason this is a guard rather than
    a note is that ambient `-W error` (or an equivalent `filterwarnings`
    entry the caller's process installs) is a real, measured case on this
    box, and the floor is `cryptography>=42.0` with no ceiling — a future
    minor version can add more categories the SAME way. What this guard does
    NOT cover: the warning's own text is a scheduled promise — "Loading this
    certificate will cause an exception in a future release" — and
    `simplefilter("ignore")` suppresses a *warning*, not an *exception*.
    Measured: once cryptography makes good on that promise and raises
    directly, this guard drops the cert exactly as the unguarded `except`
    does today, because there is no warning left for it to ignore. The
    floor stops that upgrade from happening silently underfoot (see
    `pyproject.toml`), but this guard will not survive it.

    LOCKED, because `warnings.catch_warnings()` snapshots and restores
    process-global state (`warnings.filters`, `showwarning`,
    `_showwarnmsg_impl`) and this function is reachable from the daemon's
    `watch_refcount` thread concurrently with per-connection `_serve_client`
    threads. Measured (forced, deterministic interleave, not GIL timing
    luck): thread B enters, waits for thread A to install its own
    `simplefilter("ignore")`, then exits — restoring B's PRE-ignore snapshot
    — before A's load runs, so A's own "ignore" is gone when A's warning
    fires and A's certificate is dropped. `except Warning:` does not fix
    this or the "no test can detect the guard's removal" gap either: it
    would still race, and when a warning fires as an error the load
    ABORTS — there is no certificate object for a handler to hand back.
    Locking the whole guarded section removes the interleave rather than
    trying to detect it after the fact.
    """
    with _LOAD_CERT_LOCK, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return x509.load_pem_x509_certificate(block)
        except Exception:  # noqa: BLE001 — no loader can read it: not a block
            return None


def _parseable_blocks(body: bytes) -> list[bytes]:
    """Every block a loader can read, RESUMING PAST DAMAGE rather than stopping.

    `_pem_blocks` ends its scan at the first damaged marker — every damage arm
    is `yield ...; return` — so iterating it once yields only the prefix. That
    is correct for a PREDICATE (a torn file is refused whole) and wrong for a
    REPAIR, which has to look at what is behind the tear.

    Extracted from `_salvage_bundle`, which had this loop and was the only
    caller that resumed. `_drop_unreadable_blocks` iterated `_pem_blocks`
    directly and silently kept only the prefix. Measured on
    `/etc/ssl/certs/ca-certificates.crt`, 125 blocks:

        ambient store        before   after
        CONTROL untouched      125     125
        tear at idx 0            0     124   (`_salvage_bundle` reaches 125
                                              only because it re-appends
                                              `ours`; this filter has no
                                              such append and cannot)
        tear at idx 5            5     124
        tear at idx 62          62     124

    Five roots instead of 125, in a file that LOADS CLEANLY — so nothing
    downstream flags it: not torn, so the predicate says usable and the node
    oracle says True, our CA being at index 0 ahead of everything lost.
    """
    kept: list[bytes] = []
    offset = 0
    while offset < len(body):
        stopped = False
        for label, head, _end, block in _pem_blocks(body[offset:]):
            if label is None:
                # RESUME AT THE NEXT MARKER, not one byte past this one.
                #
                # RESUME AT THE DAMAGED BLOCK'S OWN BEGIN, not past it. For a
                # WELD that BEGIN sits at `head` itself, and restarting there
                # makes it a clean line start — which is the whole repair.
                if block == b"weld" and head:
                    offset += head        # its BEGIN is here: recoverable
                else:
                    nxt = body.find(b"-----BEGIN ", offset + head + 1)
                    if nxt == -1:
                        stopped = False
                        break
                    offset = nxt          # this marker is damaged: move on
                stopped = True
                break
            if label == b"CERTIFICATE":
                if _load_cert(block) is None:
                    continue
            else:
                body_only = block.split(b"-----", 2)[-1].rsplit(b"-----END", 1)[0]
                if not _armor_decodes(body_only):
                    continue
            kept.append(block)
        if not stopped:
            break
    return kept


def _drop_unreadable_blocks(body: bytes) -> bytes:
    """Every block that parses, in order, and nothing that does not.

    THE ONLY FILTER APPLIED AT EMISSION, and it is not the "drop what we do not
    recognise" that `_join_pem` argues against. It drops what NO LOADER CAN
    READ, which is a different set: an unrecognised label is kept (the block
    parses, we simply have no opinion on it), a torn one is not.

    Why emission and not just refusal. Measured by a peer session against the
    REAL client binary (Bun/BoringSSL, not node), with a CA supplied through a
    mechanism we never touch:

        SSL_CERT_DIR=certdir, NODE_EXTRA_CA_CERTS unset      CONNECTS
        SSL_CERT_DIR=certdir, NODE_EXTRA_CA_CERTS=DAMAGED    FAILS

    A fatal block in OUR file takes down a CA we did not supply and cannot see.
    So a torn merge does not merely cost the session the corporate roots it was
    carrying — it poisons trust the user configured elsewhere. `_join_pem`'s
    verbatim pass-through was written when the cost of a bad block was thought
    to be that block; it is the whole store.

    `_salvage_bundle` already had this property by construction: it reassembles
    from parsed blocks via `_parseable_blocks`, so it cannot emit damage.
    Measured, its two sibling emission sites did not:

        CONTROL _merged_ca healthy         blocks=2 DAMAGED=False
        _merged_ca + torn ambient          blocks=1 DAMAGED=True
        _trust_file tail + torn existing   blocks=1 DAMAGED=True

    `blocks=1` there is a TWO-block fixture losing its bad half, not a repair
    rate. On a real store the same code kept only the PREFIX before the tear —
    5 of 125 for damage at index 5 — until both sites were routed through
    `_parseable_blocks`, which resumes. See that function; the count is the
    thing this table does not report and the reason the truncation shipped.

    Both concatenate `read_bytes()` with no inspection of the other file, and
    the other file is the ambient store — uncontrolled by us.
    """
    # NO `else body` FALLBACK. 0.1.22 ended this `_join_pem(*kept) if kept else
    # body`, which returned the input verbatim whenever nothing parsed — the
    # exact file this function exists to never emit. `b""` is the honest answer
    # when every block is unreadable: both callers write this to a bundle whose
    # only purpose is to be loaded, and an empty file loads as zero extras
    # instead of discarding every trust source the user configured.
    #
    # AND ONLY WHEN THERE IS DAMAGE TO REMOVE. A file with no PEM markers at
    # all is not a torn bundle — it is something we do not understand, and
    # `_join_pem`'s rule applies: pass it through rather than silently narrow
    # what the caller asked to merge. Filtering unconditionally deleted the
    # whole file for any marker-free input, which is a different failure from
    # the one this exists to prevent. Separating "torn" from "shaped unusually"
    # needs a distinction `_pem_blocks` does not currently make. Both cases
    # still lose every CA in the file, so the gap is a failure to REPAIR, not a
    # new failure introduced here.
    kept = _parseable_blocks(body)
    return _join_pem(*kept) if kept else body


def _join_pem(*parts: bytes) -> bytes:
    """Concatenate PEM files so no block's terminator welds onto the next.

    A byte concatenation of two PEM files whose first does not end in a newline
    produces::

        -----END CERTIFICATE----------BEGIN CERTIFICATE-----

    openssl rejects that block and node then loads ZERO CAs — the session
    silently loses all trust. Same outcome as a torn write, and the atomic
    publish does NOT help: the fused file is written completely and correctly,
    it is just invalid.

    Measured: all three inputs on this fleet happen to end in a newline today
    (our ca.pem, the shared ca-trust.pem, the system store), which is why this
    has never fired. That is a property of the inputs, not of this code, and
    one of those inputs is the ambient CA store — uncontrolled by us, and
    deliberately passed through verbatim rather than filtered (dropping blocks
    we do not recognise would silently narrow the bundle, which no reader can
    detect).

    Raised by a peer implementation, whose read-side guard was accepting the fused
    shape until e28abd0; their END matcher used ``indexOf``, so trailing
    content on the marker line passed.

    Adds a newline only where one is missing, so a file that already ends
    cleanly is byte-identical to a plain concatenation — the bundle is
    compared against the ambient store by certificate count elsewhere, and
    padding would be a gratuitous difference.
    """
    out = bytearray()
    for part in parts:
        if not part:
            continue
        out += part
        if not part.endswith(b"\n"):
            out += b"\n"
    return bytes(out)


def _write_bundle_atomically(bundle: Path, body: bytes) -> None:
    """Publish a CA bundle by temp-then-rename. Never write it in place.

    A bundle is read by whoever launches next, so a writer that dies mid-write
    leaves a TORN file that the next session names in ``NODE_EXTRA_CA_CERTS``.
    Node aborts the entire extras load on any block it cannot decode — every
    component CA and every corporate root at once — and says so only in a
    stderr warning, so the session fails with "unable to verify the first
    certificate" and nothing points at the bundle.

    A BEGIN/END balance check does not cover this. Truncate just after an END
    marker and the file is BALANCED with a corrupt base64 payload inside; that
    shape passes the count and still costs the session all its trust.
    (Measured by a peer implementation against their read-side guard, which now
    rejects it — but a reader's guard is a backstop, and the cause is here.)

    ``os.replace`` is atomic on POSIX and Windows, so a reader sees either the
    old bundle or the new one, never half of one.
    """
    tmp = bundle.with_suffix(f".{os.getpid()}.tmp")
    try:
        tmp.write_bytes(body)
        os.replace(tmp, bundle)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


CA_TRUST_DIR = "ca-trust.d"
CA_TRUST_FILE = "ca-trust.pem"


# WHAT COUNTS AS THE START OF A PEM BLOCK. One pattern, because the predicate
# and the salvage scanner are meant to be the same scan and drifted apart once
# already. Three properties, each of which a naive version gets wrong:  1. A
# WELDED marker is still a block. This read `^-----BEGIN ...` and a publisher
# that wrote no trailing newline produces `-----END CERTIFICATE----------BEGIN
# CERTIFICATE-----`, where the second marker does not start a line. Both
# scanners were blind to it, so the predicate found nothing wrong and returned
# True while node — which does not require the anchor — could not decode the
# fused line and truncated there. With node ABSENT (the normal case here, cswap
# is Python) and OUR CA as the welded one, node loaded ZERO — the session could
# not verify the proxy it was routed through. `_join_pem` already guards this
# shape in what WE write; the readers were never taught to see it in what
# someone else wrote.  2. A marker QUOTED IN PROSE is not a block. So the left
# side is constrained to a line start or a welded `-----`, not to nothing.  3.
# CRLF still reads. `\r?` stays: a `$`-only anchor made every CRLF bundle
# invisible, which reads as "carries no CA" and drops the whole shared file —
# the false REJECT that costs every sibling component its trust. Verified
# against all four shapes (plain LF, CRLF, welded, prose) before it replaced
# the anchored version.
_BEGIN_MARKER = rb"(?:^|-----)-----BEGIN ([A-Z0-9 ]+)-----([ \t]*)(\r?\n|\Z|.)"

def _find_end(body: bytes, label: bytes, start: int, limit: int) -> int:
    """Where ``-----END <label>-----`` TERMINATES ITS LINE, or -1.

    A bare `find` was not enough, and the gap is the same class as the welded
    BEGIN: openssl requires the terminator to end its line, so trailing text
    (`-----END CERTIFICATE-----garbage`) is not a terminator to it — it rejects
    the block and node loads ZERO extras with `PEM routines::bad end line`.
    The scanner walked straight past and called the file usable. Measured with
    node ABSENT, which is the arm with no oracle to veto it: predicate True,
    session trusts nothing, including its own CA.

    Trailing whitespace IS allowed, and `\r` with it: a builder concatenating
    files leaves CRLF, openssl loads those happily, and refusing them is the
    false reject that costs every sibling component its trust.

    A sibling implementation reached this from the other side — their END
    matcher used `indexOf`, so trailing content passed, fixed in e28abd0.
    """
    needle = b"-----END " + label + b"-----"
    at = body.find(needle, start, limit)
    while at != -1:
        rest = body[at + len(needle) : limit]
        stripped = rest.lstrip(b" \t\r")
        if not stripped or stripped.startswith(b"\n"):
            return at
        at = body.find(needle, at + 1, limit)
    return -1


_ORACLE_SENTINEL = b"\x02"
_ORACLE_TIMEOUT_S = 10.0


def _bundle_loads_in_node(bundle: Path, ca_path: Path) -> bool | None:
    """Ask node whether it will VERIFY OUR LEAF when handed this bundle.

    THREE OUTCOMES, never two:

        True   node completed a TLS handshake against a leaf we signed
        False  node refused it
        None   THE ORACLE WAS NOT CONSULTED — the caller must decide alone

    STOP PREDICTING, ASK. `_bundle_is_usable` predicts what node's loader will
    accept from file syntax, and a predicate over syntax is a losing race.
    Measured against node's real loader, ours called a bundle usable that node
    reads as ZERO extra CAs — and we hand that file to a session as
    NODE_EXTRA_CA_CERTS, so it trusts nothing: not our CA, not a sibling
    proxy's, not the corporate roots.

    ASK THE CONTRACT, NOT A PROXY FOR IT. The first version of this asked
    `tls.getCACertificates("extra")` — a census of what was loaded. That API
    landed in node v22.15, so on anything older the probe wrote nothing, the
    sentinel was absent, and EVERY verdict was None. The caller reads None as
    "could not ask" and falls back, so on those runtimes the oracle was not
    conservative, it was ABSENT — and it looked like a working guard on a dev
    box running a new node. A sibling implementation shipped that exact bug and
    measured it (v20.19 undefined, v22.14 undefined, v22.15 function).

    "Will you verify our leaf" is answerable on every node back to v12, and it
    is the question that actually matters: a session's failure mode is a failed
    handshake, not a wrong census. It also makes the verdict immune to bundle
    SIZE — a census echoed every certificate back on stdout, so a large
    corporate bundle could overflow the pipe and become None.

    None is the point of this function, not an afterthought: an oracle that
    could not ask must not answer. Returning False when node is merely absent
    would drop a healthy machine to its own CA and take every corporate root
    with it — the exact damage this exists to prevent, caused by the fix.

    THE LEAF LIVES BESIDE OUR CA, NOT BESIDE THE BUNDLE. The first version
    looked for `leaf.pem` next to the file under test, which is right for the
    tests (they write the bundle into the certdir) and wrong for every real
    launch: the shared `ca-trust.pem` lives in the Claude config home while our
    leaf lives in the pin-proxy certdir. So in production the leaf was never
    found, every verdict was None, and the predicate the oracle exists to
    correct went on deciding alone — an oracle that was green in tests and
    absent in the field. Takes the CA PATH now, so the question is set up from
    where the answer actually lives.
    """
    import shutil
    import subprocess
    import tempfile

    node = shutil.which("node")
    if not node:
        return None
    # The leaf must be signed by the CA we are asking about, or the handshake
    # answers a different question.
    try:
        ca_dir = Path(ca_path).parent
        leaf_pem, leaf_key = ca_dir / "leaf.pem", ca_dir / "leaf.key"
        if not (leaf_pem.exists() and leaf_key.exists()):
            return None
        # ...and that leaf must actually be OURS, else a passing handshake
        # proves nothing about the CA in question. A SUBJECT-NAME comparison
        # cannot tell: `_make_ca` gives every cswap-pin CA the identical
        # subject `CN=cswap pin-proxy CA`, so a leaf from any OTHER cswap-pin
        # certdir — a different key entirely — would pass a name check. Verify
        # the SIGNATURE instead, same shape as `_certs_consistent`.
        leaf = x509.load_pem_x509_certificate(leaf_pem.read_bytes())
        ca_cert = x509.load_pem_x509_certificate(Path(ca_path).read_bytes())
        ca_cert.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )
    except Exception:  # noqa: BLE001 — cannot set the question up: not an answer
        return None

    probe = (
        "const tls=require('tls'),fs=require('fs');"
        "const s=tls.createServer("
        "{key:fs.readFileSync(process.argv[2]),cert:fs.readFileSync(process.argv[3])},"
        "c=>c.end());"
        "s.listen(0,'127.0.0.1',()=>{"
        "const c=tls.connect({host:'127.0.0.1',port:s.address().port,"
        "servername:'api.anthropic.com'},()=>{"
        "process.stdout.write('\\x02OK');c.destroy();s.close();});"
        "c.on('error',()=>{process.stdout.write('\\x02NO');s.close();});});"
    )
    # The child must not inherit anything that answers a DIFFERENT question.
    # `*_proxy` was already stripped: the child would otherwise route its own
    # loopback connect through us while we are deciding what to trust. (That
    # filter also catches NODE_USE_ENV_PROXY, which node >= 24 honours.)  But
    # two more change what a successful handshake MEANS, and neither ends in
    # `_proxy`. NODE_TLS_REJECT_UNAUTHORIZED=0 makes the probe answer True for
    # a bundle carrying NO CA at all — that is not "this bundle verifies our
    # leaf", it is "this node was told not to check". NODE_OPTIONS is the same
    # class: it can carry --use-openssl-ca
    # and friends, so the child would consult a different trust store than the
    # one under test. Raised by a peer implementation, whose probe had the
    # mirror-image gap: they cleared these two and not the proxy family.
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    for leak in ("NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS"):
        env.pop(leak, None)
    env["NODE_EXTRA_CA_CERTS"] = str(bundle)
    try:
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "probe.js"
            script.write_text(probe, encoding="utf-8")
            r = subprocess.run(
                [node, str(script), str(leaf_key), str(leaf_pem)],
                capture_output=True,
                env=env,
                timeout=_ORACLE_TIMEOUT_S,
            )
    except Exception:  # noqa: BLE001 — cannot ask: not an answer
        return None
    # EXIT STATUS CANNOT SEPARATE "it answered no" FROM "it never ran". The
    # sentinel written before the verdict is the only proof the probe reached
    # its own conclusion.
    if not r.stdout.startswith(_ORACLE_SENTINEL):
        return None
    return r.stdout[len(_ORACLE_SENTINEL):].startswith(b"OK")


def _armor_decodes(body: bytes) -> bool:
    """Whether openssl will read this non-certificate block's armor.

    ONE FUNCTION, because the predicate and salvage must agree and had
    already drifted: 0.1.16 fixed the slice in both and the emptiness in
    neither, so a block openssl refuses was kept by both readers.

    `base64.b64decode(..., validate=True)` is necessary and NOT sufficient —
    it accepts three shapes openssl rejects, each measured against node with
    a corp root beside the block (correct answer 2, node loaded 1):

        empty / whitespace-only body   no openssl warning at all
        `QUFB=`  (5 chars)             bad base64 decode
        a blank line before END        bad end line

    The first is the dangerous one: the session loses every corporate root
    with nothing on stderr to say why. openssl needs at least one whole
    4-character quantum and will not tolerate a blank line before the
    terminator, which is exactly what the three conditions encode.

    `validate=True` stays: a body carrying stray dashes (what a concatenating
    builder produces on a torn seam) is accepted without it.
    """
    import base64

    data = b"".join(body.split())
    if not data or len(data) % 4:
        return False
    # THE BLANK-LAST-LINE RULE LIVES IN `_pem_blocks` NOW, not here. It was
    # added in this arm first, which is exactly why it missed: a CERTIFICATE
    # never reaches this function, and the real bundle is 132 CERTIFICATE
    # blocks and nothing else. Keeping a copy here would be dead code —
    # `_pem_blocks` refuses the shape before yielding, verified — and a dead
    # guard is worse than none: it reads as protection.
    try:
        base64.b64decode(data, validate=True)
    except Exception:  # noqa: BLE001
        return False
    return True


def _pem_blocks(body: bytes):
    """Every block whose BEGIN **and** END each own their line.

    ONE SCANNER FOR BOTH READERS. A PEM marker has two edges, and this file
    fixed them one at a time: welds on the left of BEGIN, then a terminator
    on the right of END. The other two were never guarded, and both landed in
    the dangerous direction — measured, node deciding:

        END welded to the base64 line   predicate True, node loaded 1 of 2
                                        (OUR CA gone: cannot verify our proxy)
        BEGIN carrying trailing text    predicate True, node loaded 2 of 3
                                        (fires with node PRESENT too — our CA
                                         is after the damage, so the handshake
                                         still succeeds and cannot veto)

    Four edges, two readers, and they had already drifted apart once. Yielding
    from one place is what stops the next edge from being fixed in only one of
    them.

    HANDS OUT BYTES VERBATIM, never a repaired copy. The predicate used to
    rebuild the terminator (`body[head:end] + b"-----END ...-----\n"`), which
    REPAIRS a fused block for the parser — cryptography read it happily and
    the predicate then answered True about a file that is still fused on disk.
    A reader that reconstructs what it is judging cannot judge it.

    Yields ``(label, head, body_end, block)``: `head` is the BEGIN, `body_end`
    is where the terminator starts, `block` is the whole thing including its
    END line. A malformed block is simply not yielded; the callers decide what
    that means, which differs between them (refuse vs skip).
    """
    import re as _re

    begin = _re.compile(_BEGIN_MARKER, _re.M)
    pos = 0
    while True:
        m = begin.search(body, pos)
        if not m:
            return
        label = m.group(1)
        nxt = begin.search(body, m.end())
        limit = body.index(b"-----BEGIN ", nxt.start()) if nxt else len(body)
        head = body.index(b"-----BEGIN ", m.start())
        # A WELDED BEGIN means the file is already fused: openssl cannot read a
        # marker sharing a line with the previous END, whatever the blocks
        # around it look like.
        if head != m.start():
            # A WELD: this block's own BEGIN is at `head`, so a caller that
            # restarts THERE sees a clean line start and recovers it.
            yield None, head, -1, b"weld"
            return
        # AND THE BEGIN MUST END ITS OWN LINE. The marker now MATCHES a BEGIN
        # carrying trailing text instead of skipping past it — skipping made
        # the block INVISIBLE, so the predicate never saw it and approved a
        # file node truncates at. Group 3 is the byte that follows: a newline
        # or end-of-input is a real marker, anything else is damage.
        if m.group(3) not in (b"\n", b"\r\n", b""):
            # The marker itself is damaged; restarting here would re-reject it
            # forever. Only a LATER block can be recovered.
            yield None, head, -1, b"marker"
            return
        end = _find_end(body, label, m.end(), limit)
        if end == -1:
            yield None, head, -1, b""
            return
        # AND THE END MUST START ITS OWN LINE. `_find_end` bounds the RIGHT
        # side of the terminator; this is the left. A terminator welded onto
        # the last base64 character is what openssl refuses while a rebuilt
        # copy parses fine.
        if end > 0 and body[end - 1 : end] != b"\n":
            yield None, head, -1, b""
            return
        # AND THE LINE BEFORE THE TERMINATOR MUST CARRY SOMETHING. openssl
        # refuses a blank-or-whitespace-only last line whatever the LABEL is,
        # and this is the only place both labels and both readers pass through.
        # It lived in `_armor_decodes` — the NON-certificate arm — so a
        # CERTIFICATE went to `x509.load_pem_x509_certificate` instead, and
        # cryptography parses the shape happily. A whitespace line before the
        # first END gave predicate True and node extras=0 of 133 — the whole
        # extras load dropped, so the session could not verify its own proxy.
        line = body[max(0, body.rfind(b"\n", 0, end - 1) + 1) : end - 1]
        if line.strip() == b"":
            yield None, head, -1, b""
            return
        term = b"-----END " + label + b"-----"
        yield label, head, end, body[head : end + len(term)] + b"\n"
        pos = end


def _salvage_bundle(body: bytes, ours: bytes) -> bytes:
    """Every block of ``body`` node can actually load, plus our own CA.

    REFUSING THE BUNDLE MUST NOT COST THE CORPORATE ROOTS. The old fallback
    for an unusable shared bundle was "our CA alone", which on a corporate
    network is a session that can verify our proxy and nothing else — every
    https destination fails. That made the oracle's verdict a cliff: a single
    torn block, or merely having no node on PATH, and the machine lost 131
    working roots to protect against one broken one.

    Node's failure mode is what makes salvage the right answer rather than a
    hedge — and it is TRUNCATE, not abort. Measured on this host (node
    v24.11.1), asking two independent questions about the same ours+TORN+corp
    bundle — how many extras did the loader keep, and will it complete a
    handshake against our leaf:

        bundle                    node v24.11.1 extras   handshake vs our leaf
        ours + corp (healthy)     2                      OK
        ours + TORN + corp        1   <- corp LOST       OK      <-- the hole

    node keeps every block BEFORE the first undecodable one and drops
    everything from there on, including blocks that are themselves perfectly
    valid. That is exactly why a handshake-only verdict ("will you verify our
    leaf") is not sufficient proof the bundle survived intact: with our CA
    ahead of the tear, the handshake still succeeds while roots after the tear
    vanished silently. Dropping only the bad block is not a guess about
    intent, it is the minimum edit that turns a file node truncates into the
    same file node loads whole.

    Deliberately drops nothing else. A block that decodes is kept verbatim,
    including CRLs and key blocks a real corporate bundle carries — narrowing
    what we do not understand is how a reader silently shrinks a bundle, which
    `_bundle_is_usable`'s docstring already refuses to do.
    """
    import base64
    import re as _re

    kept: list[bytes] = []
    # THE SCANNER STOPS AT DAMAGE; SALVAGE MUST NOT. Its whole job is to keep
    # every block that still decodes, and a healthy root sitting AFTER the
    # damage is exactly what the session loses otherwise — the narrowing this
    # file refuses everywhere else. So walk the body in segments, restarting
    # one byte past each broken marker, rather than recursing.
    kept = _parseable_blocks(body)
    # Ours goes in unconditionally — a bundle that dropped it is exactly the
    # case where the session could not verify the proxy it is routed through.
    if not _bundle_is_usable(b"".join(kept), ours):
        kept.append(ours.strip() + b"\n")
    return _join_pem(*kept)


def _bundle_is_usable(body: bytes, ours: bytes) -> bool:
    """Would Node actually LOAD this bundle, and does it carry our CA?

    Counting ``BEGIN``/``END`` markers cannot answer the first question, and
    the gap is not academic: measured on this host against a real TLS
    handshake through ``NODE_EXTRA_CA_CERTS``, a bundle with a torn
    certificate BEFORE ours passes the marker count and node refuses the whole
    extras load — so the session cannot verify the very proxy it is routed
    through and every request dies. That is the dangerous direction, and the
    marker count waved it through.

    Node does NOT abort the whole extras load on one undecodable block — it
    TRUNCATES at the first one and keeps everything before it. Measured on
    this host (node v24.11.1), asking two independent questions about the
    same ours+TORN+corp bundle — how many extras did the loader keep, and
    will it complete a handshake against our leaf:

        bundle                    node v24.11.1 extras   handshake vs our leaf
        ours + corp (healthy)     2                      OK
        ours + TORN + corp        1   <- corp LOST       OK      <-- the hole

    That is why a handshake-only verdict is not sufficient: with our CA ahead
    of the tear, node still verifies our leaf (True) while every block after
    the tear, including corporate roots, is gone. So every block still has to
    be proven decodable here — not just ours, and not just the ones labelled
    CERTIFICATE — because a bundle that is usable in the sense this function
    means (nothing silently dropped anywhere in it) requires the WHOLE file
    to be clean, not merely the prefix node's loader happened to keep. What
    "decodable" means differs by label: a CERTIFICATE must parse as X.509
    (valid base64 is not enough, a well-formed body that is not a certificate
    still truncates the load from there on), while a CRL or a PUBLIC KEY
    needs only intact base64 armor. Demanding X.509 of those would reject the
    CRLs and key blocks a real corporate bundle legitimately carries — a
    false reject costs every sibling CA for the whole session, which is the
    failure this shared bundle exists to prevent.

    Identity is by DER, not by substring: a re-encoded or CRLF-normalized copy
    of our CA is still our CA, and a substring test calls it a stranger.

    Where it cannot tell, it REFUSES. Refusing costs one session's sibling
    CAs; accepting costs the session entirely. See
    a peer implementation, which measured this same guard
    wrong in both directions in the sibling implementation.
    """
    import base64
    import re as _re

    if not ours:
        return False  # an empty CA makes any containment test vacuous
    try:
        want = x509.load_pem_x509_certificate(ours).public_bytes(
            serialization.Encoding.DER
        )
    except Exception:  # noqa: BLE001 — our own CA is unreadable; trust nothing
        return False

    # `\r?$` because a bundle builder that concatenates files can leave CRLF
    # endings, and openssl loads those happily. A `$`-only anchor made every
    # CRLF bundle invisible to this scan — which reads as "carries no CA" and
    # drops the whole shared file, the false reject that costs every sibling
    # component its trust.
    carries_us = False
    seen_any = False
    for label, _head, _end, block in _pem_blocks(body):
        if label is None:
            return False  # malformed on either edge — node truncates there
        seen_any = True
        if label == b"CERTIFICATE":
            cert = _load_cert(block)
            if cert is None:
                return False
            der = cert.public_bytes(serialization.Encoding.DER)
            if der == want:
                carries_us = True
        else:
            # Not a certificate: node skips it, but only if the armor decodes.
            #
            # SPLIT ON THE DASHES, not on `-----\n`. `_find_end` and
            # `_BEGIN_MARKER` deliberately tolerate CRLF and trailing
            # whitespace on a marker line — refusing those is the false reject
            # that costs every sibling component its trust. A separator that
            # demands a bare LF therefore does not exist in those blocks:
            # `[-1]` returned the WHOLE block, `rsplit(b"-----END")` left
            # `b""`, and empty base64 decodes fine, so the check was a no-op. A
            # CERTIFICATE is saved by its x509 parse; a CRL or key block has
            # only this, which is why a certificate-only test hides it.
            body_only = block.split(b"-----", 2)[-1].rsplit(b"-----END", 1)[0]
            if not _armor_decodes(body_only):
                return False
    del seen_any
    return carries_us


def _trust_file(ca_path: Path, existing: str | None) -> Path:
    """The single file to name in ``NODE_EXTRA_CA_CERTS``.

    Prefers the shared merged bundle when a launcher has built one: it already
    contains every component's CA plus the ambient roots, so a proxy added
    later is trusted without cswap knowing it exists. Falls back to merging
    ours with whatever the caller already trusted, and to ours alone when there
    is nothing else — which is the no-launcher, no-other-MITM case and behaves
    exactly as before.
    """
    try:
        get_claude_config_home = require("paths").get_claude_config_home

        shared = get_claude_config_home() / CA_TRUST_FILE
        if shared.is_file() and shared.stat().st_size > 0:
            ours = Path(ca_path).read_bytes().strip()
            # SYMMETRIC WITH `_publish_ca`, and this is the site that needed it
            # more. Both read the same `ca_path` and treat the bytes as OUR CA;
            # `_publish_ca` refused an empty one and this arm did not. The
            # failures are not the same size: `_publish_ca` skipping a write
            # costs one file in `ca-trust.d` that the next launch rewrites,
            # while this arm decides what the SESSION gets. With an empty
            # `ours`, `_salvage_bundle` appends nothing — the append is gated
            # on `_bundle_is_usable(kept, ours)`, and that answers False here
            # by its own vacuity guard rather than because containment failed.
            # RETURN, NOT RAISE. 0.1.20 raised here and said in this comment
            # that it fell through to "our own path". It did not: the raise
            # landed in the blanket `except Exception: pass` below, and control
            # continued into the tail merge, which concatenates `ca_path`
            # unconditionally and produced the SAME bundle the guard was
            # written to prevent. Say where it goes.
            if not ours:
                return Path(ca_path)
            body = shared.read_bytes()
            # Carrying our CA is necessary but not sufficient. An unbalanced
            # BEGIN/END anywhere in the file makes Node reject the WHOLE extras
            # bundle — every component CA and every corporate root at once —
            # and it says so only in a stderr warning, so the session dies on
            # "unable to verify the first certificate" with no visible cause.
            # Checking that we are in there cannot see that; count the markers.
            # A bundle that is BALANCED and CONTAINS us but has silently lost
            # other roots is deliberately NOT guarded here, and not because we
            # lack the information: a reader is the wrong PLACE to decide it.
            # Even holding the previous bundle, a shrink is legitimate whenever
            # a root was retired or a component uninstalled, and only the
            # builder knows which happened — so a reader acting on a shrink
            # would reject a correct bundle in exactly the cases the shrink was
            # intended. The builder keeps the last good bundle for this reason;
            # that is where the decision belongs. This comment previously read
            # "2 certs on one and 132 on another". The 132 was right for this
            # host; the 2 was the COMPONENT COUNT (ca-trust.d holds one PEM per
            # component, one certificate each), not a bundle size — two
            # different quantities reported as one measurement. The conclusion
            # survives and is in fact stronger, but it was not supported by the
            # numbers cited. NOTE what this rules out and what it does not. It
            # rules out an ABSOLUTE floor in a READER. It does not rule out a
            # builder comparing its output against the inputs IT just read,
            # which is a per-build quantity rather than a constant and does not
            # need to hold across hosts. The two cases below are also a
            # different severity class: both leave the session unable to verify
            # its OWN proxy, so every request dies. Narrowing keeps our chain
            # intact and costs someone else's. Do not add a cert-count floor
            # here.
            #
            # ASK THE LOADER FIRST, PREDICT ONLY IF IT CANNOT BE ASKED.
            # `_bundle_is_usable` predicts from file SYNTAX what node's loader
            # will accept, and it was wrong in the dangerous direction: it
            # called a bundle usable that node reads as ZERO extra CAs. Believe
            # that and the session trusts nothing — not our CA, not a sibling
            # proxy's, not the corporate roots — so every request fails to
            # verify the proxy it is routed through. None from the oracle is
            # NOT "unusable": it means the probe never ran (no node on PATH,
            # which is normal here — cswap is Python). Answering "unusable"
            # there would drop a
            # healthy machine to its own CA and take every corporate root with
            # it, which is the exact damage this is meant to prevent. So fall
            # back to the predicate, which is the only judge left, and say
            # which arm decided.
            verdict = _bundle_loads_in_node(shared, Path(ca_path))
            if verdict is None:
                verdict = _bundle_is_usable(body, ours)
                _log_lifecycle(
                    f"ca-bundle: node not consulted, predicate says "
                    f"{'usable' if verdict else 'unusable'}"
                )
            elif verdict:
                # THE ORACLE'S True IS A VETO'S ABSENCE, NOT AN APPROVAL. It
                # only asked "will you verify our leaf", and node TRUNCATES the
                # extras load at the first bad block rather than aborting it —
                # so True survives even when every block after a tear,
                # including corporate roots placed after ours, was silently
                # dropped. AND it with the predicate, which inspects the WHOLE
                # file: the oracle keeps its power to REFUSE a file the
                # predicate wrongly approves (0.1.9's fix, must not regress),
                # but loses the power to APPROVE a file the predicate says is
                # torn.
                verdict = _bundle_is_usable(body, ours)
            if verdict:
                return shared
            # REFUSED — but refusing the FILE must not mean refusing its
            # CONTENTS. Falling through to "our CA alone" costs the session
            # every corporate root to avoid one bad block, so keep every block
            # that does decode and drop only the ones that do not. That makes
            # both the False and the None arms cost at most the broken block.
            salvaged = Path(ca_path).parent / "ca-bundle.pem"
            salvage = _salvage_bundle(body, ours)
            _write_bundle_atomically(salvaged, salvage)
            _log_lifecycle(
                f"ca-bundle: {shared} refused, salvaged "
                f"{salvage.count(b'-----BEGIN')} of {body.count(b'-----BEGIN')} "
                f"blocks to {salvaged}"
            )
            return salvaged
    except Exception:
        # A SALVAGE-WRITE FAILURE (disk full, a read-only cert dir) LANDS HERE
        # TOO, same as a missing/corrupt shared bundle — and collapses into "no
        # shared bundle" rather than into an error the caller sees. The session
        # never loses the ability to verify ITS OWN proxy. What it loses is the
        # corporate roots the shared or merged bundle would have carried, which
        # is the same "narrowing" this file already treats as a builder-owned,
        # not a reader-owned, decision everywhere else (see
        # `_bundle_is_usable`'s docstring and
        # `TestNarrowingIsDeliberatelyUnguarded`) — not a new failure mode this
        # `except` introduces.
        pass
    # No shared bundle: merge with what THIS env trusts. Deliberately not
    # _merged_ca, which also consults the ambient process environment and a
    # recorded upstream CA — wire_env is handed the environment it must
    # describe, and reaching past it would wire a session to trust something
    # its caller never mentioned.
    if not existing or Path(existing) == Path(ca_path):
        return Path(ca_path)
    # DOOR FOUR. Same shape as `_merged_ca`: reads `ca_path`, concatenates it
    # unconditionally, returns the merge. 0.1.20 guarded the salvage arm and
    # `_merged_ca` and shipped a commit titled "three doors" — this is the
    # fourth, and it is the one the other guards FALL INTO, because a refusal
    # above lands here rather than at a return.
    #
    # It is also the live path wherever `NODE_EXTRA_CA_CERTS` is already set,
    # which `wire_env` passes straight in as `existing`:
    #
    #   hostname -s            host-a
    #   NODE_EXTRA_CA_CERTS    /etc/ssl/certs/ca-certificates.crt
    #
    # so the `if not existing` return above is never taken there and an empty
    # ca.pem produced a bundle carrying the corporate CA and nothing of ours.
    try:
        if not Path(ca_path).read_bytes().strip():
            return Path(ca_path)
    except OSError:
        return Path(ca_path)
    bundle = Path(ca_path).parent / "ca-bundle.pem"
    try:
        _write_bundle_atomically(
            bundle,
            _drop_unreadable_blocks(
                _join_pem(Path(ca_path).read_bytes(), Path(existing).read_bytes())
            ),
        )
        return bundle
    except OSError:
        return Path(ca_path)


def publish_ca(ca_path: Path, name: str = "cswap-pin") -> Path | None:
    """Publish our CA where any component's launcher can pick it up.

    ``NODE_EXTRA_CA_CERTS`` names ONE file, so every MITM in the chain that
    writes it as an overwrite silently drops the others. Two already do it for
    the same host, and each new one repeats the fight — which is how a pinned
    session ended up verifying everything it SENDS while every Remote Control
    SSE reconnect failed with ``unable to verify the first certificate``
    (measured: 13 attempts, 0 connects, while worker/heartbeat and
    client/presence answered 200 in the same process).

    So publish instead of overwrite: one file per component under
    ``<claude-config>/ca-trust.d/``, named after the component, and nobody
    touches anybody else's. A launcher concatenates the directory; a component
    that only needs to be trusted just drops its file. Adding a proxy stops
    being a negotiation.

    Deliberately knows nothing about which proxies exist: with no launcher and
    no other MITM the directory is simply unread, and behaviour is unchanged.
    Best-effort — trust plumbing must never block a launch.

    Written ATOMICALLY, which the contract needs rather than merely prefers: a
    builder reads this directory while N producers write it on their own
    schedules, and a reader that catches a half-written PEM does not get a
    partial bundle — Node refuses the WHOLE extras file
    (``PEM routines::bad end line``, on stderr, not an error) and then trusts
    no component CA and no corporate root at all. The session dies on
    ``unable to verify the first certificate`` with the cause in a warning
    nobody reads. A truncate-then-write is exactly what produces that state.
    """
    try:
        get_claude_config_home = require("paths").get_claude_config_home

        ours = Path(ca_path).read_bytes().strip()
        if not ours:
            return None
        out = get_claude_config_home() / CA_TRUST_DIR / f"{name}.pem"
        out.parent.mkdir(parents=True, exist_ok=True)
        # Idempotent: rewriting on every launch would churn the mtime the
        # launcher's own rebuild check keys on.
        if out.exists() and out.read_bytes().strip() == ours:
            return out
        # Same directory, so the rename cannot cross a filesystem and stays
        # atomic; the pid keeps two concurrent launches off each other's temp.
        tmp = out.with_name(f"{out.name}.{os.getpid()}.tmp")
        try:
            tmp.write_bytes(ours + b"\n")
            os.replace(tmp, out)
        finally:
            tmp.unlink(missing_ok=True)
        return out
    except Exception:
        return None


def _resolve_pinned_slot(backup_root: Path, email: str) -> str | None:
    """The slot number that currently holds ``email``, or None.

    Identity is stored by email because slots move (`cswap move`), so the
    number comes from the registry rather than being cached with the pin.
    None means a DANGLING pin — the account it names is gone — and every
    caller must treat that as "nothing to serve" rather than as an error.
    """
    try:
        seq = json.loads((backup_root / "sequence.json").read_text(encoding="utf-8"))
        accounts = seq.get("accounts") or {}
        return next(
            (num for num, rec in accounts.items()
             if (rec.get("email") if isinstance(rec, dict) else rec) == email),
            None,
        )
    except Exception:
        return None


#: The splice's own lock budget when the caller names none -- a hand-run
#: `cswap pin`, where waiting is better than skipping the write.
#: A watcher greps this, so it is a symbol here rather than a literal in one
#: f-string. Same rule as DEAF_REPORT_MARK: a rename must break the matcher
#: loudly instead of turning it into a permanent "no verdict yet".
PIN_NOT_NAMED_AT_MINT = (
    "could not name the pin in the live config before minting a bridge")


_SPLICE_LOCK_S = 5.0


_HEAL_DEFER_FILE = ".heal-deferred"


def _clear_heal_defer(certdir: Path) -> None:
    """Forget an outstanding sighting. The record means "a deferral is OPEN".

    Left behind, it is a sentence a later daemon can inherit without earning
    it: pids are reused, and a reused pid that happens to carry the same stale
    fingerprint would be retired on its FIRST sight rather than its second —
    the cut this deferral exists to prevent, caused by its own bookkeeping.
    """
    try:
        (Path(certdir) / _HEAL_DEFER_FILE).unlink(missing_ok=True)
    except OSError:  # nothing to clear is the state we wanted anyway
        pass


def _watchdog_had_its_turn(certdir: Path, pid: int, fingerprint) -> bool:
    """True when this exact stale daemon was already seen once and left alone.

    THE ONLY DAEMON `heal` CAN TERM IS ONE THAT IS ALIVE AND ANSWERING on code
    we no longer ship — which is the code watchdog's own trigger, and the
    watchdog retires it WITHOUT darkening the port. The two mechanisms do one
    job and only one of them costs replies.

    heal wins that race every time, because it runs at the instant of an
    install and the watchdog on a tick. So the fix is not to narrow the branch
    (the population is exactly the case it exists for) but to let the gapless
    path go first. A second sighting of the SAME pid on the SAME stale
    fingerprint, an interval later, has MEASURED that it did not act — a
    daemon from a release predating the watchdog, which nothing else retires.

    TWO INTERVALS: one tick to notice, one to act. Keyed on pid AND
    fingerprint so a successor is a fresh subject rather than an inherited
    sentence. The mtime is the clock; there is no second timestamp to disagree
    with it.
    """
    path = Path(certdir) / _HEAL_DEFER_FILE
    seen = _read_json(path) or {}
    if seen.get("pid") == pid and seen.get("fingerprint") == fingerprint:
        try:
            return (time.time() - path.stat().st_mtime) >= _CODE_WATCH_INTERVAL_S * 2
        except OSError:
            return False
    try:
        path.write_text(json.dumps({"pid": pid, "fingerprint": fingerprint}))
    except OSError:
        # A SIGHTING WE CANNOT RECORD IS ONE WE CANNOT DEFER ON. Returning
        # False here would defer forever on an unwritable certdir and make
        # every stale daemon immortal — the failure this branch exists to
        # prevent, reintroduced by its own guard.
        return True
    return False


def heal(backup_root: Path, identity: dict | None = None,
         lock_timeout: float = _SPLICE_LOCK_S) -> bool:
    """Bring the pin back if it is pinned but not serving. True when it did.

    ``identity`` is the ``oauthAccount`` the live config should name while the
    pin is set. KEYWORD-DEFAULTED so an older host that calls ``heal(root)``
    keeps working unchanged; when it is absent this function's owner-field
    behaviour is exactly what it was. Passing it re-asserts the field on every
    launch, which is the half a single splice at switch time cannot cover.

    ``lock_timeout`` is the caller's budget for the config lock. The host
    budgets its OWN launch lock at half a second and had no way to say so
    across this boundary, so the splice's default made a contended launch wait
    ten times that -- twice, since `ensure_proxy` takes the same lock after.
    Keyword-defaulted for the same reason as ``identity``.

    RECOVERY WITHOUT A SESSION RESTART. Everything else in this module reacts
    to a launch: ``ensure_proxy`` runs when a NEW session starts, so if the
    daemon dies while sessions are up, nothing brings it back — and if the dead
    wiring has blocked every session, no new one can start to trigger it. That
    is a deadlock, and it is exactly what was measured: a human had to
    re-pin by hand.

    So this needs no switcher: the pinned identity comes from settings.json and
    the slot from the account registry, both on disk. The repair itself is
    cheap when healthy — a state read plus one loopback connect, and it returns
    immediately — but this is no longer the whole cost: since 0.1.81 the bridge
    pointer sweep runs first on every call. It always reads the registry and
    every job record (13 and 12 on this machine), and then one glob plus a
    64 KiB tail read PER CANDIDATE — up to two per job, since a resumed job
    offers both of its session ids. Candidates are sessions that ended and have
    not been restamped yet, so the steady state is zero and the worst case is
    bounded by how many sessions the machine runs. The rc hook backgrounds this
    call, so a launch waits on none of it.

    WHO CALLS IT, stated because the previous answer here was wrong and cost 22
    hours. This used to say "callable from anything that already runs
    periodically (the status line does, every few seconds)". A status line is
    ONE MACHINE'S PERSONAL CONFIG, so recovery living there means every user
    without that hook has no recovery at all — the hook was removed on purpose,
    and this docstring was left as the only record of a design that no longer
    existed. It then said the periodic caller is :func:`_watch_own_code` — also
    wrong, in the same field, on the second try: that watcher recycles itself
    through `_spawn_daemon` and never calls this function. **Nothing calls
    `heal` periodically.** Its callers are `cswap pin --ensure` (the rc hook,
    before a hand-launched `claude`) and a hand-run `cswap pin --heal`, both of
    which are per-launch or per-command. Verified by grep in this package and
    in the host, not by reading the sentence above.

    The port is REBOUND, not reallocated: the daemon reclaims the port recorded
    in proxy.json, else port.hint. That is what makes live sessions recover on
    their own — they are already wired to that address, so a daemon returning
    to it is picked up by the next request with no restart and nothing to
    reconnect by hand.

    Serialized by the same spawn lock ``ensure_proxy`` takes, so N status lines
    across N sessions elect ONE spawner instead of racing.
    """
    backup_root = Path(backup_root)
    certdir = backup_root / "pin-proxy"
    try:
        pin = load_pin(backup_root)
    except Exception:
        return False
    if not pin:
        return False  # nothing pinned — not our business
    email = pin[0]
    # THE CONFIG HALF OF THE SAME RULE the block below states for the DAEMON. A
    # release that ADDS an env key kept the old key set in `.claude.json` until
    # a full session launch: `--ensure` heals a broken daemon and clears DEAD
    # configs, and a live wiring with a stale key set is neither. The deploy
    # looked finished and was not.
    #
    # HERE AND NOT IN THE HOST: `cswap pin --ensure` already reaches this
    # function on every launch, so the bridge package needs no new line to
    # trigger it. Pin behaviour stays in the pin. The return value is
    # deliberately untouched — the caller reads True as "the daemon was
    # restarted" and renders "Restored the cloud pin", which a refreshed config
    # is not. And it cannot raise: this runs from an rc hook before every
    # launch.
    try:
        rewire_if_version_changed(certdir)
    except Exception:  # noqa: BLE001 — a launch must never fail on the pin
        pass
    # AN UPGRADE MUST NOT WAIT FOR A LAUNCH. `ensure_proxy` recycles a stale
    # daemon, but it only runs when a NEW session starts — so installing a fix
    # left every running daemon on the old code until someone happened to open
    # a session. The installer changes files; nothing told the daemon. This
    # function runs before every hand-launched `claude` (the rc hook's `cswap
    # pin --ensure`), which makes it the one caller positioned to notice. It
    # just never asked: an earlier draft of this sentence said "every few
    # seconds from the status line" — the third time that claim was written
    # into this function, and wrong every time; the status line's
    # `_try_heal_pin` was removed and nothing calls `heal` on a timer.
    # `_read_alive_port` without a fingerprint reads a stale daemon as healthy.
    # Ask WITH one, and an upgrade takes effect on its own, on the same port,
    # with no session restarted and no command typed. Deliberately NOT reusing
    # the ensure_proxy fast path: this must be the slow, locked path so the
    # recycle is serialized against every other status line on the box.
    #
    # RESOLVE THE SLOT BEFORE KILLING ANYTHING. A dangling pin must be a no-op,
    # exactly as it was before the recycle existed.

    fp = daemon_fingerprint()
    alive = _read_alive_port(certdir, fingerprint=fp)
    # `_read_alive_port` returns None for an `unpinnable` daemon REGARDLESS of
    # fingerprint, so "fingerprinted read failed but a bare read succeeded" is
    # true for a daemon running the NEWEST code that merely cannot read its
    # credential (the macOS keychain rc=36 case). Ask the record directly
    # instead of inferring staleness from two probes that differ for more than
    # one reason.
    #
    # RESOLVED BEFORE ANY KILL. A dangling pin (the account gone from the
    # registry) has nothing to spawn afterwards, so recycling first and looking
    # the slot up after left the wiring naming a port nobody serves — the
    # outage this recycle exists to prevent, caused by the recycle.
    account_num = _resolve_pinned_slot(backup_root, email)

    # AND THE OWNER FIELD, WHICH ONE SPLICE CANNOT HOLD. `_perform_switch`
    # writes the pin's identity into `~/.claude.json`'s `oauthAccount` on both
    # of its config-write branches, and that is correct and it is not enough:
    # something else rewrites the field between switches. Measured on one mac,
    # sampling the field beside the roster's `activeAccountNumber` so a switch
    # is separable from anything else --
    #
    #   slot 3 -> 5, field became the PIN     a switch ran and the splice took
    #   slot 5 -> 5, field became a THIRD     nothing switched, so something
    #                account                  else owns the field
    #
    # The second row is the one that matters: between switches the field drifts
    # with nobody to put it back, and Claude Code compares each bridge pointer
    # against it on relaunch. A pointer stamped while it is wrong makes the
    # reattach fail -- fresh bridge, server-invented title, history suppressed.
    #
    # HERE BECAUSE THIS IS THE LAUNCH. `cswap pin --ensure` routes to this
    # function immediately before a hand-launched `claude` mints its bridge,
    # which is the moment the field has to be right. The same reason the carry
    # below lives here.
    #
    # THE HOST HAS TO SUPPLY THE IDENTITY, and that is not fastidiousness. The
    # value lives in cswap's per-slot config backup, whose layout is the
    # package's business to stay out of -- and worse, that backup is POISONED
    # under a pin: a switch archives the live config as the outgoing slot's
    # backup, so it already names the pin and reading it back would be reading
    # our own writing. `identity` comes through the seam or this does nothing.
    #
    # Idempotent, so the usual case writes nothing: the splice returns early
    # when the field already names the pinned ACCOUNT, and every live Claude
    # Code watches that file.
    #
    # BEFORE THE CARRY, AND THAT ORDER IS LOAD-BEARING. `_carry_history_pointers`
    # reads `_login_identity()` — this same field — to decide whose pointers to
    # restamp. Run after a drifted field it stamps every idle session with the
    # wrong owner, which is the veto this whole block exists to prevent.
    #
    # THE VERDICT COMES FROM THE STATE, not from the call. The splice swallows
    # every real failure itself and answers False for BOTH "could not write"
    # and "already correct", so an `except` around it guards a case that
    # cannot arrive. Re-read instead: a field that still does not name the pin
    # after a splice that claimed nothing to do is a config we cannot write.
    if identity and account_num:
        # THE FRESHER COPY WINS, and it is remembered BEFORE the splice so the
        # splice writes it: the host's identity is the pinned slot's stored
        # config, whose profile stamp is as old as that slot's last login.
        identity = remember_pin_identity(backup_root / "pin-proxy",
                                         identity) or identity
        try:
            # BOTH KEYS, like the splice's own no-op test. Comparing the
            # account uuid alone calls a config healthy whose ORG has drifted,
            # and Claude Code's pointer comparison uses both.
            wrote = splice_config_identity(identity,
                                           lock_timeout=lock_timeout)
            _now = _login_identity()
            _want = tuple(identity.get(k) or None
                          for k in ("accountUuid", "organizationUuid"))
            if not wrote and (not _now or tuple(_now) != _want):
                _log_lifecycle(
                    "could not re-assert the pin in the live config — "
                    "bridges minted before the next switch keep a pointer "
                    "that will not reattach")
        except Exception:  # noqa: BLE001 — a launch must never fail on the pin
            pass

    # THE ACTUAL PER-LAUNCH HOOK LANDS HERE, NOT IN `ensure_proxy`. The rc file
    # runs `cswap pin --ensure` before every hand-launched `claude`, and that
    # flag routes to THIS function — `ensure_proxy` is reached only from `cswap
    # run` and a hand-typed `cswap pin <n>`. Hooking only there meant the carry
    # never ran for the way sessions are actually started here. AFTER the slot
    # resolve, so a dangling pin (account gone from the registry) stays the
    # total no-op the rest of this function works to keep. And NOT on a timer.
    # That is the whole evidence — an earlier draft here also cited a dotfiles
    # test as asserting it, and that test asserts something else (no-spawn in
    # the feature-ABSENT case) against a function that no longer exists. The
    # placement is safe because of the code, not because of that test. The rc
    # hook backgrounds this (`&!`), so it can lose the race against the launch
    # it precedes. That costs the CURRENT launch, never correctness: a pointer
    # this pass misses is fixed by the next launch on the machine, and
    # `ensure_proxy` runs the same sweep synchronously before `execvpe`.
    if account_num:
        _carry_history_pointers(certdir)
        # AND THE LIVE ONES, in the same act as the splice above. The two ends
        # of CC's comparison are `bridgeOwnerAccountUuid` and this config's
        # `oauthAccount`, read at different times: the pointer is stamped when
        # a job record is written, the comparison runs at reattach. The splice
        # just moved the second end, so anything stamped before it and
        # reattaching after it disagrees and CC MINTS -- `restored_owner_mismatch`
        # in the binary, "minting fresh, history channels suppressed" in its log.
        #
        # `_carry_history_pointers` is documented for sessions with a bridge and
        # NO PROCESS, so it leaves exactly the live ones. Those waited for the
        # daemon's next `.claude.json` mtime poll; measured, a revived session
        # reattached ONE SECOND later and lost its bridge, well inside it.
        #
        # UNDER `identity`, THE SAME CONDITION THE SPLICE RUNS UNDER. This
        # carry has no pin-org guard — its sibling `_carry_history_pointers`
        # does — and what stands in for one is that the splice just wrote the
        # field it reads. On the no-identity call, the one that FORGETS, the
        # splice does not run, so `_login_identity()` is whatever is signed in
        # and this would restamp every LIVE session onto an account that does
        # not own their bridges. Handing Claude Code a bridge it cannot use is
        # a 500; a lost history is survivable.
        if identity:
            try:
                _live = _pointer_owner(backup_root / "pin-proxy")
                if _live:
                    carry_live_pointers(_live)
            except Exception:  # noqa: BLE001 — a launch must not fail on the pin
                pass

    stale_st = read_daemon_state(certdir)
    stale_fp = (stale_st or {}).get("fingerprint")
    recycled = False
    # `stale_fp is None` is a record with no fingerprint at all, which
    # `read_daemon_state` accepts (it requires only port and pin). Excluding it
    # made such a daemon IMMORTAL — it can never match the current fingerprint,
    # so it is stale by definition, and 0.1.5 recycled it. Treat a missing
    # fingerprint as stale, which is what it means.
    fp_stale = stale_fp != fp
    # A WEDGE: current code, not marked unpinnable (that gap is a credential
    # problem no respawn fixes -- see the case below), but the fingerprinted
    # probe still refused it. The only way `alive is None` reaches here under
    # a MATCHING fingerprint and no `unpinnable` mark is `_serving_can_pin`
    # answering False -- it already retried and confirmed nothing comes back.
    # Without this, `stale_fp != fp` never held for a daemon running code we
    # DO ship, so a wedge on current code was never a match and `heal` read
    # it as healthy forever. Measured on a Mac: `cswap pin --heal` printed
    # "Nothing to heal" twice against a trio that accepted TCP and never
    # answered.
    wedged = not fp_stale and not (stale_st or {}).get("unpinnable")
    stale_is_serving = (alive is None and (fp_stale or wedged)
                        and _read_alive_port(certdir) is not None)
    if not stale_is_serving:
        # The watchdog did its job (or there was never anything stale), so no
        # sighting is outstanding. This is the COMMON exit -- the deferral
        # works by the daemon being replaced without us -- and therefore the
        # clear that actually keeps the record from going stale.
        _clear_heal_defer(certdir)
    if stale_is_serving:
        # Serving, but running code we no longer ship (or wedged on code we
        # do). Recycle it: the spawn below rebinds the SAME port, so live
        # sessions never see the swap.
        #
        # NOT WITHOUT A SLOT. A dangling pin (its account gone from the
        # registry) has nothing to spawn afterwards, so killing here would
        # leave the wiring naming a port nobody serves — the outage this
        # recycle exists to prevent, caused by the recycle.
        if not account_num:
            return False
        # LET THE GAPLESS PATH GO FIRST -- BUT ONLY FOR THE REASON IT EXISTS
        # FOR. `_watchdog_had_its_turn` defers one tick so the code watchdog's
        # own gapless replacement can win the race; that watchdog fires on a
        # STALE FINGERPRINT, and a wedge is not a code deploy -- the same
        # deadlock that broke `/health` may just as well have broken the
        # watchdog's own thread, so waiting a tick on it wastes exactly the
        # time a wedge should not get.
        stale_pid = int((stale_st or {}).get("pid") or 0)
        if fp_stale and stale_pid and not _watchdog_had_its_turn(
                certdir, stale_pid, stale_fp):
            _log_lifecycle(
                "a daemon on stale code is serving — leaving it to its own "
                "code watchdog, which replaces it without darkening the port. "
                "The next heal retires it if that did not happen")
            return False
        # Past the deferral: this daemon is being retired, so the sighting has
        # done its job and must not outlive it.
        _clear_heal_defer(certdir)
        try:
            # BOUNDED, BECAUSE A DEPLOY CALLS THIS SYNCHRONOUSLY. The holder
            # can be a handover draining a Remote Control channel, which lives
            # as long as its session — measured at 72 minutes on a healthy
            # fleet. Blocking here made `pin --heal` hang with no output and
            # took the deploy with it. Saying "could not repair right now" is
            # recoverable; a hung deploy is not, and the next launch or heal
            # does this anyway.
            with _spawn_lock(certdir, timeout=_HEAL_LOCK_WAIT_S):
                if _read_alive_port(certdir, fingerprint=fp) is not None:
                    return False  # another status line just did it
                stale = read_daemon_state(certdir)
                # "Alive" is not "still ours" — a pid is reused freely, so ask
                # whether it is a pin daemon for THIS certdir before signalling
                # it. Same gate ensure_proxy uses; when identity cannot be
                # established (no ``ps``) this kills nothing rather than
                # killing on faith.
                if stale and int(stale.get("pid") or 0) in _pin_daemon_pids(certdir):
                    # Save the port BEFORE the kill. The daemon unlinks its own
                    # state on TERM, so afterwards there is nothing to reclaim
                    # from and the successor would take a FRESH port — which
                    # strands every session already wired to the old one, the
                    # exact damage this recycle exists to avoid.
                    if isinstance(stale.get("port"), int):
                        _write_port_hint(certdir, stale["port"])
                    _kill_daemon(int(stale["pid"]), certdir)
                    # ONLY AFTER A KILL. `recycled` decides whether the spawn
                    # guard below is fingerprinted, and setting it merely for
                    # ENTERING this branch made a no-op recycle look like a
                    # real one: with no `ps` (the documented blind spot) the
                    # identity gate kills nothing, and heal then spawned a
                    # successor over a daemon that is still serving.
                    recycled = True
        except SpawnLockBusy as exc:
            # NOT THE SAME FALSE AS "nothing to heal". Both reach the caller as
            # a bare False and it prints "Nothing to heal" — the opposite of
            # what happened. The return type cannot carry the difference, so
            # this line does.
            #
            # TO THE CALLER'S STDERR, NOT TO `daemon.log`. `_log_lifecycle`
            # writes to stderr and stderr IS the log only inside the daemon;
            # heal runs in the CLI, so this reaches whoever ran it — a deploy's
            # own output — and searching the daemon corpus for it finds
            # nothing. Anything that must survive the process goes in a file
            # under certdir instead (see `_watchdog_had_its_turn`).
            _log_lifecycle(f"heal gave up waiting for the spawn lock: {exc}")
            return False
        except Exception:  # noqa: BLE001 — a heal must never raise
            return False
        # Fall through to the spawn path below, which reclaims that port.
    if alive is not None:
        # SERVING IS NOT THE SAME AS WIRED. Returning False here left that
        # state permanent: the proxy served on a port no session was told
        # about, and only a hand-typed `cswap pin <n>` restored it. Re-wiring
        # is the whole point of a heal. It costs one config read when the
        # wiring is already correct, and it is what makes the pin come back BY
        # ITSELF once the daemon is healthy again.
        if _wired_port() == alive:
            return False  # serving AND wired — genuinely nothing to do
        try:
            wire_global_config(alive, certdir / "ca.pem",
                               lock_timeout=lock_timeout)
            return True
        except Exception:  # noqa: BLE001 — a heal must never raise
            return False
    # The SPAWN needs a slot, and a dangling pin has none. Gated here rather
    # than at the top so the serving-but-unwired re-wire above still runs: that
    # path needs no registry, and gating it made an unreadable sequence.json
    # block a repair that would otherwise have worked.
    if not account_num:
        return False  # dangling pin: its slot is gone, nothing to serve
    try:
        # BOUNDED, LIKE THE FIRST ONE. heal takes this lock TWICE and only the
        # recycle branch's acquisition was bounded, so heal could still hang
        # here for the length of a session — the same defect, at the site the
        # first fix did not look at.
        with _spawn_lock(certdir, timeout=_HEAL_LOCK_WAIT_S):
            # Re-check under the lock — another caller may have just spawned.
            #
            # WITH THE FINGERPRINT. A bare liveness check re-reads the very
            # daemon the recycle above was for: its state file outlives a kill
            # that did not complete (and, when a caller stubs the kill,
            # always), so heal would bail here and the obsolete daemon would
            # serve forever — the exact staleness this path exists to end.
            # Asking for the current fingerprint means "someone spawned a
            # daemon running the code we ship", which is the only thing that
            # makes this a no-op.
            #
            # ANYTHING SERVING IS ENOUGH — unless we just recycled. A
            # fingerprinted check here loops forever on a daemon that runs
            # CURRENT code but is marked `unpinnable` (it cannot read the
            # credential — the macOS keychain rc=36 case). `_read_alive_port`
            # returns None for that daemon whatever the fingerprint, so a
            # fingerprinted guard reads "nothing is serving", spawns a
            # successor that re-marks itself unpinnable, and the next tick does
            # it again. Something IS serving, so heal is done — the pin is
            # fail-open and a respawn cannot fix a credential it also cannot
            # read. The exception is the branch above: it killed the daemon
            # whose record this would find, and a kill that did not complete
            # leaves that record behind. There the fingerprint is the right
            # question, because only a successor running OUR code means the
            # work is done.
            probe = (
                _read_alive_port(certdir, fingerprint=fp)
                if recycled
                else _read_alive_port(certdir)
            )
            if probe is not None:
                return False
            port = _spawn_daemon(account_num, email, certdir)
        if port is None:
            # Could not start. Make sure a stale wiring is not left behind to
            # block sessions; better unpinned than unusable.
            unwire_if_dead(certdir, lock_timeout=lock_timeout)
            return False
        wire_global_config(port, certdir / "ca.pem",
                           lock_timeout=lock_timeout)
        return True
    except SpawnLockBusy as exc:
        # Same reason as the recycle branch: a bare False reaches the caller as
        # "Nothing to heal", which is the opposite of "could not get the lock".
        _log_lifecycle(f"heal gave up waiting for the spawn lock: {exc}")
        return False
    except Exception:
        return False


# How many times, and how far apart, `unwire_if_dead` asks before it strips a
# wiring. Three probes a second apart clear a single-stage blip outright.
#
# WHAT IT COSTS A DEAD PIN, and it is not one number. A REFUSED connect — the
# loopback case, and what "dead" normally looks like — returns at once, so the
# cost is the two gaps: about two seconds. A BLACKHOLED port, which is a stale
# wiring pointing at something a firewall rule or a wedged listener owns, burns
# each probe's full `timeout=1` as well: 3 x 1 s of connect plus 2 x 1 s of gap
# is five. That second shape is exactly the state this function exists to clean
# up, so it is the one to size against, and it lands on the interactive path of
# every session start. Deliberately NOT sized to survive the full 70 s: a
# launch must never block that long, and a pin that is dead for a minute SHOULD
# be unwired. The target is the momentary gap, which is what was producing
# false positives.
_UNWIRE_PROBES = 3
_UNWIRE_PROBE_GAP = 1.0


def unwire_if_dead(certdir: Path,
                   lock_timeout: float = _SPLICE_LOCK_S) -> bool:
    """Strip a pin wiring whose daemon is gone. True when it removed one.

    The teardown path restores ``.claude.json`` itself, but it only runs when
    the daemon exits in an orderly way. A SIGKILL, an OOM kill, a crash — or a
    daemon that never started at all, which is what was measured when
    ``cryptography`` vanished from its environment — leaves the env block
    naming a port nothing listens on. Claude Code applies that block at boot,
    so every session from then on dials a dead proxy and retries forever while
    the upstream proxies are perfectly healthy behind it.

    Called at launch, before anything reads the wiring, so a broken pin costs
    the PIN and never the session. The check is the same one
    ``_read_alive_port`` makes — a recorded pid that is alive AND a port that
    answers — because either alone lies: a wedged process keeps its pid, and a
    port can be inherited by something else entirely.

    Deliberately does NOT try to revive the daemon. That is ``ensure_proxy``'s
    job and it needs the switcher; this runs on paths that may not have one,
    and a launch must never block on starting a background service.
    """
    try:
        st = read_daemon_state(certdir)
    except Exception:
        st = None
    if st:
        try:
            if _pid_alive(int(st["pid"])):
                with socket.create_connection(
                    ("127.0.0.1", int(st["port"])), timeout=1
                ):
                    return False  # serving — leave the wiring alone
        except (OSError, KeyError, TypeError, ValueError):
            pass

    # NO RECORD IS NOT PROOF OF DEATH. `_spawn_daemon` UNLINKS proxy.json as
    # its first act, so between that unlink and a failed spawn the state file
    # is missing while the original daemon is still happily serving. Deciding
    # from the record alone unwired a live pin on linux: daemon 4035232 had
    # been up 38h, pid alive, port answering, and the env block was stripped
    # anyway because proxy.json had just been deleted out from under this
    # check. (It fires on a code change, because ensure_proxy matches on a
    # FINGERPRINT: same daemon, new fingerprint, so it tries to replace one
    # that is fine, and the spawn fails on the port the healthy daemon holds.)
    # So ask the WIRING itself, which is the thing we are about to remove: if
    # the port it names still answers, something is serving on it and the
    # wiring is correct regardless of what any file says.
    #
    # ONE REFUSED CONNECT IS NOT DEATH, IT IS A MOMENT. A single 1 s probe
    # landing in either gap reads "the pin is dead" and this function then
    # strips the WHOLE env block, so every claude launched from then on runs
    # unpinned, silently, until someone notices. That is what a live machine
    # was found in that night: the pin healthy and serving on 36301, `env`
    # empty, and nothing in any log able to say which of two implementations
    # with identical clear-semantics had done it. So ask again, spaced past a
    # handover rather than inside one. The cost of being slow here is a launch
    # waiting a couple of seconds for a pin that really is dead; the cost of
    # being fast is unpinning the machine.
    port = _wired_port()
    if port is not None:
        for attempt in range(_UNWIRE_PROBES):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return False  # the wired address is live — do not touch it
            except OSError:
                if attempt + 1 < _UNWIRE_PROBES:
                    time.sleep(_UNWIRE_PROBE_GAP)

    try:
        return wire_global_config(None, None, lock_timeout=lock_timeout)
    except Exception:
        return False


def _wired_port() -> int | None:
    """The pin port currently named in the global config, or None.

    Read straight off the env block rather than from our own state, so it stays
    truthful while the state file is absent (see ``unwire_if_dead``).
    """
    try:
        get_global_config_path = require("paths").get_global_config_path

        raw = json.loads(get_global_config_path().read_text(encoding="utf-8"))
        env = raw.get("env") if isinstance(raw, dict) else None
        if not isinstance(env, dict):
            return None
        val = env.get("CSWAP_PIN_PORT")
        return int(val) if val is not None else None
    except Exception:
        return None


def wire_global_config(port: int | None, ca_path: Path | None,
                       lock_timeout: float = _SPLICE_LOCK_S) -> bool:
    """Route hand-launched ``claude`` sessions through the pin proxy.

    Claude Code applies the ``env`` block of its global config into
    ``process.env`` at startup, so a session the user starts themselves — no
    cswap, no wrapper, no shell edit — picks the pin up. That block lives in
    ``.claude.json``, the same file cswap already rewrites to swap accounts,
    so this touches nothing new: not ``settings.json`` (Claude Code's own),
    not a shell rc, not a shim on PATH.

    Only keys THIS function wrote are ever modified, tracked by name in
    ``_WIRE_MARK``. A proxy the user (or their launcher) set themselves is
    left exactly as found, and clearing the pin restores it rather than
    deleting it — the ordering matters, because the env block is applied on
    top of the process environment and would otherwise silently displace a
    wrapper's own proxy.

    Passing ``port=None`` unwires. Returns True when the file changed.

    Not retroactive: a session already running keeps the environment it was
    exec'd with (only a ``settings.json`` change re-applies env to a live
    process, and that file is not ours to write). New sessions are wired.
    """
    claude_config_lock = require("claude_locks").claude_config_lock
    get_global_config_path = require("paths").get_global_config_path

    path = get_global_config_path()
    # Claude Code writes this file concurrently, and we replace it whole — a
    # write landing between our read and our rename would be discarded along
    # with the account, project history and settings it carried. Hold the same
    # lock every other writer in this codebase takes, across read AND write.
    try:
        # THE CALLER'S BUDGET, NOT OURS. A launch that can afford half a second
        # reaches this through `heal`, and a hardcoded five put the stall back
        # on the path the budget exists to bound.
        with claude_config_lock(timeout=lock_timeout):
            return _wire_global_config_locked(path, port, ca_path)
    except Exception:
        # A lock we cannot take is a reason to skip the write, not to fail a
        # launch: the pin degrades to "not wired", which is the fail-open
        # behaviour the rest of this module is built on.
        return False


def _wire_global_config_locked(
    path: Path, port: int | None, ca_path: Path | None
) -> bool:
    """The read-modify-write of :func:`wire_global_config`, under its lock."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(raw, dict):
        return False

    env = raw.get("env")
    env = dict(env) if isinstance(env, dict) else {}
    before = dict(env)
    # THE RECEIPT, from wherever the last writer put it. See `_ledger_path`:
    # it moved out of `.claude.json` into the account store, and BOTH are read
    # because an older cswap-pin still writes the config key.
    prev = _read_ledger(path, raw)
    ours = prev.get(_WIRE_MARK)
    ours = list(ours) if isinstance(ours, list) else []

    # AND ANY MARKER THE CONFIG STILL CARRIES, which the sidecar answer hides.
    # `_read_ledger` stops at a sidecar that says "not wired" — correct, an
    # unwire writes exactly that and falling through would resurrect what it
    # emptied. But claude-swap's `_clear_ledger` deliberately does NOT silence
    # a marker in the config ("a receipt this clear never saw"), so the two
    # states coexist: empty sidecar, config marker still present.
    #
    # Read as `ours == []` that is not merely a missed cleanup. The keys stay
    # in `env`, and twenty lines down `displaced` records them as the USER'S
    # pre-existing values — so the next unwire faithfully restores our own
    # dead proxy vars as if they had always been there. Losslessness pointed
    # at the wrong owner.
    #
    # Union, not fallback: the sidecar remains authoritative for what IT
    # recorded, and a config-only receipt from an older cswap-pin is added
    # rather than allowed to override.
    config_mark = raw.get(_WIRE_MARK) if isinstance(raw, dict) else None
    if isinstance(config_mark, list):
        ours += [k for k in config_mark if k not in ours]

    # Drop what we wrote last time, restoring anything we displaced.
    saved = prev.get(f"{_WIRE_MARK}Saved")
    saved = dict(saved) if isinstance(saved, dict) else {}
    for key in ours:
        env.pop(key, None)
    # HEAL A MACHINE THAT ALREADY CARRIES A BANNED KEY, whoever wrote it.
    # `ours` only covers what THIS install recorded, so a config written by an
    # older cswap-pin — or by a peer with the same behaviour — keeps its
    # SSL_CERT_FILE forever and no amount of re-wiring removes it. Every one of
    # these REPLACES a trust store rather than adding to it, so leaving one
    # behind leaves a machine one MDM change away from trusting nothing.
    #
    # Unconditional, and deliberately not restored from `saved` below: if the
    # user had set one themselves we would rather hand it back to them
    # explicitly than resurrect it here, and no machine of ours ever had one
    # that we did not write.
    for banned in _REPLACE_CLASS_CA_VARS:
        env.pop(banned, None)
        saved.pop(banned, None)
    for key, value in saved.items():
        env[key] = value

    ledger = {_WIRE_MARK: [], f"{_WIRE_MARK}Saved": {},
              "writtenBy": _own_version()}
    if port is None or ca_path is None:
        pass  # `ledger` above already records "not wired"
    else:
        # The CA lives in the cert dir, so its parent IS the cert dir — which
        # is where the proxy credential lives too. Deriving it here keeps the
        # public signature unchanged for every caller.
        proxy = _proxy_url(port, Path(ca_path).parent)
        node_ca = _merged_ca(ca_path, env.get("NODE_EXTRA_CA_CERTS"))
        # PYTHON DOES NOT READ NODE_EXTRA_CA_CERTS, and cswap's usage poll is
        # plain urllib -- so it obeys the proxy vars above while trusting
        # nothing that signs them.
        wanted = {
            "HTTPS_PROXY": proxy,
            "https_proxy": proxy,
            # Claim it so every var names the same hop. Scoped to this file,
            # which Claude Code applies to itself; the shell path deliberately
            # does not create one (see wire_env).
            "ALL_PROXY": proxy,
            # Node takes exactly ONE file here, so replacing an existing CA
            # blinds the session to every host the proxy behind us re-signs.
            "NODE_EXTRA_CA_CERTS": str(node_ca),
            # Self-loop marker. Claude Code applies this block into
            # process.env, which its Bash-tool children inherit — so a `cswap`
            # run from inside a pinned session sees our own proxy as its
            # ambient one. Without the marker it records THAT as the upstream
            # and the daemon starts CONNECTing to itself.
            "CSWAP_PIN_PORT": str(port),
        }
        # NO SSL_CERT_FILE. NOT "gated better" — NOT WRITTEN AT ALL. The gate
        # was correct and still the wrong shape, for two reasons that only
        # appeared once two independent implementations were compared:  A PROOF
        # GOES STALE. It holds at the moment of writing. The store it proved
        # against can be replaced by MDM, become unreadable, or simply change —
        # and the variable stays behind naming a bundle that no longer subsumes
        # anything. On a corporate laptop that is total: no system roots means
        # no TLS to anywhere.
        #
        # EVERY GATE GREW A DEFAULT-ALLOW ARM. This one passed on host-a partly
        # because the ambient store is a capath with no cafile, which is
        # "nothing to compare", not "proven superset". The sibling
        # implementation returned ok when the store was UNREADABLE, on the same
        # reasoning. Two authors, one hole: a property of the approach, not a
        # pair of bugs. The replacement cannot narrow anything and so needs no
        # proof: `oauth._pin_aware_ssl_context()` builds
        # `create_default_context()` and calls `load_verify_locations(pin CA)`.
        # Python ADDS. Node ADDS via NODE_EXTRA_CA_CERTS, kept above. Nothing
        # is left for a replace-class variable to do. Remember what we are
        # about to displace, so unwiring is lossless.
        displaced = {k: env[k] for k in wanted if k in env}
        env.update(wanted)
        ledger = {_WIRE_MARK: list(wanted),
                  f"{_WIRE_MARK}Saved": displaced,
                  # WHO WROTE THIS, so a later launch can tell a
                  # wiring produced by the installed code from one
                  # produced by the version before it.
                  "writtenBy": _own_version()}

    if env == before and _WIRE_MARK not in raw and not ours:
        return False
    # THE RECEIPT FIRST, AND IT MUST SUCCEED — see `_write_ledger`. That is
    # false for this path, because the same function pops those keys three
    # lines below. Only a hand edit fixes it, which is what `clear_wiring`
    # exists to make unnecessary. So the CONFIG write is the one that becomes
    # conditional. Unwired is a working session; wired-with-no-receipt is an
    # outage nobody can clear.
    if not _write_ledger(path, ledger):
        _log_lifecycle(
            "could not record the wiring receipt — leaving .claude.json "
            "untouched rather than wiring it unremovably"
        )
        return False
    # THE CONFIG KEYS GO, whichever location we read from. They are where the
    # receipt USED to live; leaving them behind means an older claude-swap
    # keeps reading a stale copy of a receipt this write just replaced.
    raw.pop(_WIRE_MARK, None)
    raw.pop(f"{_WIRE_MARK}Saved", None)
    if env:
        raw["env"] = env
    else:
        raw.pop("env", None)
    try:
        # PID-SUFFIXED AND O_EXCL, like every other atomic write in this file.
        # A fixed name is two bugs: two processes wiring at once share it, and
        # O_CREAT's mode argument is IGNORED for a file that already exists —
        # so a leftover temp from an earlier crashed write dictates the final
        # mode, and the rename makes it permanent.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
        # 0600 from creation, and never wider than what we are replacing.
        # ``.claude.json`` carries primaryApiKey, inline MCP credentials and
        # (once the gate is armed) the proxy URL's own credential. A plain
        # write takes its mode from the umask, so a normal 022 would publish
        # all of that at 0644 — and because this is a rename, the mode
        # SURVIVES: wiring the pin permanently downgrades a 0600 config.
        mode = _mode_of(path, default=0o600)
        try:
            tmp.unlink()  # our own pid's leftover; O_EXCL would reject it
        except OSError:
            pass
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, json.dumps(raw, indent=2).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        # THE RECEIPT NOW OVERSTATES, and that is the safe direction. It says
        # keys are ours that the config does not carry, so `--clear` removes
        # nothing and reports nothing — a no-op, not an outage. The opposite
        # order fails the other way, which is why the write above is first.
        return False
    return True


def _mode_of(path: Path, default: int) -> int:
    """The file's current permission bits, or ``default`` when it has none yet.

    Never widens: a config someone tightened to 0400 stays 0400, and a file
    that does not exist yet is created owner-only rather than at the umask.
    """
    try:
        return stat.S_IMODE(path.stat().st_mode) & 0o777
    except OSError:
        return default


def _ambient_chain(
    env: dict[str, str] | None = None, certdir: Path | None = None
) -> "tuple[str | None, str | None]":
    """``(hop, next_hop)`` as this launch can see them.

    When a launch prefers a recorded inner proxy over the one its own shell
    exports, the shell's value is not noise — it is the hop the inner one
    chains THROUGH, observed directly. Discarding it left the record
    single-hop, and a single-hop chain falls to a direct dial the moment its
    one hop blinks. Returning both is what lets the walk step past a dead
    inner proxy to the outer one.
    """
    src = os.environ if env is None else env
    shell_value = src.get("HTTPS_PROXY") or src.get("https_proxy")
    hop = _ambient_proxy(env, certdir)
    shell_parsed = parse_upstream_proxy(shell_value)
    hop_parsed = parse_upstream_proxy(hop)
    if (
        shell_parsed is None
        or hop_parsed is None
        or shell_parsed.address == hop_parsed.address
        or shell_parsed.port == _self_port(src)
    ):
        return hop, None
    return hop, shell_value


def _ambient_proxy(
    env: dict[str, str] | None = None, certdir: Path | None = None
) -> str | None:
    """The egress proxy this launch inherited, or ``None`` for a direct dial.

    Skips a value that already points at OUR daemon: a shell that ran
    ``pin-env`` (or a re-launch inside a pinned session) exports the pin proxy
    itself, and recording that would make the daemon CONNECT to itself — every
    request looping until the socket dies.
    """
    src = os.environ if env is None else env
    value = src.get("HTTPS_PROXY") or src.get("https_proxy")
    parsed = parse_upstream_proxy(value)
    if parsed is None:
        # Nothing in OUR environment — but a launcher may still put a proxy in
        # the session's, and our env block displaces it. `cswap pin` runs in a
        # plain shell where that value does not exist yet, so ask the config
        # what the last session was actually told to use.
        return _wired_over_proxy()
    if parsed.host in _LOOPBACK and parsed.port == _self_port(src):
        return _wired_over_proxy()
    # This shell has A proxy — but not necessarily the one Claude Code runs
    # behind. A launcher may start a per-session cache proxy and points
    # HTTPS_PROXY at THAT; an ordinary shell, and every ssh shell, only has the
    # machine-wide egress proxy the launcher itself chains to. Prefer the
    # recorded one when it is still serving — it is the inner link, and it
    # reaches this one anyway. Two places can name the inner proxy: what our
    # env block displaced on a previous launch, and what a previous launch
    # recorded as the chain.
    for prev in (_wired_over_proxy(), _recorded_upstream(certdir)):
        prev_parsed = parse_upstream_proxy(prev)
        if (
            prev_parsed is not None
            and prev_parsed != parsed
            and prev_parsed[0] in _LOOPBACK
            and prev_parsed[1] != _self_port(src)
            and _port_is_serving(*prev_parsed.address)
        ):
            return prev
    return value


def _recorded_upstream(certdir: Path | None) -> str | None:
    """The chain a previous launch recorded, as a URL. See the caller."""
    if certdir is None:
        return None
    # Raw, for the same reason write_upstream_hint keeps it raw: this value
    # feeds back INTO the hint, so reconstructing it here launders the
    # credential out on the other side of the same round trip.
    return _read_upstream(certdir, "proxy") or None


def _proxy_url(port: int, certdir: Path | None) -> str:
    """The proxy URL to hand a client, carrying the credential when there is one.

    Userinfo in the URL is how every client we wire (Node, curl, python) is
    told to send ``Proxy-Authorization`` — measured: the real Claude Code
    client sends ``Proxy-Authorization: Basic`` on CONNECT when HTTPS_PROXY
    carries user:pass, and sends nothing when it does not. That measurement is
    the whole reason this can be enforced without cutting every session off.

    No secret (a cert dir we could not write) yields the bare URL, so the pin
    keeps working unauthenticated rather than becoming unusable.
    """
    if certdir is not None:
        secret = read_proxy_secret(certdir)
        if secret:
            from urllib.parse import quote

            return f"http://cswap:{quote(secret, safe='')}@127.0.0.1:{port}"
    return f"http://127.0.0.1:{port}"


def _port_is_serving(host: str, port: int) -> bool:
    """Whether something still accepts connections there. Cheap and local."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _wired_over_proxy() -> str | None:
    """The proxy our env block is currently displacing, if any.

    Recorded by :func:`wire_global_config` when it wrote over a value that was
    already there. Without this, wiring from a shell that has no proxy (the
    normal case: a launcher sets one only when it execs Claude Code) would
    record "no upstream" and the pinned session would bypass that launcher's
    proxy entirely.
    """
    get_global_config_path = require("paths").get_global_config_path

    try:
        path = get_global_config_path()
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    # THROUGH `_read_ledger`, not `raw` directly. The receipt moved to the
    # account store; reading the config key alone would see nothing on any box
    # a new pin has already written, and this function's silence is what makes
    # a pinned session bypass the launcher's own proxy.
    saved = _read_ledger(path, raw).get(f"{_WIRE_MARK}Saved")
    if isinstance(saved, dict):
        value = saved.get("HTTPS_PROXY") or saved.get("https_proxy")
        if value:
            return value
    return None


def _self_port(env: dict[str, str]) -> int | None:
    """Our own daemon's port as this environment records it, if any."""
    try:
        return int(env.get("CSWAP_PIN_PORT", ""))
    except ValueError:
        return None


_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def _as_chain(value) -> "_Chain | None":
    """Coerce whatever named the chain into a ``_Chain``.

    The chain reaches the dial from several directions — the parsed hint, a
    constructor argument, a test's stub — and a plain ``(host, port)`` from
    any of them must simply mean "no credential, not TLS" rather than raising
    at the CONNECT. Normalizing at the point of USE covers all of them; doing
    it at one producer covers only that producer.
    """
    if value is None:
        return None
    return value if isinstance(value, _Chain) else _Chain(*value)


def _verifying_ctx(extra_ca: "Path | None" = None) -> ssl.SSLContext:
    """A verifying TLS context that trusts what THIS machine trusts.

    System roots, plus any corporate root on ``NODE_EXTRA_CA_CERTS`` — which
    is where the corporate root actually lives in the environments this
    package exists to work in. A bare ``create_default_context()`` trusts
    only public roots, so an https:// corporate proxy (signed by that same
    corporate root) fails to verify: the module is careful not to narrow the
    CLIENT's trust and would then have narrowed its own.
    """
    ctx = ssl.create_default_context()
    # Python 3.13+ VERIFY_X509_STRICT rejects a leaf with no Authority Key
    # Identifier; a corp MITM leaf may lack one. Chain-of-trust stays on.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    for cafile in (extra_ca, os.environ.get("NODE_EXTRA_CA_CERTS")):
        if not cafile:
            continue
        try:
            ctx.load_verify_locations(cafile=str(cafile))
        except (OSError, ssl.SSLError):
            pass  # unreadable/malformed: keep the roots we do have
    return ctx


class _TLSInTLS:
    """An inner TLS session carried over a socket that is ALREADY TLS.

    ``SSLContext.wrap_socket`` re-wraps the underlying FILE DESCRIPTOR, not the
    TLS stream, so calling it on an ``SSLSocket`` does not layer — it starts a
    second handshake in the clear on a socket whose peer is speaking TLS, and
    destroys the outer session doing it. Measured: the second wrap raises
    (UNEXPECTED_MESSAGE / ECONNRESET, depending on which side notices first)
    and the outer socket's ``fileno()`` is -1 afterwards, so the connection is
    unrecoverable and every pinned request through an ``https://`` egress
    proxy died at EOF with no response ever reaching the client.

    An ``https://`` proxy needs exactly that layering: the CONNECT rides the
    outer TLS, the origin's TLS rides inside it. Memory BIOs are the only way
    to get it — the inner session never touches the fd.

    Presents the subset of the socket surface this module uses upstream:
    ``sendall`` / ``recv`` / ``pending`` / ``settimeout`` / ``fileno`` /
    ``close``.
    """

    def __init__(self, ctx: ssl.SSLContext, sock, server_hostname: str) -> None:
        self._sock = sock
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._in, self._out, server_hostname=server_hostname)
        self._drive(self._obj.do_handshake)

    def _drive(self, fn, *args):
        """Run one SSLObject operation, moving bytes until it completes."""
        while True:
            try:
                out = fn(*args)
            except ssl.SSLWantReadError:
                self._flush()
                chunk = self._sock.recv(65536)
                if chunk:
                    self._in.write(chunk)
                else:
                    self._in.write_eof()
                continue
            except ssl.SSLWantWriteError:
                self._flush()
                continue
            self._flush()
            return out

    def _flush(self) -> None:
        data = self._out.read()
        if data:
            self._sock.sendall(data)

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[self._drive(self._obj.write, view) :]

    def recv(self, n: int = 65536, flags: int = 0) -> bytes:
        if flags:
            raise ValueError("flags are not supported on a layered TLS socket")
        try:
            return self._drive(self._obj.read, n)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return b""

    def pending(self) -> int:
        return self._obj.pending()

    def settimeout(self, value) -> None:
        self._sock.settimeout(value)

    def gettimeout(self):
        return self._sock.gettimeout()

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def _wrap_upstream(ctx: ssl.SSLContext, sock, server_hostname: str):
    """TLS to the origin — layered when the socket underneath is already TLS."""
    if isinstance(sock, ssl.SSLSocket):
        return _TLSInTLS(ctx, sock, server_hostname)
    return ctx.wrap_socket(sock, server_hostname=server_hostname)


# How long one HOP gets to accept and answer a CONNECT before it is treated as
# unusable and the walk moves to the hop behind it.
#
# NOT the same number as the upstream dial budget, and the difference is the
# point. A hop is on loopback and answers in well under a second (a real
# chain: ~260ms median, ~300ms worst for a hop that dials out itself, 0ms for
# a caching one). The upstream is across the internet and needs seconds.
#
# The budget matters because a hop can ACCEPT AND NEVER ANSWER — a process
# stopped by a signal, a listener bound before its logic is ready. Nothing
# raises, so only a deadline moves the walk on to the next hop; on the
# upstream's 15s that costs every request 15s and reads as a hang. 2s is
# ~7x the slowest healthy CONNECT, so a real hop is never cut.
_HOP_CONNECT_BUDGET_S = 2.0
# A kept upstream socket idle longer than this is dialled fresh. Node's
# default server keep-alive is 5 s and the hop behind us is a Node proxy: a
# request sent into its closed side gets EOF, and the client an unanswered
# request.
_UPSTREAM_IDLE_REUSE_S = 4.0
# Reaching a hop and getting its answer are two different legs. The dial is
# loopback or LAN; the CONNECT reply waits for the hop's OWN outbound round
# trip to the upstream, so it carries real internet latency and needs a budget
# sized for that, not for the dial. Sharing one number cuts healthy hops.
_HOP_REPLY_BUDGET_S = 6.0

# HOW LONG TO WAIT OUT A HOP THAT IS RESTARTING, before falling through to a
# direct dial. A little over twice that leaves room for a slower box without
# turning a genuinely absent hop into a stall — a host with no chain at all
# never enters this loop, because an empty candidate list falls straight
# through.
_CHAIN_HEAL_GRACE_S = 2.5
# Refused dials are ~free, so poll often enough that the second the hop comes
# back is the second we use it.
_CHAIN_HEAL_POLL_S = 0.2


def _dial_chain(
    chain: "_Chain",
    timeout: float | None = None,
    extra_ca: "Path | None" = None,
) -> socket.socket:
    """Connect to the egress proxy, wrapping in TLS when the URL said https.

    Without this an ``https://`` proxy got a plaintext dial to what is a TLS
    port, so the handshake never happened and every pinned request failed in
    an environment where that proxy is the only route out.

    ``extra_ca`` is the CA recorded alongside the proxy in ``upstream.json``.
    Passing it matters because the daemon is spawned from a plain shell, which
    normally has no ``NODE_EXTRA_CA_CERTS`` — so a corporate root that exists
    only in the hint would otherwise never be consulted, and verification of
    the very proxy it describes would fail.
    """
    # READ THE BUDGET AT CALL TIME. As a default argument it was frozen at
    # import, so nothing could adjust it afterwards — not a future caller, and
    # not a test pointing the walk at a hop that never answers.
    if timeout is None:
        timeout = _HOP_CONNECT_BUDGET_S
    sock = socket.create_connection(chain.address, timeout=timeout)
    # create_connection leaves the DIAL budget on the socket, where it would
    # then bound every read. Reaching a hop and waiting for its answer are
    # different legs: the dial is loopback or LAN, the answer waits on the
    # hop's own outbound round trip. Hand back a socket already carrying the
    # budget for the leg that comes next, so no caller has to remember.
    sock.settimeout(_HOP_REPLY_BUDGET_S)
    if not chain.tls:
        return sock
    try:
        return _verifying_ctx(extra_ca).wrap_socket(sock, server_hostname=chain.host)
    except (OSError, ssl.SSLError):
        sock.close()
        raise


def _dial_with_no_chain(upstream: tuple[str, int], timeout: float = 15):
    """What to do when NO hop is usable and none is recorded behind them.

    THE ONE PLACE THIS DECISION IS MADE, deliberately. A direct dial is not
    "no proxy" on a machine whose direct route is a TLS-inspecting corporate
    proxy: the leaf it returns has no Authority Key Identifier, so a strict
    verifier refuses it and OAuth against claude.ai breaks with nothing on
    screen. Refusing instead would honour that — at the cost of the standing
    rule that a pin must never block traffic, and on a machine with no
    inspector the direct dial is simply correct.

    Dials. Changing it to refuse is this function's body and nothing else.
    """
    return socket.create_connection(upstream, timeout=timeout)


def _connect_ok(status: "str | None") -> bool:
    """Whether a CONNECT status line reports success.

    ``" 200" in status`` reads the whole line, reason phrase included, so a
    refusal that merely MENTIONS 200 was accepted as one. Measured on real
    shapes a filtering proxy emits: ``502 Bad Gateway (upstream returned
    200)``, ``403 Blocked by policy rule 200`` and ``HTTP/1.1 2000 Nonsense``
    all passed. The blind tunnel then pumped the proxy's HTML error page to
    the client as if it were the origin's TLS bytes, and the "chain refused →
    dial direct" rescue never ran.
    """
    parts = (status or "").split()
    return len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1] == "200"

_UPSTREAM_FILE = "upstream.json"

# Registration of THIS client, not ownership of the session.
_PRESENCE = re.compile(r"^/v1/(code/)?sessions/[^/]+/client/presence(/|$|\?)")

_WORKER_SUBTREE = re.compile(r"^/v1/(code/)?sessions/[^/]+/worker(/|$|\?)")
# THE ONE REQUEST THAT NEVER COMPLETES. Remote Control's inbound channel is a
# GET held open for the life of the session, so it cannot migrate on
# `Connection: close` the way a reply does — it has to be closed.
_EVENT_STREAM = re.compile(r"/worker/events/stream")
# A PIN-BROKERED RE-REGISTRATION IS A BIRTH TOO. `POST .../<id>/bridge`
# mints the id again exactly as a create does, but matches neither pattern
# above, so `_note_bridge_traffic` dropped it before the startup grace ever
# saw it -- unreachable for an id whose create predates this daemon (a
# handover, or one this daemon never served at all).
_BRIDGE_REGISTER = re.compile(r"^/v1/(code/)?sessions/[^/]+/bridge(/|$|\?)")

# The session id inside a worker path, which is the bridge the call belongs
# to. Same shape as the routes above, captured rather than merely matched.
_BRIDGE_ID = re.compile(r"^/v1/(?:code/)?sessions/([^/]+)/")

# REMOTE CONTROL HAS TWO FRONT DOORS. The REPL's `/remote-control` mints
# `/v1/code/sessions/<id>/bridge`, which the table below has always pinned;
# `claude remote-control` registers an ENVIRONMENT instead, and nothing here
# matched that subtree at all:
#
#     POST   /v1/environments/bridge                      -> environment_id
#     DELETE /v1/environments/bridge/<env>
#     POST   /v1/environments/<env>/bridge/reconnect
#     GET    /v1/environments/<env>/work/poll
#     POST   /v1/environments/<env>/work/<id>/ack|stop|heartbeat
#
# The lifecycle calls carry `Authorization: Bearer <getAccessToken()>`, so they
# are OAuth ownership routes exactly like `/bridge`, and the registration is a
# CREATE the server cannot transfer afterwards.
#
# THE HEADER BUILDER IS NOT THE DISCRIMINATOR — the WRAPPER is. Measured in the
# shipped bundle: ONE Authorization builder serves all nine call sites,
# `pollForWork` included, so "from one header builder" cannot separate them.
# What separates them is the 401-refresh wrapper, the sole `getAccessToken()`
# caller IN THE RC CLIENT: the lifecycle calls go through it, the `work/` ones
# take a token as an argument. Scope is load-bearing for anyone rechecking
# this -- the binary also bundles unrelated auth libraries defining a method
# of the same name, so a bare grep answers 33 and reproduces nothing.
#
# `?beta=true` IS THE DISCRIMINATOR AND IT IS LOAD-BEARING. The managed-agents
# SDK shares this subtree, spells every one of its environment calls with that
# flag, and authenticates as an API client rather than as this login. Swapping
# a credential we have not looked at is the `/worker` mistake, so it stays out.
_ENV_BRIDGE = re.compile(
    r"^/v1/environments"
    # THE COLLECTION IS A READ, and it belongs here for the reason
    # `/v1/sessions` does. REASONED BY ANALOGY, NOT TRACED HERE: the 200 with
    # the wrong account's contents was measured on `/v1/sessions` (see that
    # route's own note), and the same shape is EXPECTED here -- the pinned
    # machines simply absent, nothing looking broken. The decision does not
    # rest on it either way: listing creates nothing and mints nothing, so
    # there is no ownership to get wrong by including it.
    r"(?:$|\?"
    r"|/(?:bridge(?:/|$|\?)"
    r"|[^/?]+/bridge/reconnect(?:/|$|\?)))"
)

# `/v1/environments/<env>/work/*` IS ABSENT ON PURPOSE, for the reason
# `/worker` is: `pollForWork`, `acknowledgeWork`, `stopWork` and
# `heartbeatWork` each take a token as an ARGUMENT and send whatever the caller
# hands them, so a swap turns a 200 into a 401. Ownership is still the pin's,
# because the register is; the work queue is not an ownership route.
_ENV_SDK_BETA = re.compile(r"[?&]beta=true(?:&|$)")



# How rarely presence may trigger a superseded-bridge sweep. Presence is posted
# by every attached session on the server's poll interval, so without a floor
# this would list the account several times a second on a busy machine. Ten
# minutes is far below the time a stale duplicate costs anything (it sits until
# someone clicks the wrong one) and far above the cost of a listing.
_BRIDGE_SWEEP_COOLDOWN_S = 600.0

# How rarely a slow request may take a line. A genuinely slow endpoint would
# otherwise fill the log with what the first line already said.
_SLOW_REPORT_COOLDOWN_S = 60.0
# Same ceiling, same reason: one line per request would bury the count.
_BUSY_REPORT_COOLDOWN_S = 60.0
_STREAM_END_COOLDOWN_S = 60.0
_SLOW_RECHECK_S = 5.0
_SLOW_CACHE: dict = {}


def slow_report_ms(certdir) -> "float | None":
    """Milliseconds above which a request takes a log line, or None for off.

    OFF UNTIL SOMEONE ASKS. This is a diagnostic and it writes into
    `daemon.log` — the one file a person reads to find out why the daemon
    died. Always-on it produced ~38 lines an hour on one fleet, about 900 a
    day, in a package installed on other people's machines. A diagnostic
    nobody armed is noise in somebody else's incident.

    IT LIVES WHERE THE PIN ALREADY LIVES, and that is the whole point of
    putting it here rather than behind a switch of its own::

        "remoteControl": { "pinnedEmail": "...", "debugSlowMs": 1500 }

    `settings.json` is the file `cswap pin <email>` already writes and this
    module already reads, in the same section. The alternative this replaced
    was `<certdir>/slow-ms`, and it failed the only test that matters for a
    switch: nobody remembers it. `certdir` is jargon for a directory whose
    name appears in nothing a person reads, so the instruction had to carry
    an explanation with it every time.

    Editable while the daemon serves, re-read on a short interval, because
    restarting the daemon is the one act guaranteed to hide an intermittent
    stall.

    `CSWAP_PIN_SLOW_MS` still wins for a deployment that would rather set it
    in the environment. Unreadable, absent or not a number is OFF, never an
    error: a diagnostic that can break a request is worse than none.
    """
    env = os.environ.get("CSWAP_PIN_SLOW_MS")
    if env:
        try:
            return float(env)
        except ValueError:
            return None
    if certdir is None:
        return None
    key = str(certdir)
    seen, value = _SLOW_CACHE.get(key, (0.0, None))
    now = time.time()
    if now - seen < _SLOW_RECHECK_S:
        return value
    value = None
    try:
        _settings = require("settings")
        raw = _settings._read_raw(
            _settings.settings_path(Path(certdir).parent))
        section = raw.get("remoteControl")
        if isinstance(section, dict):
            value = float(section["debugSlowMs"])
    except Exception:  # noqa: BLE001 — a diagnostic must not cost a request
        value = None
    _SLOW_CACHE[key] = (now, value)
    return value


# THE TWO LINES `_report_deaf_bridges` writes, as symbols rather than prose.
# A peer watcher greps the daemon log for these; exported so it can assert at
# runtime that the substrings it looks for are actually present HERE, in the
# installed package. Without that, a rename does not break the watcher — it
# turns it into a permanent "no verdict yet", which is indistinguishable from
# a healthy fleet. Same silent-absence shape as a check with no caller.
#: How recently a bridge must have posted to be judged. ONE definition: the
#: clear line and `deaf_bridges` must reason about the same population.
_DEAF_WINDOW_S = 300.0

#: A bridge opens its ear seconds after its first post; until then it has
#: lost nothing. The stream GET follows register within seconds and Claude
#: Code's own reconnect backoff tops out at 16s, so 30s covers it.
_DEAF_STARTUP_GRACE_S = 30.0

DEAF_REPORT_MARK = "post but hold no inbound stream"
DEAF_REPORT_CLEAR = "every posting bridge holds an inbound stream"
# THE THIRD ANSWER, because two of them leak the case that actually happens.
# A successor holds none of its predecessors' streams, so during a handover it
# can only ever say "deaf" — about sessions that are fine.
DEAF_REPORT_BLIND = "cannot say whether any bridge is deaf"

# THE TWO LINES `_note_attachment` writes. Same contract as the deaf pair:
# a watcher matches them, so a reword is a fleet-wide silent break.
RENAME_REPORT_OK = "a session rename reached the bridge"
RENAME_REPORT_FAIL = "a session rename was REFUSED by the bridge"
ATTACH_REPORT_OK = "claude.ai attachment downloaded as the pinned account"
ATTACH_REPORT_FAIL = "claude.ai attachment could NOT be downloaded"


def trace_target(certdir) -> "str | None":
    """Where to write the request trace, or None for off.

    The env still wins, so an existing deployment behaves exactly as before.
    Absent one, ``<certdir>/trace-to`` names the file — created and removed
    while the daemon serves, which is the whole point: the alternative is
    restarting the thing you are trying to observe.

    An unreadable or empty switch is OFF, not an error: this is a diagnostic,
    and a diagnostic that can break a request is worse than no diagnostic.
    """
    env = os.environ.get("CSWAP_PIN_DEBUG")
    if env:
        return env
    if certdir is None:
        return None
    key = str(certdir)
    seen, target = _TRACE_CACHE.get(key, (0.0, None))
    now = time.time()
    if now - seen < _TRACE_RECHECK_S:
        return target
    try:
        target = (Path(certdir) / _TRACE_SWITCH_FILE).read_text().strip() or None
    except OSError:
        target = None
    _TRACE_CACHE[key] = (now, target)
    return target


# ---------------------------------------------------------------------------
# Inference follows the active account, for hosts that inject their own login.
#
# WHY THIS EXISTS. The pin's premise is that inference bills whatever cswap
# swapped onto disk, and for the `claude` CLI that holds: it reads the
# Keychain. Claude Desktop's Code tab does not. It spawns its bundled CLI with
# the APP's own login in CLAUDE_CODE_OAUTH_TOKEN, and under a desktop
# entrypoint Claude Code drops any settings `env` entry naming a variable the
# host set at spawn (`hostSpawnEnvKeys`) — so no configuration reaches it.
# Desktop keeps billing the account the app is signed into, and a rotation
# that moved every other client leaves it blocked on "Weekly limit reached".
#
# Its traffic still arrives HERE (the `.claude.json` env block that wires the
# pin is not a host-set key), and its User-Agent names the entrypoint, so this
# proxy is the one place that can close the gap. Opt-in, per entrypoint, and
# only on the inference routes: ownership routes keep their pinned bearer, and
# `/api/oauth/*`, usage and profile calls keep the host's own.
# ---------------------------------------------------------------------------

_INFERENCE_ROUTES = frozenset({"/v1/messages", "/v1/messages/count_tokens"})
# Seconds a read of the active credential is reused. The read goes through
# cswap's Keychain reader (a `security` subprocess, 5s timeout), and every
# Desktop turn makes several inference calls — reading per request would put
# that subprocess on the hot path. A rotation is picked up within this bound.
_ACTIVE_TOKEN_TTL_S = 30.0
# A token this close to expiry is not handed out: the swap would 401, and the
# retry would bill the host account anyway. The CLI refreshes the Keychain
# copy on its own schedule; we never refresh it (refresh tokens are
# one-time-use, and a second refresher strands every other copy).
_ACTIVE_TOKEN_MIN_LIFE_S = 60.0
_INFERENCE_STATS_FLUSH_S = 10.0
_INFERENCE_CACHE: dict = {}
_UA_ENTRYPOINT = re.compile(r"^\s*claude-cli/\S+\s+\(([^)]*)\)")


def inference_follow_entrypoints(certdir) -> "frozenset[str]":
    """Client entrypoints whose inference is re-billed to the active account.

    ``CSWAP_PIN_INFERENCE_FOLLOWS`` (comma-separated) wins; absent it,
    ``<certdir>/inference-follows`` lists one entrypoint per line, re-read at
    most every ``_TRACE_RECHECK_S`` — so the switch reaches a daemon that is
    already serving, exactly like ``trace-to``. Missing, empty or unreadable
    is OFF: this must never be the thing that breaks a request.
    """
    env = os.environ.get("CSWAP_PIN_INFERENCE_FOLLOWS")
    if env is not None:
        return frozenset(e.strip() for e in env.split(",") if e.strip())
    if certdir is None:
        return frozenset()
    key = str(certdir)
    seen, value = _INFERENCE_CACHE.get(key, (0.0, frozenset()))
    now = time.time()
    if now - seen < _TRACE_RECHECK_S:
        return value
    try:
        text = (Path(certdir) / _INFERENCE_SWITCH_FILE).read_text()
        value = frozenset(
            line.split("#", 1)[0].strip() for line in text.splitlines()
        ) - {""}
    except OSError:
        value = frozenset()
    _INFERENCE_CACHE[key] = (now, value)
    return value


def ua_entrypoint(ua: str) -> "str | None":
    """The entrypoint a Claude Code User-Agent names, or None.

    Claude Code sends ``claude-cli/<ver> (external, <entrypoint>[, …])`` on
    its API calls (binary: ``(external, ${CLAUDE_CODE_ENTRYPOINT??"cli"}…)``).
    The ``claude-code/<ver>`` form used on session routes carries no
    entrypoint and never matches, which is fine: it never reaches inference.
    """
    m = _UA_ENTRYPOINT.match(ua or "")
    if not m:
        return None
    parts = [p.strip() for p in m.group(1).split(",")]
    return parts[1] if len(parts) > 1 and parts[1] else None


def is_inference_follow_route(path: str, ua: str,
                              entrypoints: "frozenset[str]") -> bool:
    """Whether this request's bearer should become the active account's."""
    if not entrypoints:
        return False
    if path.split("?", 1)[0].rstrip("/") not in _INFERENCE_ROUTES:
        return False
    return ua_entrypoint(ua) in entrypoints


def _active_oauth_credential() -> "tuple[str | None, float | None]":
    """(access token, expiry in epoch seconds) of cswap's active account.

    Same reader as :func:`_active_oauth_token`, keeping ``expiresAt`` so a
    token about to lapse is not handed out.
    """
    try:
        sw = require("switcher").ClaudeAccountSwitcher()
        raw = json.loads(sw._read_credentials() or "{}")
        oauth_ = raw.get("claudeAiOauth") or {}
        exp = oauth_.get("expiresAt")
        return (oauth_.get("accessToken") or None,
                float(exp) / 1000.0 if exp else None)
    except Exception:  # noqa: BLE001 — never take the daemon down
        return None, None


class _ActiveTokenCache:
    """The active account's token, re-read at most every ``ttl`` seconds.

    NON-BLOCKING for everyone but the reader. A Keychain read that hangs
    (measured here: one still hung after 2d19h) must not park every Desktop
    request behind it, so a request that finds a refresh in flight uses the
    cached token if it is still good and otherwise passes through on the
    host's own bearer.
    """

    def __init__(self, reader=None, ttl: float = _ACTIVE_TOKEN_TTL_S,
                 min_life: float = _ACTIVE_TOKEN_MIN_LIFE_S):
        self._reader = reader or _active_oauth_credential
        self._ttl = ttl
        self._min_life = min_life
        self._lock = threading.Lock()
        self._token: "str | None" = None
        self._expires: "float | None" = None
        self._read_at = 0.0

    def _usable(self, now: float) -> "str | None":
        if not self._token:
            return None
        if self._expires is not None and self._expires - now < self._min_life:
            return None
        return self._token

    def get(self) -> "tuple[str | None, str]":
        """(token, reason). reason: ok | no-token | expiring | busy."""
        now = time.time()
        if now - self._read_at < self._ttl:
            tok = self._usable(now)
            return (tok, "ok") if tok else (None, self._why_not(now))
        if not self._lock.acquire(blocking=False):
            tok = self._usable(now)
            return (tok, "ok") if tok else (None, "busy")
        try:
            self._token, self._expires = self._reader()
            self._read_at = time.time()
        finally:
            self._lock.release()
        now = time.time()
        tok = self._usable(now)
        return (tok, "ok") if tok else (None, self._why_not(now))

    def _why_not(self, now: float) -> str:
        return "no-token" if not self._token else "expiring"

    def invalidate(self) -> None:
        self._read_at = 0.0


class _InferenceStats:
    """Counters for the inference-follow path, flushed to a JSON file.

    The file is how anyone checks this is working without a trace: a
    monitor reads ``swapped``/``retried`` and the timestamps. Written by a
    background thread only — the request path never opens a file (see
    `_write_capped_line` for why that rule exists).
    """

    def __init__(self, certdir):
        self._path = (Path(certdir) / f"inference-follows.{os.getpid()}.json"
                      if certdir else None)
        self._lock = threading.Lock()
        self._data = {
            "pid": os.getpid(),
            "component": _COMPONENT,
            "startedAt": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "entrypoints": [],
            "swapped": 0,
            "retriedUnswapped": 0,
            "passthrough": {"no-token": 0, "expiring": 0, "busy": 0,
                            "same-token": 0},
            "lastSwapAt": None,
            "lastRetryAt": None,
        }
        self._dirty = True
        self._thread = None

    def bump(self, key: str, sub: "str | None" = None,
             stamp: "str | None" = None) -> None:
        with self._lock:
            if sub is None:
                self._data[key] = self._data.get(key, 0) + 1
            else:
                bucket = self._data.setdefault(key, {})
                bucket[sub] = bucket.get(sub, 0) + 1
            if stamp:
                self._data[stamp] = _dt.datetime.now(
                    _dt.timezone.utc).isoformat()
            self._dirty = True
        self._ensure_flusher()

    def note_entrypoints(self, eps: "frozenset[str]") -> None:
        cur = sorted(eps)
        with self._lock:
            if cur != self._data["entrypoints"]:
                self._data["entrypoints"] = cur
                self._dirty = True
        self._ensure_flusher()

    def _ensure_flusher(self) -> None:
        if self._thread is not None or self._path is None:
            return
        t = threading.Thread(target=self._flush_loop,
                             name="inference-stats", daemon=True)
        self._thread = t
        t.start()

    def _flush_loop(self) -> None:
        self._prune()
        while True:
            self.flush()
            time.sleep(_INFERENCE_STATS_FLUSH_S)

    def _prune(self) -> None:
        """Drop other daemons' files once they are dead and a week old."""
        if self._path is None:
            return
        now = time.time()
        for f in self._path.parent.glob(_INFERENCE_STATS_GLOB):
            try:
                pid = int(f.name.split(".")[1])
                if pid == os.getpid() or _pid_alive(pid):
                    continue
                if now - f.stat().st_mtime > _INFERENCE_STATS_KEEP_S:
                    f.unlink()
            except (ValueError, IndexError, OSError):
                continue

    def flush(self) -> None:
        if self._path is None:
            return
        with self._lock:
            if not self._dirty:
                return
            snap = json.loads(json.dumps(self._data))
            snap["updatedAt"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
            self._dirty = False
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(snap, indent=2) + "\n")
            os.replace(tmp, self._path)
        except OSError:
            pass


# Claude Code's own clients. cswap's urllib callers say ``claude-swap/``.
_CLAUDE_CODE_UA = ("claude-code/", "claude-cli/")


def _is_claude_code_ua(ua: str) -> bool:
    return bool(ua) and ua.lstrip().lower().startswith(_CLAUDE_CODE_UA)


def is_pinned_route(path: str, ua: str = "") -> bool:
    """Whether a request path's bearer must be swapped to the pinned account.

    True for the routes whose server-side ownership is decided by the OAuth
    bearer — Remote-Control session lifecycle, Artifact ("frame") deploys,
    and Ultrareview (a claude.ai capability gated on the same bearer).
    False for everything else, most importantly ``/v1/messages`` (which must
    keep billing the currently-swapped inference account).

    ``/v1/sessions/<id>/...`` is the RC session-lifecycle sibling of
    ``/v1/code/sessions`` — reconnect unarchives via ``/v1/sessions/{id}/
    unarchive`` (measured). It MUST swap too: if unarchive keeps the disk
    bearer while the bridge is swapped, the session's ownership splits and the
    reconnect resolves on the disk account, so the pinned account never sees
    it. The trailing ``/`` is the boundary; the bare ``/v1/sessions`` list has its own row below.

    **The ``/worker`` subtree is deliberately excluded.** Those calls do not
    carry the OAuth token at all: the worker authenticates with a session JWT
    (binary: ``auth:"session-jwt"`` → ``Ter()``/``Kb()``), minted per session
    and carrying its own ``session_id``/``account_uuid`` claims. Swapping that
    Authorization for the pinned OAuth token makes the server reject every
    worker call — measured live as a 403 storm on ``GET/PUT .../worker`` while
    ``POST .../client/presence`` (genuinely OAuth) returned 200 in the same
    trace, leaving Remote Control stuck in a reconnect loop.

    Ownership is still pinned, because the JWT's own issuance is: ``/bridge``
    is OAuth-authenticated and IS swapped, so it mints a worker JWT for the
    pinned account (verified by decoding it). After that the JWT must travel
    untouched.
    """
    # ``client/presence`` is NOT ownership, it is REGISTRATION. It posts
    # {client_id, clear} and gets a poll interval back — it is how this CLI
    # tells the server "I am attached to this session, send me things".
    # Swapped, the server registers the PINNED account as the attached client
    # while the process actually listening is the active one, so inbound has
    # nobody to go to. The pin is about who OWNS the claude.ai-side assets, not
    # about who is sitting at the terminal. Registration must stay with the
    # account whose process will do the receiving.
    if _PRESENCE.search(path):
        return False
    if _WORKER_SUBTREE.search(path):
        return False
    # The `claude remote-control` environment lifecycle — see `_ENV_BRIDGE`.
    if _ENV_BRIDGE.search(path) and not _ENV_SDK_BETA.search(path):
        return True
    # ``/api/oauth/validate`` IS THE ROUTE THAT KEEPS A LIVE BRIDGE ALIVE
    # ACROSS A SWAP, and it is the only one here that is not about creating or
    # owning an asset — it is a QUESTION.
    #
    # Claude Code pins the bridge's owner and watches ``~/.claude.json`` for a
    # change. When cswap rotates the active account, CC sees the identity file
    # name someone else and does NOT give up: it asks the server who the new
    # credential actually belongs to (2.1.234, ``a7t()``):
    #
    #     POST ${BASE_API_URL}/api/oauth/validate
    #     Authorization: Bearer <token from ~/.claude.json>
    #
    # If the server attributes it to the bridge's owner, CC logs
    # ``[bridge:owner-pin] identity file names another account but the server
    # attributes the credential to the owner — re-baselining``, returns
    # "unchanged", and KEEPS SERVING. Otherwise it returns "changed", which
    # tears the bridge down with ``Remote Control disconnected — signed-in
    # claude.ai account or organization changed on this machine``.
    #
    # Unswapped, that question travels under the NEW account's bearer, so the
    # server answers with the NEW account and every rotation reads as a real
    # login change — killing every live bridge on the machine at once, which
    # is exactly what a user reported while this was being traced. Swapped,
    # the server sees the pinned account, the answer matches the owner, and CC
    # re-baselines instead of disconnecting.
    #
    # EXACT MATCH, NOT A ``/api/oauth/`` PREFIX. The sibling ``/api/oauth/
    # token`` is a REFRESH: it mints a credential for whoever's refresh_token
    # was sent. Swapping its bearer would mint against a different account —
    # handing one account's credential to another, which is the objection that
    # ruled out pinning ``oauthAccount`` itself.
    if path.split("?", 1)[0].rstrip("/") == "/api/oauth/validate":
        return True
    # ``/api/oauth/profile`` is pinned for Claude Code's own client and for
    # nobody else. Claude Code merges the answer into ``oauthAccount`` and
    # drops Remote Control when it names a different account than the one it
    # holds (`/login`, an account switch, a re-fetch after a rotation), so the
    # unswapped route ended every bridge on the host at each switch. cswap's
    # ``fetch_oauth_profile`` asks the same route over urllib, through the same
    # proxy vars, and must keep seeing the live account: it is the oracle that
    # decides which slot a credential belongs to. The User-Agent is the only
    # thing that tells the two callers apart.
    if _is_claude_code_ua(ua) and (
        path.split("?", 1)[0].rstrip("/") == "/api/oauth/profile"
    ):
        return True
    # ``/api/claude_code/policy_limits`` IS THE ROUTE THAT DECIDES WHETHER
    # REMOTE CONTROL IS ALLOWED AT ALL, and a wrong answer here is permanent.
    # Claude Code polls it hourly and feeds the answer into `setSessionCache`,
    # which `isPolicyAllowed("allow_remote_control")` reads. The same answer is
    # written to the machine-wide `policy-limits.json`, and the pre-fetch that
    # `/remote-control` runs first returns early when a document is already
    # cached — it opens `if (getResponseFromCache() !== null) return` — so a
    # denial that lands once
    # is never re-asked for the life of the process. No restart, no recovery,
    # and no request on the wire to see. Same reasoning as
    # ``/api/oauth/validate`` above: both are QUESTIONS about who this session
    # is, and its work travels as the pin — so the question must travel as the
    # pin too. Asking under the active account applies one org's restrictions
    # to another org's session, which is the exact thing the pin exists to
    # prevent. EXACT MATCH, not an ``/api/claude_code/`` prefix, for the same
    # reason validate is: nothing else known under that subtree is decided by
    # ownership, and a prefix would swap routes nobody has looked at.
    if path.split("?", 1)[0].rstrip("/") == "/api/claude_code/policy_limits":
        return True
    # Bridge attachments: CC fetches `/api/oauth/files/<uuid>/content` with the
    # OAuth bearer and renders any non-200 as "could not be downloaded". The
    # file belongs to the pinned account, so it must be asked for as the pin.
    # Safe as a PREFIX because it only READS — it mints and creates nothing.
    # Not `/api/oauth/`: that would sweep in `token`.
    #
    # AND THE BARE COLLECTION, which the trailing slash above kept out. That
    # exclusion was a side effect of writing the lifecycle prefix, not a
    # decision: nothing here ever said the list should answer as the active
    # account, and answering that way is what breaks cross-session messaging.
    # `GET /v1/sessions` is how Claude Code enumerates your sessions on other
    # machines -- the listing behind ListAgents and SendMessage. Traced live
    # while calling ListAgents on this host: GET /v1/sessions pinned=False
    # swapped=False  ->  200 OK so it asked the ACTIVE account, which owns none
    # of the Remote Control sessions, and the peer list came back without them.
    # The docs give one condition for a remote session to appear -- both ends
    # running with Remote Control -- and say nothing about accounts, so a pin
    # that leaves this route unswapped is the thing standing between the two. A
    # READ, like `/api/oauth/files/`: listing creates nothing and mints
    # nothing, so there is no ownership to get wrong. `== "/v1/sessions"` and a
    # query-string form only -- never a prefix, because `/v1/sessions/` already
    # has its own row above and a prefix here would say the same thing twice.
    # BOTH COLLECTIONS TAKE THE QUERY FORM, and the `/v1/code/` one lost it
    # for a commit. A paginated list is the same read as the bare one, so
    # leaving `?limit=…` unswapped asks the ACTIVE account for the pinned
    # account's sessions and gets 200 OK with the wrong contents — the exact
    # failure the `/v1/sessions` row above was written for, arriving through
    # the sibling spelling.
    #
    # THE ABSENCE THAT JUSTIFIED DROPPING IT CANNOT BE OBSERVED. It was
    # removed on "no trace shows Claude Code emitting the query form", but the
    # always-on instrument is `_note_slow_request`, and it does
    # `path.split("?", 1)[0]` — it strips the query string by design, with a
    # test asserting it does. An instrument that cannot show a thing reports
    # its absence either way.
    #
    # A `?` cannot cross a path segment boundary, so this costs nothing
    # against the guard two lines up that keeps `/v1/code/sessionsXYZ` out.
    return (
        path == "/v1/code/sessions"
        or path.startswith("/v1/code/sessions/")
        or path.startswith("/v1/code/sessions?")
        or path.startswith("/v1/sessions/")
        or path == "/v1/sessions"
        or path.startswith("/v1/sessions?")
        or path.startswith("/api/frame/")
        or path.startswith("/v1/ultrareview/")
        or path.startswith("/api/oauth/files/")
        # THE WRITE HALF OF THAT SAME PAIR, and leaving it out put every file
        # this CLI sends on the wrong account. `/api/oauth/files/` covers the
        # READ; the UPLOAD is `/api/oauth/file_upload`, which that prefix does
        # not match -- no trailing slash, different word. So the bytes went up
        # as the ACTIVE account and the browser, logged in as the PINNED one,
        # asked its own org for a uuid that was never there. Exact match plus
        # the query form, never a prefix: the neighbouring rows are exact for
        # the same reason, and `startswith("/api/oauth/file")` would silently
        # pin whatever is added beside it next.
        or path == "/api/oauth/file_upload"
        or path.startswith("/api/oauth/file_upload?")
    )


@dataclass(frozen=True)
class CertBundle:
    """Paths to the generated MITM material.

    ``ca_path`` is what the client trusts via ``NODE_EXTRA_CA_CERTS``;
    ``leaf_path``/``leaf_key_path`` back the server-side TLS context.
    """

    ca_path: Path
    leaf_path: Path
    leaf_key_path: Path


# TWO LIFETIMES, because the two certificates answer to different rules. The CA
# stays long. It is what the client trusts through NODE_EXTRA_CA_CERTS, and
# rotating it invalidates every session already wired to it — so its life
# should be as long as we can make it, not as short as the leaf's. The LEAF is
# capped by Apple. Security.framework rejects a TLS *server* certificate whose
# lifetime exceeds 398 days, issued after September 2020, with "certificate is
# not standards compliant" — and that is a rejection of SHAPE, so no CA and no
# bundle repairs it. `_make_leaf` backdates `not_valid_before` by a day, so the
# SPAN Apple measures is `_LEAF_DAYS + 1`. 397 produced a 398-day certificate —
# exactly on the cap, with no room for a clock skew either side. The previous
# single constant was justified as matching "the 10-year leaf a sibling proxy
# issues" — an argument from another implementation rather than from any client
# that has to verify ours.
_CA_DAYS = 3650
_LEAF_DAYS = 396


def ensure_ca(ca_dir: Path, host: str) -> CertBundle:
    """Generate (once) a root CA and a leaf cert for ``host`` under ``ca_dir``.

    Idempotent: an existing CA is reused, so the client keeps trusting the same
    root across restarts. The CA carries a SubjectKeyIdentifier and
    BasicConstraints CA:TRUE; the leaf carries a SAN for ``host``, serverAuth
    EKU, and an AuthorityKeyIdentifier derived from the CA. The leaf AKI is
    NOT optional here: OpenSSL (Python's ssl and Node both link it) rejects a
    leaf without one — "Missing Authority Key Identifier" — even though
    ``openssl verify`` on the file alone passes. Deriving the AKI requires the
    CA SKI, which is why the CA must carry it.
    """
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca_pem = ca_dir / "ca.pem"
    ca_key = ca_dir / "ca.key"
    leaf_pem = ca_dir / "leaf.pem"
    leaf_key = ca_dir / "leaf.key"

    # Serialized, because the CA test and the leaf test used to be independent
    # conditions over four separately-written files with nothing holding them
    # together.
    with _spawn_lock(ca_dir, name=".ca.lock"):
        if not _certs_consistent(ca_pem, ca_key, leaf_pem, leaf_key, host):
            # KEEP A CA THAT IS STILL GOOD, and re-issue only the leaf under
            # it. That argues the REVERSE case: a CA being replaced cannot keep
            # its leaf. A leaf can always be re-issued from a CA that is still
            # valid, and doing so is what keeps the client's trusted root
            # stable. It only became load-bearing when the leaf's life dropped
            # from 3650 days to 397 for Apple's cap. At 3650 the renewal fired
            # once a decade and nobody noticed the CA going with it; at 397 it
            # fires every year, and a new CA breaks every session already wired
            # to the old one. That is the one thing the pin must never do.
            reused = _load_ca_if_usable(ca_pem, ca_key)
            if reused is None:
                ca_cert, ca_priv = _make_ca()
                _write_public(
                    ca_pem, ca_cert.public_bytes(serialization.Encoding.PEM))
                _write_key(ca_key, ca_priv)
            else:
                ca_cert, ca_priv = reused
            leaf_cert, leaf_priv = _make_leaf(host, ca_cert, ca_priv)
            _write_public(leaf_pem, leaf_cert.public_bytes(serialization.Encoding.PEM))
            _write_key(leaf_key, leaf_priv)

    return CertBundle(ca_path=ca_pem, leaf_path=leaf_pem, leaf_key_path=leaf_key)


def _load_ca_if_usable(
    ca_pem: Path, ca_key: Path
) -> tuple[x509.Certificate, rsa.RSAPrivateKey] | None:
    """The CA on disk when it can still sign a new leaf, else ``None``.

    Asks about the CA ALONE. `_certs_consistent` answers "is this whole set
    usable", which is the right question for the caller and the wrong one here:
    a near-expiry leaf makes it False while the CA is perfectly good, and
    replacing that CA is what breaks every session already wired to it.

    Four ways it can be unusable, and each returns None rather than raising —
    the caller's next move is to mint a fresh CA, which is correct for all of
    them:
      - either file missing
      - the certificate does not parse
      - the key does not parse, or is not the key that signed the certificate
      - the CA is inside its own 30-day renewal window (matching
        `_certs_consistent`; a root that expires mid-session takes the session
        with it, and a leaf issued now under a CA expiring next week is not a
        repair)
    """
    try:
        cert = x509.load_pem_x509_certificate(ca_pem.read_bytes())
        priv = serialization.load_pem_private_key(
            ca_key.read_bytes(), password=None,
            unsafe_skip_rsa_key_validation=True,
        )
    except Exception:  # noqa: BLE001 — any unreadable half means "mint a new one"
        return None
    if not isinstance(priv, rsa.RSAPrivateKey):
        return None
    if priv.public_key().public_numbers() != cert.public_key().public_numbers():
        return None
    soon = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30)
    if cert.not_valid_after_utc <= soon:
        return None
    return cert, priv


def _certs_consistent(
    ca_pem: Path, ca_key: Path, leaf_pem: Path, leaf_key: Path, host: str
) -> bool:
    """Whether the four files on disk form ONE usable, unexpired set.

    Every existence test here used to stand alone, so a dir holding a CA from
    one generation and a leaf from another passed. What the client actually
    needs is a single question: does the CA it will trust sign the leaf this
    proxy will serve, for this host, today. Answering it directly also covers
    expiry — the previous code tested only ``exists()``, so a CA reaching its
    ``not_valid_after`` would have been reused forever.
    """
    try:
        if not all(p.exists() for p in (ca_pem, ca_key, leaf_pem, leaf_key)):
            return False
        ca = x509.load_pem_x509_certificate(ca_pem.read_bytes())
        leaf = x509.load_pem_x509_certificate(leaf_pem.read_bytes())
        # The check defends against an ATTACKER-supplied key (fault attacks on
        # a key you did not make); it is not a corruption check. PEM framing,
        # DER structure, and the algorithm are still parsed and still raise on
        # a truncated or foreign file, which is the only failure this function
        # is asking about. Landed in cryptography 39.0, well under the 42.0
        # floor above.
        serialization.load_pem_private_key(
            ca_key.read_bytes(), password=None, unsafe_skip_rsa_key_validation=True
        )
        lkey = serialization.load_pem_private_key(
            leaf_key.read_bytes(), password=None, unsafe_skip_rsa_key_validation=True
        )
        if lkey.public_key().public_numbers() != leaf.public_key().public_numbers():
            return False
        # Renew a month early: a cert that expires mid-session takes the
        # session with it, and regenerating is cheap.
        soon = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30)
        if min(ca.not_valid_after_utc, leaf.not_valid_after_utc) <= soon:
            return False
        # AN OVER-LONG LEAF IS UNUSABLE, not merely unfashionable. Capping
        # `_LEAF_DAYS` only affects a certificate that gets GENERATED, and
        # every install already carrying a 3650-day leaf keeps it: it is
        # unexpired, correctly signed, and has the right SAN, so every other
        # test here passes for another decade. The cap would have shipped and
        # changed nothing on the machines that actually fail — which is the
        # entire reason it exists. Security.framework rejects it outright
        # ("certificate is not standards compliant"), so for the verifier this
        # proxy has to satisfy, a leaf this long is as broken as an expired
        # one. Only the leaf. The CA is the client's trusted root, the cap does
        # not apply to it, and `ensure_ca` keeps a good one — so this rotates
        # the certificate macOS objects to without disturbing the trust anyone
        # is already wired to.
        if (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days > _LEAF_DAYS + 1:
            return False
        san = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        if host not in san:
            return False
        ca.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )
        return True
    except AttributeError as exc:
        # NOT the same as a cert failure.
        #
        # A MISSING API means the CODE is wrong for the cryptography that is
        # installed — and "regenerate" is the worst possible response: it is
        # deterministic, so it fires on EVERY launch and the daemon serves a
        # leaf under a CA the session was never handed. That is how a floor of
        # `cryptography>=41.0` turned into CERTIFICATE_VERIFY_FAILED on every
        # request, silently, for anyone whose resolver picked 41.x
        # (`not_valid_after_utc` landed in 42.0).
        #
        # BUT ONLY FOR THE VERSION MISMATCH. The same AttributeError is raised
        # by a perfectly valid cert dir that simply is not RSA — this function
        # uses `public_numbers()` and PKCS1v15, so a self-consistent Ed25519
        # pair (a restored backup, someone's own openssl run) hit the re-raise
        # too. 0.1.3 returned False there and regenerated on the next launch;
        # propagating instead kills `PinProxy.__init__`, which does NOT fail
        # open, so the daemon dies at construction and can never repair a
        # directory the previous release healed by itself. Name the API this
        # code requires. Absent -> the library moved, be loud. Present -> the
        # certs are simply of another kind, regenerate.
        if not hasattr(x509.Certificate, "not_valid_after_utc"):
            raise
        return False
    except TypeError:
        # Same reasoning, and the same narrow intent: a changed SIGNATURE in
        # the library. Anything a cert itself can cause is a cert failure.
        if not hasattr(x509.Certificate, "not_valid_after_utc"):
            raise
        return False
    except Exception:  # noqa: BLE001 — any failure to prove it means regenerate
        return False


def _write_public(path: Path, data: bytes) -> None:
    """A world-readable PEM, written whole or not at all.

    ``write_bytes`` on the live path leaves a truncated file readable by a
    concurrent reader; the temp-then-replace makes the swap atomic. The pid
    suffix is not decoration: ``O_CREAT``'s mode argument is IGNORED for a
    file that already exists, so a fixed temp name left behind by a crashed
    write would dictate the final mode and the rename would make it permanent.
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _make_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cswap pin-proxy CA")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=_CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            # OpenSSL 3 (Python 3.14's ssl, Node) rejects a signing CA that
            # lacks keyCertSign — "CA cert does not include key usage
            # extension". an openssl-generated CA happened to carry it;
            # be explicit.
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_leaf(
    host: str, ca_cert: x509.Certificate, ca_priv: rsa.RSAPrivateKey
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=_LEAF_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_priv, hashes.SHA256())
    )
    return cert, key


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    """A private key that is never briefly world-readable.

    ``write_bytes`` then ``chmod`` creates the file at the process umask —
    0644 under the usual 022 — and the complete key bytes sit at that mode
    until the chmod lands. A reader that opens the path inside that window
    keeps a valid fd afterwards, so the later chmod does not close it. The CA
    key is the one secret here whose compromise no restart can undo, so it is
    created at 0600 and never exists at anything wider. Pid-suffixed and
    O_EXCL because ``O_CREAT``'s mode is IGNORED for an existing file: a
    leftover temp from a crashed write would otherwise dictate the mode.
    """
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def resolve_pin_token(
    credentials: str,
    refresh: Callable[[str], "oauth.RefreshOutcome"],
) -> tuple[str | None, str | None]:
    """Return a live access token for the pinned account, refreshing if needed.

    ``credentials`` is the pinned account's stored credential JSON. If its
    access token is still valid the token is returned unchanged with no
    rotation (second element ``None``). If it is near/at expiry, ``refresh`` is
    invoked; on success the rotated credential JSON is returned as the second
    element so the caller can persist it, and the new access token as the
    first. On refresh failure (or no data) the token is ``None`` so the proxy
    can fall back to leaving the request's original bearer in place.
    """
    data = oauth.extract_oauth_data(credentials)
    if not data:
        return None, None
    access = data.get("accessToken")
    if access and not oauth.is_oauth_token_expired(data.get("expiresAt")):
        return access, None

    outcome = refresh(credentials)
    if not outcome.credentials:
        return None, None
    new_data = oauth.extract_oauth_data(outcome.credentials) or {}
    return new_data.get("accessToken"), outcome.credentials


def load_pin(backup_root: Path) -> tuple[str, str] | None:
    """Read the pinned account identity from settings.json.

    Returns ``(email, organizationUuid)`` or ``None`` when nothing is pinned.
    Identity is stored by (email, org) — slot numbers move (``cswap move``).
    """
    _settings = require("settings")

    raw = _settings._read_raw(_settings.settings_path(backup_root))
    section = raw.get("remoteControl")
    if not isinstance(section, dict):
        return None
    email = section.get("pinnedEmail")
    if not email:
        return None
    return email, section.get("pinnedOrganizationUuid", "") or ""


def save_pin(backup_root: Path, email: str | None, org_uuid: str | None) -> None:
    """Persist (or clear, with ``email=None``) the pin in settings.json.

    Lives in its own ``remoteControl`` section; ``save_settings`` preserves
    unknown sections, so autoswitch writes never clobber it.

    Reads through the host's WRITE-side reader, which raises on a malformed
    file instead of degrading to ``{}``. ``_read_raw``'s degrade is right for
    a read — a corrupt settings file should not stop the app — but in a
    read-modify-write it means starting from empty and then writing back only
    the pin section, silently discarding autoswitch, UI and every unknown key
    from a file that was probably still hand-recoverable.
    """
    _settings = require("settings")

    path = _settings.settings_path(backup_root)
    # ``_read_raw_for_write`` is newer than this package's floor on the host,
    # so fall back rather than fail the pin outright on an older claude-swap.
    read = getattr(_settings, "_read_raw_for_write", None) or _settings._read_raw
    raw = read(path)
    if email:
        # REBUILD WITH THE PAIR FIRST, NEIGHBOURS CARRIED IN THEIR ORDER.
        # `_read_raw_for_write` above guards the OUTER dict so a
        # read-modify-write cannot discard autoswitch, UI and every unknown
        # section. `remoteControl` is shared too: `debugSlowMs` is read here
        # and written by nobody in this function, so it must survive too.
        section = raw.get("remoteControl")
        if not isinstance(section, dict):
            section = {}
        section.pop("pinnedEmail", None)
        section.pop("pinnedOrganizationUuid", None)
        raw["remoteControl"] = {
            "pinnedEmail": email,
            "pinnedOrganizationUuid": org_uuid or "",
            **section,
        }
    else:
        # CLEARING DROPS THE PIN, NOT THE SECTION. Removing the whole thing
        # takes every neighbouring key with it, which is the same deletion by
        # a different route.
        section = raw.get("remoteControl")
        if isinstance(section, dict):
            section.pop("pinnedEmail", None)
            section.pop("pinnedOrganizationUuid", None)
            if not section:
                raw.pop("remoteControl", None)
        else:
            raw.pop("remoteControl", None)
    # ORDER PRESERVED, never sorted: the pair is written first and every
    # neighbour follows in its prior order. A pin is therefore a fixed point —
    # a file the old code left pair-last is normalised ONCE, on its next pin,
    # to the dotfiles record's order, and stays byte-stable after that.
    _settings.atomic_write_json(path, raw)


def live_remote_control_sessions() -> list[str]:
    """Names of sessions that currently hold a Remote Control binding.

    Ownership of an RC session is fixed by the bearer that created it, so a
    re-pin cannot move one that is already open — reconnecting inside it can
    (that mints a new session under the new pin). Knowing which sessions those
    are is what lets `cswap pin` say so instead of guessing.

    Claude Code records one file per live session with a ``bridgeSessionId``
    that is set only while RC is connected. Best-effort: an unreadable or
    absent registry just yields nothing.

    THE CLEARED POINTER COUNTS TOO, and this is the reader where omitting it
    costs the most: a teardown blanks that field and CC does not rewrite it
    when the bridge returns, so the session this exists to WARN about would
    drop out and `cswap pin` would report nothing to reconnect. Silence here
    is read as "nothing is affected", which is the one answer it must not give
    by accident. ``_live_bridge_records`` states the job-record join.
    """
    get_claude_config_home = require("paths").get_claude_config_home
    home = get_claude_config_home()

    names: list[str] = []
    try:
        entries = sorted((home / "sessions").glob("*.json"))
    except OSError:
        return names
    for path in entries:
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        bridge, job = rec.get("bridgeSessionId"), rec.get("jobId")
        if not bridge and job:
            st = _read_json(home / "jobs" / str(job) / "state.json")
            bridge = (st or {}).get("bridgeSessionId")
        if bridge:
            names.append(str(rec.get("name") or rec.get("sessionId") or path.stem))
    return names


def _live_bridge_records() -> list[tuple[str, str | None, str | None]]:
    """``(bridge id, name, nameSource)`` for every session alive here.

    A record alone is not liveness: Claude Code leaves the file behind when a
    session dies, so the registry accumulates — once measured at 562 records
    against 16 live processes. Treat the ratio as the point and not the
    numbers: the same host later read 16 records with 15 alive, so a census
    frozen here goes stale faster than anyone rereads it.

    The name comes back unfiltered — ``None`` included — because the three
    callers need different things from it and one of them must not drop a
    nameless session (see ``_live_bridge_ids``).

    ``nameSource`` rides along rather than being re-read by a parse of its
    own: it is already in the record this reads. NOT a saving in I/O -- a
    caller wanting names AND provenance still calls two functions that each
    walk the directory. What it removes is a SECOND PLACE that decides what a
    session record means, which is the half that goes stale.

    THE PAIRING IS A TWO-FILE JOIN, and the callers' "one record, one live
    pid" wording predates that. Claude Code clears the registry's
    ``bridgeSessionId`` on RC teardown and does not rewrite it when the bridge
    returns, so the id can only be recovered from the job record. An id
    sourced that way says the session HELD it, not that the server still has
    it -- bounded at one sweep, since ``clear_dead_bridge_records`` writes
    ``""`` there for a bridge the listing no longer carries.

    SORTED, because a resume leaves the old registry record beside the new one
    and the join can make both resolve to one bridge.
    """
    get_claude_config_home = require("paths").get_claude_config_home

    out: list[tuple[str, str | None, str | None]] = []
    try:
        entries = sorted((get_claude_config_home() / "sessions").glob("*.json"))
    except OSError:
        return out
    for path in entries:
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        bridge, pid = rec.get("bridgeSessionId"), rec.get("pid")
        if not isinstance(pid, int) or not _pid_alive(pid):
            continue
        if not bridge:
            # CLEARED ON TEARDOWN AND NOT REWRITTEN when the bridge returns, so
            # a live session with a live bridge reads here as having none. The
            # JOB record keeps the id across that and the registry names the
            # job, so this is a two-file join rather than one record — see
            # `_live_bridge_records`' own contract note above.
            #
            # NOT WRITTEN BACK FROM THE WIRE, which is the obvious alternative:
            # the new id exists only in the RESPONSE to `POST /v1/code/
            # sessions`, and this proxy hooks that route on the REQUEST path and
            # streams the response through unparsed. Attribution is the second
            # wall (no portable pid-from-socket here), not the first.
            job = rec.get("jobId")
            st = _read_json(get_claude_config_home() / "jobs" / str(job)
                            / "state.json") if job else None
            bridge = (st or {}).get("bridgeSessionId")
            if not bridge:
                continue  # never had one, or swept; naming it invents a pairing
        name = rec.get("name")
        source = rec.get("nameSource")
        out.append((str(bridge), str(name) if name else None,
                    str(source) if source else None))
    return out


def _both_spellings(bridge: str) -> tuple[str, str]:
    """The API renames the id it hands back: ``session_…`` here, ``cse_…``
    in the listing. Every lookup has to work either way round."""
    return bridge, bridge.replace("session_", "cse_")


# The same two facts under two spellings, because Claude Code keeps ONE bridge
# pointer in TWO stores and picks by whether `CLAUDE_JOB_DIR` is set: `Ekw`
# writes `~/.claude/jobs/<jobId>/state.json`, `Rsr` appends a `bridge-session`
# record to the transcript. A carry that knows only the transcript reaches
# almost nobody; one that knows only the job record strands every session
# resumed interactively, so both are needed.
_TRANSCRIPT_OWNER = ("ownerAccountUuid", "ownerOrganizationUuid")
_JOB_OWNER = ("bridgeOwnerAccountUuid", "bridgeOwnerOrganizationUuid")
# Keyed by VALUE, not identity. `owner_keys is _TRANSCRIPT_OWNER` looked
# equivalent and fails open: an equal-but-distinct tuple makes `other` the pair
# itself, and the wrong-pair guard degenerates to `not x and x` — permanently
# false, in the one direction it exists to catch.
_OTHER_OWNER = {_TRANSCRIPT_OWNER: _JOB_OWNER, _JOB_OWNER: _TRANSCRIPT_OWNER}


def _login_identity() -> tuple[str, str] | None:
    """``(accountUuid, organizationUuid)`` of the login, or None.

    The identity Claude Code compares a bridge pointer against, read from the
    same file it reads. cswap rewrites this on every account switch, which is
    the whole reason the pointer goes stale.

    THROUGH THE RESOLVER, NOT ``Path.home()``. This first hardcoded
    ``~/.claude.json`` while everything else in the sweep enumerates from
    ``get_claude_config_home()``, so wherever ``CLAUDE_CONFIG_DIR`` is set the
    two disagree: it read the DEFAULT profile's login while walking the
    ISOLATED profile's sessions and stamped one account's pointers with
    another's. That does not miss a fix, it manufactures the fault — a pointer
    that already agreed is rewritten until it disagrees, and its session is
    vetoed on a launch that would otherwise have reattached cleanly.

    WHICH CALLER, stated precisely because an earlier draft named the wrong
    one. It is NOT ``cswap run``: the host puts ``CLAUDE_CONFIG_DIR`` only in
    the CHILD's env dict, never in ``os.environ``, so `wire_launch_env` runs
    with the default profile on both sides and is self-consistent. The split
    happens one hop further in — a ``heal`` fired from INSIDE a session-mode
    `claude`, whose environ does carry it. The resolver also knows about the
    legacy ``.config.json``, which this had no chance of finding.
    """
    raw = _read_json(require("paths").get_global_config_path()) or {}
    acct = raw.get("oauthAccount")
    if not isinstance(acct, dict) or not acct.get("accountUuid"):
        return None
    return str(acct["accountUuid"]), str(acct.get("organizationUuid") or "")


def _carry_pointer(record: dict, login: tuple[str, str],
                  owner_keys: tuple[str, str]) -> dict | None:
    """The pointer restamped with the CURRENT login, or None to leave it alone.

    THE FAULT. At launch Claude Code hydrates a bridge pointer and compares the
    owner it carries against ``~/.claude.json``'s ``oauthAccount``:

        bt = Boolean(Qe.ownerAccountUuid)
        if (bt && _t?.accountUuid && !Pne(_t, {accountUuid: …, organizationUuid: …}))
            -> "reattach vetoed … minting fresh, history channels suppressed"

    ``Pne`` requires both uuids. CC stamps that field with its OWN login rather
    than the bearer this proxy swapped in, so cswap rotating the active account
    between two runs of one session is enough to veto a bridge that was
    perfectly reattachable — measured, 14 of 14 live sessions in that state.

    WHY RESTAMP RATHER THAN REMOVE, which is what this did first. Removing the
    owner also clears the veto (``bt`` gates it), but look at what it costs::

        if (!He) { He = Qe.id, Oe = Qe.seq;
                   if (!Ir || !hzs()) Ke = true;      // Ir = owner MATCHES login
                   … `${Ke ? "reattach-or-fail" : "fresh-mint fallback"}` }

    No owner means ``Ir`` false means ``Ke`` true: **reattach-or-fail, with the
    fresh-mint fallback switched off.** So a pointer naming a bridge that is
    gone — deleted by another machine's sweep, by `/cleanup-rc`, or from
    claude.ai — stops being "you get a new bridge" and becomes "you get no
    Remote Control at all". Proving the bridge still exists would need the
    pin's own token and a network call on the launch path, and any cached proof
    is a window in which that answer can go wrong.

    A MATCHING owner has neither problem. ``Ir`` is true, so CC reattaches with
    ``restored_owner_match`` and keeps the fallback it would have used anyway.
    A wrong guess then costs a fresh mint, which is exactly today's behaviour —
    which is why nothing here has to prove who owns a bridge, and why there is
    no cache to go stale.

    ONE CAVEAT, VISIBLE IN THE SNIPPET ABOVE: the fallback also depends on
    ``hzs()``, a statsig gate (``tengu_sequential_puffin``) whose ``true`` is
    only a client-side default. If it is ever turned off, a MATCH also yields
    reattach-or-fail. That is not a reason to prefer removing the owner —
    removing it fails that way unconditionally, matching only if the gate
    flips — but the guarantee is Anthropic's to keep, not ours to assert.

    WHAT IT DOES NOT RECOVER. ``noHistoryBackfill`` is copied through, and
    ``if (Qe.noHistoryBackfill) le = true`` runs on the reattach branch too, so
    a pointer carrying it reattaches with history channels still suppressed —
    12 of 12 job records here carry it, and CC ORs it forward so it never
    clears. What this restores is the bridge itself: same conversation, same
    name, same sequence position, instead of a new one under an invented title.
    Clearing the flag would push transcript history to the server, which is not
    this proxy's call to make.
    """
    if not record.get("bridgeSessionId"):
        # `clearBridgeSession` appends `bridgeSessionId: ""` to say this
        # conversation has no bridge. Pointing it at one would undo that.
        return None
    account, org = login
    if record.get(owner_keys[0]) == account \
            and (record.get(owner_keys[1]) or "") == org:
        return None  # already matches; rewriting it every launch would never stop
    # AN OWNERLESS POINTER IS STAMPED TOO, which the first version declined on
    # the grounds that `bt` gates the veto so it "already reattaches". Half
    # right: no veto, but `Ir = bt && Pne(…)` is false as well, so
    # `if (!Ir || !hzs()) Ke = true` — reattach-or-fail with the fresh-mint
    # fallback OFF, the exact state the argument above exists to avoid. It is
    # therefore the case where stamping helps most, not the one to skip.
    #
    # ...WHICH COSTS THE ONE SIGNAL THAT CAUGHT A WRONG KEY PAIR. Before, a job
    # record read with the transcript spelling looked ownerless and returned
    # None; now it would look ownerless and get transcript-shaped keys grafted
    # onto it. The two vocabularies are mutually exclusive in a real record, so
    # carrying the OTHER store's owner is proof this pair is the wrong one.
    had_owner = bool(record.get(owner_keys[0]))
    other = _OTHER_OWNER.get(owner_keys, owner_keys)
    if not had_owner and record.get(other[0]):
        return None
    # NOTHING IS ADDED BESIDE THE OWNER — and one draft did add something. It
    # wrote `noHistoryBackfill: True` on the ownerless branch, reasoning that
    # stamping makes `Ir` true and so disables the host-directed arm's
    # `else le = true` ("attaching with history channels suppressed"). That arm
    # needs `He` truthy, `He` is `reattachSessionId`, and at a LAUNCH — the
    # only moment this write is read — it is undefined. The arm was
    # unreachable; the suppression it protected did not exist.
    #
    # What the flag did reach is one line higher and fires on every branch:
    # `if (Qe.noHistoryBackfill) le = true`. That costs the conversation's
    # messages (`initialMessages: le ? void 0 : A`), and the name — the title
    # block is `else if (!le)`, so the session gets `<host>-<adj>-<noun>`, the
    # invented name this whole feature exists to stop. And permanently: CC
    # latches it into `M.current` and writes it back on every connect.
    #
    # An ownerless pointer already reattaches with its history and its name.
    # The stamp alone adds the fresh-mint fallback. There was nothing to
    # protect and something to lose.
    out = {**record, owner_keys[0]: account}
    # AN EMPTY ORGANIZATION IS NOT AN ORGANIZATION, and writing one would undo
    # the whole fix. BOTH stores validate the pair against a uuid regex — the
    # transcript scanner and the job-record schema's own transform — and drop
    # BOTH fields when either fails, so `""` discards the perfectly good
    # account uuid beside it and lands back in the ownerless shape above.
    # Omission is what `Rsr` itself writes, and `Pne` normalizes absent,
    # `null` and `""` alike, so an org-less login still matches an org-less
    # pointer.
    out.pop(owner_keys[1], None)
    if org:
        out[owner_keys[1]] = org
    return out


# How much of a transcript's tail to read looking for the pointer. This is a
# BOUND on the launch path, not a search, and two of the twelve have nothing in
# this window. Finding nothing is "skip", never "there is no pointer".
_POINTER_TAIL_BYTES = 65536


def _log_carry(certdir: Path, what: str) -> None:
    """Append one carry event to the daemon log, with a timestamp.

    NOT ``_log_lifecycle``, which writes to stderr. That is right for the
    daemon, whose stderr IS ``daemon.log`` — but this sweep runs in the
    LAUNCHING CLI, moments before ``os.execvpe``, so its stderr is the user's
    terminal and Claude Code paints over it immediately. A record of what was
    written into Claude Code's own files has to outlive the launch that wrote
    it, or the comment justifying it is not true.
    """
    try:
        with daemon_log_path(certdir).open("a", encoding="utf-8") as fh:
            fh.write(f"[{_iso_utc(time.time())}] {_COMPONENT} carry: {what}\n")
    except OSError:
        pass


def _read_json(path: Path):
    """Parsed JSON object at ``path``, or None for anything else."""
    try:
        out = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return out if isinstance(out, dict) else None


def _live_session_ids() -> list[str]:
    """Session ids of processes that are alive, from the registry."""
    out: list[str] = []
    try:
        home = require("paths").get_claude_config_home()
        for path in (home / "sessions").glob("*.json"):
            rec = _read_json(path)
            if not isinstance(rec, dict):
                continue
            pid, sid = rec.get("pid"), rec.get("sessionId")
            if not pid or not sid:
                continue
            try:
                os.kill(int(pid), 0)
            except Exception:  # noqa: BLE001
                continue
            out.append(str(sid))
    except Exception:  # noqa: BLE001
        return []
    return out


def _live_job_pids() -> dict[str, int]:
    """Job id -> pid of the LIVE process that owns it, from the registry.

    `_live_job_ids` is this with the pid dropped, kept for its own callers
    that never needed it.
    """
    out: dict[str, int] = {}
    try:
        home = require("paths").get_claude_config_home()
        for path in (home / "sessions").glob("*.json"):
            rec = _read_json(path)
            if not isinstance(rec, dict):
                continue
            pid, job = rec.get("pid"), rec.get("jobId")
            if not pid or not job:
                continue
            try:
                os.kill(int(pid), 0)
            except Exception:  # noqa: BLE001 — gone, or not ours to signal
                continue
            out[str(job)] = int(pid)
    except Exception:  # noqa: BLE001 — no host, nothing to enumerate
        return {}
    return out


def _live_job_ids() -> list[str]:
    """Job ids of sessions with a LIVE process, from the registry.

    The opposite selection to `_carry_candidates`, which takes only sessions
    with NO process. Both are needed: that one keeps an ended session's bridge
    across a rotation, this one keeps a RUNNING session's reattach possible.
    """
    return list(_live_job_pids())


def _carry_candidates() -> list[tuple[str, str | None]]:
    """``(session id, job id)`` for sessions with a bridge and no process.

    ENUMERATED FROM THE JOB DIRS, NOT THE REGISTRY. Claude Code garbage-collects
    the registry itself — every enumeration unlinks records whose pid is gone,
    and its callers include the resume picker — so "a dead registry record" is a
    set that empties itself. Measured: 15 of 15 registry records had a LIVE pid
    while 12 job dirs sat on disk. Keying on the registry would have found
    nobody and looked exactly like a fix with nothing to do.

    LIVENESS IS KEYED ON THE JOB ID, NOT THE JOB RECORD'S OWN SESSION ID, and
    that distinction is the difference between this and rewriting a running
    session's state. `state.json` keeps the id the job was CREATED with; a
    resume writes the NEW id into `resumeSessionId` and into the registry and
    leaves `sessionId` alone. Measured: job `bbc76cfa` reads `sessionId=bbc76cfa`
    with `resumeSessionId=1e49df17`, and 1e49df17 is alive on pid 465486 with
    three tasks in flight. Comparing session ids called that job ENDED, so the
    first version of this had exactly one candidate on this machine and it was
    a live session. Comparing job ids gives the true answer: 0.
    """
    get_claude_config_home = require("paths").get_claude_config_home
    home = get_claude_config_home()
    live: set[str] = set()
    found: dict[str, str | None] = {}

    for path in (home / "sessions").glob("*.json"):
        rec = _read_json(path)
        if not rec:
            continue
        sid, pid, job = rec.get("sessionId"), rec.get("pid"), rec.get("jobId")
        if not sid:
            continue
        if isinstance(pid, int) and _pid_alive(pid):
            # Both keys go in one set: a session uuid and a job id cannot
            # collide, and if they somehow did the only effect is skipping a
            # candidate, which is the safe direction.
            live.add(str(sid))
            if job:
                live.add(str(job))
        elif rec.get("bridgeSessionId") and not job:
            # No job dir: the pointer is in the transcript. One of thirteen
            # here — and the one covering a foreground `claude`, which has no
            # CLAUDE_JOB_DIR at all.
            found[str(sid)] = None

    for path in (home / "jobs").glob("*/state.json"):
        st = _read_json(path)
        if not st or not st.get("bridgeSessionId"):
            continue
        job = path.parent.name
        # THE RESUMED ID IS THE ONE WITH A LIVE TRANSCRIPT. `sessionId` is the
        # id the job was CREATED with and a resume never rewrites it — it puts
        # the new id in `resumeSessionId`, and that id has its OWN transcript
        # file. Keying the transcript half on the created id restamps a dead
        # file and leaves the live one vetoed — the exact fault the both-stores
        # fix exists to close, reintroduced through the id rather than the
        # store. Both are offered; whichever has a pointer gets it.
        for sid in (st.get("resumeSessionId"), st.get("sessionId")):
            if not sid or job in live or str(sid) in live:
                continue
            # A job record OVERWRITES a transcript-only entry rather than
            # deferring to it: with both stores now written, naming the job is
            # strictly more work done, and `setdefault` here would leave a job
            # record unfixed whenever its session also has a jobId-less
            # registry record.
            found[str(sid)] = job
    return list(found.items())


def _carry_job_record(job_id: str, login: tuple[str, str]) -> bool:
    """Restamp a background session's job record. True when it changed.

    The store Claude Code uses whenever ``CLAUDE_JOB_DIR`` is set, which here is
    12 of 13 live Remote Control sessions. Rewritten whole rather than appended
    to, so every key the harness owns is copied through untouched.

    NOT ``settings.atomic_write_json``, which chmods the PARENT to 0700 — this
    parent is Claude Code's job directory, not ours to narrow. The file's own
    0600 is preserved by hand instead: CC writes it ``mode:384``, and matching
    that is the point — ``~/.claude`` is 0700 here so no other user can
    traverse in today, which makes the narrower mode a defence that costs
    nothing rather than a wall holding something back.
    """
    # ponytail: read-modify-write with no lock, self-healing at the next
    # connect. Ceiling — the job's own process writes this file too (`Ekw`,
    # `ojh`), and the two overlap only in the narrow windows where it is alive
    # but not yet in the registry, or gone from the registry and still writing.
    # A lost update there overwrites a fresh `bridgeSessionId`/`Seq` with the
    # stale one and costs the next respawn one reattach. Upgrade path: take the
    # same re-read-after-write CC uses, if that window is ever observed firing.
    get_claude_config_home = require("paths").get_claude_config_home
    path = get_claude_config_home() / "jobs" / job_id / "state.json"
    state = _read_json(path)
    if state is None:
        return False
    out = _carry_pointer(state, login, _JOB_OWNER)
    if out is None:
        return False
    # DOT-PREFIXED AND PID-SUFFIXED. Claude Code watches this directory with
    # `if (u && !u.startsWith("state.json")) return;` — a `state.json.tmp` name
    # passes that filter and wakes the watcher for a file that is not the
    # state; a leading dot does not. The pid keeps two concurrent launches on
    # one job dir from writing the same temp.
    tmp = path.with_name(f".state.json.cswap-{os.getpid()}")
    try:
        # 0600 AT CREATION, not after. `write_text` makes the file 0644 under
        # the usual umask and the content is already on disk before a later
        # chmod narrows it — a window, however short, on a file holding account
        # uuids and the session's output tail.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        tmp.replace(path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass  # a temp we cannot remove must not abort the whole sweep
        return False
    return True


def _last_pointer(session_id: str) -> tuple[Path, dict] | None:
    """The transcript and its last ``bridge-session`` record, from the tail.

    ONE SESSION ID CAN NAME TWO FILES, and when it does this declines rather
    than picking. Measured on this account, 1 duplicate in 1869 ids: a 7.3 MB
    transcript under one project and a 146-byte stub under another, and only
    the stub holds a pointer — so "exactly one candidate carries a pointer" is
    both the safe rule and, at 0 ambiguous candidates today, a free one.

    The alternative was to derive the project directory from the session's
    ``cwd``. That rule belongs to Claude Code, and a copy of it drifts in
    silence: the registry's ``cwd`` for a worktree session is the repo root
    while the transcript is filed under the worktree path, so the derived name
    missed a real session on the first machine it was tried on.
    """
    get_claude_config_home = require("paths").get_claude_config_home
    found: list[tuple[Path, dict]] = []
    # A guard here would also make `_carry_history_pointers`' stated reason for
    # its outer catch-all untrue.
    for path in (get_claude_config_home() / "projects").glob(f"*/{session_id}.jsonl"):
        try:
            with path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - _POINTER_TAIL_BYTES))
                lines = fh.read().split(b"\n")
        except OSError:
            continue
        for raw in reversed(lines):
            if b"bridge-session" not in raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue  # also swallows the leading partial line
            if not isinstance(rec, dict) or rec.get("type") != "bridge-session":
                continue
            if rec.get("sessionId") not in (None, session_id):
                # A transcript holds one session's records today, so this is
                # latent — but if that ever stops holding, restamping X while
                # appending to Y's file counts a carry that fixed nobody.
                continue
            found.append((path, rec))
            break
    return found[0] if len(found) == 1 else None


def _pointer_owner(certdir) -> "tuple[str, str] | None":
    """The account a live bridge pointer must name: the PIN when there is one.

    A bridge is minted as the pin (`/v1/code/sessions` is swapped), so that is
    who owns it server-side, and `/api/oauth/validate` answers the same. Stamp
    the login instead and the two disagree the moment the config returns to
    the pin: CC compares owner against file, asks validate, hears the pin,
    finds it is not the owner it recorded, and tears the bridge off --
    measured, four live sessions in three seconds. Without a pin the login is
    the owner and the pointer follows it, as before.
    """
    ident = remembered_pin_identity(certdir) if certdir is not None else None
    if ident and ident.get("accountUuid"):
        return (str(ident["accountUuid"]),
                str(ident.get("organizationUuid") or ""))
    return _login_identity()


def carry_live_pointers(login: "tuple[str, str]") -> int:
    """Point a RUNNING session's bridge record at the account that owns it.

    ``login`` is what the caller resolved through :func:`_pointer_owner`: the
    pin when one is set, else the account signed in.

    WHY THIS EXISTS BESIDE `_carry_history_pointers`. That one is documented
    "for sessions with a bridge and NO PROCESS" and means it — measured, it
    returned 0 candidates on a host where one live session's pointer named
    a dead account and was the only session being refused Remote Control.
    Claude Code compares that pointer to `~/.claude.json`'s `oauthAccount`;
    on a mismatch it will not reattach, it MINTS — and minting is the path
    the org-policy gate can refuse.

    THE RACE THAT JUSTIFIED EXCLUDING LIVE SESSIONS IS HANDLED BY SCOPE,
    not by a lock. The session's own process writes `bridgeSessionId` and
    `lastSequenceNum` to this file; this writes ONLY the two owner fields,
    and re-reads immediately before the rename so every other field comes
    from the freshest copy on disk. A lost race therefore costs one sweep
    of ours and nothing of theirs — the opposite of the read-modify-write
    that made excluding them the safe choice.

    NO WRITE WHEN IT ALREADY AGREES: this runs on a beat, and rewriting a
    correct record every pass is contention on a file its owner is also
    writing, bought for nothing.

    `bridgeOwnerAccountUuid` HAS TWO WRITERS THAT MEAN OPPOSITE THINGS, and
    anything reading it has to say which one it wants. Claude Code writes
    the bridge's true server-side owner while a session runs. This writes
    the account now SIGNED IN, so CC's local comparison agrees and it
    reattaches instead of minting. Neither is wrong; they answer different
    questions.

    So a reader must pick, and the two questions want opposite values:

        reattach-or-mint    the LOGIN. CC compares the stored pointer to
                            `~/.claude.json`'s `oauthAccount`, never to the
                            pin, and mints on a mismatch.
        who owns the bridge the PIN. The pin re-asserts its identity on the
                            request that mints one, so that is who the
                            bridge belongs to server-side.

    Three separate readers have already taken the wrong one, which is what
    makes this worth stating here rather than at any one of them: a
    reattach path that compared against the pin, a disconnect path that
    compared against the login, and an external gate that graded THIS
    function's deliberate output as a veto risk. All three read a field
    whose value was correct.

    A fourth reader will arrive. If it asks "does this pointer match what
    CC will compare it against", it wants the login and this function's
    output is the answer. If it asks "whose bridge is this", it wants the
    pin and must not read this field at all while a session is live.
    """
    account, org = login
    if not account:
        return 0
    # NO PIN-ORG GUARD HERE, and that is deliberate. The launch-path carry
    # refuses when the pin's org differs from the login's; copying that
    # here made this a no-op in the NORMAL case, because a pin account that
    # differs from the active account is not an anomaly — it is the entire
    # point of the pin. Refusing there refuses the state the feature exists
    # to serve.
    #
    # The server side is already handled and not by this stamp:
    # `/api/oauth/validate` is a pinned route, so when Claude Code asks who
    # the current credential belongs to, the answer comes back as the
    # PINNED account and CC re-baselines instead of tearing the bridge
    # down. This stamp only has to make the LOCAL comparison agree so a
    # reattach is attempted at all.
    home = _config_home_for_policy()
    carried = 0
    for job in _live_job_ids():
        path = home / "jobs" / job / "state.json"
        rec = _read_json(path)
        if not isinstance(rec, dict) or not rec.get("bridgeSessionId"):
            continue
        if rec.get(_JOB_OWNER[0]) == account and \
                (rec.get(_JOB_OWNER[1]) or "") == (org or ""):
            continue
        fresh = _read_json(path)          # re-read: theirs wins on the rest
        if not isinstance(fresh, dict) or not fresh.get("bridgeSessionId"):
            continue
        fresh[_JOB_OWNER[0]] = account
        fresh[_JOB_OWNER[1]] = org
        tmp = path.with_name(f".state.json.cswap-{os.getpid()}")
        try:
            tmp.write_text(json.dumps(fresh), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            continue
        carried += 1
    # THE OTHER STORE, and leaving it out is why the first cut of this
    # changed nothing for the session it was written for. `_carry_history_
    # pointers` writes BOTH and says why: an interactive resume has no
    # CLAUDE_JOB_DIR, so Claude Code reads the TRANSCRIPT.
    for sid in _live_session_ids():
        found = _last_pointer(sid)
        if not found:
            continue
        path, rec = found
        out = _carry_pointer(rec, (account, org), _TRANSCRIPT_OWNER)
        if out is None:
            continue
        try:
            # O_APPEND and the newline check, exactly as the launch-path
            # carry does it: a transcript truncated mid-write ends without
            # one, and appending there would fuse two records into a line
            # neither side can parse.
            with path.open("a+b") as fh:
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":
                    fh.write(b"\n")
                fh.write(json.dumps(out).encode("utf-8") + b"\n")
        except OSError:
            continue
        carried += 1
    if carried:
        _log_lifecycle(
            f"carried {carried} running session(s) bridge pointer onto the "
            f"account that owns them")
    return carried

def _carry_history_pointers(certdir: Path) -> int:
    """Let sessions that are not running keep their bridge across a rotation.

    See :func:`_carry_pointer` for what the stamp does and why matching beats
    removing. This is the sweep that applies it, on the LAUNCH path: the
    pointer has to agree with the login before Claude Code reads it, and at
    that moment the session about to be resumed is the ended one.

    IT IS GLOBAL, not scoped to the session being launched: every idle
    session's pointer is set to whatever account is live at this launch. That
    is self-correcting for anything started through cswap, since the next
    launch restamps again, and background respawns read the job record this
    just fixed. It is NOT self-correcting for a bare ``claude --resume`` or an
    IDE integration that never runs this hook — those get whatever the last
    cswap launch left, which is still strictly better than the veto.

    NEVER RAISES, and that is load-bearing rather than tidy. The caller wraps
    ``ensure_proxy`` in ``except Exception: pass`` and then falls through to
    clearing the wiring — so an exception here does not skip the carry, it
    skips the daemon spawn and unpins the machine. ``require`` raises
    ``HostMissing`` and ``Path.glob`` raises ``ValueError``, neither of which
    the inner handlers catch, hence the outer one.
    """
    carried: list[str] = []
    try:
        login = _login_identity()
        if login is None:
            return 0  # no readable login: nothing to agree with
        # A PIN ON ANOTHER ORG MEANS THE STAMP WOULD LIE, so do not stamp. So
        # restamping to a login that does not own it hands CC a bridge it
        # cannot use — and the veto this sweep exists to defeat was the thing
        # keeping that failure down to "lose the history". A lost history is
        # survivable, a 500 is not.
        #
        # KEYED ON THE PIN, not on the bridge's owner, because the owner is the
        # thing this file deliberately never proves (see `_carry_pointer`: it
        # would need a network call on the launch path). The pin's org is on
        # disk and free to read, and a pin naming a different org is sufficient
        # evidence that a bridge minted under it will not match this login.
        # Unpinned machines keep the carry unchanged.
        pin = load_pin(Path(certdir).parent)
        if pin and pin[1] and pin[1] != login[1]:
            return 0
        for sid, job in _carry_candidates():
            # BOTH STORES, NOT WHICHEVER ONE ANSWERED FIRST. Writing both costs
            # nothing — a record that already agrees returns None and is not
            # rewritten.
            if job and _carry_job_record(job, login):
                carried.append(f"{job}(job)")
            found = _last_pointer(sid)
            if not found:
                continue
            path, rec = found
            out = _carry_pointer(rec, login, _TRANSCRIPT_OWNER)
            if out is None:
                continue
            try:
                # O_APPEND, so a second launch appending at the same moment
                # cannot land on the offset this one computed. The seek is only
                # to read the last byte: a transcript truncated mid-write ends
                # without a newline, and appending to that would concatenate
                # two records into one line neither side can parse.
                with path.open("a+b") as fh:
                    fh.seek(-1, os.SEEK_END)
                    if fh.read(1) != b"\n":
                        fh.write(b"\n")
                    fh.write(json.dumps(out).encode("utf-8") + b"\n")
            except OSError:
                continue
            carried.append(sid[:8])
    except Exception:  # noqa: BLE001 — see the docstring: a raise unpins the box
        _log_carry(certdir, "the bridge-pointer carry stopped early after "
                            f"{len(carried)} record(s)")
    if carried:
        # WRITING INTO CLAUDE CODE'S OWN FILES LEAVES NO OTHER TRACE. The
        # appended line is deliberately shaped like one CC writes, so without
        # this nothing afterwards can say what touched what.
        _log_carry(certdir, "restamped the bridge pointer for "
                            + ", ".join(sorted(carried)))
    return len(carried)


def _outbound_only_bridge_ids() -> set[str]:
    """Bridges whose record says they hold no inbound stream BY DESIGN.

    `bridgeOutboundOnly` is an input to Claude Code's reattach and is False or
    absent on every record this fleet has written so far; when a build starts
    setting it, such a bridge posts and never opens the event stream, which is
    exactly the shape the deaf report names. Excluding them here is a no-op
    until then, so absent/False stays byte-identical to today.
    """
    out: set[str] = set()
    try:
        home = _config_home_for_policy()
        paths = list((home / "jobs").glob("*/state.json")) + \
            list((home / "sessions").glob("*.json"))
    except Exception:  # noqa: BLE001 — no host, nothing to read
        return out
    for path in paths:
        rec = _read_json(path)
        if isinstance(rec, dict) and rec.get("bridgeOutboundOnly") is True \
                and rec.get("bridgeSessionId"):
            out.update(_both_spellings(str(rec["bridgeSessionId"])))
    return out


def _live_bridge_ids() -> set[str]:
    """Bridge ids whose owning process is still alive on THIS machine.

    NAMELESS SESSIONS COUNT. This set is the sweep's negative guard — never
    close something running here — so a session that never took a name is
    exactly as protected as one that did.
    """
    live: set[str] = set()
    for bridge, _name, _src in _live_bridge_records():
        live.update(_both_spellings(bridge))
    return live


#: OUR OWN FIELD, stamped into Claude Code's `jobs/<id>/state.json` next to
#: `bridgeSessionId` -- nothing else in this codebase keeps a record mapping
#: a bridge to its creating pid, so `_dead_creator_bridge_ids` has to make
#: one before it can ever read one back.
_CREATOR_PID_KEY = "cswapPinCreatorPid"

#: The same binding, kept IN MEMORY. Claude Code removes `jobs/<id>/`
#: whole once it settles a job -- sometimes inside a second of the creator
#: dying -- taking the file-only stamp with it before anything ever reads
#: it back. This copy is what survives that removal; it does not survive a
#: restart of THIS process, so a successor after a handover still depends
#: on the file for whatever job records it inherits.
_creator_pid_by_bridge: dict[str, int] = {}


def _dead_creator_bridge_ids(stamp: bool = True) -> set[str]:
    """Bridge ids named in a job record THIS HOST wrote, whose creating
    process is CONFIRMED gone -- POSITIVE evidence only.

    `_live_job_ids` / `_live_bridge_ids` condemn by SUBTRACTION: a session
    record that is merely absent, unparseable, or answers a signal with
    anything other than "no such process" reads exactly like a dead one to
    both -- fine as a NEGATIVE guard (never close something provably alive),
    wrong as the sole gate on a DELETE, since one torn or GC'd record then
    removes a bridge from protection and adds it to condemnation in the same
    step. Measured: a missing session record, a torn one, and an EPERM from
    `os.kill` were all indistinguishable from "the creator is dead" through
    that path.

    So this keeps its own record. STAMP FIRST, while a live job's pid is
    still knowable -- there is no earlier record of it to read back, and
    once the creator is gone this is the only chance there will ever be.
    Every live job, every call: cheap (a handful of jobs at most), and
    correctness needs the FIRST stamp landed before the process dies, not
    the latest one.

    Then READ: a bridge is dead only when its job's `state.json` carries
    BOTH `bridgeSessionId` and a stamped pid, and signalling that exact pid
    raises ``ProcessLookupError`` -- not merely "some" exception. No record,
    an unreadable one, no stamped pid, or any other errno (most of all
    ``PermissionError`` -- a reused pid now owned by someone else) all
    resolve to KEEP, never to dead.

    ``stamp=False`` skips the write pass (and `_live_job_pids()` with it) and
    reads only what is already on disk -- for a caller on the request thread,
    where N unserialized callers sharing the sweep's one tmp filename would
    tear a live job's `state.json`. The sweep (its own thread, serialized by
    `_sweep_lock`) still stamps; a request-thread read of a not-yet-stamped
    record just resolves to KEEP until the sweep gets to it.
    """
    try:
        home = require("paths").get_claude_config_home()
    except Exception:  # noqa: BLE001 — no host, nothing to enumerate
        return set()

    if stamp:
        for job, pid in _live_job_pids().items():
            path = home / "jobs" / job / "state.json"
            rec = _read_json(path)
            if not isinstance(rec, dict) or not rec.get("bridgeSessionId"):
                continue
            _creator_pid_by_bridge[str(rec["bridgeSessionId"])] = pid
            if rec.get(_CREATOR_PID_KEY) == pid:
                continue  # already agrees -- no write, no contention with CC
            rec[_CREATOR_PID_KEY] = pid
            tmp = path.with_name(f".state.json.cswap-{os.getpid()}")
            try:
                # 0600 AT CREATION, not after -- see `_carry_job_record`'s own
                # note on this exact pattern. `write_text` makes the file 0644
                # under the usual umask and widens a file CC itself writes 0600
                # (bridgeOwnerAccountUuid, resumeSessionId, the session output
                # tail all live in it).
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(rec, fh)
                tmp.replace(path)
            except OSError:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass  # a temp we cannot remove must not abort the whole sweep

    out: set[str] = set()
    seen: set[str] = set()
    for path in (home / "jobs").glob("*/state.json"):
        rec = _read_json(path)
        if not isinstance(rec, dict):
            continue
        bridge, pid = rec.get("bridgeSessionId"), rec.get(_CREATOR_PID_KEY)
        if not bridge:
            continue
        seen.add(str(bridge))
        if not isinstance(pid, int):
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            out.update(_both_spellings(str(bridge)))
        except Exception:  # noqa: BLE001 — unknown resolves to KEEP
            continue

    # THE JOB DIRECTORY CAN BE GONE BY NOW -- see `_creator_pid_by_bridge`.
    # A bridge whose job record still exists was already judged above and
    # is skipped here; this only covers the ones the file-only pass can no
    # longer see at all.
    for bridge, pid in list(_creator_pid_by_bridge.items()):
        if bridge in seen:
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            out.update(_both_spellings(bridge))
        except Exception:  # noqa: BLE001 — unknown resolves to KEEP
            continue
    return out


def observed_bridge_owners() -> dict[str, str | None]:
    """``bridge id -> the organizationUuid its record says it belongs to``.

    OBSERVED, not configured. `load_pin` returns what we WROTE; this returns
    what the machine actually has. Measured 2026-08-17, all three at once:

        cswap pin says       the pinned account           (slot 1)
        the live bridge is   a different org              (slot 2)
        the login is         a third org                  (slot 3)

    `cswap pin` reported the first and nothing compared it to the second, so a
    session ran on a bridge its login did not own until the server answered
    `500` and the user had to switch Remote Control off to recover.

    LOCAL AND FREE. The owner is already in the job record next to the pointer.
    This is NOT the server-side proof `_carry_pointer` declines to obtain — that
    one needs the pin's token and a network call on the launch path. Reading a
    file we already read is a different thing entirely.

    ``None`` for a live bridge whose owner is not recorded, and the key is kept.
    Absent and unknown carry opposite remedies: absent means there is nothing to
    disagree with, unknown means the caller must not claim agreement. Dropping
    the key would let a status line report a match for a session it could not
    read — the same shape as the defect this exists to surface.

    THE ORGANIZATION ONLY, AND THAT UNDER-DETECTS ON A ROSTER THIS ONE IS NOT.
    Claude Code compares BOTH the account uuid and the organization uuid, so a
    caller keying on this value alone cannot see two slots that share an
    organization: switching between them changes the account, CC mints a fresh
    bridge with history suppressed, and an org comparison stays silent.
    Measured: six enabled slots, six distinct organizations, no pair — so an
    org match implies an account match here and the narrowing costs nothing.
    That is a fact about the roster, not about this function. Widen the return
    to the pair the day any two enabled slots land in one organization.
    """
    home = require("paths").get_claude_config_home()
    owners: dict[str, str | None] = {}
    try:
        entries = list((home / "sessions").glob("*.json"))
    except OSError:
        return owners
    for path in entries:
        rec = _read_json(path)
        if not isinstance(rec, dict):
            continue
        bridge, pid, job = (rec.get("bridgeSessionId"), rec.get("pid"),
                            rec.get("jobId"))
        if not isinstance(pid, int) or not _pid_alive(pid):
            continue
        # THE SAME CLEARED POINTER `_live_bridge_records` RECOVERS, and this
        # one feeds a cross-org WARNING — so dropping the session reads as
        # agreement rather than as an unanswered question, the failure the
        # `None` return below already exists to avoid.
        st = _read_json(home / "jobs" / str(job) / "state.json") if job else None
        bridge = bridge or (st or {}).get("bridgeSessionId")
        if not bridge:
            continue
        owner = st.get(_JOB_OWNER[1]) or None if isinstance(st, dict) else None
        owners[str(bridge)] = owner
    return owners


def ca_path_for_trust() -> "Path | None":
    """The CA a PYTHON client should ADD to verify the proxy it dials, or None.

    A python caller routed through the pin is talking to a MITM of
    api.anthropic.com, so a default SSL context cannot verify it and every
    request dies CERTIFICATE_VERIFY_FAILED. The fix is one line at the call
    site — `ctx.load_verify_locations(cafile=ca_path_for_trust())` — and this
    exists so the caller does not have to know where the pin keeps its files,
    which is not the same path on every platform.

    NOT `SSL_CERT_FILE`, and the difference decides whether the fix works.
    That variable REPLACES OpenSSL's store, so it is safe only where the
    bundle subsumes what it displaces. Measured per machine, by certificate
    SET:

        host-a     ambient 124  bundle 126  safe
        host-b      ambient 128  bundle 167  NOT — 27 missing
        host-c  ambient 128  bundle   2  NOT — 128 missing

    So the writer that sets it refuses on both Macs — correctly — and every
    python caller there stays broken. Adding this CA to a default context
    keeps every ambient root and needs no variable at all. Measured on
    host-c, same process and proxy: default context
    CERTIFICATE_VERIFY_FAILED; default context plus this CA, HTTP 200.

    OUR OWN CA, NOT THE MERGED BUNDLE. The bundle exists for
    NODE_EXTRA_CA_CERTS, which ADDS to node's built-in roots; handed to a
    python context it would still only add, but it also carries whatever a
    launcher merged in, and a caller asking "what do I need to trust YOU"
    should get exactly that. One certificate, one reason.

    None when there is nothing to add: no pin state, or a CA that is not
    there. A path that does not exist would raise inside the caller's SSL
    context and take down a call that worked fine unpinned.
    """
    try:
        from cswap_pin._host import require

        root = Path(require("paths").get_backup_root())
    except Exception:  # noqa: BLE001 — no host, no pin, nothing to add
        return None
    ca = root / "pin-proxy" / "ca.pem"
    try:
        return ca if ca.is_file() and ca.stat().st_size else None
    except OSError:
        return None


#: THE ONLY TWO VALUES THAT SAY A PERSON CHOSE THE NAME. Everything else in
#: the field's closed domain (`derived`, `collision`, `auto`, `hook`) counts
#: as invented, and stating it as a COMPLEMENT is the point: a value added in
#: a later release lands on the REFUSING side instead of slipping through. An
#: allow-list of invented values expires the day the product adds one.
#:
#: Refusing is the safe side because the errors are not symmetric — restoring
#: wrongly OVERWRITES a name somebody typed, refusing wrongly only leaves a
#: server title in place — and it is cheap, because a server SLUG is restored
#: either way (`_looks_generated`, at the call site).
#:
#: `peer` is a `user` name relayed. ABSENT is in neither list and counts as
#: chosen; `invented_bridge_names` carries why, and it is not the age of the
#: record.
_CHOSEN_NAME_SOURCES = ("user", "peer")


def invented_bridge_names() -> set[str]:
    """Bridge ids whose LOCAL name is one nobody chose.

    Claude Code stamps a session record with `nameSource`, so this is the
    product's own statement about provenance rather than a guess from the
    name's shape. `_CHOSEN_NAME_SOURCES` says which values do NOT.

    TWO VALIDATORS SHIP AND THIS READS THE REGISTRY ONE. The session-registry
    parser closes the domain at six values; a separate zod schema for JOB
    state allows only `user`, `auto`, `collision`. Anyone grepping will find
    both, so: the six-value list is the one that governs the file read here.

    AN ABSENT FIELD IS NOT COUNTED, and the source for that is the bundle's
    own label formatter, which groups absent WITH `user` and `peer` as "has a
    chosen name". Counting absent as invented would refuse the restore for
    most live sessions -- the population the feature exists for.

    NOT ARGUED FROM CREATION. An earlier version of this said a `--name`
    launch builds `source:"user"` and lands with the field ABSENT, offered as
    a mechanism rather than a count. Measured on the one host it can be
    checked on: 15 live records, ZERO carrying `--name` in argv, yet 6
    carrying an explicit `user`/`peer` -- so creation is not the only writer
    and that sentence explained the wrong thing. The field is also written
    later, on naming, which is why the census and the mechanism disagreed.

    The bundle holds BOTH positions on absent, so this is a choice between
    them rather than a reading of one: the label formatter above, against a
    job-state sync that reads an absent field as `auto`.
    """
    return {spelling
            for bridge, _name, source in _live_bridge_records()
            if source is not None and source not in _CHOSEN_NAME_SOURCES
            for spelling in _both_spellings(bridge)}


#: Read a transcript backwards in chunks this size when looking for the
#: newest title. A rename is re-emitted on later turns, so one chunk
#: normally settles it.
_TRANSCRIPT_TAIL_STEP = 1 << 16


def _last_custom_title(path: Path) -> str | None:
    """The newest ``custom-title`` in a transcript, read from the END.

    A forward scan is a second of I/O — measured 952 ms on the 752 MB
    transcript this fleet's busiest session carries — and the caller sits on
    a request path. Backwards costs one chunk when a rename exists; a
    transcript with none still costs the whole file every beat, which is why
    only invented-name records get this far — and an adopted one flips to a
    chosen source, so it is read once and never again.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos, tail = fh.tell(), b""
            while pos > 0:
                step = min(_TRANSCRIPT_TAIL_STEP, pos)
                pos -= step
                fh.seek(pos)
                lines = (fh.read(step) + tail).split(b"\n")
                # lines[0] is PARTIAL until the read reaches the start, so it
                # is carried into the next chunk rather than parsed.
                head, whole = (b"", lines) if pos == 0 else (lines[0], lines[1:])
                for line in reversed(whole):
                    if b'"custom-title"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(rec, dict) and rec.get("type") == "custom-title":
                        return str(rec.get("customTitle") or "") or None
                tail = head
    except OSError:
        return None
    return None


def adopt_renamed_sessions() -> int:
    """Carry a rename the session registry never heard about into its record.

    Claude Code stamps ``sessions/<pid>.json`` once, at launch, and a later
    rename — typed here, or made on claude.ai and pulled down — lands in the
    TRANSCRIPT and on the server without touching that record. Everything
    local then reads the launch name: the peer list, ``@``-completion, and
    this proxy's own title restore. Measured on this fleet: an RC session sat
    at its derived launch name for a day while the transcript and claude.ai
    both read the name its owner had chosen.

    Only an INVENTED name is replaced — `_CHOSEN_NAME_SOURCES`' complement,
    the same test `invented_bridge_names` applies — so this can never
    overwrite a name somebody typed, and an absent source counts as chosen
    there as here.
    """
    home = require("paths").get_claude_config_home()
    try:
        entries = sorted((home / "sessions").glob("*.json"))
    except OSError:
        return 0
    adopted = 0
    for path in entries:
        rec = _read_json(path)
        if not isinstance(rec, dict):
            continue
        source, pid = rec.get("nameSource"), rec.get("pid")
        sid = rec.get("sessionId")
        if source is None or source in _CHOSEN_NAME_SOURCES or not sid:
            continue
        if not isinstance(pid, int) or not _pid_alive(pid):
            continue
        title = next((_last_custom_title(tx) for tx in
                      (home / "projects").glob(f"*/{sid}.jsonl")), None)
        if not title or title == rec.get("name"):
            continue
        rec["name"], rec["nameSource"] = title, "user"
        rec["nameSince"] = int(time.time() * 1000)
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(rec), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            continue
        adopted += 1
    if adopted:
        _log_lifecycle(f"adopted the chosen name on {adopted} session "
                       f"record(s) a rename had left at a generated one")
    return adopted


def live_bridge_names() -> dict[str, str]:
    """Bridge id -> the name its live session goes by, in both spellings.

    THE PAIRING THE CLOUD LOSES. A restart drops the RC binding; Claude Code
    mints a NEW cloud session and never writes the new id back to the
    transcript, so the name the user chose stays local while claude.ai shows
    whatever the server invented for the replacement. Measured on this account
    after one `cc-update --apply --force`: 'Session interrupted by user' twice
    and six 'host-a-<word>-<word>', for sessions that all had names.

    This registry is where both halves meet, keyed by a pid that says whether
    the session is still there — one record, or that record plus the job one
    it names once a teardown has cleared the pointer (see
    ``_live_bridge_records``). No cwd to resolve, no branch signature to
    match, no ambiguity to decline.
    """
    names: dict[str, str] = {}
    for bridge, name, _src in _live_bridge_records():
        if name:
            for spelling in _both_spellings(bridge):
                names[spelling] = name
    return names


# RETIRED, deliberately not left behind as a helper nobody calls. It matched
# any lowercase-hyphen-word-word string with no anchor, so it claimed
# `ai-inter-session` — a name the user chose — was the server's. See
# `_looks_generated`, which is now anchored on this machine's host slug.


def _looks_generated(title: str) -> bool:
    """A SLUG the server minted for a nameless bridge.

    NARROWED TO THE ONE SHAPE THE PRODUCT ITSELF RECOGNISES. The slug a
    nameless bridge gets (`host-a-cozy-badger`) is applied SERVER-SIDE — the
    client sends only `machine_name` at bridge registration and derives no
    title from the hostname — so no local RECORD of it exists, and "just read
    the local record" is the mistake three earlier rounds made. The GRAMMAR,
    though, IS shipped: the bundle carries the word lists and mints
    `${adjective}-${noun}`, with a recogniser that accepts only two parts,
    both from those lists.

    The SENTENCES claude.ai writes for an active bridge are recorded nowhere
    and no reader of them survives in this package, so this answers False for
    those and callers must say what they do about it.

    The two rules that used to live here are gone. The `" " in title` rule
    claimed every title with a space was the server's, which overwrote
    'Email advice'. And the regex had no anchor: it matched any
    lowercase-hyphen-word-word string, including the user's own
    `ai-inter-session`.

    ANCHORED ON THIS MACHINE'S HOST SLUG, which is what the server actually
    prefixes: `host-a-…`, `host-b-…`, `host-c-…`. Derived
    at call time from the hostname rather than listed, so a new machine needs
    no edit here — the failure mode of a hardcoded list is that it goes stale
    the first time a host is renamed.

    AND BOUNDED AT EXACTLY TWO TRAILING SEGMENTS, per that grammar. The
    suffix used to be `+`, harmless while nothing called this and a defect the
    moment the title guard did: `<host>-notes` is not a slug, and reading it
    as one lets the restore overwrite a name somebody typed.

    THE NUMERIC TAIL IS DELIBERATELY NOT MATCHED. A SECOND recogniser in the
    bundle — the one that strips a generated suffix, not the two-part one
    above — also accepts a de-duplicating `-<digits>`, so `<host>-cozy-badger-2`
    answers False here.
    Matching it needs `(?:-[0-9]{1,4})?`, which also claims
    `<host>-my-notes-2024`; the product can afford that only because it ALSO
    checks both words against its lists, and copying those here would go
    stale. So that slug merely survives, where a loose anchor destroys a name.

    A blank title counts: there is nothing to overwrite.
    """
    title = title.strip()
    if not title:
        return True
    host = _host_slug()
    if not host:
        return False
    return bool(re.match(rf"^{re.escape(host)}(?:-[a-z0-9]+){{2}}$", title))


def _host_slug() -> str:
    """This machine's name as the server slugifies it, or "" if unknowable.

    `host-a`, `host-b`, `host-c` — measured from the
    titles this account actually received. Lowercased, non-alphanumerics to
    hyphens, which is what produced those three from the real hostnames.

    THE DOMAIN GOES FIRST, and for a while it went nowhere. This ended with
    `slug.split(".")[0]`, run AFTER a regex that has already replaced every
    `.` with a `-` — so it could never match anything and an FQDN hostname
    slugified whole: `HOST-C.local` -> `host-c-local`.
    `gethostname()` returning an FQDN is routine on macOS and on any
    DNS-suffixed Linux box, and `host-c` above is what the SERVER
    produced from that same machine, so the anchor stopped matching the slug
    it is anchored to and the restore silently did nothing there — with no
    log line to separate it from "nothing to do".
    """
    try:
        raw = socket.gethostname()
    except OSError:
        return ""
    return re.sub(r"[^a-z0-9]+", "-", raw.split(".")[0].lower()).strip("-")


def should_wait_for_pin(method: str, path: str) -> bool:
    """Is this the request where failing open costs something PERMANENT?

    The swap fails open everywhere by design — a pin that cannot resolve must
    never block work — and that is right for `/v1/messages`: the request bills
    the other account and the next one is fine.

    Creating a bridge is the exception. `POST /v1/code/sessions` is where the
    server fixes the session's owner, and there is no transfer afterwards, so
    one lost race gives a session away for good: its name, its history, and
    the account it appears under.

    THE "12 OF 14" THAT USED TO BE CITED HERE WAS NOT THIS. That count came
    from a health check reading `ownerAccountUuid` out of transcripts, and
    Claude Code writes that field from its OWN login rather than from the
    bearer we swapped in — so it says nothing about whether the swap fired.
    Re-measured against the pinned account's own listing: the bridges it called
    mis-owned are listed under the pin, meaning the swap had worked every time.
    The retry below is still right — an unpinned bridge really is permanent —
    but it is a guard against a race nobody has yet caught in the act, not the
    fix for a fault that was measured. See `_carry_pointer` for what those
    sessions were actually losing.

    The race it guards is momentary. `consume-busy` means the usage collector
    holds that slot's refresh lock for an instant, and the daemon's own note
    calls it "a race with the usage collector, not a broken daemon". So the
    answer here is only whether to RETRY briefly; the caller still gives up
    and sends, because a launch that hangs is worse than a session on the
    wrong account.
    """
    bare = path.split("?", 1)[0].rstrip("/")
    # `POST /v1/environments/bridge` is the same bargain one subtree over: it
    # is where `claude remote-control` fixes the ENVIRONMENT's owner, and an
    # environment registered on the wrong account cannot be moved either — the
    # machine simply never appears on the pinned account's claude.ai.
    return method == "POST" and bare in (
        "/v1/code/sessions", "/v1/environments/bridge")


#: Titles this pin has PUT, keyed by bridge id. The one thing that separates
#: "the server invented a name" from "a person renamed it in the browser":
#: neither is the local name, and the server record carries no timestamp saying
#: when its title was set (measured — `created_at` and `last_event_at` only).
_TITLES_WRITTEN = "titles-written.json"


def _titles_we_wrote(certdir) -> dict:
    # NO CERTDIR MEANS NO LEDGER, and the documented default for a bridge we
    # have never named is RESTORE. Failing closed here would disarm the whole
    # feature for anything constructed without one.
    if not certdir:
        return {}
    try:
        return json.loads((Path(certdir) / _TITLES_WRITTEN).read_text())
    except (OSError, ValueError):
        return {}


def _record_title(certdir, sid: str, title: str) -> None:
    """Remember a title we just PUT, so a later change AWAY from it is somebody
    else's edit and not ours to undo."""
    if not certdir:
        return
    try:
        d = _titles_we_wrote(certdir)
        # RE-INSERTED, NOT REASSIGNED, so the cap below evicts by WRITE order.
        # A plain `d[sid] = title` leaves an existing key where it was, and
        # `[-500:]` would then drop the entry we just wrote in favour of one
        # untouched for five hundred writes.
        d.pop(sid, None)
        d[sid] = title
        # BOUNDED. One entry per bridge this machine has ever named would grow
        # without limit; the restore only ever asks about LIVE ones.
        if len(d) > 500:
            d = dict(list(d.items())[-500:])
        tmp = Path(certdir) / (_TITLES_WRITTEN + ".tmp")
        tmp.write_text(json.dumps(d))
        tmp.replace(Path(certdir) / _TITLES_WRITTEN)
    except (OSError, ValueError):
        pass


def titles_to_restore(
    sessions: list[dict], names: dict[str, str], ours: "dict | None" = None,
    invented: "set | None" = None,
) -> list[tuple[str, str]]:
    """``(bridge id, name)`` for listed bridges the server titles wrongly.

    Only a DIFFERENCE is worth a request. This runs on every RC connect, so
    rewriting titles that already match would put one PUT per live session on
    the wire every time any one of them opens a bridge.

    ``ours`` and ``invented`` DEFAULT TO ARMED. None means "unknown" and
    disarms the guard that reads it, and cswap's own copy of this repair calls
    through a TWO-PARAMETER shim -- so on the caller that was actually
    overwriting names, both guards were dead code. The package owns the policy
    (the shim's docstring says so), and both facts are readable here with no
    argument, so the default reads them rather than trusting a caller to pass
    them. Only that caller pays the walk; the daemon passes both.

    THE TWO HALVES DO NOT ARRIVE EQUALLY ARMED. `_record_title` has one caller
    and it is the daemon's, so through the two-argument door the ledger covers
    only bridges the daemon has ALSO named; provenance carries the rest, and
    only for what `_CHOSEN_NAME_SOURCES` excludes. Closing that gap needs a
    title recorded where it is PUT — bookkeeping the other side owns.
    """
    # A HOST WE CANNOT REACH LEAVES THE DEFAULT WHERE IT WAS. `require` raises
    # when cswap is not importable, and refusing every restore on that is worse
    # than the state this widens.
    try:
        if ours is None:
            ours = _titles_we_wrote(
                Path(require("paths").get_backup_root()) / "pin-proxy")
        if invented is None:
            invented = invented_bridge_names()
    except Exception:  # noqa: BLE001 — no host, no provenance to read
        pass
    out: list[tuple[str, str]] = []
    for item in sessions:
        sid = item.get("id")
        want = names.get(sid)
        if not sid or not want:
            continue
        current = (item.get("title") or "").strip()
        if current == want.strip():
            continue
        # ANY DIFFERENCE, BECAUSE THE REGISTRY ALREADY PROVED OWNERSHIP.
        # `names` comes from this machine's own session registry, which pairs a
        # name with a live pid — and, when the pointer has been cleared on a
        # teardown, with the bridge id from that session's job record. A bridge
        # is in it only because a session running HERE holds or held it and
        # gave it that name, so a cloud title that differs is one this side did
        # not ask for. `_live_bridge_records` states the join and its bound.
        #
        # THREE NARROWER RULES CAME AND WENT, AND EACH BROKE THE FEATURE. A
        # shape regex claimed names people had chosen. Reading only what Claude
        # Code RECORDED (`ai-title`) missed every sentence claude.ai writes for
        # an active bridge, because the server records those nowhere locally —
        # so the restore selected nothing at all while a live session's cloud
        # name drifted from one sentence to the next. A third pass added "not
        # in any local record" plus a slug guard, and the slug guard was
        # protecting a case the registry makes impossible.
        #
        # A FOURTH RULE, AND IT IS A LEDGER RATHER THAN A SHAPE TEST: a title
        # we PUT is ours to overwrite, and one that has moved AWAY from what we
        # last wrote was set by somebody else. The server cannot settle it —
        # its record carries no timestamp for a title — so this side's record
        # is the only half of the question anyone has. UNKNOWN MEANS RESTORE:
        # a bridge we have never named is the population the feature exists
        # for, and refusing it there would disarm the whole thing.
        #
        # ponytail: one-shot per bridge. A drift the SERVER caused after our
        # write reads identically to a person's rename, and reverting a person
        # is the worse of the two errors. Upgrade path, if the slug ever comes
        # back on a named bridge: drop its entry when this proxy sees that
        # bridge's own reconnect go by.
        if ours is not None and sid in ours and current != (ours[sid] or "").strip():
            continue
        # A NAME NOBODY CHOSE MUST NOT OVERWRITE ONE SOMEBODY TYPED. The ledger
        # above only protects the window between a rename and the next restore:
        # once this pin has pushed a derived name, the ledger records it as
        # "ours", the two agree, and the guard stops firing. A new bridge id
        # opens the same hole from the other end, since unknown means restore.
        #
        # `invented` holds the bridges Claude Code's own record says nobody
        # named. REFUSED ONLY AGAINST A TITLE A PERSON COULD HAVE TYPED:
        # `_looks_generated` answers True for a server slug AND for a blank
        # title, so it subsumes the blank carve-out rather than adding a rule.
        # It answers False for a server-written SENTENCE, which therefore
        # still stands on an invented-named bridge — 2 of 8 in this file's
        # sample, and see that function for why nothing can do better.
        if invented and sid in invented and not _looks_generated(current):
            continue
        out.append((sid, want.strip()))
    return out


def apply_pin(switcher, email: str | None, org_uuid: str | None,
              identity: dict | None = None) -> bool:
    """Set (or clear, with ``email=None``) the pin AND bring the world in line.

    Storing the pin is only half the job: hand-launched sessions read the
    proxy out of the global config, so a pin that is saved but not wired does
    nothing, and — worse — a pin CLEARED but not unwired leaves that config
    pointing at a proxy which idle-tears-down, breaking egress for every new
    `claude` with no way back but editing the file by hand.

    Both entry points (the CLI and the TUI menu) go through here so they
    cannot drift apart again. Returns whether a proxy is now serving.
    """
    save_pin(switcher.backup_dir, email, org_uuid)
    if not email:
        wire_global_config(None, None)
        # AND STOP NAMING THE EX-PIN. An unpinned machine kept minting under
        # the ex-pin until some later switch happened to rewrite it. `identity`
        # is the caller's to supply here exactly as it is when setting: only
        # cswap can resolve an account in its own backup store. None therefore
        # means "could not look one up", and the splice leaves the field alone
        # rather than erasing it — cswap's own switch rewrites it on the next
        # rotation, and a blank owner is worse than a stale one. DISARM. The
        # gate is only meaningful while a pin exists, and leaving the secret
        # behind means "I turned the pin off" and "the proxy still demands a
        # credential" are both true at once — a state no user has a model for.
        # Worse, the next `cswap pin` re-arms it against sessions wired in
        # between, which is exactly the 407 storm this is fixed for.
        #
        # ABSENT AND REFUSED ARE NOT THE SAME OSError. FileNotFoundError means
        # there was never anything armed — fine, `False` is correct. Any other
        # OSError (permission denied, a read-only mount) means the secret is
        # STILL THERE and this function is about to return the exact `False` a
        # successful disarm would, which every caller reads as "nothing is
        # armed". RE-RAISE rather than log: logging still returns the false
        # `False`, and the caller's next decision — including the next `cswap
        # pin` re-arming against sessions wired in the meantime — is made on
        # that return value, not on a log line nobody is required to read.
        try:
            splice_config_identity(identity)
        except Exception:  # noqa: BLE001 — the clear must work regardless
            _log_lifecycle("could not un-name the cleared pin in the live "
                           "config — bridges keep its owner until the next "
                           "switch")
        remember_pin_identity(switcher.backup_dir / "pin-proxy", None)
        try:
            proxy_secret_path(switcher.backup_dir / "pin-proxy").unlink()
        except FileNotFoundError:
            pass  # never armed, or already disarmed: nothing to do
        return False
    # Mint the proxy credential HERE, not in the daemon. This is the one path
    # that also rewrites the wiring, so the gate and the URL that satisfies it
    # arrive together, at a moment an operator chose. A daemon respawn must
    # never arm it by itself: that would fire on a fingerprint recycle, a
    # deploy or an idle teardown, with nothing a human could connect to the
    # resulting failures. An existing secret is reused, so re-pinning does not
    # invalidate anything.
    certdir = switcher.backup_dir / "pin-proxy"
    # Arming is a ONE-WAY DOOR for every session already running, so count
    # them BEFORE minting — afterwards the connections are already being
    # refused and the number is gone. Only when the secret does not exist
    # yet: re-pinning reuses it and cuts off nobody.
    global _last_arm_cutoff
    _last_arm_cutoff = None
    if read_proxy_secret(certdir) is None:
        port = _read_alive_port(certdir)
        if port is not None:
            _last_arm_cutoff = clients_that_arming_would_cut_off(port)
    try:
        certdir.mkdir(parents=True, exist_ok=True)
        ensure_proxy_secret(certdir)
    except OSError:
        pass  # unwritable cert dir: serve unauthenticated rather than not at all
    # AND THE CONFIG MUST NAME THE PIN, which is the half that was missing.
    # Best-effort by design: the record is written and the proxy is serving by
    # the time we get here, so a config that cannot be written is a worse pin,
    # not a failed command — and raising would roll back a pin that works.
    # THE VERDICT COMES FROM THE STATE. `splice_config_identity` swallows every
    # real failure itself and answers False for both "could not write" and
    # "already correct", so an `except` around it guards a case that cannot
    # arrive -- a lock timeout, which this path can now hit, was silent here.
    identity = remember_pin_identity(certdir, identity) or identity
    try:
        if not splice_config_identity(identity):
            now = _login_identity()
            if not now or now[0] != (identity or {}).get("accountUuid"):
                _log_lifecycle("could not name the pin in the live config — "
                               "bridges will be minted under the active "
                               "account until the next switch")
    except Exception:  # noqa: BLE001 — the pin is already live
        pass
    return ensure_proxy(switcher) is not None



_PIN_IDENTITY_NAME = "pin-identity.json"


def remember_pin_identity(certdir, identity: dict | None) -> "dict | None":
    """Leave the pinned ``oauthAccount`` where the daemon can re-apply it.

    THE PACKAGE NEVER DERIVES THIS. ``identity_for_config`` lives host-side on
    purpose — it reads cswap's own backup store, whose layout this package has
    no business knowing — so every splice here is handed its identity by a
    caller. The daemon has no caller: it is still serving requests long after
    the launch that knew the answer exited. Arming has the answer and writes it
    once; the host still computes, the package only stores.

    NEVER DOWNGRADES FRESHNESS. The host hands over the pinned slot's stored
    config, whose `profileFetchedAt` is whenever that account was last the
    live login; the daemon refreshes this file from the server. Same account
    and a newer stamp on disk means the disk copy is the truer one, so it is
    kept -- and RETURNED, because what this returns is what the caller must
    splice. Writing the stale copy over it would re-open Claude Code's
    profile fetch on the very next launch.
    """
    p = Path(certdir) / _PIN_IDENTITY_NAME
    if not identity:
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    kept = remembered_pin_identity(certdir)
    if (kept and kept.get("accountUuid") == identity.get("accountUuid")
            and _profile_stamp_ms(kept) > _profile_stamp_ms(identity)):
        return kept
    try:
        p.write_text(json.dumps(identity), encoding="utf-8")
    except OSError:
        pass  # a pin that cannot cache its identity still pins
    return identity


def remembered_pin_identity(certdir) -> dict | None:
    """What :func:`remember_pin_identity` last wrote, or None."""
    try:
        d = json.loads(
            (Path(certdir) / _PIN_IDENTITY_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return d if isinstance(d, dict) and d.get("accountUuid") else None


def live_pin_identity_state(ident: dict) -> "tuple[bool, str]":
    """`(does the config name ``ident`` now, what it names instead)`.

    ONE READ ANSWERS BOTH, and that is the point. A separate reader for the
    log can succeed where the check failed and then name the PIN as the
    drifted owner — a line that contradicts itself, on a healthy config, in
    the one field that exists to make the next occurrence diagnosable.

    WHAT THIS DOES NOT PROVE. It reads after `splice_config_identity` released
    the config lock, and Claude Code reads the field again after the POST it
    is about to forward returns. So a True is a fact about the file at this
    instant, never a guarantee about the value CC will stamp. It is here to
    catch the skipped write, which is the failure that was silent; the
    residual race is not something an in-process check can close.

    Unreadable is NOT live and names itself as such — an answer we could not
    take must never stand in for the one we wanted.
    """
    try:
        cfg = require("paths").get_global_config_path()
        here = json.loads(cfg.read_text(encoding="utf-8")).get("oauthAccount")
    except Exception:  # noqa: BLE001 — unreadable is not "it is fine"
        return False, "unreadable"
    if not isinstance(here, dict):
        return False, "not-an-object"
    keys = [k for k in ("accountUuid", "organizationUuid") if ident.get(k)]
    live = bool(keys) and all(here.get(k) == ident.get(k) for k in keys)
    # THE UUID ONLY, never the surrounding object: this string ships to a log
    # on other people's machines and the object beside it carries an address.
    return live, str(here.get("accountUuid") or "no-uuid")[:12]


def splice_config_identity(identity: dict | None,
                           lock_timeout: float = _SPLICE_LOCK_S) -> bool:
    """Make the live config name ``identity``. True when it changed anything.

    ONLY ``oauthAccount``. Everything else in that file belongs to Claude Code,
    and cswap's switch says the same thing in its own comment: this field is
    identity, not authority. Inference keeps following the active account
    through the credential store, which is what makes a pin usable at all.

    Idempotent, because every live Claude Code watches this file and a rewrite
    that changes nothing is a wake-up for all of them.

    A config this cannot parse is left alone. `.get` on a list raises, and a
    file we do not understand is one we must not rewrite — the same rule the
    backup repair had to learn when `null` and `[]` escaped its guard.
    """
    if not identity:
        return False
    # THROUGH `require`, like every other reader of this path in this file.
    # The host package is resolved at call time, never imported at module
    # scope: this package is the optional extra and must not make cswap's
    # layout a hard dependency.
    cfg = require("paths").get_global_config_path()
    # UNDER THE SAME LOCK EVERY OTHER WRITER OF THIS FILE TAKES, across read
    # AND write. We replace the file whole, so a Claude Code write landing
    # between our read and our rename is discarded along with the account,
    # project history and settings it carried. `wire_global_config` in this
    # module already holds it for exactly that reason; this writer did not,
    # and was safe only while it ran from a human typing `cswap pin`. It now
    # runs from the launch hook on a machine with live sessions, and the
    # window is widest right after CC writes the very field we are repairing.
    #
    # A lock we cannot take is a SKIPPED write, never a raise: the field stays
    # drifted until the next launch, which is the fail-open this whole path
    # already has.
    try:
        with require("claude_locks").claude_config_lock(
                timeout=lock_timeout):
            return _splice_config_identity_locked(cfg, identity)
    except Exception:  # noqa: BLE001 — a launch must never fail on the pin
        return False


def _splice_config_identity_locked(cfg, identity: dict) -> bool:
    """The read-modify-write half of :func:`splice_config_identity`.

    Split out so the lock is held across BOTH halves rather than around a
    call that re-reads afterwards.
    """
    try:
        data = json.loads(cfg.read_text())
    except (OSError, ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    # DECIDE ON THE ACCOUNT, NOT ON THE DICT. Comparing whole dicts can never
    # be equal when the host hands over a roster SYNTHESIS — three keys, built
    # when the machine has never switched into the pinned account so no stored
    # config exists to copy. The rewrite then fires on every launch and strips
    # the fields Claude Code owns (`displayName`, `organizationName`,
    # `organizationRole`), which CC restores, which re-arms the next one. The
    # host learned this on its own copy of this comparison and guards it the
    # same way.
    # ONLY THE KEYS THE IDENTITY ACTUALLY ASSERTS. The host's synthesis fills
    # a missing org with `or ""`, so comparing that empty string against a
    # config Claude Code has filled in is never equal -- the rewrite fires and
    # DOWNGRADES a real `organizationUuid` to "". CC's pointer comparison needs
    # both uuids, so every bridge minted afterwards cannot reattach: the repair
    # causing the failure it exists to prevent, which is worse than the
    # whole-dict comparison it replaced.
    #
    # An empty value is "I do not know", not "it is empty". `accountUuid` is
    # present on both host paths, so `keys` is never empty in practice and an
    # identity asserting nothing falls through to the write rather than
    # matching everything.
    here = data.get("oauthAccount")
    keys = [k for k in ("accountUuid", "organizationUuid") if identity.get(k)]
    freshening = False
    if isinstance(here, dict) and keys and all(
        here.get(k) == identity[k] for k in keys
    ):
        # NAMES THE PIN ALREADY. Rewrite only to carry a FRESHER profile
        # stamp: Claude Code re-fetches its profile as the ACTIVE account once
        # the stamp is a day old, and that fetch is what moves this field off
        # the pin. Strictly newer, so two writers can never ping-pong -- CC
        # only ever writes a newer stamp than the one it read.
        if _profile_stamp_ms(identity) <= _profile_stamp_ms(here):
            return False
        freshening = True
    was = here.get("accountUuid") if isinstance(here, dict) else here
    data["oauthAccount"] = identity
    # ATOMIC. A torn write here is read by every live session, and is worse
    # than an unspliced pin.
    tmp = cfg.with_suffix(cfg.suffix + f".pin-{os.getpid()}")
    try:
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, cfg)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False
    # SAY WHO IT REPLACED. The field has a writer outside this package and
    # neither side leaves a trace, so this line is what makes the next drift
    # attributable rather than merely visible. AFTER the write, or a failed
    # `os.replace` records a splice that did not happen -- which is the one
    # thing an attribution line must never do. Truncated uuids, never
    # addresses: this log ships on other people's machines.
    if freshening:
        _log_lifecycle("freshened the pin's profile stamp in the live config, "
                       "so Claude Code does not re-fetch it as the active "
                       "account")
    else:
        _log_lifecycle("splicing the pin into the live config: "
                       f"{str(was)[:12]} -> "
                       f"{str(identity.get('accountUuid'))[:12]}")
    return True


# Set by the last apply_pin: how many live clients that call's arming cut off,
# or None when it armed nothing (or could not measure). A module global rather
# than a return value because apply_pin's bool is load-bearing for two callers
# and the TUI menu; this is advisory, and a caller that ignores it is correct.
_last_arm_cutoff: int | None = None


def last_arm_cutoff() -> int | None:
    """Live clients cut off by the most recent :func:`apply_pin`, if any.

    None means nothing was armed — the usual case, since the secret is minted
    once and reused. A number means those sessions will 407 on their next
    request and only a relaunch fixes them, which is the thing an operator has
    to be told at the moment they can still act on it.
    """
    return _last_arm_cutoff


# HOW LONG A PINNED REQUEST WAITS ON `refresh_lock` BEFORE GIVING UP. The
# work inside that lock is the HOST's, not this module's, and a contended
# refresh pays for all of it: a cold Keychain read (macos_keychain's own
# `get_password` bounds that subprocess to 5s), then -- should the held
# token be expired -- `consume_backup_grant`'s own `.consume-<n>.lock` wait
# (`FileLock`'s default `timeout=10.0`), the switcher's `self.lock_file`
# wait (another 10s), a Keychain RE-read (5s again) and the refresh POST
# (`oauth.try_refresh_oauth_credentials`'s default `timeout_s=10.0`) --
# 5+10+10+5+10 = 40s worst case. Set above that, or a healthy refresh that
# is merely slow and contended gets cut off as if it were stalled.
_MINT_LOCK_BOUND_S = 45.0


def make_pin_token_provider(switcher, account_num: str, email: str):
    """Build the ``pin_token_provider`` callable for :class:`PinProxy`.

    Reads the pinned account's credential from cswap's backup store and
    returns a live access token, refreshing (and persisting the rotation back
    to the store) when expired. Returns ``None`` — meaning "leave the
    request's bearer alone" — when the pinned account is currently the ACTIVE
    account (its live credential is already on disk and owned by the client;
    the backup copy may be stale) or when no usable token can be produced.

    **Which account is pinned is re-read from disk per request**, not frozen
    at spawn. Switching accounts in cswap never asks you to restart a session,
    and re-pinning should not either: a live session holds only the proxy's
    address, so the daemon can start serving a different account underneath it
    the moment ``cswap pin`` writes one. ``account_num``/``email`` are the
    fallback for when the pin cannot be resolved (a removed account).

    **Refresh is serialized.** The provider runs once per pinned request and
    each MITM connection is its own thread, so an expiry under load would
    otherwise have N threads POST the SAME one-time refresh token
    concurrently: one wins and the rest come back ``invalid_grant``, with the
    last writer persisting a credential whose grant was already consumed —
    exactly the lineage-death shape cswap exists to prevent. A thread that
    waited on the lock re-reads the store first and uses the winner's
    rotation instead of refreshing again.

    **Across PROCESSES too.** A thread lock only binds this daemon, and this
    daemon is not the only thing that refreshes a backup slot: the usage
    collector and the autoswitcher do it from their own processes. Two
    processes POSTing one one-time grant is the same lineage death by a
    different door, so the refresh goes through the switcher's
    ``consume_backup_grant`` gate, which holds a per-slot FILE lock across
    re-read → POST → fingerprint-CAS. The gate persists the rotation itself;
    the thread lock stays because it is cheaper for the in-process case and
    keeps N threads off the file lock.
    """
    refresh_lock = threading.Lock()
    # {account_num: (read_at, credential_json)}. Per provider, so it dies with
    # the daemon and no state outlives a recycle.
    _cred_cache: dict = {}
    # SET/CLEARED ONLY BY WHOEVER HOLDS `refresh_lock`. Lets a reader that
    # peeks the lock non-blocking (`_mint_lock_busy`) say how long it has
    # been held -- the fact that tells a stalled Keychain read apart from a
    # merely slow one, on the one probe that must never wait behind either.
    # Attached to `provider` below, once it exists.

    # PER-CALLING-THREAD, not a shared flag. Each request runs on its own
    # thread, and a bare module-level flag was cleared on entry by whoever
    # called `provider()` NEXT and read by whichever thread asked -- so one
    # thread's genuine stall could read as cleared (a wrong fail-open) or an
    # unrelated thread's stall could read as this one's own (a wrong 503).
    _stalled = threading.local()

    def mint_stalled() -> bool:
        """True when THIS THREAD's last call returned None only because it
        could not take `refresh_lock` within `_MINT_LOCK_BOUND_S`, not
        because minting genuinely failed. The request path uses this to
        answer 503 instead of going out unpinned -- see
        `_refuse_stalled_mint`."""
        return getattr(_stalled, "flag", False)

    def _consume(creds: str, num: str, mail: str) -> "oauth.RefreshOutcome":
        """Refresh through the host's interprocess gate, direct POST as
        fallback. An older claude-swap has no gate; a pinned request must
        still be served, and a same-process race is still covered by
        ``refresh_lock``.

        The gate can answer ``consume-busy`` (another process holds the
        slot). That yields no token, so this request goes out unpinned and
        the next one retries — the same fail-open the provider already has
        for an unreadable credential, and strictly better than the direct
        POST it replaces, which answered ``invalid_grant`` and killed the
        lineage outright.
        """
        gate = getattr(switcher, "consume_backup_grant", None)
        if gate is None:
            return oauth.try_refresh_oauth_credentials(creds)
        outcome = gate(num, mail, creds)
        # Remember a DEFERRAL. "consume-busy" means another process holds the
        # slot right now, which is a race with the usage collector, not a
        # broken daemon — and the caller's only other signal is a None token,
        # which it reads as "this daemon cannot pin" and records permanently.
        if getattr(outcome, "error", None) == "consume-busy":
            _deferred.add(1)
            _note_busy_slot()
        return outcome

    # A deferral is benign and it was also completely silent: the outcome
    # went into `_deferred`, which only `pin_is_noop` reads, so "is this slot
    # actually contended?" had no answer anywhere. The two possible answers
    # have very different consequences -- a handful an hour is the race the
    # design anticipates, while a steady stream means requests keep going out
    # on the active account's bearer, and for a bridge-creating route that is
    # permanent and cannot be transferred afterwards.
    #
    # Rate-limited for the same reason the slow-request line is: a contended
    # slot would otherwise write one line per request. The count of the ones
    # it stands for is what makes the number readable.
    _busy = {"last": None, "since": 0}

    def _note_busy_slot() -> None:
        now = time.monotonic()
        last = _busy["last"]
        if last is not None and now - last < _BUSY_REPORT_COOLDOWN_S:
            _busy["since"] += 1
            return
        _busy["last"] = now
        more = f"; {_busy['since']} more" if _busy["since"] else ""
        _busy["since"] = 0
        _log_lifecycle(
            "a pinned request went out unpinned because another process held "
            f"the slot's refresh lock{more} -- benign as a race, but a steady "
            "stream of these means bridges are being created on the wrong "
            "account"
        )

    def _live_token(creds: str) -> str | None:
        data = oauth.extract_oauth_data(creds)
        if not data:
            return None
        access = data.get("accessToken")
        if access and not oauth.is_oauth_token_expired(data.get("expiresAt")):
            return access
        return None

    def _current_target() -> tuple[str, str] | None:
        """The account to pin RIGHT NOW, re-read so `cswap pin <other>` takes
        effect without restarting anything. Falls back to the one this daemon
        was spawned for when the pin is unreadable, and returns None when the
        pin was cleared outright (leave every bearer alone)."""
        _exc = require("exceptions")
        AccountNotFoundError, ConfigError = _exc.AccountNotFoundError, _exc.ConfigError

        try:
            pin = load_pin(switcher.backup_dir)
        except Exception:
            return account_num, email
        if pin is None:
            return None
        try:
            num, mail, _ = switcher.resolve_account(pin[0])
            return num, mail
        except (AccountNotFoundError, ConfigError, Exception):
            return account_num, email

    def _pin_is_the_live_login(num: str) -> bool:
        """Whether slot ``num`` really holds the live login.

        NOT `current_account_number()` alone. That resolves the identity in
        `~/.claude.json`'s `oauthAccount`, and THIS PIN OVERWRITES that field
        with the pinned identity so a live Remote Control bridge survives an
        account rotation. Asking it is asking our own forgery: it answers "the
        pin is already active", the provider swaps nothing on every request
        afterwards, and `pin_is_noop` calls that the correct answer — so a
        dead swap looks exactly like a healthy one, everywhere.

        The roster's `activeAccountNumber` is cswap's own record and the pin
        never writes it, so it is what separates our splice from a person
        genuinely logged in as the pinned account.

        THE PIN OWNS THIS, not the host. The host has an un-splice of its own,
        and while it is there the two agree — but it lives on a branch that is
        not merged, and the pin's own bearer swap must not be one rebase away
        from silence.
        """
        if switcher.current_account_number() != num:
            return False
        # It claims to be us. Was that our splice?
        try:
            recorded = (switcher._get_sequence_data() or {}).get(
                "activeAccountNumber")
        except Exception:  # noqa: BLE001 — an unreadable roster is not a verdict
            return True
        if recorded is None:
            return True
        return str(recorded) == str(num)

    # A one-shot flag for the pass currently running: set when the refresh was
    # DEFERRED rather than failed, so pin_is_noop can say "no token, but do not
    # condemn this daemon". A set is used only for its atomic add/discard.
    _deferred: set[int] = set()

    def provider() -> str | None:
        _deferred.discard(1)
        _stalled.flag = False
        target = _current_target()
        if target is None:
            return None
        num, mail = target
        if _pin_is_the_live_login(num):
            return None
        # THE READ IS NOT FREE ON EVERY PLATFORM. It costs 0.02ms on linux and
        # 19.77ms on a mac, where it shells out to the keychain — and a Remote
        # Control session posts `/worker/events` continuously, so that was
        # ~20ms added to the one channel whose latency is what a live claude.ai
        # view times out on.
        #
        # KEYED ON THE ACCOUNT, which is what keeps `cswap pin <other>` working
        # under a live session. The pin is still re-read from disk every
        # request; only the CREDENTIAL for an account already resolved is held,
        # so a re-pin is a different key and therefore a miss. The TTL then
        # bounds the one case the key cannot see: the same account's credential
        # rotated underneath us by the usage collector or the autoswitcher.
        # KEYED ON (slot, email), NOT the slot alone. A slot is stable while
        # the identity in it is not — `cswap move` renumbers, and a stub that
        # returned one number for two emails proved the point in the suite: the
        # re-pin case failed because the cache answered for the previous
        # account. The email is the half that actually identifies who this
        # credential belongs to.
        ckey = (num, mail)
        # EXPIRY IS THE INVALIDATION, NOT TIME. An access token carries its
        # own expiry, and another process rotating the stored credential does
        # not revoke the one already in hand -- it stays valid until it
        # expires. A TTL would therefore re-read on a timer to discover
        # something that cannot have happened yet, and the first cut of this
        # cache had a 5s one for exactly that non-reason.
        #
        # The rotation case is handled where it matters: when the held token
        # IS expired, the refresh path below takes the lock and re-reads the
        # store before deciding. That re-read predates this cache.
        cached = _cred_cache.get(ckey)
        if cached is not None:
            provider.blind_reason = ""
            token = _live_token(cached)
            if token:
                return token  # common path: no lock, no network
            creds = cached
        else:
            # COLD -- the very first read for this key, which is EVERY key on
            # a fresh daemon (`_cred_cache` starts empty every start). This
            # used to run right here, outside `refresh_lock` and unbounded:
            # the same store the refresh below already treats as capable of
            # wedging forever, invisible to `_mint_lock_busy` and therefore to
            # `/health` and the self-heal watchdog. It goes under the same
            # bounded lock the refresh uses, below.
            creds = None

        # BOUNDED, not `with refresh_lock:`. The critical section below can
        # call into the host's Keychain read and a network refresh, and a
        # stalled credential store can wedge either one forever (measured: a
        # `security find-generic-password -w` still hung after 2d19h) --
        # unkillable from here, so the holder of the lock stays blocked in
        # that call. Everyone else must not queue behind it: they fail this
        # one request instead. See `_MINT_LOCK_BOUND_S`.
        if not refresh_lock.acquire(timeout=_MINT_LOCK_BOUND_S):
            _stalled.flag = True
            provider.blind_reason = (
                f"mint stalled: the refresh lock has been held over "
                f"{_MINT_LOCK_BOUND_S:.0f}s for slot {num} ({mail}) -- a "
                "stuck credential read or refresh, not a broken pin")
            return None
        provider._lock_acquired_at = time.monotonic()
        try:
            # Someone may have rotated it while we waited, or this is the
            # cold-cache case above and this IS the first read — either way
            # the read happens here, under the lock.
            creds = switcher.read_account_credentials(num, mail) or creds
            if not creds:
                # SAY WHICH SLOT, or "could not be read" is unfalsifiable. An
                # empty read and a read of the WRONG slot are indistinguishable
                # from the warning alone, and hours went into a machine where
                # the second was never excluded. The provider is the only
                # place that knows what it asked for.
                provider.blind_reason = f"no credential for slot {num} ({mail})"
                return None
            provider.blind_reason = ""
            # REPLACE THE HELD COPY, or the cache keeps handing back the
            # expired blob and every later request re-enters this lock.
            _cred_cache[ckey] = creds
            token = _live_token(creds)
            if token:
                return token
            # CARRY THE REFRESH VERDICT OUT. `RefreshOutcome.error` already
            # classifies this -- `invalid_grant` means the lineage is dead and
            # only a person can fix it, `transient` means try again -- and it
            # was being dropped on the floor. The warning then said "could not
            # be read" for a credential that read perfectly, whose ACCESS token
            # had merely expired and whose refresh the server had rejected.
            # Those need opposite responses and looked identical in a log.
            def _consume_recording(c):
                out = _consume(c, num, mail)
                err = getattr(out, "error", None)
                if err:
                    provider.blind_reason = (
                        f"refresh {err} for slot {num} ({mail})")
                return out

            token, rotated = resolve_pin_token(creds, _consume_recording)
            if token is None and not getattr(provider, "blind_reason", ""):
                # The refresh reported no error and still produced nothing.
                # Say that rather than nothing.
                provider.blind_reason = (
                    f"no token after refresh for slot {num} ({mail})")
            if rotated:
                # HELD COPY, SAME AS THE COLD-READ WRITE ABOVE. `_cred_cache`
                # was left holding the pre-refresh (expired) blob after a
                # successful refresh -- `can_pin_cached()`, and therefore
                # `/health`'s `can_pin`, kept reading a permanently-expired
                # cache after every rotation, until the NEXT credential read
                # happened to run.
                _cred_cache[ckey] = rotated
            # The gate persists internally (under the slot lock, CAS on the
            # refresh-token fingerprint). Persisting again here would write
            # back OUTSIDE that lock and could clobber a racing writer's
            # newer lineage — the exact failure the gate exists to prevent.
            if rotated and not hasattr(switcher, "consume_backup_grant"):
                switcher.persist_backup_credentials(num, mail, rotated)
            return token
        finally:
            provider._lock_acquired_at = None
            refresh_lock.release()

    def pin_is_noop() -> bool:
        """True when returning no token is the CORRECT answer, not a failure.

        ``provider`` returns None for two opposite reasons and the caller
        cannot tell them apart: the credential could not be read (bad — every
        pinned request goes out unpinned), or there is deliberately nothing to
        swap. The second happens whenever the pinned account IS the active
        account — the live bearer already belongs to it — and whenever the pin
        was cleared outright.

        Without this split the fail-open warning cries wolf. Measured on
        host-c: pinned account == active account, so the provider
        correctly returned None on the very first request and the daemon
        logged "the pinned account token could not be read ... on macOS this
        is usually a daemon started outside the GUI session". Nothing was
        wrong; the keychain read was fine (rc=0, 509 bytes). It cost the
        reader ten minutes down a keychain rabbit hole, and a warning that
        fires when nothing is wrong is worse than no warning at all — this one
        exists to be believed on the day it is real.
        """
        if 1 in _deferred:
            # The refresh was DEFERRED, not failed: another process holds the
            # slot's consume lock (the usage collector polls on its own
            # schedule and contends for exactly this slot). This request goes
            # out unpinned and the next one retries — but the caller's only
            # other reading of a None token is "this daemon cannot pin", which
            # it records into proxy.json permanently, so one lost race would
            # condemn a healthy daemon for good.
            return True
        target = _current_target()
        if target is None:
            return True  # pin cleared: leaving every bearer alone IS the job
        return _pin_is_the_live_login(target[0])

    def can_pin_cached() -> bool:
        """Whether the pin can apply RIGHT NOW using only what is already in
        hand -- no store read, no lock, no network. This is what `/health`
        asks: the store read `provider()` may need to answer for real is
        exactly the call that can wedge (see `_MINT_LOCK_BOUND_S`), and
        `/health` must never make it -- see `_can_pin_from_cache`.

        True on a no-op pin (nothing to swap) or a cached, still-live token.
        False otherwise: a cold or expired cache, which used to be resolved
        by calling `provider()` from the health thread itself. The daemon-
        start warm (`_warm_mint_cache`) is what keeps this True on a healthy
        daemon before the first real request arrives.
        """
        if pin_is_noop():
            return True
        target = _current_target()
        if target is None:
            return True
        cached = _cred_cache.get(target)
        return bool(cached and _live_token(cached))

    provider.pin_is_noop = pin_is_noop
    provider.mint_stalled = mint_stalled
    provider.refresh_lock = refresh_lock
    provider.can_pin_cached = can_pin_cached
    provider._lock_acquired_at = None
    return provider


def _mint_lock_busy(provider) -> "float | None":
    """Non-blocking peek at the provider's refresh lock.

    None when the lock is free, or the provider carries none (a bare
    callable, the shape a test double or an old caller uses). A float when
    it is held RIGHT NOW: how long, when the holder recorded taking it,
    else ``0.0`` when that is unknown. Never blocks — this is what lets
    `/health` and the self-heal watchdog ask "can this daemon mint" without
    queuing behind a stalled credential store the way a request that calls
    `provider()` itself would.
    """
    lock = getattr(provider, "refresh_lock", None)
    if lock is None:
        return None
    if lock.acquire(blocking=False):
        lock.release()
        return None
    since = getattr(provider, "_lock_acquired_at", None)
    return (time.monotonic() - since) if since is not None else 0.0


def _can_mint(provider) -> "bool | None":
    """Whether the pinned token can be minted RIGHT NOW, or None if unaskable.

    The self-heal watchdog's reader of that fact (`/health` reads
    `_can_pin_from_cache` instead — see there for why).

    None means there is nothing to ask: no provider at all (a stand-in server
    in a test), or its refresh lock is held RIGHT NOW (`_mint_lock_busy`) — a
    refresh genuinely in progress, possibly a stalled one, that this call must
    not wait behind. Callers must treat it as "cannot tell" and act on
    `is False`, never on falsiness: a bare `not _can_mint(...)` recycles every
    test server, and would recycle a daemon over a refresh merely in flight.
    """
    if provider is None:
        return None
    if _mint_lock_busy(provider) is not None:
        return None
    try:
        return bool(provider()) or _pin_is_noop(provider)
    except Exception:  # noqa: BLE001 — a health question is never fatal
        return False


def _can_pin_from_cache(provider) -> bool:
    """`/health`'s reading of whether the pin can apply, without ever calling
    `provider()` -- the call that can wedge on a stalled credential store,
    on the ONE probe every monitor, `cswap pin --heal` and the installer's
    activation check use for liveness (see `_MINT_LOCK_BOUND_S`).

    Uses the provider's own cached-state reading (`can_pin_cached`) when it
    has one -- every provider `make_pin_token_provider` builds does. Falls
    back to `_can_mint` for anything else: a bare test double with no cache
    of its own, which carries no store access to wedge on in the first
    place.
    """
    cached = getattr(provider, "can_pin_cached", None)
    if cached is not None:
        return cached()
    return _can_mint(provider) is not False


_last_mint_busy_log: dict = {"at": None}


def _note_mint_busy(age: float) -> None:
    """Log, at most once per `_BUSY_REPORT_COOLDOWN_S`, that the self-heal
    watchdog is skipping a recycle because the mint's refresh lock is
    currently held. Same idiom as `_note_busy_slot` and for the same reason:
    a stalled store is checked on every watchdog tick and one line per tick
    would bury the signal it exists to be."""
    now = time.monotonic()
    last = _last_mint_busy_log["at"]
    if last is not None and now - last < _BUSY_REPORT_COOLDOWN_S:
        return
    _last_mint_busy_log["at"] = now
    _log_lifecycle(
        f"cannot mint the pinned token right now: the refresh lock has been "
        f"held for {age:.0f}s -- not replacing ourselves for a stall a "
        "successor would only inherit"
    )


def _pin_is_noop(provider) -> bool:
    """Ask a token provider whether None means "nothing to do" right now.

    Tolerates a provider without the hook — tests inject bare lambdas, and a
    plain callable must keep working — by answering False, which is the old
    behaviour (treat None as a failure).
    """
    try:
        return bool(getattr(provider, "pin_is_noop", None) and provider.pin_is_noop())
    except Exception:
        return False


def _keychain_denied_here() -> bool:
    """macOS only: whether THIS process is refused Claude Code's OAuth
    Keychain item. A process outside the login session is (``security``
    rc=36: the access prompt cannot be shown there), and a daemon it spawns
    inherits the refusal for its whole lineage, successors included. Two
    reads a second apart, so a transient burst is not a denial; an absent
    item is not one either."""
    if sys.platform != "darwin":
        return False
    try:
        kc = require("macos_keychain")
        cred = require("credentials")
    except Exception:  # noqa: BLE001 -- no host, nothing to ask
        return False
    for attempt in range(2):
        try:
            kc.get_password(cred.CLAUDE_CODE_KEYCHAIN_SERVICE,
                            kc.keychain_account_name())
            return False
        except kc.KEYCHAIN_ERRORS as e:
            if "rc=36" not in str(e):
                return False
        if attempt == 0:
            time.sleep(1.0)
    return True


def ensure_proxy(switcher) -> tuple[int, Path] | None:
    """Make sure a pin proxy is serving for the pinned account.

    Returns ``(port, ca_path)`` to wire into the child env, or ``None`` when
    no pin is set (or the pinned account no longer exists — a dangling pin
    must never block a launch). Reuses a live daemon recorded in
    ``<backup>/pin-proxy/proxy.port`` (one proxy shared across sessions);
    otherwise spawns one.
    """
    _exc = require("exceptions")
    AccountNotFoundError, ConfigError = _exc.AccountNotFoundError, _exc.ConfigError

    pin = load_pin(switcher.backup_dir)
    if not pin:
        return None
    email, _org = pin
    try:
        account_num, email, _ = switcher.resolve_account(email)
    except (AccountNotFoundError, ConfigError):
        return None
    certdir = switcher.backup_dir / "pin-proxy"
    certdir.mkdir(parents=True, exist_ok=True)

    # The second of the sweep's two hooks; `heal` carries the other, and the
    # README's table says which sessions each one reaches. This one is
    # synchronous before `execvpe`, so a `cswap run` launch never races it.
    _carry_history_pointers(certdir)

    # Re-stamp the egress proxy on EVERY launch, before any reuse decision.
    # This is what makes the daemon follow the environment instead of the
    # environment that happened to exist when it spawned: a wrapper that sets
    # a proxy, one that moved ports, or one that went away entirely.
    # ...and the hop BEHIND it, asked of that hop while it is answering. A
    # launch is the only moment that question has a trustworthy answer, and it
    # is what lets a dead hop fall through to the next one instead of to a
    # direct dial (see ``_probe_next_hop``).
    ambient, observed_next = _ambient_chain(certdir=certdir)
    # Two independent sources for the hop BEHIND this one, and they fail in
    # different conditions: the probe needs the inner hop to be answering,
    # while the shell's own proxy is visible whether or not it is. Prefer the
    # probe (it is what the hop reports about itself) and fall back to what
    # this launch observed directly.
    write_upstream_hint(
        certdir,
        ambient,
        os.environ.get("NODE_EXTRA_CA_CERTS"),
        next_hop=_probe_next_hop(ambient or _read_upstream(certdir, "proxy"))
        or observed_next,
    )
    fp = daemon_fingerprint(account_num, email)

    ca = certdir / "ca.pem"
    # Generate the CA here rather than leaving it to the daemon: publishing has
    # to happen before the client is exec'd, and on the very first launch the
    # daemon has not run yet, so there would be nothing to publish. ensure_ca is
    # idempotent, so this only ever does work once.
    try:
        ensure_ca(certdir, UPSTREAM_HOST)
    except Exception:
        pass
    # Publish on EVERY launch, not only when another CA happens to be in play.
    # A launcher builds its merged bundle from this directory as it starts us,
    # so a CA published later would miss that build, and a component whose cert
    # dir was wiped must reappear on the next launch rather than stay silently
    # absent.
    publish_ca(ca)

    # Fast path (no lock): a fresh, current daemon is reused as-is.
    port = _read_alive_port(certdir, fingerprint=fp)
    if port is not None:
        wire_global_config(port, ca)
        return port, ca

    # Slow path: take an exclusive lock so concurrent launches elect ONE
    # spawner (an mkdir election). Re-check under the lock — another launch
    # may have spawned while we waited.
    with _spawn_lock(certdir):
        port = _read_alive_port(certdir, fingerprint=fp)
        if port is not None:
            wire_global_config(port, ca)
            return port, ca
        # A HANDOVER IN FLIGHT IS NOT "NOTHING IS SERVING". `_read_alive_port`
        # returns None for it, correctly — the recorded daemon has stopped and
        # its successor has not published — but that None means "wait", not
        # "spawn". Taken as "spawn" it produces the mirror image of the bug
        # this file spent a night on: `cswap pin <n>` reporting "no proxy is
        # running, so nothing is pinned yet" while the successor published 16
        # seconds later and the pin was fine. A false failure sends someone
        # chasing a repair that is already happening.
        #
        # Same bounded wait and same loop as the recycle branch below, because
        # it is the same question: the holder owns the replacement and we are
        # waiting for it to appear.
        settling = read_daemon_state(certdir)
        if settling and settling.get("handover"):
            for _ in range(int(_SPAWN_WAIT_S * 10)):
                time.sleep(0.1)
                port = _read_alive_port(certdir, fingerprint=fp)
                if port is not None:
                    wire_global_config(port, ca)
                    return port, ca

        # A daemon exists but is stale (wrong account, or redeployed code) —
        # recycle it before spawning, so a redeploy/repin takes effect instead
        # of a stale daemon serving forever.
        stale = read_daemon_state(certdir)
        # "Alive" is not "still ours". An unclean exit leaves proxy.json
        # behind, and a pid is reused freely — so liveness alone would aim
        # SIGTERM (then SIGKILL) at whatever unrelated process inherited the
        # number. Ask whether the pid is a pin daemon for THIS certdir, which
        # is exactly what the orphan sweep already asks.
        #
        # When the identity cannot be established at all (no ``ps``), this
        # recycles nothing rather than killing on faith. The stale daemon
        # keeps its port, the successor binds an ephemeral one and the
        # wiring is rewritten to it — degraded, but nobody else's process
        # gets killed. The same blind spot already bounds the orphan sweep.
        if stale and int(stale["pid"]) in _pin_daemon_pids(certdir):
            # Save the port BEFORE the kill: the daemon unlinks its own state
            # on TERM, so afterwards there is nothing left to reclaim from and
            # the successor would take a fresh port — stranding every session
            # already wired to the old one.
            if isinstance(stale.get("port"), int):
                _write_port_hint(certdir, stale["port"])
            if _recycle_daemon(certdir, int(stale["pid"])):
                # THE HOLDER OWNS THE REPLACEMENT.
                for _ in range(int(_SPAWN_WAIT_S * 10)):
                    port = _read_alive_port(certdir)
                    if port is not None:
                        wire_global_config(port, ca)
                        return port, ca
                    time.sleep(0.1)
        if _keychain_denied_here():
            _log_lifecycle(
                "not spawning the pin daemon from here: this process cannot "
                "read the Keychain (security rc=36), and a daemon it starts "
                "could never mint. Start it from the login session -- the TUI "
                "does, and so does `cswap pin --ensure` in a terminal there")
            return None
        port = _spawn_daemon(account_num, email, certdir)
        if port is None:
            # The spawn failed. Anything still wired in .claude.json may name a
            # port nothing serves, and Claude Code applies that block at boot —
            # so a stale entry would take the SESSION down, not just the pin.
            #
            # unwire_if_dead re-checks liveness itself and leaves a SERVING
            # daemon alone, which matters here: "our spawn failed" is not the
            # same as "nothing is serving". A concurrent launch may have won
            # the race and started one, and a spawn can fail precisely because
            # a healthy daemon already owns the port.
            unwire_if_dead(certdir)
            return None
    # Re-point hand-launched sessions at the port that is actually serving.
    # Done on every launch, not just on pin: an idle teardown followed by a
    # respawn would otherwise leave .claude.json naming a dead port, and a
    # session wired to a dead port leaves WITHOUT the pin instead of failing.
    wire_global_config(port, ca)
    return port, ca


class SpawnLockBusy(RuntimeError):
    """Raised when a bounded `_spawn_lock` could not be taken in time."""


#: How long `heal` waits for the spawn lock before giving up. It runs inside a
#: DEPLOY, synchronously, and a deploy that stalls with no output is worse than
#: one that says it could not repair right now: the operator can re-run a heal,
#: they cannot un-hang a script. Everything heal would have done is done again
#: by the next launch or the next heal.
_HEAL_LOCK_WAIT_S = 10.0


def _spawn_lock(certdir: Path, name: str = ".spawn.lock",
                timeout: "float | None" = None):
    """Exclusive file lock serializing daemon spawns (one elected spawner).

    ``name`` picks which lock: cert generation takes its own so it cannot
    deadlock against a spawn that is itself waiting on cert generation.

    ``timeout`` bounds the wait and raises `SpawnLockBusy`; None keeps the
    blocking behaviour every existing caller has. A bounded wait exists because
    the holder can legitimately hold this for HOURS — the handover drains a
    Remote Control channel that lives as long as its session — so a caller with
    somebody waiting on it must be able to give up and say so.
    """
    import fcntl
    import time as _time
    from contextlib import contextmanager

    @contextmanager
    def _locked():
        Path(certdir).mkdir(parents=True, exist_ok=True)
        lockf = open(Path(certdir) / name, "w")
        try:
            if timeout is None:
                fcntl.flock(lockf, fcntl.LOCK_EX)
            else:
                deadline = _time.monotonic() + timeout
                while True:
                    try:
                        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if _time.monotonic() >= deadline:
                            raise SpawnLockBusy(
                                f"{name} still held after {timeout:.0f}s")
                        _time.sleep(0.1)
            yield
        finally:
            try:
                fcntl.flock(lockf, fcntl.LOCK_UN)
            finally:
                lockf.close()

    return _locked()


def _kill_daemon(pid: int, certdir: "Path | None" = None) -> None:
    """TERM a daemon, then escalate to KILL if it does not exit — so a daemon
    that ignores TERM (or hangs mid-teardown) never lingers as an orphan
    holding a port. Mirrors a supervisor recycle: bounded wait, then force.

    THE TERM BUDGET IS DERIVED FROM THE DRAIN, NOT CHOSEN. A daemon answering
    TERM runs ``stop(drain=_DRAIN_SECONDS)``, so a fixed 2s wait here SIGKILLed
    it mid-drain and the release's headline guarantee — in-flight requests
    survive an upgrade — held only for a signal sent by hand, never for the
    recycle the code itself performs. Measured against a real streaming client:
    the client received 4 of 10 SSE events and the drain marker was never
    written, because the process was killed before ``stop`` returned.

    Two independently-chosen timeouts that must be ordered is a bug that comes
    back every time either is tuned, so the ordering is computed. The slack
    covers teardown that is not draining (closing conns, unlinking state).

    AND IT IS THE SIGNAL ARM IT IS DERIVED FROM, which is the only one a TERM
    can reach: `teardown_drain_budget` gives a signal `_DRAIN_SECONDS` while a
    handover gets `_HANDOVER_DRAIN_SECONDS`, now infinite. So a daemon already
    inside an uncapped drain, TERMed by `_sweep_orphan_daemons`' excess reap,
    gets thirty seconds on the signal arm and is then KILLed with replies still
    moving. That is the intended outcome and not an oversight — the sweep only
    reaches that branch after deciding this predecessor is the cheapest one to
    lose, and a reap that could be outwaited forever is not a reap.
    """
    import time

    # A PID, NOT A GROUP. In ``kill(2)`` a pid of 0 addresses the CALLER'S OWN
    # process group and a negative pid addresses the group named by its
    # absolute value — so a derived-but-wrong 0 arriving here does not fail, it
    # SIGTERMs this daemon and whatever spawned it. A peer landed exactly here
    # with SIGKILL and took down its own test runner.
    if pid <= 0:
        return
    try:
        os.kill(pid, 15)  # SIGTERM
    except OSError:
        return
    # +2s of slack past the drain ceiling; the loop exits the moment it dies,
    # so a daemon with no live clients still returns in milliseconds.
    for _ in range(int(_DRAIN_SECONDS * 10) + 20):
        if not _pid_alive(pid):
            return
        # A DRAIN THAT ANNOUNCED ITSELF IS NOT AN ORPHAN. This escalation
        # exists so a daemon that IGNORES the signal never lingers holding a
        # port; a daemon that took it and is beating its marker is leaving on
        # its own and holds nothing anyone waits for. `_sweep_orphan_daemons`
        # already spares exactly this case with exactly this predicate -- its
        # own comment records the same incident, a handover that cut nothing
        # becoming a TERM one second later that cut 13 mid-response replies.
        #
        # NOT A LONGER WAIT: returning. Blocking here would hold a deploy open
        # for as long as a legitimate three-hour reply takes. The marker
        # expires by MTIME, so a drainer that stops beating stops being spared
        # and the next sweep reaps it -- the leak stays bounded without this
        # loop having to be the thing that bounds it.
        if certdir is not None and is_draining(certdir, pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, 9)  # SIGKILL escalation
    except OSError:
        return
    for _ in range(10):  # up to ~1s for the port to actually free
        if not _pid_alive(pid):
            return
        time.sleep(0.1)


def _recycle_daemon(certdir: Path, pid: int) -> bool:
    """Replace a stale daemon. True when a successor is already on the way.

    UNDER A HOLDER THIS IS NOT OURS TO DO, and doing it anyway was two
    mistakes at once (both measured):

      the TERM makes the daemon exit `_RESTART_ME_CODE`, so the holder
      replaces it AT ONCE — with the same stale code the recycle was meant to
      retire, and at zero backoff

      the caller then spawns, which starts a SECOND holder for a port the
      first one still holds. It cannot bind, falls back, and the wiring is
      rewritten to a different port: 44411 -> 41569, with every live session
      still naming 44411.

    So under a holder we TERM and report "handled": the holder puts a
    successor on the socket it owns, and the code watchdog inside that
    successor retires it again if the file on disk has moved on. Without a
    holder this is the old behaviour, unchanged — kill, and let the caller
    spawn.
    """
    held = _holder_owns(certdir)
    _kill_daemon(pid, certdir)
    return held


def _holder_owns(certdir: Path) -> bool:
    """Is a holder holding the port for ``certdir``?

    /proc FIRST, `ps` only as the fallback. `ps -eo command=` TRUNCATES a long
    command line — measured inside the test runner, where a holder's argv
    arrived as "--hold-port 0 1 a@" with the certdir cut off entirely, so the
    match could never succeed and the caller silently took the double-holder
    path. `/proc/<pid>/cmdline` is the argv the kernel actually holds, with no
    width to run out of. It does not exist on macOS, which is why `ps` stays
    as the fallback rather than the primary.

    Cannot tell -> False, which means "recycle the old way". Guessing True
    would skip a recycle that was asked for.
    """
    targets = {str(Path(certdir)), str(Path(certdir).resolve())}

    proc = Path("/proc")
    if proc.is_dir():
        for entry in proc.glob("[0-9]*"):
            try:
                argv = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
            except OSError:
                continue
            cmd = argv.decode("utf-8", "replace").rstrip()
            if _HOLDER_MODULE_ARG not in cmd:
                continue
            if any(cmd.endswith(" " + t) for t in targets):
                return True
        return False

    import subprocess

    try:
        out = subprocess.run(
            ["ps", "-ww", "-eo", "pid=,command="], capture_output=True, text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    for line in out.splitlines():
        cmd = line.strip().partition(" ")[2].rstrip()
        if _HOLDER_MODULE_ARG not in cmd:
            continue
        if any(cmd.endswith(" " + t) for t in targets):
            return True
    return False


def _pin_daemon_pids(certdir: Path) -> list[int]:
    """Pids of every running pin_proxy daemon serving THIS certdir. Matched on
    the daemon's argv (``-m claude_swap.pin_proxy ... <certdir>``) via ps, so a
    daemon for another backup dir is never touched."""
    import subprocess

    target = str(Path(certdir).resolve())
    pids: list[int] = []
    try:
        out = subprocess.run(
            ["ps", "-ww", "-axo", "pid=,command="],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return pids
    for line in out.splitlines():
        line = line.strip()
        if not any(m in line for m in _DAEMON_MODULE_NAMES):
            continue
        # The certdir must be the LAST argv token, not merely present. This
        # gate decides whether to SIGTERM-then-SIGKILL, and a substring match
        # also selects anything that happens to MENTION both — a shell whose
        # command line quotes them, a wrapper, a grep.
        head, _, rest = line.partition(" ")
        if not rest.rstrip().endswith(" " + target):
            continue
        # NOT THE HOLDER. Its argv is the daemon's plus one flag, so it passes
        # both gates above — and it is the one process here whose death takes
        # the port with it, which is the outage the holder exists to prevent.
        if f" {_HOLDER_MODULE_ARG} " in rest:
            continue
        # NOR THE STANDBY, for the same reason and with the same stakes. Its
        # argv is the daemon's plus one flag too, so it passes both gates above
        # — and it is the process whose death removes the port's last cover. It
        # ignores SIGTERM by design, so being selected here does not merely
        # stop it, it takes the SIGKILL escalation: no handler, no log, and
        # nothing places a replacement. A zombie stays in the process table
        # until reaped, so `ps`, `kill -0` and every check that asks the table
        # instead of the STATE reported a standby that did not exist.
        if f" {_STANDBY_MODULE_ARG} " in rest:
            continue
        try:
            pids.append(int(head))
        except ValueError:
            continue
    return pids


def _sweep_orphan_daemons(certdir: Path, keep_pid: int) -> None:
    """Kill every pin_proxy daemon for ``certdir`` except ``keep_pid`` — orphans
    that fell out of proxy.json (a redeploy/recycle replaced them but they
    didn't die) hold ports and never idle-teardown. Best-effort; never raises."""
    _collect_dead_markers(certdir)
    draining: list[tuple[int, float, int]] = []
    for pid in _pin_daemon_pids(certdir):
        if pid == keep_pid or pid == os.getpid():
            continue
        # A PREDECESSOR FINISHING ITS REPLIES IS NOT AN ORPHAN. See
        # `announce_draining`: it accepts nothing and exits by itself, which is
        # the opposite of the "holds a port and never idle-teardowns" this
        # sweep exists for. Killing it is how a handover that cut nothing
        # became a TERM one second later that cut 13 mid-response replies.
        if is_draining(certdir, pid):
            draining.append((draining_streams(certdir, pid),
                             draining_live(certdir, pid),
                             draining_owed(certdir, pid),
                             draining_since(certdir, pid), pid))
            continue
        _kill_daemon(pid, certdir)

    # BUT A PILE OF THEM IS A LEAK, and this count is the only thing bounding
    # it now that `_HANDOVER_DRAIN_SECONDS` is infinite. The count tells them
    # apart; the clock was cutting the first to catch the second. CHEAPEST
    # FIRST, AND AGE IS ONLY THE TIEBREAK. The first version reaped the
    # longest-running, on the reasoning that old means probably finished.
    # Longest-first therefore took the stream with the most work already sunk
    # and the worst retry odds. The count of replies owed is what a reap
    # actually COSTS, so that is what orders it. AND 'CHEAPEST' MEANS LIVE
    # ANSWERS, NOT DEBTS. At the limit that made the reaper prefer to kill the
    # predecessor still doing real work. `live_replies` counts answers rather
    # than debts, by SSE event name rather than by any threshold.
    #
    # AND A DAEMON CARRYING A BRIDGE IS NOT PART OF THE PILE. This limit bounds
    # predecessors that will not finish; one still carrying a live channel is a
    # SESSION, and it ends when that session does. Ordering alone was not
    # enough: a daemon whose only remaining job is that stream has zero live
    # replies, so it sorted CHEAPEST and was always the one taken — the reap
    # the fleet chose first was the one no session can recover from by itself.
    reapable = [d for d in draining if d[0] == 0]
    excess = len(draining) - _MAX_DRAINING_PREDECESSORS
    if excess > 0 and not reapable:
        _log_lifecycle(
            f"{len(draining)} draining predecessors, over the "
            f"{_MAX_DRAINING_PREDECESSORS} this fleet can produce — taking "
            "NONE: every one is still carrying a live channel, and cutting "
            "one costs a session something it cannot reopen. They exit when "
            "their sessions do")
    if excess > 0 and reapable:
        reapable.sort()  # fewest live replies, then fewest owed, then oldest
        for streams, live, owed, since, pid in reapable[:excess]:
            _log_lifecycle(
                f"{len(draining)} draining predecessors, over the "
                f"{_MAX_DRAINING_PREDECESSORS} this fleet can produce — "
                f"taking pid={pid}, draining {time.time() - since:.0f}s, "
                f"owing {'?' if owed == _OWED_UNKNOWN else owed} repl"
                f"{'y' if owed == 1 else 'ies'} of which "
                f"{'?' if live == _OWED_UNKNOWN else live} still being "
                f"written, quiet for "
                f"{_quiet_phrase(draining_quiet(certdir, pid))}. "
                "A drain that never ends is "
                "the leak the removed wall clock used to bound; this line is "
                "the signal it happened")
            _kill_daemon(pid, certdir)


def _quiet_phrase(secs: "float | None") -> str:
    """How long the reaped daemon's worst reply had been silent, in words.

    THREE STATES, NOT TWO. `draining_quiet` answers None for a marker written
    by a version that did not record it, and that is not the same as 0.0 — a
    predecessor from an older release must not read as the healthiest thing on
    the box at the moment somebody decides to kill it.

    This is `draining_quiet`'s production caller, and it exists because a
    reader with no caller is a reader the next person deletes and then
    re-derives from the marker by hand, one file over, slightly differently.
    """
    if secs is None:
        return "an unknown time (older daemon, no such record)"
    return f"{secs:.0f}s"


def _collect_dead_markers(certdir: Path, keep_pid: int | None = None) -> None:
    """Remove `.draining-<pid>` markers nothing has beaten since the TTL.

    A DRAINER THAT IS SIGKILLED CANNOT UNLINK ITS OWN, and every reap above
    produces one, as does an OOM kill or a crash. `is_draining` already stops
    honouring a silent marker, so this is litter rather than a safety hole —
    but it is litter in the one directory somebody opens to find out what a
    handover did, and this sweep already walks it.

    Best-effort and silent: failing to tidy must never stop the sweep from
    doing the job it exists for.
    """
    cutoff = time.time() - _DRAINING_MARKER_TTL
    try:
        markers = list(Path(certdir).glob(f"{_DRAINING_PREFIX}*"))
    except OSError:
        return
    keep = None if keep_pid is None else f"{_DRAINING_PREFIX}{keep_pid}"
    for path in markers:
        # NEVER THE CALLER'S OWN. A beat reaps before it refreshes, so on a
        # drain whose beat is slower than the TTL this would delete the marker
        # that protects it and the write that follows would raise on a missing
        # file -- the drain then loses its protection mid-reply and the sweep
        # TERMs it. An invariant here, not an ordering the next edit can undo.
        if keep is not None and path.name == keep:
            continue
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            continue


def _install_signal_teardown(cleanup) -> None:
    """Register SIGTERM/SIGINT so a recycle/cc-update TERM runs ``cleanup``
    (stop the server, remove the state file) instead of a bare default kill —
    the daemon leaves no stale state or bound port behind."""
    import signal

    def _handler(signum, frame):
        try:
            # NAME THE SIGNAL. A TERM from a recycle and an idle teardown are
            # the same code path and left the same (empty) trace, so a daemon
            # that vanished could not be told from one that was killed.
            cleanup(f"signal {signal.Signals(signum).name}")
        except TypeError:
            cleanup()  # a cleanup that takes no reason (tests)
        finally:
            # A TERM IS A RECYCLE, NOT A RELEASE. Somebody wants this daemon
            # replaced — a redeploy, a repin, a fingerprint change — and under
            # a holder that means "put a successor on this socket", not "give
            # the port back".
            #
            # THE HOLDER IS IDENTIFIED BY THE HAND-DOWN VARIABLES, not by
            # LISTEN_PID. Only when a holder owns the socket: without one there
            # is nothing to interpret the code, and 0 is what every existing
            # caller reads.
            os._exit(
                _RESTART_ME_CODE
                if held_by_a_holder()
                else 0
            )

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # not on the main thread (tests) — best effort


_DAEMON_MODULE = "cswap_pin.proxy"
# Same module, same certdir, one flag apart — which is why `_pin_daemon_pids`
# has to exclude it explicitly rather than by argv shape.
_HOLDER_MODULE_ARG = "--hold-port"

# The orphan sweep finds daemons by matching their argv, so during the split it
# must recognise BOTH module paths. A machine mid-cutover can have a daemon
# spawned by the OLD in-tree module still serving while the new package is
# installed; matching only the new name would make that daemon invisible to the
# sweep and leave it holding its port forever — the exact leak aab7246 fixed.
# The old name stays until every deployed machine has been re-pinned under
# cswap-pin; removing it early costs a leaked daemon, removing it late costs
# nothing.
_DAEMON_MODULE_NAMES = (_DAEMON_MODULE, "claude_swap.pin_proxy")

_STATE_FILE = "proxy.json"
# Writing this file reaches a daemon that is already serving.
_TRACE_SWITCH_FILE = "trace-to"
# Same live-switch shape as `trace-to`: one client entrypoint per line
# (`claude-desktop`) whose inference is re-billed to cswap's active account.
_INFERENCE_SWITCH_FILE = "inference-follows"
# Counters for that path, ONE FILE PER DAEMON PID, written by a background
# thread (see _InferenceStats). Per pid because a handover leaves two daemons
# alive at once — the successor serving, the predecessor draining — and a
# shared file let the successor's zeroes overwrite the counts that mattered.
_INFERENCE_STATS_GLOB = "inference-follows.*.json"
_INFERENCE_STATS_KEEP_S = 7 * 24 * 3600
# Re-read at most this often: the check sits on the request path, and a stat
# per request buys nothing when the answer changes once a day at most.
_TRACE_RECHECK_S = 2.0
_TRACE_CACHE: dict = {}
# How long `_spawn_daemon` waits for a successor to publish. 10s because a
# FIRST run generates an RSA key pair before it can serve.
_SPAWN_WAIT_S = 10.0
# The pin's OWN settings, in the pin's OWN directory. Settings for an optional
# feature do not belong in another program's exclusive file, and a user who
# wanted a fixed port had nowhere to say so.
_SETTINGS_FILE = "settings.json"
_FIFO_NAME = "refcount.fifo"
_LOG_NAME = "daemon.log"
# WHO WROTE THE LINE. Two proxies on this fleet emit drain lines — this one and
# the cache-fix fork — and `drained clean` was a phrase neither owned, so a
# reader handed one line could not say which produced it.
#
# INSERTED BEFORE `pid=`, never around the phrases. Peer readers match `drained
# clean` and `cut .* in-flight` UNANCHORED (checked, not assumed:
# `pin_cut_count` in the fleet tooling, and this file's own suite, whose only
# positional assertion is `"pid=" in text`). Renaming or wrapping those tokens
# would break every one of them; a token ahead of `pid=` cannot.
#
# AT THE FUNNEL rather than on the two lines that collide today, so a line type
# added next month gets it without anyone remembering to.
def _component_tag() -> str:
    """`cswap-pin/<version>`, or the bare name if the version cannot be read.

    THE VERSION IS PART OF THE PROVENANCE, and leaving it out cost a night.
    0.1.113-0.1.115 printed a `content-free` value that measured the wrong
    quantity; 0.1.116 fixed it. Both shapes sit in the same log, spelled
    identically, so every reader — my own watcher, a peer's table, me — has to
    know WHEN each machine was upgraded to tell a usable number from a
    worthless one. A line that names the code that wrote it never needs that.

    Cheap enough to compute once at import: this is the same funnel the
    component name goes through, so a line type added later is covered without
    anyone remembering.

    Falls back to the bare name rather than raising or printing "unknown": a
    daemon that cannot read its own metadata must still log.
    """
    try:
        from cswap_pin import __version__

        tag = f"cswap-pin/{__version__}"
    except Exception:  # noqa: BLE001 — a log line is not worth an exception
        return "cswap-pin"
    return tag + _host_head()


def _host_head() -> str:
    """`+<name>@<sha>` for a host installed from a checkout, else "".

    THE VERSION NAMES THIS PACKAGE AND NOTHING ELSE. A pin release runs on
    whatever host tree is installed beside it, and that tree is what carries
    the open pull requests -- so two daemons logging the same version can be
    running different host code, and a reader months later cannot tell which.
    The version answers "which pin"; this answers "which of everything else".

    Read from `.git` directly rather than through a subprocess: this runs at
    import in a proxy that must not spawn, and a detached HEAD or a missing
    ref simply yields no suffix. A wheel install has no `.git` and is silent,
    which is correct -- there its version IS the whole provenance.
    """
    try:
        import pathlib
        host = __import__("claude_swap")
        d = pathlib.Path(host.__file__).resolve().parent
        for root in (d, *d.parents):
            g = root / ".git"
            if not g.is_dir():
                continue
            head = (g / "HEAD").read_text().strip()
            if head.startswith("ref: "):
                ref = g / head[5:]
                head = ref.read_text().strip() if ref.exists() else ""
            return f"+{root.name}@{head[:8]}" if head else ""
        return ""
    except Exception:  # noqa: BLE001 — provenance must not cost a log line
        return ""


_COMPONENT = _component_tag()
_LOG_MAX_BYTES = 64 * 1024
#: The ARMED trace only. `daemon.log` is always on and its 64 KiB is a
#: deliberate bound on a file nobody asked for; the request trace is written
#: only while `trace-to` exists, so its ceiling is a diagnostic decision and
#: not a disk one. MEASURED: at 64 KiB the trace retained 1.1 minutes on a
#: busy host and rotated TWICE inside a seven-second control window, which
#: voided the measurement outright. A diagnostic that cannot outlive the
#: thing being diagnosed is not one.
_TRACE_MAX_BYTES = 4 * 1024 * 1024


def configured_port(certdir: Path) -> int | None:
    """The port the user asked us to serve on, or None for an ephemeral one.

    ONE SOURCE: ``settings.json``, written by ``cswap pin --set_port``.

    NOT ``CSWAP_PIN_PORT``: `wire_global_config` writes that name into
    `.claude.json` as the self-loop marker and Claude Code applies the block
    at boot, so inside a pinned session it is already the LIVE daemon's port.
    Reading it as config made the pin fight itself for a port it was on.

    0 is not a port to bind: `bind()` reads it as "choose one for me", so
    `--set_port 0` CLEARS the setting, which is how a dynamic port is asked
    for.
    """
    try:
        port = int(_settings_port(certdir))
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _settings_port(certdir: Path) -> object:
    """The persisted port, raw. Unreadable or absent is no opinion."""
    try:
        raw = json.loads(
            (Path(certdir) / _SETTINGS_FILE).read_text(encoding="utf-8")
        )
    except Exception:  # noqa: BLE001 — absent/unreadable/malformed: no opinion
        return None
    return raw.get("port") if isinstance(raw, dict) else None


def draining_marker_path(certdir: Path, pid: int) -> Path:
    """Where a daemon announces that it is finishing replies and will exit."""
    return Path(certdir) / f"{_DRAINING_PREFIX}{pid}"


def announce_draining(certdir: Path, pid: int | None = None, server=None):
    """Say "I am leaving on my own" so the orphan sweep does not TERM us.

    THE TWO FIXES THAT WERE EACH RIGHT ALONE AND OPPOSED TOGETHER. A handover
    releases the port and then waits up to `_HANDOVER_DRAIN_SECONDS` for the
    replies it already owes. `_sweep_orphan_daemons` kills every pin daemon for
    this certdir that is not the recorded one, and `_spawn_daemon` runs it the
    moment the successor is serving. To that sweep, a predecessor patiently
    draining is indistinguishable from an orphan.

    Measured on host-a 2026-08-18, the 0.1.100 rollout:

        08:21:19Z  pid=616877  serving on port 36301
        08:21:19Z  pid=2932386 stopping (signal SIGTERM)
        08:21:49Z  pid=2932386 cut 13 (13 mid-response, 0 before headers)

    one second between the successor serving and its predecessor being
    signalled. And the 0.1.99 ceiling is what made it bite: before it the
    predecessor exited inside thirty seconds and the sweep usually found
    nothing, so widening the wait twentyfold widened the window to be killed in.

    THE SWEEP'S OWN DOCSTRING NAMES A DIFFERENT POPULATION — daemons that "hold
    ports and never idle-teardown". A drainer holds no port it will accept on
    and exits by itself within the ceiling. Two populations, one pid filter.

    ANNOUNCED RATHER THAN INFERRED. "Is it still listening" cannot separate
    them: site 1 releases its listener but site 3 keeps a duplicate fd on
    purpose, so the observable is the same for a drainer and an orphan. The
    process that knows is the one doing it.

    NOT A LOCK AND NOT A PROMISE. A marker that cannot be written changes
    nothing — the drain still runs, the sweep still kills, and the outcome is
    exactly today's. Failing open here is the whole design: this file may only
    ever REMOVE a kill, never cause one.
    """
    pid = os.getpid() if pid is None else pid
    # REAP THE CORPSES FIRST, because this is the only LIVE path that runs
    # often enough to. `_collect_dead_markers` is otherwise reachable only
    # from `_spawn_daemon`, so a marker whose process died without a
    # subsequent spawn sits past its TTL indefinitely. A drain starting is
    # the natural moment: it is the event markers exist for, and it is rare.
    try:
        _collect_dead_markers(certdir)
    except Exception:  # noqa: BLE001 — housekeeping must not stop a drain
        pass
    path = draining_marker_path(certdir, pid)
    key = str(path)
    with _DRAINING_LOCK:
        first = _DRAINING_DEPTH.get(key, 0) == 0
        _DRAINING_DEPTH[key] = _DRAINING_DEPTH.get(key, 0) + 1
    if first:
        try:
            path.write_text(str(time.time()))
        except OSError:
            # THE FILE IS ADVICE TO OTHER PROCESSES; THE DEPTH IS OUR OWN
            # KNOWLEDGE.
            # `teardown_drain_budget(handed_over=this_process_is_draining())`
            # reads it now, so the rollback broke the promise one paragraph up:
            # an ENOSPC or a read-only certdir made a daemon mid-handover
            # report "not draining", take the 30s held ceiling instead of the
            # uncapped one, and cut the live mid-response replies that ceiling
            # was removed to save. A failed write must cost the SWEEP its
            # information, never cost us a reply.
            pass

    # ANSWERABLE FROM THE MOMENT IT EXISTS. Line 0 alone is a marker
    # `draining_bridges` cannot read: it takes `body[5]`, gets IndexError, and
    # reports "cannot be asked" -- the verdict reserved for a release predating
    # the held-bridge record. That window is not a race lost occasionally. The
    # announce deliberately precedes `_spawn_daemon`, which BLOCKS waiting for
    # the successor to publish, so the process reading this one-line file is
    # the successor being spawned, every time.
    #
    # THROUGH `beat_draining`, never by writing the layout here. A second place
    # that knows which line holds what is a mirror, and the mirrors in this
    # file have rotted twice.
    if first and server is not None:
        try:
            beat_draining(certdir, pid,
                          owed=server.inflight_requests(),
                          live=0,
                          quiet=server.content_free_seconds(),
                          streams=(server.live_stream_count()
                                   + _PUMP.live_pairs()),
                          bridges=server.held_bridge_ids())
        except Exception:  # noqa: BLE001 — a marker is advice, never a promise
            pass

    released = False

    def _done():
        # IDEMPOTENT PER CALLER, so a caller that releases twice cannot take
        # the count below the drains still running.
        nonlocal released
        if released:
            return
        released = True
        with _DRAINING_LOCK:
            _DRAINING_DEPTH[key] = _DRAINING_DEPTH.get(key, 1) - 1
            last = _DRAINING_DEPTH[key] <= 0
            if last:
                _DRAINING_DEPTH.pop(key, None)
        if not last:
            return
        try:
            path.unlink()
        except OSError:
            pass

    return _done


def beat_draining(certdir: Path, pid: int | None = None,
                  owed: int | None = None, live: int | None = None,
                  quiet: float | None = None,
                  streams: int | None = None,
                  bridges: "set | None" = None) -> None:
    """Say the drain is still alive, so its marker does not go stale under it.

    A HANDOVER DRAIN HAS NO CEILING ANY MORE, so the marker cannot expire on
    the drain's longest possible duration — there isn't one. It expires on
    SILENCE instead, and this is what breaks the silence. A drain that is
    genuinely finishing an hour-long reply keeps its protection by saying so
    every few seconds; a drainer that was SIGKILLed says nothing and its
    marker is stale inside `_DRAINING_MARKER_TTL`.

    Best-effort, exactly like the announcement: a beat that cannot be written
    changes nothing except that the sweep may take this daemon, which is the
    outcome that existed before any of this.
    """
    path = draining_marker_path(certdir, os.getpid() if pid is None else pid)
    # REAP THE CORPSES HERE, not only where a drain ANNOUNCES. That call runs
    # once per drain; this one runs for as long as one lasts, which is when a
    # marker's owner actually dies. Measured: a marker 410s past a 150s TTL sat
    # beside a live drain beating its own every few seconds.
    _pid = os.getpid() if pid is None else pid
    try:
        _collect_dead_markers(certdir, keep_pid=_pid)
    except Exception:  # noqa: BLE001 — housekeeping must not stop a beat
        pass
    try:
        if owed is None:
            os.utime(path)
            return
        # AND WHAT IT WOULD COST TO REAP US. The sweep runs in ANOTHER
        # process, so it cannot read this daemon's `_owed` — the only channel
        # is this file. See `_sweep_orphan_daemons`: over the limit it takes
        # the predecessor with the fewest replies to lose, which it can only
        # do if each one says how many it has.
        start = path.read_text().split("\n")[0].strip()
        # THIRD LINE IS WHAT A REAP WOULD COST IN LIVE ANSWERS, second is what
        # it would cost in debts. They differ exactly when a predecessor holds
        # replies that stopped: twelve owed, zero live.
        live_n = int(owed) if live is None else int(live)
        # FOURTH LINE IS THE LONGEST SILENCE ANY OWED REPLY IS SITTING IN. An
        # exit-time instrument says nothing about the case that does not exit.
        # APPENDED, never inserted: `draining_owed` and `draining_live` index
        # lines 2 and 3 by position, and a reader from a version that predates
        # this one takes the first three and ignores the rest. See
        # `draining_quiet` for the other half of the skew.
        #
        # FIFTH LINE IS HOW MANY LONG-LIVED CHANNELS WOULD DIE WITH US, and it
        # outranks every other cost in the reap order: a reply can be retried,
        # and a session whose bridge stream is cut cannot reopen it for itself.
        # Appended, never inserted, for the same reason as the fourth.
        tail = "" if quiet is None else f"\n{float(quiet):.1f}"
        if streams is not None:
            tail = f"{tail or chr(10) + '0.0'}\n{int(streams)}"
        # SIXTH LINE IS WHICH BRIDGES THOSE CHANNELS BELONG TO, because the
        # count above says how much a reap would cost and nothing says WHOSE.
        # A successor holds none of its predecessors' streams, so asked from
        # its own memory it calls every pre-existing session deaf. The union
        # is the answerable question and this file is the only channel
        # between the two processes.
        if bridges is not None:
            if streams is None:
                tail = f"{tail or chr(10) + '0.0'}\n0"
            tail = f"{tail}\n{' '.join(sorted(bridges))}"
        # ATOMIC, BECAUSE A READER CANNOT TELL A SHORT FILE FROM AN OLD ONE.
        # `write_text` truncates and then writes, so a beat -- which fires
        # every few seconds -- is a window in which `draining_bridges` reads
        # fewer than six lines and reports "cannot be asked". That is the
        # verdict reserved for a predecessor predating the record, and it is
        # indistinguishable from catching this write mid-flight.
        #
        # No fsync: the requirement is that other PROCESSES see one version or
        # the other, which `os.replace` gives on its own. Durability across a
        # crash is worthless for a beat that repeats.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
        try:
            tmp.write_text(f"{start}\n{int(owed)}\n{live_n}{tail}")
            os.replace(tmp, path)
        except (OSError, ValueError):
            # NOT O_EXCL and unlinked here rather than left: the name is
            # scoped to this pid, and a survivor would otherwise be litter in
            # the one directory somebody opens to read a handover.
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
    except (OSError, ValueError):
        pass


def draining_since(certdir: Path, pid: int) -> float:
    """When ``pid``'s drain STARTED — `time.time()`, not monotonic.

    The marker's contents are its start; its mtime is its last beat. Two
    different questions, and the sweep asks the first one: over the limit it
    takes the drains that have been running LONGEST, which are the ones least
    likely to still be delivering.

    An unreadable marker answers "just now", because this number only ever
    decides who is killed FIRST and a file we cannot parse is not evidence
    that the process behind it is wedged.
    """
    try:
        head = draining_marker_path(certdir, pid).read_text().split("\n")[0]
        return float(head.strip())
    except (OSError, ValueError):
        return time.time()


def draining_live(certdir: Path, pid: int) -> int:
    """How many of ``pid``'s owed replies are still being WRITTEN.

    Third line of the marker. Absent — a marker from a version that did not
    record it — answers `_OWED_UNKNOWN`, the same expensive default
    `draining_owed` uses, because this decides what to kill.
    """
    try:
        body = draining_marker_path(certdir, pid).read_text().split("\n")
        return int(body[2].strip())
    except (OSError, ValueError, IndexError):
        return _OWED_UNKNOWN


def draining_quiet(certdir: Path, pid: int) -> "float | None":
    """The longest silence any of ``pid``'s owed replies is sitting in.

    Fourth line of the marker; ``None`` when it is absent, which is a marker
    written by a version that did not record it. NOT 0.0 for that case — zero
    reads as "answering this instant", the safest number there is, and this
    fleet runs mixed versions through every upgrade, so an older predecessor
    would be reported as the healthiest thing on the box.

    Nothing DECIDES on this. It is read by a human, or by a later version that
    has a population to choose a threshold from; see `content_free_intervals`
    for why the number cannot come from anywhere else.
    """
    try:
        body = draining_marker_path(certdir, pid).read_text().split("\n")
        return float(body[3].strip())
    except (OSError, ValueError, IndexError):
        return None


def draining_streams(certdir: Path, pid: int) -> int:
    """Long-lived channels ``pid`` would take with it if reaped.

    Fifth line of the marker. A marker without one was written by a version
    that did not record it, and that answers 0 — not "expensive" like
    `draining_owed`, because the alternative is that every predecessor from an
    older release becomes unreapable and the pile this limit exists to bound
    stops being bounded at all.
    """
    try:
        body = draining_marker_path(certdir, pid).read_text().split("\n")
        return int(body[4].strip())
    except (OSError, ValueError, IndexError):
        return 0


def draining_bridges(certdir: Path, pid: int) -> "tuple[set, bool]":
    """Bridge ids whose inbound stream ``pid`` holds, and whether it said.

    THE SECOND HALF IS THE POINT. A marker written before this line existed
    is not a daemon holding nothing — it is a daemon that cannot be asked,
    and the two must not read the same. Answering the empty set for both puts
    every bridge a predecessor is carrying back into the deaf list, which is
    the fault the sixth line exists to fix.
    """
    try:
        body = draining_marker_path(certdir, pid).read_text().split("\n")
        return set(body[5].split()), True
    except (OSError, IndexError):
        return set(), False


def draining_owed(certdir: Path, pid: int) -> int:
    """How many replies ``pid`` would lose if it were reaped right now.

    THE SWEEP CANNOT READ ANOTHER PROCESS'S `_owed`, so a drainer writes it
    into its own marker on every beat and this reads it back. Second line of
    the file; absent on a marker written by a version that did not record it.

    An unknown count answers "expensive", because the sweep uses this to pick
    what to KILL and a file we cannot parse is not permission to take the one
    that might be holding the most work.
    """
    try:
        body = draining_marker_path(certdir, pid).read_text().split("\n")
        return int(body[1].strip())
    except (OSError, ValueError, IndexError):
        return _OWED_UNKNOWN


def this_process_is_draining() -> bool:
    """Has this daemon begun handing over?

    Read from the same depth map `announce_draining` keeps, so it is true from
    the moment a handover starts — before the drain, which is the window that
    matters: both handover sites announce before the successor can exist.

    OUR OWN MARKER, not any marker this process has written. The depth map is
    keyed by marker path and a marker names a PID, so a process that announced
    on somebody else's behalf — which only tests do, but the distinction is
    free — must not answer yes for itself.
    """
    mine = f"{_DRAINING_PREFIX}{os.getpid()}"
    with _DRAINING_LOCK:
        return any(n > 0 for key, n in _DRAINING_DEPTH.items()
                   if key.rsplit("/", 1)[-1] == mine)


def is_draining(certdir: Path, pid: int) -> bool:
    """Has ``pid`` announced that it is draining and will leave on its own?

    SILENT MARKERS EXPIRE, because a drainer that is SIGKILLed cannot remove
    its own, and a pid is reused freely. Freshness is the mtime rather than
    the contents: the contents are the drain's START, and with the handover
    ceiling gone, age says nothing about health. A drain that has run three
    hours because a reply has run three hours is working. Only silence
    separates it from a dead one, so only silence expires the marker.

    Past the TTL the marker protects nobody: the answer goes back to what it
    was before this existed, which is the safe direction for a function whose
    only power is to spare a process.
    """
    try:
        beat = draining_marker_path(certdir, pid).stat().st_mtime
    except OSError:
        return False
    return (time.time() - beat) < _DRAINING_MARKER_TTL


def refcount_fifo_path(certdir: Path) -> Path:
    """Path of the refcount FIFO. Sessions hold a write fd on it; the daemon
    reads it and exits when the last holder closes (a FIFO refcount)."""
    return Path(certdir) / _FIFO_NAME


def _rotate_if_over(path: Path, cap: int = _LOG_MAX_BYTES) -> None:
    """Rotate ``path`` through ``.1`` and ``.2`` once it passes the cap.

    Extracted from `_open_daemon_log` so the OPT-IN traces get the same
    ceiling. They did not have one: `CSWAP_PIN_DEBUG` and `CSWAP_PIN_SHAPE`
    append a line PER REQUEST through a path `_LOG_MAX_BYTES` never touched,
    so the careful bound was on the file that is always on and always small,
    and absent from the two a human enables during an incident and then stops
    watching. Off by default, so a fresh install was never exposed; left on and
    forgotten, they are exactly the unbounded growth the cap exists to prevent.

    Best-effort: a rotation that cannot happen must not stop the write, and an
    unlink is the fallback the cap falls back to rather than giving up on it.
    """
    try:
        if not path.exists() or path.stat().st_size <= cap:
            return
        previous = path.with_suffix(path.suffix + ".1")
        if previous.exists():
            previous.replace(path.with_suffix(path.suffix + ".2"))
        path.replace(previous)
    except OSError:
        try:
            path.unlink()  # rotation impossible; the cap still has to hold
        except OSError:
            pass


def _append_capped(path, line: str, fh=None, cap: int = _LOG_MAX_BYTES):
    """Append ``line`` to ``path`` under ``cap``. Returns the handle.

    Pass the previous handle back in to keep it; this reopens only when the
    file rotated underneath it, which is the one case a held descriptor cannot
    survive — it would keep writing to an inode nobody can find.

    Size is read from the HANDLE (`tell()` on an append stream) rather than
    with a stat per request: the trace is opt-in and hot, one line per request
    through the proxy's own path.

    Never raises. A trace that cannot be written is a diagnostic that is
    missing, not a proxy that stops relaying. ValueError as well as OSError:
    a handle another thread let go of raises the first, not the second, and
    this sits on the request path.
    """
    try:
        if fh is None or fh.closed:
            _rotate_if_over(Path(path), cap)
            fh = open(path, "a", buffering=1, encoding="utf-8",
                      errors="replace")
        fh.write(line)
        if fh.tell() > cap:
            fh.close()
            _rotate_if_over(Path(path), cap)
            fh = open(path, "a", buffering=1, encoding="utf-8",
                      errors="replace")
        return fh
    except (OSError, ValueError):
        return None


def _write_capped_line(fh, line: str, cap: int = _LOG_MAX_BYTES):
    """Write ``line`` to the already-open ``fh``. Never opens or closes it.

    `_append_capped` opens on a first write and reopens on rotation — fine for
    a handle only one caller touches, but `self._debug` is ONE handle shared
    by every `_serve_client` thread. Re-arming the trace (or just crossing the
    cap) nulls it, and every thread then races into `open(2)` at once:
    measured as 342 `_serve_client` threads sharing one identical stack,
    parked in that same `open()` while a stalled filesystem let everything
    else in the daemon keep running.

    So the request path only ever writes to a handle something ELSE already
    opened (`PinProxy._trace_tick`, off a background loop) and drops the line
    when nothing is open — or, on crossing the cap, DROPS the reference
    (never closes it, for the same unsynchronised-threads reason
    `_append_capped` already drops rather than closes) and leaves the
    rotate-and-reopen to the next tick.

    Never raises, same contract as `_append_capped`.
    """
    if fh is None or fh.closed:
        return None
    try:
        fh.write(line)
        return None if fh.tell() > cap else fh
    except (OSError, ValueError):
        return None


def daemon_log_path(certdir: Path) -> Path:
    """Where the detached daemon's stderr goes.

    The daemon has no terminal, so a warning it writes to stderr reaches
    nobody unless it is given a destination here. Measured on three machines:
    with ``stderr=DEVNULL`` every fail-open was silent by construction, which
    is precisely what :meth:`PinProxy._warn_unpinnable` exists to prevent.
    """
    return Path(certdir) / _LOG_NAME


def _open_daemon_log(certdir: Path):
    """Open :func:`daemon_log_path` for append, or fall back to DEVNULL.

    Truncates once it passes ``_LOG_MAX_BYTES`` — a daemon that cannot mint
    warns once per process, but nothing stops a supervisor respawning it, and
    an unbounded log in the cert dir is its own defect. Returns a file object
    the caller owns; a directory that cannot be written degrades to discarding
    output rather than failing the spawn, because a pin must never block a
    launch.
    """
    import subprocess

    path = daemon_log_path(certdir)
    try:
        # THE SAME PRIMITIVE THE OPT-IN TRACES USE — see `_rotate_if_over`.
        # Two copies of a rotation policy is how one of them ends up with a
        # different number of generations than the comment below promises.
        if path.exists() and path.stat().st_size > _LOG_MAX_BYTES:
            # ROTATE, NEVER UNLINK. This runs at DAEMON START, which is the
            # instant a handover completes — so deleting here means the
            # INCOMING daemon destroys the OUTGOING daemon's teardown record.
            # The lines that say whether a recycle cost anything ("drained, N",
            # "cut N in-flight request(s)") are written by the process that is
            # dying, and were being erased by the one replacing it. The window
            # that would have named the cause was gone, and a second question
            # that hung on the same window — who emptied `.claude.json`'s env
            # block — could not be settled either. An instrument destroyed by
            # the event it exists to describe is worse than no instrument,
            # because the empty file reads as "the daemon had nothing to say".
            # TWO GENERATIONS, because one is destroyed by the same event.
            # `_open_daemon_log` runs in the SPAWNING process before the child
            # starts, so it renames the inode the OUTGOING daemon still holds
            # as stderr — its `cut N` / `drained clean` lines land in `.1`.
            # That is the same "instrument destroyed by the event it describes"
            # one generation further out.
            try:
                previous = path.with_suffix(path.suffix + ".1")
                if previous.exists():
                    previous.replace(path.with_suffix(path.suffix + ".2"))
                path.replace(previous)
            except OSError:
                path.unlink()  # rotation impossible; the cap still has to hold
        return open(path, "a", buffering=1, encoding="utf-8", errors="replace")
    except OSError:
        return subprocess.DEVNULL


def _iso_utc(ts: "float | None") -> "str | None":
    """An epoch seconds value as UTC ISO-8601, or None passed through.

    Wall-clock, deliberately: this timestamp is read against daemon.log lines
    and a human's account of when something broke, both of which are wall
    clock. A monotonic reading would be uncomparable to either.
    """
    if ts is None:
        return None
    return (
        _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _log_lifecycle(what: str) -> None:
    """Record one daemon lifecycle event, with a timestamp, to stderr.

    The daemon's stderr IS ``daemon.log`` (see :func:`_open_daemon_log`), so
    this needs no file handling of its own and cannot fight the spawner for
    the fd.

    WHY THIS EXISTS. The log carried warnings only, so a daemon that started,
    served for hours and disappeared left a ZERO-BYTE file. When every session
    on a machine went down behind a dead pin, the log could not say when the
    daemon went away, or whether it was an idle teardown, a signal, or a crash
    — and with several agents working on the box at the time, the cause stayed
    unattributable. An outage you cannot attribute is one you cannot prevent.

    Never raises: a daemon must not die trying to record that it is dying.
    """
    try:
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{stamp}] {_COMPONENT} pid={os.getpid()} {what}",
              file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001
        pass


# How long a departing daemon lets in-flight requests finish before it exits.
#
# A CEILING, not a wait: an idle daemon returns immediately, so this costs
# nothing in the common case. It is sized for a streaming `/v1/messages`
# response rather than for a whole conversation — the point is that an upgrade
# or a recycle does not cut a reply in half, not that the daemon lingers for a
# client that has gone quiet. A request still running at the end is cut, which
# is the same outcome as before this existed.
_DRAIN_SECONDS = 30.0

# THE SAME DRAIN, PAID AT A DIFFERENT MOMENT. Under a holder the daemon exits
# so the HOLDER can spawn the successor — and the holder cannot start anything
# until this process is gone, so every second of drain here is a second with
# the port bound and nobody behind it. The unheld path has the opposite shape:
# it drains AFTER `_spawn_daemon` returned, with the successor already
# accepting, so a 30s ceiling there costs nothing. Nothing was REFUSED — the
# holder's socket queues arrivals, which is what this design is for — but 30
# requests timed out at 3s waiting for a reply nobody was there to write. The
# ceiling is always paid in full on a real machine: a CONNECT tunnel is counted
# for its whole life (deliberately — that is what stops an idle watcher cutting
# a live session), and Remote Control's WebSocket lives as long as the session
# does, so the count is never zero. Still a drain, not zero: a response mid-
# stream must not be cut, which is the 34-connections-reset outage
# `stop(drain=…)` exists to prevent.
#
# THE 2 SECONDS THAT CUT THREE SESSIONS, and why the number is gone. The
# reasoning above is sound and its PREMISE was false. It says every second of
# drain here is a second with the port bound and nobody behind it, so the
# budget must be small. True — but only because the wait could never end early:
# it polled the CONNECTION count, an RC WebSocket holds that above zero for the
# life of the session, so the daemon sat here for the whole budget whether it
# had work or not. A cap was the only defence against a wait that never
# finished, and 2.0 was chosen to make the pointless wait cheap.
# `await_inflight` now waits on REQUESTS, which do reach zero. An idle daemon
# returns from it in milliseconds — the thing the small cap was buying — so the
# cap is no longer paying for anything except cutting real replies. So both
# exit paths now get the same generous ceiling. The port is only held while a
# reply is genuinely in flight, which is the one case where holding it is
# correct.
_HELD_DRAIN_SECONDS = _DRAIN_SECONDS

# THE CEILING FOR A HANDOVER WHOSE SUCCESSOR IS ALREADY SERVING, and it is a
# different number from `_DRAIN_SECONDS` because it buys a different thing.
# ZERO CUTS BEFORE HEADERS, on every host measured — the CEILING's cuts, all
# of them mid-response, which is what made the ceiling the fault. The stall
# PREDICATE that replaced it cuts the opposite class; see
# `_DRAIN_STALL_SECONDS`, and scope any count by which one produced it. So the
# drain is not malfunctioning and the count is not bookkeeping: those are
# replies that had already begun streaming to a user and genuinely did not
# finish inside thirty seconds. A pooled-idle-connection
# explanation was proposed and died on that split.
#
# So the fault is the CEILING, and at these two call sites paying
# it costs nothing. `release_listener()` has already handed the port on — site
# 1's successor was spawned by the holder and is serving, site 3's took the
# listening socket by fd — so this process accepts nothing and holds nothing
# anyone is waiting for. It is one idle process finishing the replies it
# already owes, and `await_inflight` returns the instant it owes none.
# `_DRAIN_SECONDS` CANNOT SIMPLY BE RAISED. It is also the supervisor's
# patience (`proc.wait(timeout=_DRAIN_SECONDS + 2)`, the SIGKILL escalation,
# the stop poll), so raising it would make every teardown wait on a process
# that is not coming back — and the handover ceiling below is now unbounded,
# which as a supervisor's patience would mean never giving up at all. Two
# numbers because there are two questions.
#
# NOT USED ON THE HELD PATH. There the daemon exits so the HOLDER can spawn the
# successor, which it cannot do until this process is gone — every second of
# that drain is a second with nothing serving the port. That path keeps the
# small ceiling and cutting there is the lesser evil; see
# `_HELD_DRAIN_SECONDS`.
#
# AND THEN THERE IS NO RIGHT NUMBER, which is where this ended up. 1800 cuts a
# 31-minute reply and 3600 cuts a 61-minute one; this box runs subagent replies
# past an hour, and a single cut restarts the whole run from scratch.
#
# THE QUANTITY IS WRONG, NOT THE VALUE. A clock cannot tell a slow reply from a
# wedged one; `_owed_still_moving` can, and it is what ends every healthy
# drain. On THESE TWO SITES ONLY, nothing waits on this process — the successor
# is already serving, this one accepts nothing — so the clock was never buying
# a faster handover. It was bounding a LEAK, and a per-process clock cannot
# tell one predecessor legitimately finishing a three-hour reply from a pile of
# them that will never finish. A COUNT can, so the leak bound moved to
# `_MAX_DRAINING_PREDECESSORS` and this became infinite.
#
# NOT ON THE OTHER TWO. The held path exits so a HOLDER can respawn, and
# `_teardown` under a signal has a supervisor doing `proc.wait(_DRAIN_SECONDS +
# 2)` before SIGKILL. There the clock is load-bearing and raising it past the
# supervisor's patience only trades a logged cut for an unlogged one.
_HANDOVER_DRAIN_SECONDS = float("inf")


def ensure_wired_to(port: int, certdir: Path) -> bool:
    """Point `.claude.json` at `port` when it names anything else. True if written.

    THE SERVING DAEMON OWNS THE WIRING, because nothing else was putting it
    back. A departing daemon unwires when it sees the port unserved, and that
    check is right at the instant it runs — but on a holder restart the
    predecessor has released and the successor has not bound yet, so the port
    IS unserved for that instant and the wiring goes. Only a LAUNCH or a `heal`
    wrote it, so it stayed gone: every hand-launched session afterwards ran
    unpinned while a healthy daemon served the port nobody was told about.

    NO-OP WHEN ALREADY CORRECT — one config read on a normal start, no write.
    Never raises: a wiring failure must not stop a daemon that is otherwise
    serving, and the next launch or heal still repairs it.
    """
    try:
        if _wired_port() == port:
            return False
        wire_global_config(port, Path(certdir) / "ca.pem")
        _log_lifecycle(
            "rewired .claude.json to this port — it named something else, "
            "which is what a departing daemon leaves behind when it unwires "
            "into the gap before a successor binds")
        return True
    except Exception as exc:  # noqa: BLE001
        _log_lifecycle(f"could not rewire .claude.json: {exc!r}")
        return False


def drain_fate(budget: float) -> str:
    """What a drain announcing itself may promise. Decided by its ceiling.

    The two arms printed the SAME sentence and only one could keep it. On the
    handover arm the budget is `_HANDOVER_DRAIN_SECONDS` and "stays until they
    end" is true. On the signal arm it is capped and the TERM's sender SIGKILLs
    two seconds past the cap, so the same words are false by construction.

    Not cosmetic. Every clean drain on record was a handover and this sentence
    sat on all of them, so "the handover is gapless by construction" was said
    to a peer on that evidence -- hours before an external TERM racing a
    handover cut 13 mid-response replies at exactly the cap, with the successor
    already serving and the promise printed twice.

    A drain that CAN cut has to say so BEFORE it cuts. The cut line is honest
    and it arrives too late to inform anything read from the log.
    """
    if budget == float("inf"):
        return "left intact, and this process stays until they end"
    return (f"left intact for now — but this drain is CAPPED at {budget:.0f}s "
            "and cuts whatever is still moving when it expires, so this is "
            "not the gapless arm")

# NO BYTES FOR THIS LONG AND IT IS WEDGED, NOT SLOW. See `_owed_still_moving`:
# this is what actually ends a drain now, and the budgets above are backstops
# against a bug in that predicate.
#
# ABOVE THE MEASURED DISTRIBUTION, NOT INSIDE IT. The fleet watcher banks ONE
# sample per drain: the longest byte-free wait any COMPLETED reply survived in
# that daemon's life — p90 16s, p99 60s, max 123s. So the percentiles are over
# daemon lifetimes, not over replies; only the MAX carries over, and it is the
# number this has to clear.
#
# THE CORPUS IS BLIND TO WHAT THIS ACTUALLY CUTS. `_byte_gap` starts at the
# SECOND response byte, so a reply with fewer banks nothing; and a ZERO-write
# request is aged from ARRIVAL by the `_content_at` fallback in
# `_owed_still_moving` (a one-write reply, from that write). Every cut the
# PREDICATE has produced is the zero-write class, so for it the number is an
# assumption rather than a measurement. Not split into two constants: two
# observations do not size a second threshold.
#
# IT BINDS ON BOTH ARMS. On the handover arm a successor already holds the
# port, so a wedged connection only keeps an idle process alive. On the HELD
# arm the port is dark, and raising the window WIDENS the band of debts that
# are waited on rather than breaking out at second 0 — up to a whole
# `_HELD_DRAIN_SECONDS` of it, against cutting a reply the corpus says
# completes.
_DRAIN_STALL_SECONDS = 180.0
#: THE CLIENT'S OWN LIVENESS TIMEOUT, read out of the 2.1.245 bundle rather
#: than chosen: `resetLivenessTimer(){ ... setTimeout(this.onLivenessTimeout,
#: dn) }` with `dn = 45000`, re-armed on every frame received. A stream that
#: has been content-free this long is one the CLIENT is about to drop and
#: reconnect on its own, so handing it over costs nothing it was not already
#: going to do.
_CLIENT_LIVENESS_SECONDS = 45.0

# STALE MEANS UNTOUCHED, NOT OLD. This was `_HANDOVER_DRAIN_SECONDS + 60`,
# which is now infinite — a marker that never expires spares whatever pid
# inherits the number, forever, which is the exact orphan this file's only
# reader exists to kill. A drain says it is still alive instead, every
# `_DRAINING_BEAT_SECONDS`, so the TTL bounds SILENCE rather than duration and
# a three-hour drain and a SIGKILLed one stop looking alike.
_DRAINING_MARKER_TTL = 150.0
#: How long the uncapped drain waits on tunnels before letting them go.
#:
#: THE SILENCE EXIT IS UNREACHABLE FOR THE CHANNEL THE WAIT PROTECTS. Remote
#: Control RECEIVES on a WebSocket tunnel and the server keepalives it, so
#: `_PUMP.quiet_for()` never climbs to `_DRAINING_MARKER_TTL` and the loop's
#: only exit is the tunnel ending on its own. Measured on a mac 2026-08-31:
#: `drained clean in 2240.2s` while holding two sessions' bridges, and
#: unbounded in principle.
#:
#: WAITING DOES NOT SAVE THE CHANNEL. There is no fd handover here -- the
#: successor cannot inherit a live connection -- so the cut happens either
#: way; the wait only moves it to a moment nobody chose. Bounding it puts the
#: cut beside the deploy that caused it, where `_report_deaf_bridges` names it
#: in the same minute and the session re-homes on the successor's listener.
#: On that mac the sessions did exactly that, twelve seconds after the log
#: said `ONLY A NEW PROCESS CLEARS IT`.
_TUNNEL_DRAIN_SECONDS = _DRAINING_MARKER_TTL
_DRAINING_BEAT_SECONDS = 15.0

# THE LEAK BOUND THAT REPLACED THE WALL CLOCK, and it is a different quantity
# on purpose. One predecessor draining for three hours because a reply has run
# three hours is CORRECT; ten of them at once is a drain that cannot end. A
# clock scores those the same and a count separates them. Eight because a
# recycle produces one predecessor, so eight is more back-to-back deploys than
# this fleet has ever done inside one drain — and being wrong high costs idle
# RAM while being wrong low costs a reply.
#
# AND IT IS A DEPLOY-RATE LIMIT, NOT A MEMORY KNOB — say so here or the next
# reader tunes it as one. With a keepalive holding every drain open, the number
# of live predecessors grows with how often the code is REDEPLOYED inside one
# long client session, not with traffic. Eight is "more back-to-back deploys
# than this fleet has ever done inside one drain".
_MAX_DRAINING_PREDECESSORS = 8

# The marker's name, in one place: `_collect_dead_markers` globs for what
# `draining_marker_path` writes, and a literal in both is a sweep that silently
# stops matching the day the name changes.
_DRAINING_PREFIX = ".draining-"

# "This marker does not say what it would cost to reap me." Sorts after every
# known count, because this orders what to KILL and an unparseable file is not
# permission to take the one that may be holding the most work.
_OWED_UNKNOWN = 1 << 30

# TWO TEARDOWNS CAN RUN AT ONCE IN ONE PROCESS, and the first version of this
# marker did not survive that. Counted rather than flagged, and the LAST
# release removes it. A depth of one is the ordinary case and costs a dict
# lookup.
_DRAINING_LOCK = threading.Lock()
_DRAINING_DEPTH: dict[str, int] = {}

_FIRST_HOLDER_TIMEOUT = 300.0

# How long to wait before re-asking whether a daemon whose last FIFO holder
# left is still claimed. A blocking read on a writer-less FIFO returns EOF
# immediately and keeps doing so, so the re-check has to pace itself. The
# cost of waiting is an idle daemon lingering this much longer; the cost of
# not waiting is a busy loop.
_CLAIM_RECHECK_INTERVAL = 5.0


_WIRED_ONCE_MARKER = ".was-wired"


def _mark_wired_once(certdir: Path, port: int) -> None:
    """Record that the global wiring named ``port`` for THIS cert dir.

    On disk rather than in a process global: the qualification belongs to the
    daemon-and-certdir pair, and a module-level set is shared by everything in
    the interpreter. In tests that is a silent cross-contamination (one case
    wires a port, the next reuses the number for an orphan and inherits the
    qualification); in production a single process can serve more than one
    certdir over its life. Best-effort — a lost mark costs one skipped repair,
    which the next tick retries.
    """
    try:
        (certdir / _WIRED_ONCE_MARKER).write_text(str(port), encoding="utf-8")
    except OSError:
        pass


def _was_wired_once(certdir: Path, port: int) -> bool:
    try:
        return (certdir / _WIRED_ONCE_MARKER).read_text(encoding="utf-8").strip() == str(port)
    except OSError:
        return False


def _repair_wiring_if_ours(certdir: Path, port: int, live_clients=None) -> bool:
    """Re-point a pin wiring that names a DEAD port back at this daemon.

    RECOVERY HAS TO LIVE IN THE PACKAGE THAT HAS THE BUG. Until now the only
    thing that ever repaired a pin without a human was one developer's
    status line, spawning ``cswap pin --heal`` on a timer. A census of the
    host found exactly one caller of ``heal`` — the CLI, i.e. a person typing
    it. So anyone who installs cswap-pin and does not also install that
    person's dotfiles has NO automatic recovery: a wiring that points at a
    dead port stays broken, and what they see is "new sessions cannot reach
    the API", with nothing connecting that to the pin.

    The daemon is the right host because it needs no external timer, no TUI
    and no shell integration — it is already running, and it already re-reads
    the wiring every few seconds (``_is_claimed``, from ``watch_refcount``).
    That check asked "does the config still name me?" purely to decide
    whether to keep serving; the answer "no" was equally consistent with
    "someone unpinned" and with "the config is broken", and both were treated
    as the former.

    THE TWO ARE DISTINGUISHED BY WHETHER THE WIRED PORT ANSWERS:

      * it answers            -> another daemon owns the pin, or the user
                                 re-pinned elsewhere. NOT ours to touch.
      * nothing is wired      -> the pin was cleared. Leave it cleared.
      * wired, and DEAD       -> the wiring is broken and we are the daemon it
                                 should name. Repair it.

    Measured, and this is the state that motivated it: a config rewritten to
    port 52000 while this daemon served 36301. Every running session was fine
    (their env is fixed at exec) and every NEW session inherited a port
    nothing listened on. The daemon was healthy the whole time, so nothing
    that watches the daemon could see it.

    Never raises: a repair that can crash the refcount watcher would trade a
    broken wiring for a dead pin.
    """
    try:
        # ONLY A REAL, SERVING DAEMON MAY REPAIR. ``live_clients`` is the
        # daemon's own connection counter, handed in by the process that owns
        # the listening socket — so its presence IS the proof that a server
        # exists here. A bare refcount watcher with no server (a test harness,
        # a helper thread) must never rewrite a user's config: it cannot honour
        # the port it would advertise.
        if live_clients is None:
            return False
        # ONLY A DAEMON THE WIRING ONCE NAMED MAY RECLAIM IT. Without this the
        # repair is indistinguishable from a hijack, and it disables the orphan
        # reaper outright: a daemon left behind by a crashed spawn — one the
        # config never named — would see a wiring it does not match, call it
        # "broken", and rewrite the user's config to point at ITSELF. It then
        # counts as claimed forever and never times out. Being wired at least
        # once is what separates the two populations. The daemon this exists
        # for was serving a wiring that named it and then lost it; an orphan
        # never had one.
        if not _was_wired_once(certdir, port):
            return False
        wired = _wired_port()
        if wired is None or wired == port:
            return False  # unpinned, or already correct — not our business
        # Does the port the config names actually answer? If it does, someone
        # else legitimately owns the pin and rewriting would steal it.
        try:
            with socket.create_connection(("127.0.0.1", wired), timeout=1):
                return False
        except OSError:
            pass  # dead, as expected for the broken case
        # And the record must still be OURS — checked by the caller, but the
        # connect above took time, so re-read rather than trust the gap.
        st = read_daemon_state(certdir)
        if not st or int(st.get("pid") or 0) != os.getpid():
            return False
        if int(st.get("port") or 0) != port:
            return False
        wire_global_config(port, certdir / "ca.pem")
        _log_lifecycle(f"repaired a wiring that named dead port {wired} -> {port}")
        return True
    except Exception:  # noqa: BLE001 — never break the watcher
        return False


def _is_claimed(certdir: Path, live_clients=None) -> bool:
    """True when the global wiring names THIS daemon, holder or no holder.

    A FIFO holder is not the only way to claim a daemon, and it is not even the
    common one. Only ``wire_env`` and ``pin-env`` open the refcount FIFO; the
    ``.claude.json`` env block — the path every hand-launched ``claude`` takes
    — routes a session through the pin without ever touching it. So a healthy,
    fully-used daemon sits at ZERO holders indefinitely: measured on linux,
    daemon 4035232 serving 36301 for 1d17h with not one holder anywhere in
    ``/proc/*/fd``. To the first-holder timeout that is indistinguishable from
    the orphan it exists to reap, and it would tear the live pin down.

    The wiring itself is the missing claim. If ``.claude.json`` points sessions
    at our port, we are the thing they are pointed at, and that is a reference
    whether or not anyone opened the FIFO. It also separates the two
    populations exactly: a crashed spawn or a killed test leaves a daemon on a
    certdir nothing was ever wired to, so those still time out as before.

    A LIVE CONNECTION IS ALSO A CLAIM, and it is the one that matters when the
    pin is turned OFF. `cswap pin --clear` removes the wiring, so the two
    checks above both go false at once — and the daemon tore itself down while
    real sessions were still talking to it. Their HTTPS_PROXY is fixed at exec,
    so they could not be told; they got ConnectionRefused and retried forever
    (measured: 312 processes, `attempt 6/300`, plus "Auto-update failed").

    That is the same root as the 407 — env cannot be updated in a running
    process — pointing the other way: arming broke them, and disarming broke
    them too. A daemon someone is actually connected to is not idle, whatever
    the config says, so serving that traffic until it drains is what makes
    turning the pin off as harmless as turning it on.

    ``live_clients`` is that question asked of the daemon itself (its own
    connection count). It must be, because the socket-scan answer is
    Linux-only: on macOS it returns None, and None was being read as "not
    claimed" — turning the one check that protects a live session into a
    guaranteed false on the platform where the pin is used most.
    """
    try:
        st = read_daemon_state(certdir)
        if not st or int(st["pid"]) != os.getpid():
            return False  # not our record — say nothing about our own liveness
        port = int(st["port"])
        if _wired_port() == port:
            # Remember it, because this is the ONLY moment that proves we are
            # the pin's daemon rather than an orphan. See _repair_wiring_if_ours.
            _mark_wired_once(certdir, port)
            return True
        # A SUCCESSFUL REPAIR IS ITSELF A CLAIM. Discarding this return value
        # meant the daemon re-pointed the wiring at itself and then, in the
        # same call, reported "nobody references me" — and `watch_refcount`
        # answers that by tearing the daemon down, running
        # `wire_global_config(None, None)` and undoing the repair microseconds
        # after making it. The wiring was broken-but-pointing-somewhere before;
        # afterwards there is no daemon and no pin at all. It is the LIKELY
        # path on macOS, not a corner: the socket scan below reads
        # /proc/net/tcp, which macs do not have, so only `live_clients() > 0`
        # can save it — and a repair fires precisely when new sessions cannot
        # reach the daemon, i.e. when that count is trending to zero.
        if _repair_wiring_if_ours(certdir, port, live_clients):
            return True
        # Ask the daemon itself first. It is the only source that answers on
        # every platform: the socket scan below reads /proc/net/tcp, which
        # BOTH MACS lack, and its None was being coerced to "not claimed" —
        # so on macOS a hand-launched session with a live connection was
        # counted as idle and `pin --clear` tore its proxy out from under it.
        if live_clients is not None:
            try:
                if live_clients() > 0:
                    return True
            except Exception:
                pass
        live = clients_that_arming_would_cut_off(port)
        if live is None:
            # Unmeasurable, and the daemon's own count said zero (or was not
            # offered). Nothing established a claim; the caller's timeout
            # decides.
            return False
        return bool(live)
    except Exception:
        return False


def watch_refcount(
    fifo: str | Path,
    on_last_holder_gone,
    first_holder_timeout: float | None = None,
    live_clients=None,
) -> None:
    """Block on ``fifo`` until every write-holder closes, then call
    ``on_last_holder_gone``. This is a supervisor holding `cat FIFO`:
    a READ-ONLY open blocks until the first writer appears, and the subsequent
    read returns EOF (b"") only once all writer fds have closed. A read-only
    reader must NOT also hold a write end (that would mask EOF), which is why
    sessions open O_RDWR while the daemon opens read-only here.

    A daemon that NEVER gets a first holder must still die. The read-only open
    blocks forever when no writer ever appears, and "forever" is not a corner
    case: it is what happens whenever a daemon is spawned and its session dies
    before attaching (a crash between spawn and attach, a killed test). The
    process then holds its port and never idle-teardowns — measured, three such
    daemons left over from one test run, each on a ``/tmp/pytest-*`` certdir the
    per-certdir orphan sweep deliberately cannot see.

    So the FIRST open is bounded: O_NONBLOCK returns immediately (EOF-looking,
    not blocking) instead of parking forever, and we poll for a writer up to
    ``first_holder_timeout``. Once a holder has attached we switch to the
    blocking semantics above, which are the ones that give a correct EOF.
    Timeout with no holder AND no wiring claiming us => tear down, exactly as
    if the last holder left. The wiring check is not optional: zero holders is
    the STEADY STATE of a healthy daemon serving globally wired sessions, so
    without it this timeout kills the working pin (see ``_is_claimed``).

    **Both exits ask that question.** The claim check used to guard only the
    first-holder timeout, so a daemon that HAD holders tore down the moment
    the last one closed — no matter that the global wiring still named it or
    that connections were still draining on it. Those sessions cannot be told
    (their ``HTTPS_PROXY`` is fixed at exec), so they got ConnectionRefused
    and retried forever. Teardown now means "no holder and nothing else
    claims us", whichever door it arrives by.
    """
    timeout = _FIRST_HOLDER_TIMEOUT if first_holder_timeout is None else first_holder_timeout
    # O_NONBLOCK on a read-only FIFO open never blocks (POSIX), so this cannot
    # park the way the plain open did. select() then tells us when a writer has
    # actually attached; before that a read would just return EOF forever.
    fd = os.open(str(fifo), os.O_RDONLY | os.O_NONBLOCK)
    try:
        import select
        import time as _time

        # Detect a holder by REOPENING for write, never by reading. A holder
        # that attaches and stays silent — which is the normal case, the fd IS
        # the reference — writes nothing, so waiting for bytes reports "no
        # holder" for a session that is perfectly alive and tears it down.
        # (Caught by test_daemon_exits_when_all_holders_close.)
        #
        # O_WRONLY|O_NONBLOCK on a FIFO succeeds only while a READER is open,
        # and we are that reader, so it always succeeds here and says nothing.
        # The usable signal is the opposite one: with our read fd open, a
        # non-blocking read returns EOF (b"") when there is no writer and
        # EAGAIN when a writer exists but has sent nothing. EAGAIN is exactly
        # "a holder is attached and quiet".
        deadline = _time.monotonic() + timeout
        while True:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                break  # writer present, no data — a live silent holder
            if data != b"":
                break  # writer present and chatty (an attach ping)
            # EOF: no writer at all yet.
            if _time.monotonic() >= deadline:
                # ...which is NOT the same as "nobody is using me". A globally
                # wired session never opens the FIFO, so check the wiring
                # before concluding we are an orphan (see ``_is_claimed``).
                if _is_claimed(Path(fifo).parent, live_clients):
                    deadline = _time.monotonic() + timeout  # re-arm and re-check
                    continue
                on_last_holder_gone()  # nobody ever attached — do not linger
                return
            select.select([fd], [], [], 0.05)
        # Back to blocking reads: with a writer present, EOF now means what the
        # refcount needs it to mean (every holder closed), which a non-blocking
        # read cannot distinguish from "no data yet".
        os.set_blocking(fd, True)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    import time as _time

    try:
        while True:
            data = os.read(fd, 65536)  # blocks; returns b"" at EOF (no writers)
            if data == b"":
                # A FIFO holder is not the only claim, and the first-holder
                # timeout above already knows that — this end did not. The
                # last WRAPPER-launched session closing says nothing about
                # the globally-wired and hand-launched sessions that never
                # open the FIFO at all, nor about live connections still
                # draining. Tearing down on their behalf strands them on an
                # HTTPS_PROXY fixed at exec: the ConnectionRefused loop
                # ``_is_claimed`` exists to prevent, arriving by the one door
                # that never asked it.
                if _is_claimed(Path(fifo).parent, live_clients):
                    _time.sleep(_CLAIM_RECHECK_INTERVAL)
                    continue  # still referenced — keep serving, re-check
                on_last_holder_gone()
                return
            # A holder wrote an attach ping; drain and keep waiting.
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


_SECRET_FILE = "proxy.secret"


def proxy_secret_path(certdir: Path) -> Path:
    """Where the daemon's proxy credential lives (0600, in the cert dir)."""
    return Path(certdir) / _SECRET_FILE


def read_proxy_secret(certdir: Path) -> str | None:
    """The daemon's proxy credential, or None when it has none.

    None means "this daemon predates the credential" and every caller must
    treat it as no-auth-required. A pin that starts rejecting traffic after an
    upgrade is a worse failure than the one the credential prevents.
    """
    try:
        val = proxy_secret_path(certdir).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return val or None


def clients_that_arming_would_cut_off(port: int) -> int | None:
    """How many live processes are talking to the proxy right now.

    Arming the gate rejects every client whose ``HTTPS_PROXY`` carries no
    credential, and that variable is fixed at exec — a running session cannot
    be updated in place. So the honest question before minting a secret is
    "who is using this port", and the answer has to reach the operator, or the
    docstring's "pair it with a relaunch" is advice nobody can act on.

    COUNTS SOCKETS, NOT ENVIRONMENTS. A previous version of this counted
    processes whose ``/proc/<pid>/environ`` named the port, and that number was
    a different set entirely: 214 by environ against 7 actually connected, with
    an overlap of ZERO. ``environ`` is an exec-time snapshot and Claude Code
    applies ``.claude.json``'s env block at boot, so it keeps naming whatever
    the launcher had. An operator reading "214 sessions will break" concludes
    catastrophe and never arms the gate; a wrong number in the one channel
    meant to inform a decision is worse than no number.

    Returns None where it cannot be measured rather than 0 — a silent zero
    reads as "nobody is affected", which is the same lie in the other
    direction. Linux only: both macs answer no ``/proc/net/tcp``.
    """
    try:
        rows = Path("/proc/net/tcp").read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return None
    target = f":{port:04X}"
    inodes = set()
    for line in rows:
        f = line.split()
        # state 01 = ESTABLISHED. Match the LOCAL side: these are the peers
        # connected to us, not our own listening socket (state 0A).
        if len(f) > 9 and f[3] == "01" and f[2].endswith(target):
            inodes.add(f[9])
    if not inodes:
        return 0
    pids = set()
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith("socket:[") and link[8:-1] in inodes:
            pids.add(fd.split("/")[2])
    return len(pids)


def ensure_proxy_secret(certdir: Path) -> str:
    """Mint (once) the credential a client must present to use this proxy.

    THE PROBLEM: the daemon listens on unauthenticated loopback and swaps the
    Authorization header of any request matching a pinned route. Loopback
    carries no identity — the kernel does not check uid on a TCP connect — so
    any process that can reach the port can CONNECT to api.anthropic.com with
    a junk bearer and receive one minted from the pinned account's real
    credential. cswap's own store is 0700/0600 precisely so that credential
    cannot be read; the proxy hands out its effect to anyone who asks.

    Loopback is not the boundary people assume. On a single-user laptop the
    exposure is other processes running AS that user, which is a smaller
    step-up than it sounds (a sandboxed tool, a compromised npm postinstall,
    any code the user runs but does not trust with their Claude account). On a
    shared or multi-account host it is other logins outright. Neither is
    covered by file permissions, because the port is not a file.

    So: a per-daemon secret, written 0600 next to the CA key that already
    lives at 0600, and handed to clients through the same wiring that already
    tells them the port. A client that can read the secret is a client that
    could read the cert dir anyway — the credential adds nothing for an
    attacker who already has that, and everything against one who does not.

    Idempotent: an existing secret is reused, so a respawn does not invalidate
    the wiring live sessions are already using.
    """
    import secrets

    path = proxy_secret_path(certdir)
    existing = read_proxy_secret(certdir)
    if existing:
        return existing
    token = secrets.token_urlsafe(32)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    try:
        # 0600 from creation, never briefly world-readable: the umask decides
        # the mode of a plain write, and a 022 umask would publish this at
        # 0644 in the window before any chmod.
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode("ascii"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        # Cannot persist it — fail OPEN rather than block the pin. An
        # unauthenticated proxy is the status quo; a proxy nobody can use is a
        # regression.
        try:
            tmp.unlink()
        except OSError:
            pass
        return ""
    return token


#: A retired secret keeps working for this long after a rotation.
#:
#: The wiring reaches a session through `~/.claude.json`, which the client
#: reads ONCE at exec. A rotated secret is therefore unreachable to every LIVE
#: process, and refusing the old one 407s each of them until it restarts.
#: Without a window, rotating a leaked credential and cutting the fleet are the
#: same operation.
#:
#: Long enough that an operator can rewire and let sessions turn over; short
#: enough that a leaked value is not honoured indefinitely.
_RETIRED_SECRET_SECONDS = 3600.0
_RETIRED_FILE = "proxy.retired"
_retired_secret: "str | None" = None
_retired_at = 0.0


def _retired_path(certdir) -> Path:
    return Path(certdir) / _RETIRED_FILE


def _retire_secret(old: "str | None", certdir=None) -> None:
    """Keep accepting `old` for the grace window. None clears it at once.

    ON DISK WHEN A CERTDIR IS GIVEN, because the process that ROTATES is never
    the daemon that AUTHORISES. `_current_secret()` re-reads the secret file
    per request, so a rotation reaches the daemon at once -- and a retirement
    held in the rotating process's memory reaches it never. The daemon then
    demands the new value while every live session still presents the old one,
    which is the outage the window exists to prevent.
    """
    global _retired_secret, _retired_at
    _retired_secret = old or None
    _retired_at = time.time() if old else 0.0
    if certdir is None:
        return
    path = _retired_path(certdir)
    try:
        if not old:
            path.unlink(missing_ok=True)
            return
        fd = os.open(str(path) + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps({"secret": old, "at": _retired_at}).encode())
        finally:
            os.close(fd)
        os.replace(str(path) + ".tmp", path)
    except OSError:
        pass          # a window we cannot persist is a window we do not get


def _retired_still_valid(certdir=None) -> "str | None":
    """The retired secret if it is still inside the window, else None."""
    now = time.time()
    if _retired_secret and now - _retired_at <= _RETIRED_SECRET_SECONDS:
        return _retired_secret
    if certdir is None:
        return None
    try:
        d = json.loads(_retired_path(certdir).read_text())
    except (OSError, ValueError):
        return None
    sec, at = d.get("secret"), d.get("at")
    if not isinstance(sec, str) or not sec or not isinstance(at, (int, float)):
        return None
    # Bounded BOTH ways: a future stamp is clock skew, not a licence to honour
    # a retired value forever.
    return sec if -_RETIRED_SECRET_SECONDS <= (now - at) <= _RETIRED_SECRET_SECONDS else None


def rotate_proxy_secret(certdir: Path) -> str:
    """Mint a replacement credential, sparing the old one for the grace window.

    `ensure_proxy_secret` is idempotent on purpose -- a respawn must not
    invalidate wiring live sessions already hold. That makes it the wrong tool
    when the value itself has to change, which is why this exists separately
    rather than as a flag on it.

    The retirement is what keeps this from being an outage: the caller rewrites
    the wiring, new processes take the new value, and the ones already running
    keep working on the old one until they turn over.
    """
    import secrets

    old = read_proxy_secret(certdir)
    path = proxy_secret_path(certdir)
    token = secrets.token_urlsafe(32)
    tmp = path.with_suffix(f".{os.getpid()}.rot")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode("ascii"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return old or ""
    # AFTER the write, and only for a REAL predecessor. Retiring "" would put
    # an empty password into the accepted set, which authorises everyone.
    _retire_secret(old or None, certdir)
    return token


def _proxy_authorized(headers: list[tuple[str, str]], secret: str | None,
                      certdir=None) -> bool:
    """Whether a CONNECT may use this proxy.

    No secret configured => authorized, so a daemon from before this change
    (or one that could not write its secret) keeps serving. Comparison is
    constant-time; the value is a bearer for the pinned account in all but
    name.
    """
    import hmac

    if not secret:
        return True
    accepted = [secret]
    retired = _retired_still_valid(certdir)
    if retired:
        accepted.append(retired)
    for key, value in headers:
        if key.lower() != "proxy-authorization":
            continue
        scheme, _, param = value.partition(" ")
        if scheme.lower() != "basic":
            continue
        try:
            decoded = base64.b64decode(param.strip(), validate=True).decode(
                "utf-8", "replace"
            )
        except Exception:
            continue
        # user:pass — the secret is the password; the user part is cosmetic.
        _, _, presented = decoded.partition(":")
        # EVERY candidate is compared, never short-circuited: returning early
        # on the first match would make the reply time depend on WHICH secret
        # matched, which is the leak constant-time comparison exists to avoid.
        ok = False
        for candidate in accepted:
            if hmac.compare_digest(presented, candidate):
                ok = True
        if ok:
            return True
    return False


_PORT_HINT_FILE = "port.hint"


def _write_port_hint(certdir: Path, port: int) -> None:
    """Remember the port to rebind across a respawn (see ``_spawn_daemon``)."""
    try:
        (Path(certdir) / _PORT_HINT_FILE).write_text(str(port))
    except OSError:
        pass


def read_port_hint(certdir: Path) -> int | None:
    """The port a previous daemon served on, recorded across its teardown.

    ``proxy.json`` is deleted before a respawn (a stale record must never read
    as live), so the port to reclaim is carried here instead.
    """
    try:
        return int((Path(certdir) / _PORT_HINT_FILE).read_text().strip())
    except (OSError, ValueError):
        return None


def write_daemon_state(
    certdir: Path, port: int, pid: int, fingerprint: str, handover: bool = False
) -> None:
    """Record the live daemon's identity atomically (temp-then-rename).

    ``handover`` marks the record as "a successor is being spawned for this
    daemon right now". It is the ONE arbitration point across the three paths
    that share the daemon lifecycle — the code watchdog, the refcount idle
    teardown and the SIGTERM handler — because all three already read this
    file and none of them can see the others' locals. The mark says: nothing
    is serving on this record, and whoever is departing must not unwire.
    """
    import json

    rec = {"port": port, "pid": pid, "fingerprint": fingerprint}
    if handover:
        rec["handover"] = True
    tmp = Path(certdir) / f"{_STATE_FILE}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(rec))
    os.replace(tmp, Path(certdir) / _STATE_FILE)


def mark_daemon_unpinnable(certdir: Path) -> None:
    """Record that THIS daemon cannot read the pinned account's credential.

    Only the running daemon can discover this, and only ensure_proxy can act
    on it — it reuses any daemon whose fingerprint matches, so without a mark
    a blind daemon is reused forever and `cswap pin` keeps reporting success
    over a pin that never applies. Rewrites the state file in place, keeping
    port/pid/fingerprint, and only when the record is ours.
    """
    import json

    path = Path(certdir) / _STATE_FILE
    try:
        st = json.loads(path.read_text())
    except (OSError, ValueError):
        return
    if not isinstance(st, dict) or st.get("pid") != os.getpid():
        return
    st["unpinnable"] = True
    tmp = Path(certdir) / f"{_STATE_FILE}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(st))
    os.replace(tmp, path)


# HOW OFTEN A BLIND DAEMON MAY REPLACE ITSELF. First attempt is immediate --
# the common case is transient and one gapless recycle ends it -- then doubling,
# because a machine that cannot read at all would otherwise recycle on every
# tick for ever. Never gives up: the interval is capped, not the attempts, so a
# fault that clears an hour later is still repaired without anyone asking.
_BLIND_RECYCLE_BASE_S = 60.0
_BLIND_RECYCLE_MAX_S = 1800.0
_BLIND_RECYCLE_FILE = "blind-recycle.json"


def _blind_recycle_path(certdir: Path) -> Path:
    """NOT `proxy.json`. `write_daemon_state` builds that record from scratch,
    so every successor erases anything extra written into it -- the exact way
    the `unpinnable` mark went missing and let a blind daemon be reused. State
    that has to outlive a respawn cannot live in a file a respawn rewrites."""
    return Path(certdir) / _BLIND_RECYCLE_FILE


def blind_recycle_due(certdir: Path, now: float) -> bool:
    """Whether enough time has passed to replace ourselves over blindness."""
    import json

    try:
        rec = json.loads(_blind_recycle_path(certdir).read_text())
        last, n = float(rec["at"]), int(rec["n"])
    except (OSError, ValueError, KeyError, TypeError):
        return True  # never tried, or the note is unreadable: repair is due
    wait = min(_BLIND_RECYCLE_BASE_S * (2 ** max(0, n - 1)), _BLIND_RECYCLE_MAX_S)
    return (now - last) >= wait


def note_blind_recycle(certdir: Path, now: float) -> None:
    """Record that we are replacing ourselves, so the successor waits longer
    if it turns out to be blind too."""
    import json

    try:
        rec = json.loads(_blind_recycle_path(certdir).read_text())
        n = int(rec["n"])
    except (OSError, ValueError, KeyError, TypeError):
        n = 0
    try:
        _blind_recycle_path(certdir).write_text(
            json.dumps({"at": now, "n": n + 1}))
    except OSError:
        pass  # advisory; a recycle that cannot be recorded still happens


def clear_blind_recycle(certdir: Path) -> None:
    """A daemon that CAN mint ends the episode, so the next one starts fresh."""
    try:
        _blind_recycle_path(certdir).unlink()
    except OSError:
        pass


def clear_daemon_unpinnable(certdir: Path) -> bool:
    """Drop the ``unpinnable`` mark once this daemon can mint again.

    THE MARK HAD NO ERASER. `mark_daemon_unpinnable` writes it once per
    process and nothing ever took it back, so an account repaired by a
    re-login left the flag standing for the life of the daemon: the TUI kept
    showing "cloud UNPINNED" over a pin that was working, and -- worse --
    `_read_alive_port` kept REFUSING to reuse a healthy daemon, so every
    launch spawned a successor over it.

    Only when the record is ours, exactly as the mark is. Returns whether the
    mark was actually there to remove, so a caller can log a transition rather
    than a rewrite on every tick.
    """
    import json

    path = Path(certdir) / _STATE_FILE
    try:
        st = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    if not isinstance(st, dict) or st.get("pid") != os.getpid():
        return False
    if not st.pop("unpinnable", None):
        return False
    tmp = Path(certdir) / f"{_STATE_FILE}.{os.getpid()}.tmp"
    try:
        tmp.write_text(json.dumps(st))
        os.replace(tmp, path)
    except OSError:
        return False
    return True


def read_daemon_state(certdir: Path) -> dict | None:
    """The recorded daemon state (``{port, pid, fingerprint}``), or None if the
    file is absent or corrupt."""
    import json

    try:
        data = json.loads((Path(certdir) / _STATE_FILE).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "port" not in data or "pid" not in data:
        return None
    return data


def _tree_digest_input(root: Path) -> bytes:
    """Every ``.py`` under ``root``, name and bytes, in a stable order.

    WALKED, NOT LISTED, and recursively: a list omits the module somebody adds
    next, and a non-recursive glob is a list in disguise the moment a
    subpackage appears. The name is in the digest so a rename is visible,
    which pure bytes miss; the sort keeps it independent of directory order.
    """
    return b"".join(
        f.relative_to(root).as_posix().encode() + b"\0" + f.read_bytes()
        for f in sorted(root.rglob("*.py"),
                        key=lambda f: f.relative_to(root).as_posix())
    )


def _host_package_dir() -> "Path | None":
    """Where claude_swap's source lives, or None.

    RESOLVED WITHOUT IMPORTING IT. This is called at module import to take
    `_OWN_FINGERPRINT`, and claude_swap imports cswap_pin back — an import
    here would be circular. `find_spec` runs the finders only.
    """
    import importlib.util

    try:
        spec = importlib.util.find_spec("claude_swap")
    except Exception:  # noqa: BLE001 — a broken host must not kill the daemon
        return None
    origin = getattr(spec, "origin", None)
    return Path(origin).parent if origin else None


def daemon_fingerprint(account_num: str = "", email: str = "") -> str:
    """Identity of the code the daemon RUNS — this package and the host
    package it borrows from — so a redeploy of either makes a running daemon
    stale and the launcher recycles it; mirrors the fingerprint staleness a
    sibling proxy's ensure step uses.

    IT NAMED `pin_proxy.py` UNTIL 0.1.104, which is where this code lived
    before the pin became its own package. A reader following that name looks
    for a file that has not existed for months, in the docstring whose whole
    job is to say what gets hashed.

    AND THE HASH IS WHY THIS RELEASE EXISTS AT ALL. Content, not version: a
    release that bumps only `pyproject.toml` leaves this file byte-identical,
    so the fingerprint does not move and no daemon recycles. That is correct
    behaviour and it is also what made 0.1.103's drain untestable — every
    departure since it shipped happened to owe nothing, and
    `uv pip install --reinstall` of the same version could not force one,
    exactly as designed. Measured by the cswap session: T0 14:22:21Z, four
    minutes, no handover.

    So the one-line correction above is the trigger, and saying so here is
    cheaper than a reader later wondering what 0.1.104 changed.

    The pinned account is deliberately NOT part of this. It is re-read per
    request (see :func:`make_pin_token_provider`), so re-pinning takes effect
    under a live daemon; including it here would recycle the daemon on every
    `cswap pin`, and a recycle is exactly what a live session should not need.
    The parameters are kept for call-site compatibility and ignored.
    """
    import hashlib

    # `rsync -a`, `cp -p`, `tar -p` and a restored backup all preserve it, so a
    # real deploy through any of those left the old daemon serving — the stale
    # daemon this fingerprint exists to end. same content + touched mtime   ->
    # SPURIOUS. A no-op reinstall recycled a healthy daemon and cost a handover
    # for nothing. A peer proxy in the same chain hit the mirror of this by
    # comparing PATHS: it caught a relocated install and missed `git pull` in
    # place, which is the commonest deploy there is. Both are the same mistake
    # — answering a cheaper question than the one that matters.
    #
    # NO TORN READ TO GUARD AGAINST, because this hashes the file it is ALREADY
    # IMPORTING rather than a hash someone else publishes. A design that writes
    # a hash to a SIDE FILE does need temp+rename there, since a reader
    # catching a partial write compares against a truncated hash and retires a
    # healthy process. Reading the file costs one stat + one read per check
    # (the watchdog polls on an interval, not per request), against a mistake
    # that costs an outage.
    try:
        code = _tree_digest_input(Path(__file__).parent)
    except OSError:
        # UNREADABLE IS NOT UNCHANGED. Return something stable-but-distinct so
        # a daemon does not read "no fingerprint" as "same as mine" and serve
        # stale code forever; the next successful read re-establishes it.
        code = b""
    # AND THE HOST PACKAGE, because the daemon runs its code too. Every
    # request asks `switcher.current_account_number()` through the `_host`
    # seam, so a claude_swap fix deployed under a live daemon changes nothing
    # it executes — the fingerprint does not move, no recycle happens, and
    # every check reports the daemon current while it serves the old copy.
    #
    # An unresolvable host contributes nothing rather than a distinct value:
    # a pin installed without its host would otherwise recycle itself forever.
    host = _host_package_dir()
    if host is not None:
        try:
            code += b"claude_swap\0" + _tree_digest_input(host)
        except OSError:
            # UNREADABLE IS NOT ABSENT, the same rule the own-tree branch
            # above states — and this said the opposite. A walk that races a
            # host redeploy (files replaced under `rglob`) collapsed to the
            # digest of a machine with no claude_swap at all, so a daemon
            # would read "unchanged" through the one window where the host is
            # certainly changing.
            code += b"claude_swap\0<unreadable>"
    return hashlib.sha256(code).hexdigest()[:16]


# THE BYTES THIS PROCESS LOADED, captured at IMPORT and never re-read.
#
# `daemon_fingerprint()` re-reads the file every call, which is right for one
# side of the watchdog's comparison and wrong for the other. The question there
# is "does disk still match what I loaded", so the DISK side must be fresh and
# the OWN side must not move. `_watch_own_code` took its baseline by calling
# `daemon_fingerprint()` from inside the watchdog THREAD — started near the end
# of `daemon_main`, after the proxy is serving and the signal teardown is
# installed. Replace the file anywhere in that window and the baseline captures
# the NEW bytes while the process runs the OLD ones, so every later tick
# compares new against new, is true forever, and the daemon never learns it is
# stale.
#
# That is the exact outage this watchdog exists to end — a daemon served for 22
# hours on code replaced 19 hours earlier — reached through the detector rather
# than by having no detector. And it fails SILENTLY: an over-eager baseline
# costs one needless handover and corrects itself, this one costs nothing
# visible at all, which is indistinguishable from health.
#
# Module level, so it is evaluated while the interpreter is executing this very
# file. Nothing between import and the watchdog can move it.
_OWN_FINGERPRINT = daemon_fingerprint()


def _pid_alive(pid: int) -> bool:
    """Whether ``pid`` names a process we could signal. Nothing else.

    A PID MUST BE POSITIVE, and refusing the rest is the whole guard. In
    ``kill(2)`` a pid of 0 addresses the CALLER'S OWN PROCESS GROUP and a
    negative pid addresses the group named by its absolute value — so
    ``os.kill(0, 0)`` is a permission check on ourselves that ALWAYS
    succeeds, and this answered True for a process that cannot exist.

    A peer hit the same primitive one signal number away: a pid parse that
    yielded 0 turned ``kill(pid, SIGKILL)`` into ``kill(0, SIGKILL)`` and
    SIGKILLed its own test runner. Here the kill sites are gated on
    ``_pin_daemon_pids`` so 0 cannot reach one, which makes this a wrong
    ANSWER rather than an outage — and a wrong answer a later caller would
    inherit as a fact.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# HOW MANY TIMES `_serving_can_pin` RECONNECTS before calling a port that
# accepts TCP and never answers a wedge rather than "unknown". A single
# timeout is indistinguishable from an ordinary slow tick; on 0.1.240
# `/health` answers within milliseconds even under a stalled mint (see
# `mint_stalled` below), so silence across every attempt is the request
# handler itself, not the credential store.
_PIN_PROBE_ATTEMPTS = 3

# HOW LONG A `mint_stalled_s` MAY RUN before it is a reason to recycle rather
# than wait. `_MINT_LOCK_BOUND_S` already bounds one REQUEST's wait on the
# refresh lock; this bounds how long the DAEMON may report the lock busy
# before something is wrong that a request-scoped timeout cannot fix. A
# credential store the daemon cannot read is cleared only by a fresh process
# started from the GUI session (`heal-pin.sh`'s whole reason to exist), so a
# stall past this is a reason to recycle, not to keep waiting on the same
# process.
_MINT_STALL_WEDGE_S = 60.0


def _serving_can_pin(port: int, timeout: float = 1.0) -> bool | None:
    """What the daemon on ``port`` says about minting, or None if it will not say.

    Measured, and the reason this exists rather than a record read: `cswap pin
    <n>` run to completion returned rc=0, printed "Pinned the cloud account",
    left the daemon pid unchanged and `can_pin` false throughout — because the
    record it consulted had lost its `unpinnable` mark to a respawn.

    A CONNECT FAILURE IS "NOBODY THERE" and answers None on the first try:
    the caller's own dead-port check already handles that population, and
    retrying it would only cost time for no new information. A socket that
    ACCEPTS and then never answers is different -- see `_PIN_PROBE_ATTEMPTS`
    -- and reads as a confirmed wedge (False), not "it would not say" (None).
    Measured on a Mac: `cswap pin --heal` printed "Nothing to heal" twice
    against a trio that accepted TCP and never answered, because this
    returned None and every caller reads None as healthy by policy.
    """
    for attempt in range(_PIN_PROBE_ATTEMPTS):
        try:
            sk = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        except OSError:
            return None
        buf = b""
        try:
            with sk:
                sk.settimeout(timeout)
                sk.sendall(b"GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                while len(buf) < 65536:
                    chunk = sk.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        except OSError:
            pass  # a reset AFTER a full answer is still an answer -- see below
        if b"\r\n\r\n" not in buf:
            continue  # connected, but no full answer either -- a wedge
        parts = buf.split(b"\r\n\r\n", 1)
        try:
            body = json.loads(parts[1])
        except ValueError:
            return None  # a real, if malformed, answer -- not silence
        held = body.get("mint_stalled_s")
        if isinstance(held, (int, float)) and held > _MINT_STALL_WEDGE_S:
            return False
        val = body.get("can_pin")
        return val if isinstance(val, bool) else None
    # Every attempt connected and none produced an answer.
    return False


def _read_alive_port(certdir: Path, fingerprint: str | None = None) -> int | None:
    """Port of a live recorded daemon whose pid is alive, its port answers, and
    (when ``fingerprint`` is given) its fingerprint matches. Else None."""
    st = read_daemon_state(certdir)
    if not st:
        return None
    # A handover in flight means the recorded daemon has already stopped
    # serving and its successor has not published yet. The pid is still alive
    # and the port may already answer — reclaimed by that successor — so both
    # liveness checks below would read the record as healthy and hand the
    # spawner its own predecessor.
    if st.get("handover"):
        return None
    if fingerprint is not None and st.get("fingerprint") != fingerprint:
        return None
    # A daemon that has proven it cannot read the pinned credential is not a
    # daemon worth reusing. It answers /health, serves every request, and
    # silently applies no pin — so reusing it makes `cswap pin` report success
    # forever while Remote Control sessions keep landing on the wrong account.
    # Only the caller asking for a SPECIFIC fingerprint is spawning a pin, so
    # only that caller recycles; a bare liveness probe still sees it.
    if fingerprint is not None and st.get("unpinnable"):
        return None
    if not _pid_alive(int(st["pid"])):
        return None
    try:
        with socket.create_connection(("127.0.0.1", int(st["port"])), timeout=1):
            pass
    except OSError:
        return None
    # AND ASK THE DAEMON, because the field above is erasable. It is written
    # once per process, and a successor publishes a fresh record without it —
    # so between the respawn and the next unswapped request the record reads
    # clean over a daemon that mints nothing, and this returns it. `/health`
    # recomputes `can_pin` per call and cannot go stale that way.
    # Only an explicit False refuses: None is "it would not say", which must
    # read as healthy here for the same reason it does everywhere else in this
    # file — a busy daemon that misses the deadline must not be recycled on
    # every launch.
    if fingerprint is not None and _serving_can_pin(int(st["port"])) is False:
        return None
    return int(st["port"])


def wanted_port(certdir: Path) -> "int | None":
    """The port this pin should serve on, in precedence order.

    Shared by the daemon's own bind and by :class:`PortHolder`, which binds
    the same address on the daemon's behalf. Two copies of this order is how
    a holder comes to hold one port while the daemon reclaims another.

    1. what a human configured (``--set_port``): a standing instruction
    2. the port the last daemon recorded
    3. the hint a respawn left (it deletes ``proxy.json`` before starting us)
    4. what ``.claude.json`` names — the only record that survives a wiped
       cert dir, and the number live sessions are actually dialling
    """
    want = configured_port(certdir)
    if isinstance(want, int):
        return want
    prev = read_daemon_state(certdir)
    if isinstance(prev, dict) and isinstance(prev.get("port"), int):
        return prev["port"]
    want = read_port_hint(certdir)
    if isinstance(want, int):
        return want
    return _wired_port()


_SELF_HEAL_ENV = "CSWAP_PIN_SELF_HEAL"

# OPT-IN, because a holder is MEANT to outlive the thing that started it. Armed
# unconditionally it took the pin down on a normal launch: `cswap pin` and a
# shell launcher both spawn the holder and exit, so the parent is gone seconds
# later and PR_SET_PDEATHSIG fires. A peer component shipped the same default
# and took its port down twice under a live session before reverting to exactly
# this shape.
_EXIT_WITH_PARENT_ENV = "CSWAP_PIN_EXIT_WITH_PARENT"
# "I am going, put a successor on this socket." A daemon serving on a holder's
# socket exits with this instead of 0 when it was TERM'd rather than idle: the
# holder keeps the port and respawns, so a redeploy loads new code without the
# address ever unbinding. A plain 0 still means "released — do not restart".
_RESTART_ME_CODE = 75  # EX_TEMPFAIL, and nothing else in this file uses it
# "REPLACE ME, I AM STILL SERVING." The exit codes above can only be said by
# dying, which is why a redeploy under a holder costs a gap: the successor
# cannot start until the predecessor is gone. This signal separates the ASK
# from the LEAVING, so the two can overlap on one socket. `getattr`, NOT
# `signal.SIGUSR1`.
#
# THIS LINE RAN AT IMPORT AND WINDOWS HAS NO SIGUSR1, so every Windows install
# of this package failed to import — not a degraded feature, no import at all.
# It reached CI the moment claude-swap's pin extra floored onto the release
# carrying it: AttributeError: module 'signal' has no attribute 'SIGUSR1'
# .venv\Lib\site-packages\cswap_pin\proxy.py:4503 None means "this platform
# cannot do it", and every user below reads it as that rather than assuming a
# signal exists. The whole holder/daemon protocol is POSIX; what must survive a
# POSIX-less platform is the IMPORT, because `heal`, `load_pin` and `apply_pin`
# are what the host actually calls there.
_REPLACE_ME_SIGNAL = getattr(signal, "SIGUSR1", None)
# The same, for the retirement path. SIGHUP is equally absent on Windows.
_STAND_DOWN_SIGNAL = getattr(signal, "SIGHUP", None)
# How long to let the ask land before reading whether the holder survived it.
# An unhandled USR1 is fatal on delivery, so this only has to outlast the
# kernel's trip to the other process, not any work the handler does.
_ASK_SETTLE_SECONDS = 0.25
# HOW LONG `stop()` WILL WAIT FOR THE STANDBY TO ACTUALLY GO. A single
# fire-and-forget `send_signal` can race the child's own startup — the SIGHUP
# only means "release" once `standby_main` has reached
# `signal.signal(signal.SIGHUP, _release)`, and a child spawned moments
# earlier may not have gotten that far. MEASURED: a holder whose daemon spawn
# was stubbed to die on every retry (a tight, near-zero-backoff respawn loop)
# sent one SIGHUP that `os.kill` accepted without error, yet the standby was
# still alive, still holding the descriptor, minutes later — and outlived the
# whole suite to become an orphaned holder once its parent (this test
# process) finally exited. Re-sent until the child is confirmed dead, bounded
# so a genuinely wedged standby cannot hang teardown forever.
_STANDBY_RELEASE_BOUND_S = 3.0

# How long a bridge creation waits for a token it could not mint. Three tries
# at 0.3s is under a second — below the noise of opening Remote Control, and
# far longer than a `consume-busy` deferral, which is one process finishing a
# refresh. Deliberately small: the point is to survive a lock race, not to
# outlast a broken credential store, and a launch must never hang on this.
_PIN_WAIT_TRIES = 3
_PIN_WAIT_S = 0.3
# The ladder a daemon that keeps dying costs: one attempt every ~5s rather than
# four a second, so a persistently broken build does not spin the box while the
# port it holds stays answering.
_HOLD_RESTART_BASE_S = 0.25
_HOLD_RESTART_MAX_S = 5.0
# Consecutive failed spawns before the holder stops waiting for a successor and
# serves the socket itself, unpinned.
#
# THE FAILURE THIS CLOSES, measured on host-a 2026-08-15: the PyPI release was
# installed over an editable checkout, which took `cswap_pin` out of the tool
# env, and the daemon's own code watcher then asked for a successor that could
# not import. Four spawns died on `ModuleNotFoundError` and the holder kept the
# socket BOUND while it retried — so nothing was refused and every session
# wired to that port hung instead. A refusal fails fast and locally; a bound
# socket with no acceptor fails slowly, everywhere, at once. At the ladder's
# cap this is ~30s of unbroken failure, which separates "it crashed, the next
# one will be fine" from "nothing this holder starts will ever run". The first
# is what the ladder is for; the second is this.
_HOLD_DEGRADE_AT = 8

# Consecutive failed respawns before the holder says the successor cannot
# start. NOT a ceiling — it keeps retrying, because a machine that recovers on
# attempt 20 should. It is the line between "it crashed, the next one will be
# fine" and "nothing this holder starts will ever run", which look identical on
# the ladder and need opposite responses. The daemon already running kept
# serving — its code is in memory — while every successor died before reaching
# any of its own code:  .../claude-swap/bin/python: Error while finding module
# specification for 'cswap_pin.proxy' (ModuleNotFoundError: No module named
# 'cswap_pin')  repeated in `daemon.log` with nothing saying the port was one
# death away from being unrecoverable. The pin fails open by design, so this is
# exactly the class of failure that stays invisible until it is an outage.
_HOLD_RESTART_REPORT_AT = 5
# How long the holder waits for the port it was told to take. The predecessor
# is usually mid-teardown, so this is a handoff, not a contest.
_HOLD_BIND_WAIT_S = 3.0


class PortHolder:
    """Owns the pin's port, and restarts the daemon under it.

    THE CASE EVERY HANDOVER MISSES IS A CRASH. `release_listener(hand_down=True)`
    keeps the port bound across a planned restart, but it is cooperative: the
    outgoing daemon stops accepting and passes the socket on. A `kill -9`, an
    OOM kill, or a segfault skips all of that, and the port is then unowned —
    which for a live session is permanent, because its ``HTTPS_PROXY`` was
    fixed at exec and is never re-read. Measured outage: sessions on a dead
    36301 do not fail loudly, their requests leave WITHOUT the pin.

    So the socket is bound by a process that does not serve requests and has
    almost nothing to crash: it binds, spawns, waits. The daemon accepts on the
    inherited descriptor, so there is no relay, no extra hop, and no copy —
    the connection the client makes is the connection the daemon serves.

    A RELAY WOULD ALSO WORK and is what the cache proxy does (it has no way to
    pass a socket to its child). Here the socket-activation path already
    exists — ``_inherited_listener`` — so holding the port costs one bind and
    the daemon is unchanged.

    ``CSWAP_PIN_SELF_HEAL=off`` disables the restart, because a respawner
    fighting a human who is debugging the daemon is worse than a dead port.
    """

    def __init__(self, certdir: Path, account_num: str, email: str,
                 port: int | None = None, sock: socket.socket | None = None):
        self._certdir = Path(certdir)
        self._account = account_num
        self._email = email
        self._standby = None
        # Set by `_on_replace_request` so `_supervise` can tell a HANDOVER exit
        # (successor already serving on our socket) from a RELEASE exit
        # (nothing left to serve). Both are exit 0 from the daemon's side, and
        # acting on the wrong one closes the port under a live successor.
        self._replacing = False
        # Whether `_install_replace_handler` succeeded. Only then may `_spawn`
        # tell a child this holder can be asked — see `_HOLDER_REPLACE_ENV`.
        self._replace_channel = False

        # ADOPT A HANDED-DOWN SOCKET RATHER THAN BINDING. A predecessor that is
        # recycling passes its still-LISTENING socket down, and it has not let
        # go of the port — so a holder that tried to bind would lose the race
        # and fall back to an ephemeral one, taking the port out of the holder
        # exactly when an upgrade is in flight. Adopting has no race to lose:
        # the descriptor is already bound and already listening, and the
        # predecessor stopped accepting on it before passing it over.
        #
        # AN ALREADY-ADOPTED SOCKET, for the standby. It consumed the handdown
        # env to hold the descriptor, so asking `_handed_down_listener` a
        # second time would find nothing and this holder would bind a fresh
        # port — stranding the very sessions the standby stayed alive to keep.
        adopted = sock if sock is not None else _handed_down_listener()
        if adopted is not None:
            self._srv = adopted
            self.port = self._srv.getsockname()[1]
            self.daemon_pid = None
            self._stop = False
            self._failures = 0
            self._thread = None
            self._proc = None
            return

        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # THE SAME PORT THE DAEMON WOULD HAVE TAKEN. The holder binds on its
        # behalf, so it has to resolve the address the same way — otherwise a
        # live session's HTTPS_PROXY names a port the holder does not hold.
        if port is None:
            want = wanted_port(self._certdir)
            port = want if isinstance(want, int) and want > 0 else 0
        # WAIT FOR THE PORT WE WERE ASKED FOR. The predecessor may still be
        # letting go of it — this runs immediately after a daemon closed its
        # listener — and falling straight to an ephemeral port would strand
        # every session whose HTTPS_PROXY names the old one.
        deadline = time.monotonic() + _HOLD_BIND_WAIT_S
        squat_checked = False
        while port:
            try:
                self._srv.bind(("127.0.0.1", port))
                break
            except OSError:
                # A STANDBY OF OURS MAY BE SQUATTING. One left behind by a
                # holder that was KILLED rather than released keeps the
                # listener and never accepts, so the port is unbindable AND
                # unreachable at the same time. That pair is the signature:
                # a live handover's standby is also unbindable but DOES
                # answer, and retiring it would open the gap it exists to
                # close. Checked once, and only when the wait has already
                # run out, so the ordinary contended-handover path is
                # untouched.
                if not squat_checked and time.monotonic() >= deadline:
                    squat_checked = True
                    if not _port_answers(port, timeout=1.0):
                        if _retire_stale_standbys(self._certdir):
                            _log_lifecycle(
                                f"port {port} was held by a standby that had "
                                "stopped accepting — released it and retrying "
                                "the bind"
                            )
                            deadline = time.monotonic() + _HOLD_BIND_WAIT_S
                            continue
                if time.monotonic() >= deadline:
                    # REFUSE, do not serve somewhere else. A holder exists to
                    # keep ONE address answering; on any other port it is a
                    # healthy-looking daemon that no session can reach, while
                    # `.claude.json` still names the number they were given. An
                    # ephemeral fallback IS right at a cold start (port 0
                    # below) — there nothing is wired yet and any port will do.
                    # It is wrong once we have been told which port to take,
                    # because that instruction came from the live sessions.
                    self._srv.close()
                    raise OSError(
                        f"port {port} is taken — refusing to hold a different "
                        f"one, which the sessions wired to {port} cannot reach"
                    )
                time.sleep(0.05)
        if not port:
            self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(128)
        self.port = self._srv.getsockname()[1]
        self.daemon_pid: int | None = None
        self._stop = False
        self._failures = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        # BEFORE THE FIRST SPAWN, not merely before the supervisor thread. A
        # child learns whether this holder can be asked from its ENVIRONMENT,
        # written once at spawn time, so a handler installed afterwards is one
        # no already-running daemon can ever be told about. Ordered the other
        # way the first daemon falls back to the old gap for as long as it
        # lives, and nothing reports it.
        self._install_replace_handler()
        # The FIRST spawn happens here, not in the thread: `start()` returning
        # has to mean a daemon exists, or a caller that immediately reads
        # `daemon_pid` (or asks the port for a health probe) races the
        # supervisor's first loop iteration.
        self._spawn()
        # AFTER the daemon, so a machine that cannot start one at all does not
        # also leave a standby behind waiting for a holder that never worked.
        self._spawn_standby()
        self._thread = threading.Thread(target=self._supervise, daemon=True)
        self._thread.start()

    def degrade_now(self) -> None:
        """Serve the held socket ourselves, unpinned, and stop respawning.

        THE PIN IS OPTIONAL AND THE SESSION IS NOT. Every session on the
        machine has this address baked into its environment at exec, so a
        holder that cannot start a daemon is not deciding whether the pin
        works — it is deciding whether those sessions have a network. Retrying
        into a bound-but-unaccepted socket answers that question the worst way
        available: they hang, all of them, until a human notices.

        NO MITM AND NO SWAP. This forwards `CONNECT` and nothing else, which is
        exactly the pin turned off: bearers are untouched because the bytes are
        never read. That also makes it survivable in the case it exists for —
        the code is already in this process's memory, so it keeps working when
        the package is gone from disk, which is what put a machine here.

        Idempotent, and it does not un-degrade: recovery is a fresh triad, and
        `heal` builds one before the next `claude`.
        """
        if getattr(self, "_degraded", False):
            return
        self._degraded = True
        _log_lifecycle(
            f"no successor could start — this holder is serving port "
            f"{self.port} itself, UNPINNED. Remote Control and artifacts "
            f"follow the active account until a daemon starts again; "
            f"`cswap pin --heal` or the next launch rebuilds one."
        )
        threading.Thread(target=self._accept_degraded, daemon=True).start()

    def _accept_degraded(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._relay_one, args=(conn,),
                             daemon=True).start()

    def _relay_one(self, conn: socket.socket) -> None:
        """One blind CONNECT tunnel, through whatever chain the pin recorded."""
        upstream = None
        try:
            conn.settimeout(_HOP_REPLY_BUDGET_S)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            line = head.split(b"\r\n", 1)[0].decode("latin1")
            parts = line.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                # Only CONNECT is forwarded. A plain request here would need
                # the bytes read and rewritten, which is the MITM this mode
                # exists to avoid.
                conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n"
                             b"Content-Length: 0\r\n\r\n")
                return
            host, _, port_s = parts[1].rpartition(":")
            # PARSED, not passed through. `_ambient_chain` and the recorded
            # hint are both URL STRINGS; `_dial_chain` takes a `_Chain`, and
            # handing it a str fails on `.address` at the moment this mode is
            # the only thing holding the machine up.
            chain = parse_upstream_proxy(
                _ambient_chain(certdir=self._certdir)[0]
                or _read_upstream(self._certdir, "proxy")
            )
            upstream = _dial_chain(chain) if chain else \
                socket.create_connection((host, int(port_s)), timeout=15)
            if chain:
                upstream.sendall(
                    f"CONNECT {parts[1]} HTTP/1.1\r\nHost: {parts[1]}\r\n\r\n"
                    .encode("latin1"))
                reply = upstream.recv(4096)
                if b" 200" not in reply.split(b"\r\n", 1)[0]:
                    conn.sendall(reply or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            conn.settimeout(None)
            _pump(conn, upstream)
        except OSError:
            pass
        finally:
            for s in (conn, upstream):
                try:
                    if s is not None:
                        s.close()
                except OSError:
                    pass

    def _self_heal_on(self) -> bool:
        return os.environ.get(_SELF_HEAL_ENV, "").lower() not in ("off", "0", "no")

    @staticmethod
    def _backoff(failures: int) -> float:
        """How long to wait before the next respawn. A method so a test can
        take the ladder out: reaching the report threshold through the real
        one costs 0.5+1+2+4+5 = 12.5s, which is a timing test nobody wanted."""
        return min(
            _HOLD_RESTART_BASE_S * 2 ** min(failures, 5), _HOLD_RESTART_MAX_S,
        )

    def _spawn(self) -> None:
        """Start a daemon on our socket, via the socket-activation convention.

        LISTEN_PID names the CHILD, which we cannot know before it exists —
        so it is set from the child itself, in a preexec hook. The parent's own
        pid there would make ``_inherited_listener`` refuse the fd (that guard
        is what stops a grandchild adopting a descriptor it does not have) and
        the daemon would bind a fresh port, which is the stranding this class
        exists to prevent.
        """
        import subprocess
        import sys

        fd = self._srv.fileno()
        # THE PREDECESSOR PROTOCOL, not the systemd one.
        # `_handed_down_listener` was built for exactly this: the fd is named
        # by NUMBER and guarded by the PARENT's pid, which we do know.
        env = {k: v for k, v in os.environ.items() if k != "LISTEN_PID"}
        env["LISTEN_FDS"] = "0"
        env[_HANDDOWN_FD_ENV] = str(fd)
        env[_HANDDOWN_FROM_ENV] = str(os.getpid())
        # A HOLDER, not a predecessor. Both pass a listening socket down and
        # both use the variables above, but only this one is still alive
        # afterwards to put a successor on the socket — which is what makes a
        # TERM here a recycle rather than a release. A predecessor handing over
        # is itself going away, so its child must exit 0 as it always has.
        env[_HELD_BY_ENV] = str(os.getpid())
        # ONLY IF WE CAN ACTUALLY HEAR IT — see `_HOLDER_REPLACE_ENV`. Absent,
        # the child asks by exiting 75 as it always has: a longer gap, never a
        # dead holder.
        if self._replace_channel:
            env[_HOLDER_REPLACE_ENV] = "1"
        # WHAT THIS HOLDER IS RUNNING — see `_HOLDER_SHA_ENV`. The child never
        # reads it; a checker does, to answer the one question the daemon's own
        # fingerprint cannot.
        env[_HOLDER_SHA_ENV] = _OWN_FINGERPRINT
        log = _open_daemon_log(self._certdir)
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", _DAEMON_MODULE, self._account,
                 self._email, str(self._certdir)],
                env=env,
                pass_fds=(fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
        finally:
            if hasattr(log, "close"):
                log.close()
        self.daemon_pid = proc.pid
        self._proc = proc

    def _spawn_standby(self) -> None:
        """Place a third process on this descriptor that does nothing with it.

        THE HOLDER CANNOT COVER ITS OWN DEATH. It keeps the port across a daemon
        crash — measured across a SIGKILL, 407 of 408 requests served, max time
        to first byte 6.3ms — because the descriptor lives in a process that is
        not the one serving. Apply that argument once more and it says the
        descriptor must also live somewhere that is not the holder: when the
        holder exits, the kernel closes its copy, and a session whose
        ``HTTPS_PROXY`` was fixed at exec has no way to learn the address is
        gone. Measured with both gone: 198 of 199 ConnectionRefused.

        DETACHED, because the point is to outlive the parent. ``start_new_session``
        gives it its own process group, so a ctrl-C or a group-delivered TERM
        aimed at the holder does not reach it. It must also never arm
        PDEATHSIG — that primitive exists to make a child die with its parent,
        which is right for a daemon and exactly backwards here.

        NOT A RELAY. A peer needed one because node installs an accept callback
        at ``listen()`` and cannot hold a listening socket without accepting on
        it; that forced a second acceptor, byte forwarding, and a self-exclusion
        bug that took descriptors from 22 to 29,814 on one connect. CPython only
        accepts when you CALL ``accept()``, so this process can hold the socket
        and stay silent — and when it finally acts, it does not serve traffic at
        all, it puts a real daemon back on the descriptor it was already
        holding. Requests that arrive in between queue in the backlog of a
        socket that never stopped listening.
        """
        import subprocess
        import sys

        fd = self._srv.fileno()
        env = {k: v for k, v in os.environ.items() if k != "LISTEN_PID"}
        env["LISTEN_FDS"] = "0"
        env[_HANDDOWN_FD_ENV] = str(fd)
        env[_HANDDOWN_FROM_ENV] = str(os.getpid())
        # NEVER INHERIT THE DIE-WITH-PARENT REQUEST. `_EXIT_WITH_PARENT_ENV`
        # asks a child to arm PDEATHSIG, which is a test harness's way of not
        # leaking holders. Passed through to a standby it is precisely
        # backwards: the standby exists to outlive this process, and arming it
        # would make the standby die in the one event it was placed for.
        env.pop(_EXIT_WITH_PARENT_ENV, None)
        # THE PID IT WAS BORN UNDER, not a sentinel to compare against. Arming
        # on ``getppid() == 1`` is wrong wherever a subreaper collects orphans
        # (systemd --user is one): the standby never reads 1, so it never arms
        # — while still holding the descriptor. The address then ACCEPTS and
        # HANGS, which is strictly worse than the refusal it replaced, because
        # a refused client fails at once and a queued one waits out its own
        # timeout.
        env[_STANDBY_FROM_ENV] = str(os.getpid())
        log = _open_daemon_log(self._certdir)
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", _DAEMON_MODULE, _STANDBY_MODULE_ARG,
                 self._account, self._email, str(self._certdir)],
                env=env,
                pass_fds=(fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                # A FILE, never a pipe.
                stderr=log,
                start_new_session=True,
            )
        finally:
            if hasattr(log, "close"):
                log.close()
        self._standby = proc
        # ONE IN, ONE OUT — see `_retire_stale_standbys`. AFTER ours exists, so
        # the socket is never left without one; the strays cannot arm meanwhile
        # because the port is answering (the daemon above started first).
        gone = _retire_stale_standbys(self._certdir, keep_pid=proc.pid)
        if gone:
            _log_lifecycle(
                f"retired {gone} standby(s) left behind on port {self.port} by "
                f"holders that were killed rather than released"
            )

    def _reap_standby(self) -> None:
        """Notice a dead standby, say so, and stop it being a zombie.

        SAYING SO IS THE POINT. Losing the standby is not an outage — the
        holder still keeps the port across a daemon crash — so this is a
        warning, not a restart. But a holder that has lost it is back to the
        pre-standby behaviour with nothing announcing the change, and the
        machine reports a cover it does not have.
        """
        proc = getattr(self, "_standby", None)
        if proc is None or proc.poll() is None:
            return
        _log_lifecycle(
            f"standby for port {self.port} is gone (exit {proc.returncode}) — "
            f"this holder's death now takes the address with it, as it did "
            f"before the standby existed. A re-pin places a new one."
        )
        self._standby = None

    def _install_replace_handler(self) -> None:
        """Let a still-serving daemon ask for its successor.

        THE GAP THIS EXISTS TO CLOSE. `_supervise` is `wait()` then `_spawn()`,
        so under a holder the successor cannot start until the predecessor is
        gone, and that wait is time with the port bound and nobody behind it —
        measured 2 s on host-a, 30 s under load on 0.1.44 -> 0.1.46.

        The socket was never the obstacle: `_spawn` already hands this holder's
        own listening fd to every daemon it starts, so a second one can join it
        at any moment. What was missing is a way for the daemon to SAY "replace
        me" without dying, because exit 75 (replace) and exit 0 (release) are
        both only sayable by exiting.

        SIGUSR1 is that channel, and it has to be a separate one: a peer whose
        redeploy is gapless splits the same meanings across SIGHUP ("give the
        address away, do NOT replace yourself") and SIGTERM ("stop, and spawn
        your successor"), and records a draft that merged them taking a test
        from 587 ms to 10,642 ms.

        Signals reach the MAIN thread only, and `_supervise` runs on a worker
        blocked in `Popen.wait()` — verified that the handler still runs and
        can spawn there, with the predecessor staying alive.
        """
        if _REPLACE_ME_SIGNAL is None:
            return  # no such signal here — see the constant
        try:
            signal.signal(_REPLACE_ME_SIGNAL, self._on_replace_request)
            self._replace_channel = True
        except (ValueError, OSError):
            # Not the main thread, or no such signal. The daemon's exit-75 path
            # still works, so this degrades to the old gap rather than to
            # nothing.
            pass

    def _on_replace_request(self, signum, frame) -> None:
        # SPAWN FIRST, FLAG SECOND is not optional. `_supervise` is blocked in
        # `wait()` on the predecessor; the moment that returns it reads
        # `_replacing` to decide whether an exit 0 means "handover" or "release
        # the port". Setting the flag before the successor exists would make a
        # failed spawn look like a completed handover, and the holder would
        # close the socket with nothing on it.
        self._spawn()
        self._replacing = True

    def _supervise(self) -> None:
        while not self._stop:
            code = self._proc.wait()
            if self._stop:
                return
            # A HANDOVER, NOT A RELEASE. The predecessor asked us to replace it
            # while it was still serving, we did, and it then drained and left
            # with 0. That 0 means "released — do not restart" everywhere else,
            # and acting on it here would close the listening socket the
            # successor is already accepting on.
            if self._replacing:
                self._replacing = False
                _log_lifecycle(
                    f"daemon {code} retired after handing over — successor "
                    f"already serving on port {self.port}"
                )
                continue
            # A DEAD STANDBY MUST NOT BE A SILENT ONE. Checked here because
            # this loop already wakes on every daemon exit, so it costs a
            # `poll()` and no timer. Reaping is the load-bearing half: an
            # unreaped child stays `<defunct>` in the process table forever,
            # and `ps`, `kill -0` and every check that asks the TABLE rather
            # than the STATE then report a standby that is not there.
            self._reap_standby()
            # A CLEAN EXIT IS A DECISION, NOT A FAILURE. The pin tears itself
            # down when the last refcount holder closes the FIFO — that is the
            # whole idle-teardown design. Restarting it would make the port
            # this class holds immortal too, and the daemon would respawn
            # forever with nobody to serve.
            #
            # Exit status is the only thing that separates them: 0 means the
            # daemon chose to go (teardown, SIGTERM handler), anything else
            # means it was killed or crashed.
            if code == 0:
                _log_lifecycle(
                    f"daemon {self.daemon_pid} exited cleanly — releasing port "
                    f"{self.port}"
                )
                try:
                    self._srv.close()
                except OSError:
                    pass
                return
            if code == _RESTART_ME_CODE:
                # A REDEPLOY, not a teardown. Respawn at once and skip the
                # backoff: this exit was asked for, so treating it as a failure
                # would make every update wait out a ladder rung.
                _log_lifecycle(
                    f"daemon {self.daemon_pid} asked for a successor — "
                    f"restarting on the held port {self.port}"
                )
                self._failures = 0
                self._spawn()
                continue
            if not self._self_heal_on():
                # SAY WHAT HAPPENS, which is not what this used to claim. The
                # old line promised "the port stays bound but nothing is
                # serving it". A human who set this switch to debug a daemon
                # read "stays bound" and would expect their live sessions to
                # hang rather than be refused; they are refused, immediately,
                # all of them. The switch is still doing what it was built for
                # — its own rationale is that a respawner fighting a human is
                # "worse than a dead port", which accepts this cost out loud.
                # Only the line describing it was wrong, and a wrong line in
                # the one place a debugging session looks is worse than no
                # line.
                _log_lifecycle(
                    f"daemon {self.daemon_pid} exited and {_SELF_HEAL_ENV}=off — "
                    f"NOT respawning, and this holder is exiting with it, so "
                    f"port {self.port} stops answering. Every session wired to "
                    f"it gets ConnectionRefused until a pin is started again."
                )
                return
            self._failures += 1
            _log_lifecycle(
                f"daemon {self.daemon_pid} exited (code {code}); restarting "
                f"under the held port {self.port}"
            )
            # SAY IT ONCE when the successor is not merely crashing but cannot
            # start at all — see `_HOLD_RESTART_REPORT_AT`. Exactly at the
            # threshold, so a machine that keeps failing does not turn the log
            # into one warning per rung forever.
            if self._failures == _HOLD_RESTART_REPORT_AT:
                _log_lifecycle(
                    f"the successor cannot start — {self._failures} spawns in "
                    f"a row died immediately. Still retrying, but the port is "
                    f"one holder death away from being unrecoverable. The "
                    f"daemon's own stderr is above in this file."
                )
            if self._failures >= _HOLD_DEGRADE_AT:
                # STOP WAITING FOR A SUCCESSOR THAT IS NOT COMING. Retrying
                # past here is not patience, it is an outage held open: the
                # socket stays bound and unaccepted, so every wired session
                # hangs rather than failing over. See `degrade_now`.
                self.degrade_now()
                return
            time.sleep(self._backoff(self._failures))
            if self._stop:
                return
            self._spawn()

    def stop(self) -> None:
        """Let go of the port: the DAEMON dies first, then the socket closes.

        THAT ORDER IS THE INVARIANT, not a detail of how this happens to be
        written. A daemon whose holder disappears is ORPHANED, and an orphaned
        daemon's watchdog correctly puts a NEW holder back — that is the row we
        deliberately cover. Close the socket first, or drop the holder without
        stopping its child, and a deliberate release becomes indistinguishable
        from a holder that died: the daemon sees `CSWAP_PIN_HELD_BY` disagree
        with `getppid()`, concludes it was orphaned, and resurrects the thing
        that was just asked to go away.

        A peer shipped exactly that and measured it: nine holders released, all
        nine back on the same ports within 23 seconds, and the ports could
        therefore never be retired at all. Their fix was a lineage-wide
        `releasing` flag the self-heal consults. Ours needs no flag BECAUSE of
        the order — by the time anything could observe a missing holder, the
        observer is already dead.

        The cost of buying it this way is that it does not survive a new call
        site. A flag is checked wherever it is read; an ordering holds only
        where it is written. ANY future path that drops a holder without first
        stopping its daemon re-opens that resurrection silently, and there is
        no guard here that would catch it.
        """
        import signal
        import subprocess

        self._stop = True
        # RELEASE THE STANDBY FIRST, and by SIGHUP. It is detached and outlives
        # us on purpose, so the ordering trick that saves us from the daemon's
        # resurrection (see below) cannot reach it — by the time we are gone it
        # is still there, still holding the descriptor, and will arm the moment
        # `getppid()` moves. SIGHUP, never SIGTERM. Death must keep the
        # address. Only being asked releases it.
        #
        # RE-SENT UNTIL CONFIRMED DEAD — see `_STANDBY_RELEASE_BOUND_S`. A
        # single `send_signal` that `os.kill` accepts is not proof the
        # standby is gone: the signal can arrive before `standby_main` has
        # installed its own handler, and a stop that only fires once leaves
        # exactly that standby behind, still holding the descriptor.
        standby = getattr(self, "_standby", None)
        if standby is not None and getattr(standby, "returncode", 0) is None:
            deadline = time.monotonic() + _STANDBY_RELEASE_BOUND_S
            while True:
                try:
                    standby.send_signal(signal.SIGHUP)
                except (OSError, ValueError):
                    break
                try:
                    standby.wait(timeout=0.2)
                    break  # confirmed gone
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() >= deadline:
                    break
        # KILL THE CHILD WE STARTED, not a number we are holding. `daemon_pid`
        # is only meaningful while the Popen it came from is ours — and a pid
        # is reused freely, so signalling it after the child is gone aims at
        # whatever inherited the number. `Popen.terminate` cannot make that
        # mistake: it signals the process object, and CPython refuses once it
        # has been reaped.
        proc = getattr(self, "_proc", None)
        if proc is not None and getattr(proc, "returncode", 0) is None:
            try:
                proc.terminate()
                proc.wait(timeout=_DRAIN_SECONDS + 2)
            except (OSError, ValueError):
                pass
            except Exception:  # noqa: BLE001 — TimeoutExpired: escalate
                try:
                    proc.kill()
                except (OSError, ValueError):
                    pass
        try:
            self._srv.close()
        except OSError:
            pass


def run_service(certdir: Path, account_num: str, email: str,
                port: int | None = None) -> PortHolder:
    """Hold the pin's port and keep a daemon serving on it."""
    holder = PortHolder(certdir, account_num, email, port=port)
    holder.start()
    return holder


def _arm_parent_death_signal() -> None:
    """Ask the kernel to TERM us when our parent dies. Linux only; never raises.

    A HOLDER IS DELIBERATELY HARD TO KILL — its whole job is to put the daemon
    back, so it survives the daemon dying and keeps the port bound across the
    gap. That same property makes it an immortal orphan when the process that
    STARTED it dies without cleaning up: a SIGKILL runs no ``finally``, so
    nothing tells the holder to go. It reparents to init and keeps the port,
    the memory and the pipes forever, and nothing collects it afterwards
    because the only name it answers to is a pid that no longer exists.

    Measured here before this existed: launcher SIGKILLed, holder and daemon
    still alive at t+2s, t+5s, t+12s and t+20s, holder at ppid=1. A peer
    component on the same design accumulated 151 such processes over hours,
    9.17 GiB resident.

    ``PR_SET_PDEATHSIG`` is the primitive for exactly this — the kernel
    signals us however the parent dies, with no polling and no cooperation
    from the parent. A ppid==1 poll is the portable alternative and is worse
    on both counts: it costs a timer forever and it cannot fire during the
    window before the poll comes round.

    NOT A REPLACEMENT FOR THE REAPER. This is Linux-only (macOS has no
    equivalent, and two of the three machines this runs on are Macs), so
    ``tests/conftest.py``'s ``_reap_pin_processes`` stays the portable floor.

    THE SIGNAL IS TERM, NOT KILL, because the holder must still run its own
    teardown: it drains its daemon and releases the port. A KILL here would
    trade an orphaned holder for an orphaned daemon.

    NEVER RAISES AND ANSWERS NOTHING. A holder that cannot arm this is still a
    working holder, so there is no caller for whom the outcome changes
    anything: the `getppid()` check below covers the race this cannot, and the
    reaper covers the platforms it does not reach.
    """
    if sys.platform != "linux":
        return
    try:
        import ctypes
        import signal

        # 1 == PR_SET_PDEATHSIG. Hardcoded rather than read from a header
        # because ctypes gives us no access to one; the value is ABI-stable
        # (include/uapi/linux/prctl.h) and has never changed.
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(
            1, int(signal.SIGTERM), 0, 0, 0
        )
    except Exception:  # noqa: BLE001 — no libc, no prctl, wrong ABI: not fatal
        pass


def _port_returns_bytes(port: int, timeout: float | None = None) -> bool:
    """Did ANYTHING write a byte back? Not "is it healthy", not "what is it".

    NOT `_port_answers`, WHICH ALREADY EXISTS AND ASKS A DIFFERENT QUESTION.
    That one returns True on a successful CONNECT, which is the right test for
    "would a session be refused" on the teardown path it serves. It is the
    wrong test here, and catastrophically so: this process is itself holding
    the listening descriptor, so a connect always succeeds and the answer is
    always True. Shipped that way by accident — a second def of the same name,
    silently overwritten by the later one — and the standby then armed only
    after 34s by a path nobody designed. The unit tests could not see it
    because `_standby_tick` takes `answered` as a parameter and was never
    handed the real probe. Only the end-to-end run found it.

    The two questions are one word apart in English and opposite in effect, so
    they get names that cannot be mistaken for each other.

    ANY BYTE COUNTS AND THE STATUS IS IGNORED. A live daemon answers 407 to an
    unauthenticated request and a carrying peer relay answers 503 on purpose;
    both mean "somebody is behind this socket", which is the only question
    here. Parsing would make those two disagree and would need a credential.

    REFUSED AND ACCEPTED-THEN-SILENT BOTH READ FALSE, but only the second is
    subtle: this process is holding the LISTENING descriptor, so a connect to
    our own port completes from the backlog even with nobody accepting. That is
    exactly the state a descriptor scan cannot see — holder, daemon and standby
    all read as LISTEN — and it is why the probe asks for an ANSWER instead of
    asking the kernel who is bound.
    """
    # Resolved here, not as a default: this function is defined above the
    # constants block, and a default argument is evaluated at def time.
    timeout = _STANDBY_PROBE_TIMEOUT_S if timeout is None else timeout
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n"
                      b"Connection: close\r\n\r\n")
            s.settimeout(timeout)
            return bool(s.recv(1))
    except OSError:
        return False


def standby_main(account_num: str, email: str, certdir: Path) -> None:
    """Entry point for the detached standby (``-m cswap_pin.proxy --standby``).

    Holds the listening descriptor and does nothing with it until the holder
    AND its daemon are both gone, then puts a holder back on that same socket.
    It never serves a request itself — see `PortHolder._spawn_standby` for why
    that is available to us and was not to the peer that needed a relay.

    COSTS NOTHING WHILE THE HOLDER IS ALIVE. The ppid half of the predicate is
    checked first and short-circuits, so the steady state is one integer
    comparison every 250ms and no connections at all.
    """
    import signal

    srv = _handed_down_listener()
    if srv is None:
        # Nothing was handed to us. Refusing beats holding a descriptor we
        # cannot prove is the one the sessions are wired to.
        _log_lifecycle("standby got no listening descriptor — exiting")
        return
    born_of = int(os.environ.get(_STANDBY_FROM_ENV) or 0)
    port = srv.getsockname()[1]

    # THE SIGNAL TABLE IS THE CONTRACT — see `PortHolder.stop`. Only being ASKED
    # releases the address; every other way of dying keeps it.
    released = False

    def _release(*_a):
        nonlocal released
        released = True

    signal.signal(signal.SIGHUP, _release)
    # IGNORE, do not merely lack a handler. A supervisor stopping the machine,
    # or a stray `pkill -f cswap_pin`, sends TERM — and TERM is precisely when
    # the sessions still need the address.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    _log_lifecycle(
        f"standby holding port {port} for holder {born_of} — accepting nothing"
    )
    silent = 0
    wait = _STANDBY_POLL_S
    while not released:
        time.sleep(wait)
        if released:
            break
        # THE TICK CHOOSES ITS OWN NEXT INTERVAL, because only it knows which
        # state we are in — and the three states want different rates. See
        # `_standby_tick`.
        #
        # THE RECORDED DAEMON FIRST, and it costs nothing. Every window spent
        # proving nobody serves is a window in which nobody serves — the peer's
        # point, and it is right — so the cheapest evidence goes first. A live
        # recorded daemon settles it with a signal-0 and no probe at all.
        silent, arm, wait = _standby_tick(
            born_of, silent,
            lambda: (_recorded_daemon_alive(certdir)
                     or _port_returns_bytes(port)),
        )
        if arm:
            break
    if released:
        _log_lifecycle(f"standby released port {port} on request")
        try:
            srv.close()
        except OSError:
            pass
        return

    # EXACTLY ONE STANDBY MAY ARM, and a lock is the only thing that can say
    # so. Standbys accumulate legitimately: every holder that is KILLED rather
    # than released leaves its own behind, by design — that is the row this
    # covers. They all then watch the same port, so a single silent window arms
    # ALL of them and each becomes a holder.
    #
    # MEASURED ON THE LINUX HOST, not reasoned about: three armed within a minute of
    # each other and produced four acceptors on 36301, which is precisely the
    # property the whole design exists to keep. The silent window that set them
    # off was an ordinary daemon handover. Non-blocking: a loser has nothing to
    # wait for. The winner is putting a daemon back on the very socket the
    # loser is holding, so the loser's job is finished either way.
    #
    # THE PIN MUST STILL NAME THIS PORT. See `_standby_port_still_wanted`: a
    # standby left on a superseded socket hears silence forever, and reviving
    # it builds a lineage nothing can reach.
    if not _standby_port_still_wanted(certdir, port):
        _log_lifecycle(
            f"port {port} is no longer the pin's — letting it go rather than "
            f"rebuilding a lineage nothing is wired to"
        )
        try:
            srv.close()
        except OSError:
            pass
        return
    lock_fd = _claim_arm(certdir)
    if lock_fd is None:
        _log_lifecycle(
            f"another standby is already arming port {port} — exiting rather "
            f"than adding a second acceptor to the socket it is about to serve"
        )
        try:
            srv.close()
        except OSError:
            pass
        return
    _log_lifecycle(
        f"holder {born_of} is gone and port {port} answered nothing "
        f"{_STANDBY_SILENT_STREAK}x — putting a daemon back on the descriptor "
        f"this process has held all along"
    )
    # GIVE THE SIGNALS BACK BEFORE BECOMING A HOLDER. The SIG_IGN above is
    # right for a standby — TERM is when the sessions most need the address —
    # and WRONG the moment this process starts serving, because a handler
    # installed once outlives the reason for it. An armed standby kept ignoring
    # TERM and INT, so it could not be stopped by any ordinary means: `cswap`
    # could not retire it, a supervisor could not stop it, and only SIGKILL
    # reached it.
    #
    # MEASURED ON THE LINUX HOST, and it is why that box needed a manual cleanup: three
    # armed standbys had each become a holder on port 36301 — four acceptors on
    # one socket, the single property this whole design exists to keep — and
    # SIGTERM to all three did nothing at all.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    # BECOME THE HOLDER on the socket we are already holding. Everything below
    # this line is the ordinary supervisor: respawn, backoff, self-heal — and
    # it places a standby of its own, so the lineage stays covered.
    holder = PortHolder(certdir, account_num, email, sock=srv)
    holder.start()
    if holder._thread is not None:
        holder._thread.join()


def holder_main(account_num: str, email: str, certdir: Path,
                port: int | None = None) -> None:
    """Entry point for the detached holder (``-m cswap_pin.proxy --hold-port``)."""
    # ONLY WHEN ASKED — see `_EXIT_WITH_PARENT_ENV`. Outliving the process that
    # started it is the holder's whole job, so tying its life to that process
    # is a test harness's need, never production's.
    #
    # BEFORE THE PORT IS TAKEN, when it is asked for. Arming after
    # `run_service` would leave the window where the holder already owns the
    # port unprotected, which is the one window where an orphan actually costs
    # something.
    #
    # A RACE THE KERNEL CANNOT CLOSE FOR US: if the parent died between our
    # fork and this call, the signal was already delivered to a process that
    # had not armed it, so it never arrives. Check explicitly rather than trust
    # the arming alone.
    if os.environ.get(_EXIT_WITH_PARENT_ENV) == "1":
        _arm_parent_death_signal()
        if os.getppid() == 1:
            _log_lifecycle("launcher already gone before the holder armed — exiting")
            return
    try:
        holder = run_service(Path(certdir), account_num, email, port=port)
    except OSError as exc:
        # SOMEBODY ELSE IS ALREADY ON OUR PORT, which is usually a healthy pin
        # — a concurrent launch won the election, or the predecessor has not
        # finished draining after our bind budget.
        #
        # THIS USED TO SERVE AS A PLAIN DAEMON, on the premise that it would
        # "reclaim the port when it frees". A daemon cannot move its port: the
        # address is fixed at bind, and every session's HTTPS_PROXY was fixed
        # at exec. So the fallback reclaimed nothing and served on an EPHEMERAL
        # port nothing is wired to. The bind fails for two opposite reasons and
        # NEITHER wants a second daemon: if a healthy pin holds the port we are
        # redundant, and if the port is held by something not serving, another
        # port does not help. So exit.
        #
        # THE SECOND REASON IS NOW RECOVERED FROM RATHER THAN ACCEPTED, one
        # level down. `PortHolder.__init__` asks, when its bind budget runs
        # out, whether the port is bound-but-not-accepting — the signature of a
        # standby left by a holder that was killed — and SIGHUPs it before
        # giving up. Reaching here now means the port really is somebody
        # else's. Every caller already handles "no successor came up", and the
        # incumbent is by definition still there.
        _log_lifecycle(
            f"holder could not take the port ({exc}) — exiting rather than "
            f"serving on an address nothing is wired to"
        )
        return
    _log_lifecycle(f"holding port {holder.port} for account {account_num}")

    def _cleanup(reason: str = "signal") -> None:
        _log_lifecycle(f"holder stopping ({reason})")
        holder.stop()

    _install_signal_teardown(_cleanup)
    # The supervisor thread IS the service; this process has nothing else to
    # do. Joining it means the holder exits exactly when it stops supervising
    # — a clean daemon exit (idle teardown) or a self-heal switched off.
    if holder._thread is not None:
        holder._thread.join()


def _spawn_daemon(
    account_num: str, email: str, certdir: Path, listen_fd: int | None = None
) -> int | None:
    """Start the proxy daemon detached; wait for its state file. None on failure.

    Creates the refcount FIFO up front so a session can attach a holder the
    instant the daemon comes up (no gap where the daemon sees zero holders and
    tears itself down).

    ``listen_fd`` is a still-LISTENING socket the caller has stopped accepting
    on, passed to the successor so the port is never unbound. Handing the port
    NUMBER over instead leaves a hole nothing in this package can close: the
    successor is a fresh interpreter (~50ms to reach ``bind()``) and a
    listening port cannot be co-bound, with SO_REUSEADDR or SO_REUSEPORT.
    """
    import subprocess
    import sys
    import time

    certdir = Path(certdir)
    # RESOLVED BEFORE ANYTHING IS REWRITTEN. Everything below mutates the very
    # files `wanted_port` reads — proxy.json is marked handover, proxy.port is
    # unlinked — so asking afterwards gives a different, wrong answer, and a
    # holder started with it binds an address no live session is dialling.
    want_port = wanted_port(certdir)
    if not (isinstance(want_port, int) and want_port > 0):
        want_port = 0
    # Hand the outgoing port to the new daemon before clearing the state it
    # lives in: it rebinds that port so live sessions — whose HTTPS_PROXY was
    # fixed at exec — keep reaching the proxy instead of a dead address (and
    # a session on a dead address leaves WITHOUT the pin, silently).
    prev = read_daemon_state(certdir)
    if isinstance(prev, dict) and isinstance(prev.get("port"), int):
        _write_port_hint(certdir, prev["port"])
    # MARKED, NOT DELETED, and this is the whole arbitration. Deleting it made
    # the successor's own liveness poll safe (it can no longer match the
    # predecessor's entry) at the cost of blinding every OTHER reader for the
    # ~10s the spawn takes: with no record, `_release_daemon_state` reports "not
    # superseded" and a teardown arriving from the refcount watcher or from
    # SIGTERM unwires a successor that comes up perfectly healthy and never
    # rewires. The mark answers both: the record still names who is departing,
    # and every reader that asks "is anything serving here" is told no.
    if isinstance(prev, dict) and isinstance(prev.get("pid"), int):
        try:
            write_daemon_state(
                certdir, prev.get("port") or 0, prev["pid"],
                prev.get("fingerprint") or "", handover=True,
            )
        except OSError:
            pass
    else:
        try:
            (certdir / _STATE_FILE).unlink()
        except FileNotFoundError:
            pass
    try:
        (certdir / "proxy.port").unlink()
    except FileNotFoundError:
        pass
    fifo = refcount_fifo_path(certdir)
    if not fifo.exists():
        try:
            os.mkfifo(fifo)
        except FileExistsError:
            pass
    # stderr goes to a file, not DEVNULL: the daemon is detached and has no
    # terminal, so _warn_unpinnable would otherwise write into nothing and
    # every fail-open would stay silent — the exact outcome that warning
    # exists to prevent. stdout stays discarded; the daemon prints nothing
    # there and a log that also carries chatter buries the one line worth
    # reading.
    log = _open_daemon_log(certdir)
    # SCRUB, THEN SET. A daemon that was itself handed a socket still carries
    # these variables in its own environment, and a spawn that passes no fd
    # would hand that stale pair to the child verbatim — naming a descriptor
    # the child does not have. The ppid guard already refuses it, but an
    # environment that lies is one pid-reuse away from being believed, and
    # nothing needs it to survive the process it was addressed to.
    env = {k: v for k, v in os.environ.items()
           if k not in (_HANDDOWN_FD_ENV, _HANDDOWN_FROM_ENV)}
    pass_fds: tuple[int, ...] = ()
    if listen_fd is not None:
        # NAME THE NUMBER. The origin pid is the guard: these variables reach
        # every descendant but the fd does not, so a grandchild without it must
        # not adopt whatever that number became.
        env[_HANDDOWN_FD_ENV] = str(listen_fd)
        env[_HANDDOWN_FROM_ENV] = str(os.getpid())
        pass_fds = (listen_fd,)
    # EVERY SPAWN LANDS UNDER A HOLDER, cold start and handover alike. The cold
    # start needs one because nothing owns the address yet: the daemon would
    # bind it itself and a `kill -9` would take the port down with it,
    # stranding every session whose HTTPS_PROXY was fixed at exec.
    #
    # THE HANDOVER NEEDS ONE FOR A DIFFERENT REASON, learned by doing it twice
    # in one day on live machines. An old daemon notices its code changed and
    # hands its listening socket to a successor — using the handover ITS OWN
    # VERSION implements. If that successor runs unheld, the port has left the
    # holder for good — measured on two hosts the same day, each moving to a
    # fresh port and `.claude.json` following it there.
    #
    # A README saying
    # "upgrade carefully" was the first answer and it is not one: a deploy is
    # not a procedure someone follows, it is whatever the running code does.
    # The holder here ADOPTS the socket it was handed rather than binding a
    # fresh one, so it cannot lose the race that made the cold-start holder
    # fall back — there is nothing to race for.
    argv = [sys.executable, "-m", _DAEMON_MODULE, _HOLDER_MODULE_ARG,
            str(want_port if want_port else 0), account_num, email,
            str(certdir)]
    try:
        try:
            subprocess.Popen(
                argv,
                env=env,
                pass_fds=pass_fds,
                # GIVE THE CHILD ITS OWN STDIN. Without this it inherits the
                # parent's fd 0, and a daemon spawning its successor is not a
                # CLI: whatever fd 0 became in a long-lived detached process is
                # what the child gets. A child whose fd 0 is unusable dies in
                # interpreter startup, before any of its own code runs, so it
                # cannot report why — the failure is a bare init_sys_streams
                # with no Python frame and the handover produces no successor.
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log,
                start_new_session=True,
            )
        finally:
            # The child holds its own dup of the fd; ours would otherwise leak
            # on every spawn.
            if hasattr(log, "close"):
                log.close()
        # NAMED so a test can shorten it. It was inlined, and a test that
        # stubs Popen (no child ever appears) then paid the full 10s — 10% of
        # the whole suite in one case that is only asserting what the spawn
        # PASSES, not that it works.
        for _ in range(int(_SPAWN_WAIT_S * 10)):
            port = _read_alive_port(certdir)
            if port is not None:
                # New daemon is serving and recorded in proxy.json — sweep any
                # orphan pin daemons for this certdir that aren't the keeper, so
                # a recycle that left the old one alive never accumulates.
                st = read_daemon_state(certdir)
                keep = int(st["pid"]) if st else -1
                _sweep_orphan_daemons(certdir, keep_pid=keep)
                return port
            time.sleep(0.1)
    except BaseException:
        # A spawn that RAISES (fork() EAGAIN under a post-deploy herd) leaves
        # no successor, so the mark must not outlive it — see below.
        _clear_handover_mark(certdir)
        raise
    # NO SUCCESSOR CAME. The mark says "one is coming", and leaving it would
    # tell the caller's own teardown it has been superseded — so the wiring
    # would be kept pointing at a port nobody serves, which is the outage the
    # unwire exists to prevent.
    _clear_handover_mark(certdir)
    return None


def _clear_handover_mark(certdir: Path) -> bool:
    """Drop a marked record once the spawn it describes has failed.

    The mark means "a successor is coming"; leaving it after nothing came would
    make the caller's own teardown read "superseded" and keep the wiring
    pointing at a port nobody serves. The record described a daemon that has
    already stopped, so there is nothing left to preserve — the port to reclaim
    lives in the hint (see ``read_port_hint``).

    RETURNS WHETHER THE MARK IS GONE. The unlink swallowed every OSError and
    returned nothing either way, so a record that could NOT be removed — a
    read-only store, a lost mount, an immutable file — was indistinguishable
    from one that was, and the caller went on to a teardown that read
    "superseded" and left the wiring in place. Saying so does not make the
    unlink succeed; it stops the caller believing a cleanup that did not
    happen, and puts the reason in the one log a later reader has.

    True when there is no mark to clear: the postcondition this reports is
    "no stale mark remains", not "a file was deleted".
    """
    st = read_daemon_state(certdir)
    if not (st and st.get("handover")):
        return True
    try:
        (Path(certdir) / _STATE_FILE).unlink()
        return True
    except OSError as exc:
        _log_lifecycle(
            f"could not clear the handover mark ({exc}) — a teardown will "
            f"read this as superseded and leave the wiring in place"
        )
        return False


def _superseded_on_the_port(certdir: Path) -> bool:
    """Whether ``proxy.json`` names a LIVE daemon that is not us.

    "Is anyone waiting for me to be gone", which is the question the held
    drain ceiling means to ask. `this_process_is_draining()` answers the
    narrower "did I hand over myself", and the two part company for a daemon
    superseded from outside: a holder that takes the replace signal spawns the
    successor without the predecessor announcing anything.
    """
    try:
        st = read_daemon_state(certdir)
        pid = int(st["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return pid != os.getpid() and _pid_alive(pid)


def _release_daemon_state(certdir: Path) -> bool:
    """Drop ``proxy.json`` if it still names us. True when it names SOMEONE
    ELSE — i.e. we were superseded and must touch nothing further.

    A successor publishes its own state (and rewires the config to its port)
    before sweeping the orphans it replaces, so a departing daemon's cleanup
    can land on the record of the daemon that is now serving. Deleting that
    makes a LIVE daemon invisible: the next launch reads no state and spawns
    another one on top of it.

    A HANDOVER IN FLIGHT COUNTS AS SUPERSEDED. `_spawn_daemon` marks the record
    before it forks and the successor replaces it once it is serving, so for
    the length of that spawn the record still names US and yet the wiring
    belongs to a daemon that is about to own it. Reading only the pid there
    unwired a healthy successor, and nothing rewires afterwards:
    `_repair_wiring_if_ours` declines when nothing is wired at all. The mark is
    what the three lifecycle paths — this teardown's two callers and the
    watchdog that set it — share, because none of them can see the others'
    locals.

    A REFUSED delete (permission denied, a read-only mount) is not the same
    outcome as an ABSENT file, and both used to return the same `False` a
    successful release does. A refused delete leaves the file naming OUR
    (about-to-exit) pid, and the next daemon start reads it to decide which
    port to reclaim — believing a daemon it can never reach. RE-RAISE, so
    the caller (the departing daemon's teardown) is not told this succeeded.
    """
    try:
        st = read_daemon_state(certdir)
        if st and st.get("handover"):
            return True
        if st and int(st["pid"]) != os.getpid():
            return True
    except (ValueError, KeyError, TypeError):
        pass  # state file is garbage, not ours to protect — fall through
    try:
        (Path(certdir) / _STATE_FILE).unlink()
    except FileNotFoundError:
        pass  # already gone: nothing to release
    return False


_CODE_WATCH_INTERVAL_S = 30.0
# Consecutive failed handovers before the watchdog stops trying. A ceiling on
# NEVER-SUCCEEDING, not on total recycles: a daemon that hands over cleanly and
# later goes stale again starts from zero.
_HANDOVER_ATTEMPTS = 5


def _watch_own_code(
    server,
    account_num: str,
    email: str,
    certdir: Path,
    done,
    teardown,
    interval: float = _CODE_WATCH_INTERVAL_S,
    _own_fingerprint: str | None = None,
) -> None:
    """Hand over to a successor when this module's code is replaced on disk.

    WHY THIS LIVES IN THE DAEMON. Every other entry point reacts to a LAUNCH:
    `ensure_proxy` recycles a stale daemon, but only when a new session starts.
    A machine whose sessions are all already running never launches, so an
    upgrade never reaches the process. Measured: a daemon served
    for 22 hours on code that had been replaced 19 hours earlier, across six
    releases, dialling direct instead of chaining — every claude.ai handshake
    got the corporate MITM leaf and OAuth login was broken the whole time.

    `heal` already detects exactly this and recycles correctly; it was
    evaluated against that live daemon and every one of its gates passed. It
    never ran because its only caller is a human typing `cswap pin --heal`.
    The periodic caller used to be a status-line hook, and removing that was
    RIGHT: a status line is one machine's personal config, so recovery living
    there means every user without that hook has no recovery at all. This is
    the replacement, and it needs no host-side hook of any kind — the daemon
    is the one process guaranteed to be running when its own code goes stale.

    `daemon_fingerprint` hashes this module's mtime, so re-calling it IS the
    detector; nothing new is needed to sense staleness.

    THE ORDER IS LOAD-BEARING:

      1. stop and drain — the port must be free before the successor binds it,
         and draining is what keeps a recycle from cutting live requests.
      2. `_spawn_daemon` — it already hands the outgoing port to the successor
         and blocks until that successor is serving and has published its own
         state, so live sessions (whose HTTPS_PROXY was fixed at exec) keep
         reaching the same address.
      3. on success, DO NOT unwire. The successor owns the wiring now; tearing
         it down would strip the config it just wrote and send every new
         session to no proxy at all.
      4. on failure, unwire. We have already stopped serving, so leaving the
         config naming this port is the ConnectionRefused outage `_teardown`
         exists to prevent — reached by the recycle itself.

    NOT gated on the daemon being idle: a busy daemon is exactly the one that
    must upgrade, and the drain in step 1 is what protects its in-flight work.
    """
    # `_OWN_FINGERPRINT`, NOT a fresh read — see its definition. Taking the
    # baseline here would sample the disk at THREAD-START, which is late enough
    # for a deploy to land in between and blind this watchdog permanently.
    own = _own_fingerprint if _own_fingerprint is not None else _OWN_FINGERPRINT
    attempts = 0
    # ASKED ONCE, NOT EVERY TICK. A holder is expected to die on the HUP, but
    # nothing here can insist on it: the signal may not land, the process may
    # take a moment to go, and the mismatch that triggered the ask stays true
    # for as long as it does. Unguarded, that is a signal every interval for the
    # life of the daemon — the shape this file already records for the
    # unpinnable recycle: 5 ticks, 5 kills, no convergence, live sessions paying
    # for each one. One shot leaves the machine exactly as it was if it fails,
    # which is the safer of the two ways to be wrong.
    stand_down_asked = False
    # Waiting on `done` rather than sleeping, so a normal teardown ends this
    # thread at once instead of after a full interval.
    while not done.wait(interval):
        # ONE EXIT, TAKEN ON EVERY PATH. 0.1.27 had three exits and one of them
        # took neither: `_spawn_daemon` RAISING (fork() EAGAIN under a post-
        # deploy herd) landed in the guard below, which logged and returned
        # with the server already stopped, nothing unwired, and `done` never
        # set — so the process stayed alive serving nothing while
        # `.claude.json` named its port and `daemon_main` blocked on
        # `done.wait()` forever. `handed_over` is the whole arbitration: True
        # means a successor owns the wiring and we must NOT unwire; False after
        # we have stopped means nobody is serving and we MUST. The `finally`
        # applies that once, rather than each branch remembering to.
        stopped = handed_over = False
        try:
            # LEARN THE HOP BEHIND OURS WHILE IT IS STILL ANSWERING. This is
            # the only timer the daemon has, and the question is only
            # answerable before the hop dies — see `learn_next_hop`. Cheap
            # (loopback, 1s budget, writes only on a change) and never fatal:
            # the `except` below is a watchdog's, so a probe that raises must
            # not take the code watch down with it.
            try:
                server.learn_next_hop()
            except (AttributeError, OSError):
                pass  # a stand-in server in tests, or a hop that went away
            # THE OFF SWITCH STOPS EVERY AUTOMATIC REPLACEMENT, not just the
            # holder's. `CSWAP_PIN_SELF_HEAL=off` is documented on PortHolder
            # as "a respawner fighting a human who is debugging the daemon is
            # worse than a dead port", and the holder honours it — but this
            # watchdog was added later and never asked, so with the switch OFF
            # a debugging session still lost its daemon the moment anything
            # touched the file. That is the one thing the switch exists to
            # prevent, reached through the other path.
            #
            # LEARNING THE NEXT HOP STAYS ON, deliberately: it records what a
            # hop reports and replaces nothing, so it cannot fight anybody.
            # `heal` and `ensure_proxy` stay on too — those are a human or a
            # launch ASKING for a repair, and a switch meaning "do not act on
            # your own" must not refuse a direct instruction.
            if os.environ.get(_SELF_HEAL_ENV, "").lower() in ("off", "0", "no"):
                continue
            # ORPHANED IS ALSO A REASON TO RECYCLE, not just stale code. A
            # holder that dies without taking its daemon down leaves the port
            # bound — the daemon already holds the socket — but with NOTHING
            # above it. `_orphaned` rather than `not held_by_a_holder()`: a
            # daemon that was never held (a bare `daemon_main`, a test) has no
            # holder to lose and must not recycle itself forever.
            orphaned = _orphaned_from_its_holder()
            # THE THIRD REASON TO REPLACE OURSELVES, and the only one the
            # daemon can act on entirely alone. A daemon that cannot mint the
            # pinned token serves every request UNPINNED and fails open, so
            # nothing downstream complains -- meanwhile every Remote Control
            # bridge minted is owned by the wrong account permanently. Marking
            # the record only helps a LAUNCH that may be hours away, and asking
            # a human to run `cswap pin <n>` is not a repair, it is a chore.
            #
            # This is the same gapless sequence the code-changed branch uses:
            # the holder puts a successor on the socket and it is already
            # serving before we drain, so a repair costs no request.
            #
            # `is False`, never falsiness -- see `_can_mint`. And the interval
            # guard is what stops a machine that genuinely cannot read from
            # recycling on every tick.
            _mint_provider = getattr(server, "_pin_token_provider", None)
            # A STALLED LOCK IS NOT A VERDICT, in either direction. `_can_mint`
            # already answers None for it (never False, so `blind` below stays
            # False and `replace_for_blind` never fires on a stall -- the
            # successor would only inherit the same stuck credential store).
            # But a bare `not blind` also reads None as "can mint", which
            # would clear a genuine `unpinnable` mark on a tick that asked
            # nothing. Both wrong answers share one cause: treat busy as its
            # own case, not as either verdict.
            _busy_s = _mint_lock_busy(_mint_provider) if _mint_provider else None
            blind = _can_mint(_mint_provider) is False
            now = time.time()
            if _busy_s is not None:
                _note_mint_busy(_busy_s)
            elif not blind:
                clear_blind_recycle(certdir)
                # AND TAKE THE MARK BACK. Recovery is not only "stop trying to
                # recycle" -- the record has to stop saying the pin is dead, or
                # the badge lies and every launch refuses a daemon that works.
                if clear_daemon_unpinnable(certdir):
                    # Warn again if it goes bad later: the flag on the instance
                    # is once-per-process, and without this reset a second
                    # episode is silent.
                    setattr(server, "_warned_unpinnable", False)
                    _log_lifecycle(
                        "the pinned token can be minted again — cleared the "
                        "unpinnable mark"
                    )
            replace_for_blind = blind and blind_recycle_due(certdir, now)
            if (daemon_fingerprint() == own and not orphaned
                    and not replace_for_blind):
                # OUR CODE IS CURRENT; THE HOLDER'S NEED NOT BE. This branch is
                # where a machine sat after every deploy: the daemon re-execs
                # and matches, so the loop went back to sleep, and the holder
                # above it kept running the previous release forever. Nothing
                # else looks — see `_retire_stale_holder` for why no other lever
                # reaches it.
                #
                # ASK, THEN WAIT A TICK — do not fall through. Reparenting is
                # not instantaneous and `_HELD_BY_ENV` still names the pid we
                # just signalled, so on THIS pass `held_by_a_holder()` is still
                # true and the branch below would put the replace-ask to a
                # holder that is on its way out — or, failing that, exit 75 to
                # be restarted by something that no longer exists.
                #
                # The next tick sees the reparenting, `_orphaned_from_its_holder`
                # turns true, and the orphan branch below hands the socket down
                # to a successor that lands under a fresh holder. That is the
                # one path here that keeps the port bound throughout, and it is
                # already the tested one.
                if stand_down_asked or not _retire_stale_holder(own):
                    continue
                stand_down_asked = True
                _log_lifecycle(
                    "the holder above this daemon is running code we no longer "
                    "ship — asked it to stand down so a current one replaces it"
                )
                continue
            if replace_for_blind:
                note_blind_recycle(certdir, now)
                _log_lifecycle(
                    "cannot mint the pinned token — replacing ourselves so a "
                    "successor can, while this one keeps serving"
                )
            if orphaned:
                _log_lifecycle(
                    "the holder above this daemon is gone — handing over so "
                    "the successor lands under one"
                )
            # UNDER A HOLDER THERE IS NOTHING TO HAND OVER. The holder already
            # owns this socket and will put the successor on it, so the whole
            # release-spawn-drain dance below is not merely unnecessary — it
            # takes the port OUT of the holder, and the successor is then one
            # failed bind away from stranding every session.
            if held_by_a_holder():
                # ASK WHILE STILL ACCEPTING, then leave. The socket is the
                # holder's and cannot be handed down from here — that is what
                # `release_listener(hand_down=True)` refuses, and rightly. But
                # the holder can put a second daemon on it whenever it likes
                # (`_spawn` passes its own listening fd), so the only thing
                # ever missing was a way to ASK without dying first.
                #
                # ORDER IS THE WHOLE FIX: signal, then stop accepting, then
                # drain. The successor is already on the socket before we stop,
                # so the drain overlaps a serving process instead of replacing
                # one — which is also why it gets the FULL budget here.
                #
                # ANNOUNCED BEFORE THE ASK, NOT WHEN THE DRAIN STARTS. The
                # holder spawns our successor as soon as it takes this signal,
                # and the successor publishes `proxy.json` the instant it
                # serves — so from that publish until we reach `await_inflight`
                # a concurrent `ensure_proxy` sees us as "a daemon that is not
                # keep_pid" with no marker written. That is the 08:21:19Z race
                # one frame higher, and it is not narrow: `_ASK_SETTLE_SECONDS`
                # sits inside the window on purpose.
                #
                # THE RELEASER IS KEPT, and the comment here used to say it was
                # not needed because "every path out of this branch is
                # `os._exit`". One is not: the holder-did-not-survive branch
                # below RETURNS and this daemon goes back to serving, leaving
                # the depth raised for the life of the process. Harmless while
                # nothing read it; `teardown_drain_budget(handed_over=...)` now
                # does, so a daemon that never handed over would take the
                # uncapped ceiling on every later teardown and put `Connection:
                # close` on every response it ever writes again.
                _asked_done = announce_draining(certdir, server=server)
                holder = _holder_pid()
                if holder:
                    try:
                        os.kill(holder, _REPLACE_ME_SIGNAL)
                    except OSError:
                        holder = None
                if holder:
                    # THE ASK IS NOT THE OUTCOME. `os.kill` returning says only
                    # that the pid existed when we called it — nothing about a
                    # successor. So verify the holder SURVIVED being asked: an
                    # advertisement is written once at spawn and can be stale
                    # by now, but whether that process is still there cannot
                    # be. Serving stale code beats serving nothing, so we keep
                    # the port and say so.
                    time.sleep(_ASK_SETTLE_SECONDS)
                    if not _pid_alive(holder):
                        _log_lifecycle(
                            "asked the holder to replace us and it did not "
                            "survive the ask — keeping the port rather than "
                            "releasing it to nobody"
                        )
                        # WE ARE NOT DRAINING AFTER ALL. This is the one exit
                        # from this branch that keeps serving, so it is the one
                        # that has to hand the announcement back.
                        _asked_done()
                        return
                    _log_lifecycle(
                        "code on disk changed — asked the holder to replace "
                        "us while we keep serving"
                    )
                    server.release_listener()
                    # THE SUCCESSOR IS ALREADY SERVING, so this wait is free —
                    # see `_HANDOVER_DRAIN_SECONDS`. Thirty seconds here cut 16
                    # mid-response replies on this box.
                    server.await_inflight(_HANDOVER_DRAIN_SECONDS)
                    # 0, NOT 75: the successor is already serving on this
                    # socket. 75 would make the holder spawn a SECOND one.
                    os._exit(0)
                # FALL BACK TO THE OLD SHAPE, never to nothing. No holder pid,
                # or a holder that will not take the signal, means nobody has
                # started a successor — so we must still exit 75 and let the
                # supervisor do it the slow way. A gap is worse than the old
                # behaviour only if it is longer; no daemon at all is worse
                # than either.
                _log_lifecycle(
                    "code on disk changed — exiting for the holder to replace"
                )
                server.release_listener()
                server.await_inflight(_HELD_DRAIN_SECONDS)
                os._exit(_RESTART_ME_CODE)
            # NAME THE REASON THAT APPLIES.
            if not orphaned:
                _log_lifecycle(
                    "code on disk changed — handing over to a successor"
                )
            # SERIALIZED, like every other spawn caller (`heal`,
            # `ensure_proxy`). Without it, a deploy replaces proxy.py and every
            # daemon on the box goes stale in the same instant, so their timers
            # fire together and two unserialized spawns leave one successor
            # orphaned — invisible to the sweep, holding a port forever. Taken
            # BEFORE the stop so a loser waits with its server still up rather
            # than dead.
            spawned = None
            with _spawn_lock(certdir):
                # Another daemon may have recycled us while we queued.
                if daemon_fingerprint() == own and not orphaned:
                    continue
                # RELEASE THE PORT, THEN DRAIN — in that order, and with the
                # successor started in between. `stop(drain=N)` closes the
                # listener FIRST and only then waits up to N seconds for in-
                # flight requests, so the port sat unbound for the whole drain
                # and every new connection was refused. Dropping the listener
                # without draining lets the successor bind immediately; the in-
                # flight requests are still ours to finish, so the drain
                # happens after, while the new daemon is already accepting. A
                # supervisor-held port makes both moot — this is what the
                # package does when it owns the socket itself.
                #
                # AND THE SOCKET GOES WITH IT, which is what makes the handover
                # gapless rather than merely short. Passing the listening
                # socket down leaves the port bound the whole time, so arrivals
                # queue in the backlog instead: 0 refused. `release_listener`
                # joins the accept loop first — two processes accepting on one
                # socket split the connections, and the one that has stopped
                # serving drops its share.
                handed_fd = server.release_listener(hand_down=True)
                stopped = True
                # SAME WINDOW, SAME REASON. `_spawn_daemon` blocks up to
                # `_SPAWN_WAIT_S` waiting for the successor to publish, and the
                # publish is what makes us sweepable. Announcing inside
                # `await_inflight` — one line below — is one step too late.
                done_draining = announce_draining(certdir, server=server)
                spawned = _spawn_daemon(
                    account_num, email, certdir, listen_fd=handed_fd
                )
                if spawned is None:
                    # AND WE ARE NOT LEAVING AFTER ALL. The spawn failed, this
                    # daemon keeps serving, and a marker saying "draining" on a
                    # process that is back to accepting would spare a genuine
                    # orphan for the whole TTL. Released only on this path:
                    # every other way out of here ends in `os._exit`.
                    done_draining()
                    _log_lifecycle("successor did not come up")
            # THE LOCK ENDS HERE, AND THE DRAIN HAPPENS OUTSIDE IT.
            #
            # `.spawn.lock` serializes the SPAWN — two unserialized spawns
            # leave one successor orphaned, holding a port forever. The spawn
            # is done. The wait below is this process finishing connections it
            # already owns, and it is UNBOUNDED BY DESIGN: a Remote Control
            # channel lives as long as its session, so "until they end" can be
            # hours. Holding the lock across it froze every future spawn for
            # that whole time.
            #
            # Measured live: a predecessor held this lock for 72 minutes while
            # legitimately serving ONE channel, with the daemon then serving
            # the port queued behind it and `pin --heal` blocked with no output
            # — and `deploy.sh` calls heal synchronously. Nothing was wrong
            # with the drain. The lock was the fault, and the drain being
            # CORRECT is what made it unbounded.
            if spawned is not None:
                # SAY THE LOCK IS GONE, or the fix has no durable witness.
                # Moving the wait out of the lock changes no log line and no
                # ordering, so a handover under the fixed code is byte-identical
                # to one under the code that froze every spawn for the length of
                # a session. The only difference is a lock state — and a watcher
                # sampling /proc/locks on an interval can miss the whole window
                # between one holder leaving and the next arriving. Measured: a
                # 60s poll observed the before and the after and never a free
                # lock. A line in the daemon log is a record, not a sample.
                _log_lifecycle(
                    "spawn lock released — draining outside it, so nothing "
                    "waiting to spawn is blocked by however long this takes")
                # THE PORT NEVER LEFT: the listening socket went down by fd,
                # so arrivals queue in the backlog the whole time this waits.
                server.await_inflight(_HANDOVER_DRAIN_SECONDS)
                _log_lifecycle("successor is serving — leaving the wiring to it")
                # OUR COPY OF THE FD STAYS OPEN, deliberately. This process
                # returns from here into its own exit, and closing a listening
                # descriptor two processes hold is only ever dangerous in the
                # other direction: close it a moment too early and the port is
                # gone. Nothing here accepts on it — `release_listener` joined
                # the accept loop before handing it over.
                handed_over = True
                return
            # TRY AGAIN, BOUNDED. Returning here left the thread dead with the
            # code on disk still new, so the daemon served the stale code
            # forever — the 22-hour outage this watchdog exists to end, reached
            # one failed spawn later instead of by having no watchdog. The
            # machine this is FOR is the one whose sessions never relaunch, so
            # nothing else will ever try. A start failure is QUIETER once the
            # port survives it, which is exactly why it needs a ceiling. The
            # counter is on CONSECUTIVE failures, so a daemon that recycles
            # cleanly years apart still gets its full budget each time — the
            # ceiling is on never-succeeding, not on total tries.
            attempts += 1
            if attempts >= _HANDOVER_ATTEMPTS:
                _log_lifecycle(
                    f"{attempts} handovers failed in a row — staying on the "
                    f"current code, still serving"
                )
                return
            continue
        except Exception as exc:  # noqa: BLE001 — a watchdog must never raise
            # A raise here used to kill the thread silently and put the daemon
            # back in the state this whole release exists to end: correct
            # recycle machinery with nothing driving it.
            _log_lifecycle(f"code watch failed: {exc!r}")
            return
        finally:
            if stopped and not handed_over:
                # KEEP SERVING THE OLD CODE RATHER THAN NOTHING. A recycle that
                # cannot start a successor has no reason to end the pin: this
                # process is intact, it merely stopped listening, and the code
                # it runs is the code that was working a moment ago.
                if _resume_serving(server):
                    _log_lifecycle(
                        "successor did not come up — resumed serving the old "
                        "code, still on the recorded port"
                    )
                    # Clearing the flag is what keeps `done` unset below; a
                    # `return` here would do the same but swallows any
                    # in-flight exception, and Python 3.14 warns about it.
                    stopped = False
                else:
                    # Could not get the listener back either. Now the config
                    # really does name a port nothing answers, so fall back.
                    _log_lifecycle("no successor and could not resume — unwiring")
                    try:
                        teardown("failed handover")
                    except Exception as exc:  # noqa: BLE001
                        _log_lifecycle(
                            f"COULD NOT unwire after a failed handover: {exc!r}"
                        )
            if stopped:
                # Either way this daemon is finished. `done` releases
                # `daemon_main`'s `done.wait()`; leaving it unset is what made
                # the raise path a permanent zombie.
                done.set()


# CONNECTIONS THE ADOPT PROBE HAD TO ACCEPT TO PROVE THE SOCKET WAS LISTENING.
# Darwin cannot answer `SO_ACCEPTCONN`, so the only portable proof is an
# accept() — and an accept that returns is a real client, mid-request. Closing
# it loses that request, so it is parked here and the serving loop takes it
# before it asks the kernel for another. Emptied by whoever serves it; a
# process that adopts and never serves closes these itself.
_ADOPTED_BACKLOG: "list[socket.socket]" = []


def _connect_probe(sock: "socket.socket") -> int:
    """Is ``sock`` listening? Answered without consuming anybody's connection.

    For the callers that ADOPT BUT DO NOT SERVE — a holder, a standby. They
    need the same proof `_accept_probe` gives, and must not pay its price: an
    accept that returns hands back a live client, and a process with no serving
    loop holds it until the client times out. Measured: the standby swallowed a
    queued request and sat on it for the client's full 60s, which is worse than
    the drop it replaced.

    Dialling our own address separates the two states on every platform: a
    LISTENING socket completes the handshake from the backlog, a bound-but-
    never-listened one answers ECONNREFUSED. Skipping the probe entirely was
    tried first and is wrong — `case_a_listening_socket_is_adopted_where_
    SO_ACCEPTCONN_cannot_be_read` exists because adopting a non-listening
    descriptor is a real failure, and it caught this immediately.

    Costs one connection queued on our own backlog, which we close at once. The
    daemon that later drains it sees a client that hung up, which every proxy
    already handles. A TIMEOUT counts as listening: only a listening socket can
    make a connect hang, by having a full queue.
    """
    try:
        addr = sock.getsockname()
    except OSError:
        return 0
    try:
        with socket.create_connection(addr[:2], timeout=1.0):
            return 1
    except ConnectionRefusedError:
        return 0
    except (TimeoutError, socket.timeout):
        return 1
    except OSError:
        # Anything else is not evidence of "never listened"; refusing here
        # would strand the sessions this handover exists to keep.
        return 1


def _accept_probe(sock: "socket.socket") -> int:
    """Is ``sock`` listening? Answered by asking it, because Darwin will not say.

    `SO_ACCEPTCONN` is readable on Linux and raises `OSError 42` on Darwin —
    measured, same call. Treating that raise as "not listening" refused every
    handover on macOS and the successor bound a FRESH port, which is the
    stranding this whole path exists to prevent.

    A non-blocking accept() answers on both platforms: a LISTENING socket with
    an empty queue raises EAGAIN (BlockingIOError), one that never listened
    raises EINVAL. The timeout is restored either way — leaving a socket
    non-blocking would turn every later accept into a busy spin.

    ONLY FOR A CALLER THAT WILL SERVE. When the queue is NOT empty this returns
    a live client, and the old code closed it: a request that had completed its
    handshake, and usually sent its bytes, got an RST or a bare EOF. Measured
    on host-b across a handover. It is parked in `_ADOPTED_BACKLOG` now
    and the serving loop takes it first — which is only a fix if the caller has
    a serving loop, hence `will_serve`.
    """
    prev = sock.gettimeout()
    try:
        sock.settimeout(0)
        conn, _ = sock.accept()
        _ADOPTED_BACKLOG.append(conn)
        _log_lifecycle(
            "adopt probe accepted a waiting client — "
            f"parked to serve, not dropped"
        )
        return 1
    except BlockingIOError:
        return 1  # listening, queue empty — the normal case
    except OSError:
        return 0  # EINVAL: never listened
    finally:
        sock.settimeout(prev)


def _inherited_listener(will_serve: bool = False) -> "socket.socket | None":
    """The listening socket a supervisor handed us, or None to bind our own.

    The systemd socket-activation convention: ``LISTEN_FDS`` counts the fds
    passed starting at 3, and ``LISTEN_PID`` names who they were passed TO.

    LISTEN_PID is not optional. The variables are inherited by every
    descendant, so a grandchild that trusts ``LISTEN_FDS`` alone serves on
    whatever its own fd 3 happens to be — a log file, a pipe, another
    process's socket — and the port goes unserved with no error anywhere.

    Anything not a listening TCP socket is refused rather than adopted, and
    refusing means we bind our own port: a supervisor that passed us the wrong
    thing must not be able to take the pin down with it.
    """
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    try:
        count = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        return None
    if count < 1:
        return None
    try:
        sock = socket.socket(fileno=3)
    except OSError:
        return None
    try:
        if sock.type != socket.SOCK_STREAM:
            raise OSError("not a stream socket")
        # getsockname() answers on a bound socket; accept() would block, so the
        # listening state is proven by asking the socket itself.
        #
        # A PROBE THAT CANNOT ANSWER IS NOT A "NO". Treating that raise as "not
        # listening" refused every handover on macOS and the successor bound a
        # FRESH port, which is the stranding this whole path exists to prevent
        # (live sessions have the old port fixed at exec). `getsockname()`
        # below still proves it is a bound TCP socket on both platforms, so
        # only the redundant option is allowed to be absent.
        try:
            listening = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except OSError:
            # A CALLER THAT WILL NOT SERVE MUST NOT ACCEPT: an accept that
            # returns hands back a live client, and a holder or standby has no
            # loop to serve it. Both still need the proof, so they dial the
            # address instead of consuming from its queue.
            listening = (_accept_probe(sock) if will_serve
                         else _connect_probe(sock))
        if not listening:
            raise OSError("not listening")
        sock.getsockname()
    except OSError as exc:
        _log_lifecycle(f"ignoring the passed fd 3: {exc}")
        sock.detach()  # not ours — leave the fd as the supervisor left it
        return None
    return sock


_HANDDOWN_FD_ENV = "CSWAP_PIN_LISTEN_FD"
_HANDDOWN_FROM_ENV = "CSWAP_PIN_LISTEN_FROM"
# Set by a HOLDER only, naming itself. Distinguishes "my parent is still there
# and will start my successor" from "my predecessor handed me its socket on the
# way out" — the two look identical in the variables above, and they mean
# opposite things when this daemon is TERM'd.
_HELD_BY_ENV = "CSWAP_PIN_HELD_BY"
# Set by a holder that has ACTUALLY INSTALLED the replace handler, and only
# then.
#
# A CAPABILITY IS THE RECEIVER'S TO CLAIM, never the sender's to assume:
# `_REPLACE_ME_SIGNAL` is SIGUSR1, whose default disposition is TERMINATE, so
# asking a holder that cannot hear it does not degrade — it kills the holder
# and takes the listening socket with it. And the skew is not an edge case, it
# is THE case. `_watch_own_code` fires exactly when the code on disk is newer
# than the code somebody loaded, which is precisely when the holder above us is
# a long-lived process still running the PREVIOUS release — with no handler,
# forever. The gap this whole mechanism exists to remove is 2 s.
_HOLDER_REPLACE_ENV = "CSWAP_PIN_HOLDER_TAKES_REPLACE"
# The bytes the HOLDER loaded, published into its child's environment. A
# DAEMON'S FRESHNESS SAYS NOTHING ABOUT THE HOLDER ABOVE IT. The holder execs a
# fresh interpreter for every spawn, so a holder running months-old code starts
# a perfectly current daemon — proxy.json's fingerprint reports the child and
# there is no observable for the layer above. `_OWN_FINGERPRINT`, so it is what
# the holder IMPORTED. A fresh `daemon_fingerprint()` here would publish the
# disk at spawn time, which is exactly the lie this is meant to expose.
_HOLDER_SHA_ENV = "CSWAP_PIN_HOLDER_SHA"

# WHICH PID THE STANDBY WAS BORN UNDER — see `PortHolder._spawn_standby`. The
# standby compares `getppid()` against this, never against 1: a subreaper host
# reparents orphans to itself, so 1 is never reached and the standby would hold
# the descriptor forever without ever arming.
_STANDBY_FROM_ENV = "CSWAP_PIN_STANDBY_FROM"
_STANDBY_MODULE_ARG = "--standby"
# ONE ARMING STANDBY PER CERTDIR. Held for the life of the winner, so every
# later standby that reaches the same decision finds it taken and stands down.
_STANDBY_ARM_LOCK = ".standby-arm.lock"
# ONE, because the corroboration is no longer repetition. Three short windows
# replaced two long ones, and `_recorded_daemon_alive` then replaced the
# repetition itself with a different KIND of evidence: the recorded pid answers
# "does anything accept" outright, for free, where silence only implies it. A
# loaded daemon that misses a window is still ALIVE, so it can no longer be
# mistaken for a dead one.
_STANDBY_SILENT_STREAK = 1
_STANDBY_POLL_S = 0.25
# HOW LONG TO WAIT WHEN ORPHANED AND SOMETHING STILL ANSWERS. Not a tuning
# knob: that state converges to nothing, so polling it fast buys nothing and
# costs a connection every quarter second for as long as the process lives.
_STANDBY_ANSWERED_POLL_S = 2.0
# 250ms, NOT SECONDS. The wait is the DECISION, not the work: a live proxy
# answers this probe in about a millisecond, so a two-second timeout was slack
# for a stalled event loop rather than a measurement — and two of them ran
# serially, which is where 4,610ms of the recovery went. Three short windows
# give MORE independent observations than two long ones and cost a fifth of the
# time.
_STANDBY_PROBE_TIMEOUT_S = 0.25


def _retire_stale_standbys(certdir, keep_pid: int | None = None) -> int:
    """SIGHUP every standby for this certdir except the one we just placed.

    ONE IN, ONE OUT. The arm lock stops two standbys arming at the same
    instant; it does NOT remove the loser, and the loser still holds the
    descriptor, still watches the port, and is precisely what arms on the next
    silent window. So the lock defers a pile-up rather than preventing one.

    They accumulate for a reason that is not a bug: a holder KILLED rather
    than released leaves its standby behind deliberately — that is the row
    this whole design covers. Every such death adds one. Measured on host-a:
    three had piled up, one ordinary daemon handover armed them all, and the
    port ended with four acceptors.

    SIGHUP, because that is the standby's release signal and the only one it
    honours — it ignores TERM and INT on purpose, so anything else would reach
    it as a SIGKILL escalation with no handler and no log.
    """
    import subprocess

    if _STAND_DOWN_SIGNAL is None:
        return 0  # no SIGHUP here, so nothing to retire with — see the constant
    target = str(Path(certdir).resolve())
    retired = 0
    try:
        out = subprocess.run(
            ["ps", "-ww", "-axo", "pid=,command="],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    for line in out.splitlines():
        line = line.strip()
        if not any(m in line for m in _DAEMON_MODULE_NAMES):
            continue
        head, _, rest = line.partition(" ")
        # Same two gates the daemon sweep uses: the certdir must be the LAST
        # argv token, not merely present, or a shell that quotes both matches.
        if not rest.rstrip().endswith(" " + target):
            continue
        if f" {_STANDBY_MODULE_ARG} " not in rest:
            continue
        try:
            pid = int(head)
        except ValueError:
            continue
        if pid == keep_pid or pid == os.getpid():
            continue
        try:
            # THE SAME CONSTANT, not a second `signal.SIGHUP`. This call is
            # older than the one in `_retire_stale_holder` and carried the same
            # latent AttributeError on Windows; one guarded copy beside one
            # unguarded copy is how the next reader concludes the guard is
            # optional. The early return at the top is what actually keeps it
            # off a platform with no SIGHUP — this line only stops there being
            # two spellings of the same signal.
            os.kill(pid, _STAND_DOWN_SIGNAL)
            retired += 1
        except OSError:
            pass
    return retired


def _recorded_daemon_alive(certdir) -> bool:
    """Is the daemon `proxy.json` names still running? Microseconds, no socket.

    DIRECT EVIDENCE INSTEAD OF INFERRED. Silence on the port is a PROXY for
    "nothing accepts"; the recorded pid answers it outright, and a signal-0 is
    free where a probe costs a timeout. That is why the silent streak can be
    one here and had to be three without it: the corroboration moved from
    repetition to a different KIND of evidence.

    Absent or unreadable means "cannot tell", and the safe answer is TRUE —
    assume something serves and do not arm. Arming wrongly is not cheap for us:
    this standby does not carry traffic, it puts a DAEMON on the socket, and
    two daemons accepting the same listener lose requests outright (19 of 60 in
    steady state, measured). A peer can arm on a hunch because their relay
    forwards to the same hop either way; ours cannot.
    """
    try:
        rec = json.loads((Path(certdir) / _STATE_FILE).read_text())
    except (OSError, ValueError):
        return True
    pid = rec.get("pid") if isinstance(rec, dict) else None
    if not isinstance(pid, int) or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # EPERM: alive, just not ours to signal
    return True


def _standby_port_still_wanted(certdir, port: int) -> bool:
    """Does the pin still name OUR port? Only then is it worth reviving.

    STOPS A RUNAWAY, measured on host-a. Every deploy hands the daemon to a new
    lineage and leaves the previous lineage's standby holding a socket nobody
    serves and nobody dials. Silence is what it waits for, so it armed, rebuilt
    a whole holder+daemon+standby on that dead socket, and THAT standby was
    orphaned in turn: 23 processes, 21 of them unreachable, while the real pin
    sat correctly on 36301 throughout.

    A MISSING RECORD IS NOT ABANDONMENT. `_spawn_daemon` unlinks proxy.json
    before a respawn, so it is legitimately absent for a moment — and that is
    exactly the moment a standby is deciding. Absent means "cannot tell", and
    the safe answer there is to cover, because failing to revive the real port
    is the outage this exists to prevent.
    """
    try:
        rec = json.loads((Path(certdir) / _STATE_FILE).read_text())
    except (OSError, ValueError):
        return True
    recorded = rec.get("port") if isinstance(rec, dict) else None
    if not isinstance(recorded, int) or recorded <= 0:
        return True
    return recorded == port


def _claim_arm(certdir) -> "int | None":
    """Win the right to arm, or None if another standby already has it.

    THE ONLY THING THAT CAN SAY "ONLY ONE". Standbys accumulate legitimately —
    every holder KILLED rather than released leaves its own behind, which is
    the row this whole design covers — and they all watch the same port, so one
    silent window arms ALL of them at once. Measured on host-a: three armed
    within a minute, each became a holder, four acceptors on 36301.

    NON-BLOCKING, because a loser has nothing to wait for: the winner is
    putting a daemon back on the very socket the loser holds, so the loser's
    job is finished either way.

    THE FD IS RETURNED AND NEVER CLOSED. An flock lives on the open file
    description, so closing it releases the claim — and the winner must hold it
    for as long as it is the holder, not merely while it decides.
    """
    import fcntl

    try:
        fd = os.open(str(Path(certdir) / _STANDBY_ARM_LOCK),
                     os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _standby_tick(born_of: int, silent: int, answered, getppid=os.getppid):
    """One poll of the standby's arm predicate. ``(silent, arm, sleep_for)``.

    Split out of the loop because this is the part that can be WRONG in ways a
    timing test hides. The loop around it is a sleep.

    BOTH CONDITIONS, AND THE COUNTER RESETS ON EITHER. Still parented by the
    holder that placed us means the holder is alive and already respawning its
    own daemon — measured across a daemon SIGKILL, 407 of 408 requests served,
    so there is nothing here to fix and arming would put a SECOND daemon on a
    socket that already has an acceptor. Being orphaned while something still
    answers means a daemon outlived its holder, and that daemon's own watchdog
    puts a fresh holder back; arming would race it.

    Only "orphaned AND nothing answers" is the case no other part of this
    system covers. `_STANDBY_SILENT_STREAK` windows of it, and the streak is 1
    — the recorded-pid check inside `answered` is direct evidence, so a second
    window would only add latency to a question already settled.
    """
    if getppid() == born_of:
        # THE PARENT TEST COMES FIRST AND SHORT-CIRCUITS, so the normal state
        # opens no socket at all — one integer comparison per poll, forever.
        return 0, False, _STANDBY_POLL_S
    if answered():
        # ORPHANED BUT SOMETHING IS SERVING. A real and possibly long-lived
        # state: a daemon that outlived its holder keeps answering, and its own
        # watchdog puts a fresh holder back — but OUR parent stays dead, so
        # this branch never stops being taken. At the tight poll that is a dial
        # every ~250ms forever, because an answered probe returns in about a
        # millisecond. Nothing is converging here, so there is nothing to poll
        # quickly for.
        return 0, False, _STANDBY_ANSWERED_POLL_S
    silent += 1
    # Silence IS converging — each one is a step toward arming — so stay tight.
    return silent, silent >= _STANDBY_SILENT_STREAK, _STANDBY_POLL_S


def _successor_is_serving() -> bool:
    """Is SOMEBODY ELSE serving the wired port?

    The teardown asks the port rather than a file, because a successor that
    came up while we drained is real and unwiring past it would strip a
    working pin — measured: unwire at 19:16:35, successor serving at 19:16:36,
    a live session retrying in between.

    BUT A HOLDER'S SOCKET IS NOT SOMEBODY ELSE. Under a holder,
    `release_listener` DETACHES rather than closes (the port is not ours to
    take down), so the socket we just stopped serving is still bound and
    listening — and a listen-only socket completes a TCP handshake. The probe
    therefore answered "served" about our own corpse: the unwire was skipped,
    the daemon exited 0, the holder released the port on that clean exit, and
    `.claude.json` was left naming an address nothing listens on. That is the
    ConnectionRefused-forever outage this whole guard exists to prevent,
    reached through the guard itself.

    So a port that answers counts only when it is NOT the one our own holder
    is holding for us.
    """
    live = _wired_port()
    if live is None or not _port_answers(live):
        return False
    return not held_by_a_holder()


def teardown_drain_budget(reason: str, held: bool,
                          handed_over: bool = False) -> float:
    """How long a shutdown may wait for the replies it still owes.

    A FOURTH EXIT PATH, AND THE ONLY ONE STILL CUTTING. Measured on host-a, the
    0.1.99 rollout: the handover at 08:04:18Z emitted no drain line at all — it
    handed the port over and kept living, which is exactly what the handover
    ceiling is for. Then at 08:08:18Z this path fired `stopping (refcount)` on
    that same lingering daemon and cut 13 replies, every one of them
    mid-response, on thirty seconds. The cost had been moved, not removed.

    THREE ARMS, AND THE REASON STRING IS WHAT SEPARATES THEM — the same field
    that was added so a TERM and an idle teardown would stop leaving identical
    traces. What each arm is really asking is *who is waiting for this process
    to be gone*:

    ``held``
        A recycle. The holder cannot put the successor on the socket until we
        are gone, so every second here is a second with nothing behind the
        port. Short.

    a signal
        Somebody is waiting, and the supervisor's patience is
        ``_DRAIN_SECONDS + 2`` before SIGKILL. Draining longer than that saves
        no reply — it guarantees a harder kill partway through one. Short, and
        this is why the handover ceiling must NOT be used here.

    ``refcount``
        Nobody is waiting. No successor is coming for this port, no supervisor
        is counting, and ``release_listener`` has already freed the address so
        a fresh daemon could bind at once. The only cost of waiting is this
        process finishing the replies it already owes. Long.

    THE COMMON CASE PAYS NOTHING EITHER WAY: refcount reaching zero normally
    means no sessions, so nothing is owed and ``await_inflight`` returns in
    milliseconds. The long ceiling is only ever spent by a daemon that outlived
    its holder and still has work — precisely the one measured above.

    A FUNCTION RATHER THAN A BRANCH INSIDE ``_teardown``, because in there it
    is reachable only through a live daemon's sockets and state file, and a
    harness that reconstructs those can be wrong in its own right — the same
    reason `case_teardown_restores_the_config` asserts on the parse tree.
    """
    # THE HELD ARM'S PREMISE, CHECKED RATHER THAN ASSUMED. "The holder cannot
    # put the successor on the socket until we are gone" was true before the
    # replace-ask existed. For a daemon that has already handed over it is
    # FALSE: `_watch_own_code` signals the holder, verifies it survived the
    # ask, and the successor is serving on the same socket while this process
    # drains. There is no unserved port time left to buy, so the short ceiling
    # buys nothing and spends live replies. A second drain re-armed the very
    # clock the first had removed.
    #
    # THE SIGNAL ROW STILL DOES NOT MOVE, handed over or not: the supervisor
    # SIGKILLs at `_DRAIN_SECONDS + 2`, so a longer ceiling there buys a harder
    # kill partway through a reply rather than a finished one.
    if held and not handed_over:
        return _HELD_DRAIN_SECONDS
    if reason == "refcount":
        return _HANDOVER_DRAIN_SECONDS
    return _DRAIN_SECONDS


def held_by_a_holder(ppid: int | None = None, env=None) -> bool:
    """Whether a holder owns this daemon's socket and will outlive it.

    The distinction the whole restart story turns on. A PREDECESSOR that hands
    its socket down is leaving, so its successor owns the port and must hand it
    on in turn. A HOLDER is still there and will put the next daemon on the
    same socket — so this daemon has nothing to hand over and should simply go.
    """
    env = os.environ if env is None else env
    ppid = os.getppid() if ppid is None else ppid
    return env.get(_HELD_BY_ENV) == str(ppid)


def _holder_pid(env=None) -> "int | None":
    """The pid of the holder above us, or None if there is not one.

    THE SAME GUARD `held_by_a_holder` USES, and for the same reason: the
    variable reaches every descendant, so a grandchild reading it bare would
    signal a pid that is not its parent — and by then that number may belong to
    something else entirely. Only a holder that is our own parent is one we may
    ask to replace us.
    """
    env = os.environ if env is None else env
    # NOTHING TO ASK WITH. Returning a pid here would hand the caller a number
    # it goes on to `os.kill(pid, None)` with, which is a TypeError inside a
    # watchdog — see `_REPLACE_ME_SIGNAL`.
    if _REPLACE_ME_SIGNAL is None:
        return None
    # THE HOLDER HAS TO CLAIM IT. Identity is not capability: our parent may be
    # a holder from the PREVIOUS release, which is the normal case here since
    # this path only runs when the disk is newer than somebody's memory. That
    # holder has no handler, and `_REPLACE_ME_SIGNAL` unhandled is fatal — so
    # an unclaimed holder is not one to ask, it is one to leave alone.
    if env.get(_HOLDER_REPLACE_ENV) != "1":
        return None
    raw = env.get(_HELD_BY_ENV)
    if not raw or raw != str(os.getppid()):
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _retire_stale_holder(own_fingerprint: str, env=None) -> bool:
    """Send the holder above us away when it is running code we no longer ship.

    THE ONE THING A DEPLOY CANNOT REACH. Daemons and standbys are spawned, so
    they exec the new file within a tick of an install. A holder is not spawned
    again — it keeps running whatever it loaded, and every lever misses it:
    `pin <n>` on an already-pinned account is a no-op (measured: rc=0, a success
    line, identical pids, zero new log lines), `heal` only acts when the port is
    NOT serving, and SIGTERM is ignored by design. Measured ages at the time
    this was written: 7 days and 3 days, on machines whose daemons were minutes
    old. So the honest answer to "when does it recycle itself" was "at the next
    reboot".

    SIGHUP, and the choice is deliberately VERSION-BLIND — the lesson of
    `_HOLDER_REPLACE_ENV` applied to the other direction. NO holder of any
    version handles it: the `_release` handler belongs to a STANDBY, and the
    promotion path hands the signals back (`SIGHUP -> SIG_DFL`) precisely
    because "a handler installed once outlives the reason for it". So a holder
    always takes the default, which terminates it — the outcome this wants, in
    every release, with nothing to advertise.

    Measured before automating it, by hand on two machines whose holders were
    7 and 3 days old: SIGHUP, and each was replaced by a fresh triad at a cost
    of 0 failed requests out of 60.

    That safety is NOT "the versions happen to agree". It is that this caller
    does not release the socket, so the descriptor stays bound in this daemon
    whatever the holder does. Contrast the replace-ask, where handled and
    unhandled differ catastrophically — THAT is what makes a capability need
    advertising, not the mere possibility of a version gap.

    That the daemon survives losing its holder is not an assumption. This file
    already records the experiment, isolated port 60759: after SIGHUP to the
    holder, the daemon was reparented to init, HOLDERS REMAINING 0, PORT ALIVE
    True.
    """
    if _STAND_DOWN_SIGNAL is None:
        return False  # no SIGHUP here — see the constant
    env = os.environ if env is None else env
    published = env.get(_HOLDER_SHA_ENV)
    # Nothing published means no holder told us anything — a bare daemon, a
    # test, or a holder too old to publish. Not a mismatch, so not our business.
    if not published or published == own_fingerprint:
        return False
    if not held_by_a_holder(env=env):
        return False  # the variable reached us through some other descendant
    try:
        os.kill(os.getppid(), _STAND_DOWN_SIGNAL)
    except OSError:
        return False
    return True


def _parent_is_a_holder(pid: int) -> bool:
    """Whether ``pid``'s argv is actually a ``--hold-port`` holder.

    `_HELD_BY_ENV` is set by whatever ran :class:`PortHolder`, which in
    production is the holder process and in a test is the test runner. Signal
    on the variable alone and a daemon spawned by a PortHolder living inside
    another program sends SIGHUP to THAT program — default disposition, so it
    dies. The variable says who spawned us; only the argv says what they are.

    Unknown is not a holder: no ``ps``, an unreadable line, anything but a
    clear match declines. A retirement that does not happen leaves the machine
    as it was, which is the safe direction here.
    """
    import subprocess

    try:
        out = subprocess.run(
            ["ps", "-ww", "-o", "command=", "-p", str(pid)],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    line = out.strip()
    if not line or not any(m in line for m in _DAEMON_MODULE_NAMES):
        return False
    return f" {_HOLDER_MODULE_ARG} " in f" {line} "


def _retire_blind_holder(env=None) -> bool:
    """Send this daemon's holder away when we cannot read the pinned credential.

    NOT CALLED FROM THE REQUEST PATH ANY MORE -- see `_warn_unpinnable`. Firing
    it there manufactured an orphan every tick and the orphan branch has no
    backoff, so the triad rebuilt every 31 seconds without converging. Kept
    because it is still the right action for a holder that IS the fault, and
    it must only ever be reached from a caller that throttles it.

    THE LEVER NOTHING PULLED. A holder is spawned once and never again, and
    every daemon it places on the socket inherits its process context — on
    macOS that includes the audit session which decides whether the login
    keychain can be read. A holder born where it cannot read therefore produces
    blind daemons for ever, each respawn re-inheriting the fault. That is what
    `_heal` is describing when it says a respawn cannot fix a credential it
    also cannot read, and why `repin_current`'s claim that "a successor born
    somewhere that CAN read mints again" does not hold: the successor is born
    from the HOLDER, never from whoever ran the command.

    THE OBSERVATION THAT MOTIVATED THIS DID NOT SUPPORT IT. A holder alive
    across three daemon respawns with every successor can_pin false was read
    as evidence for the inheritance above; the cause turned out to be
    `invalid_grant` on the pinned slot — a dead refresh lineage that no
    respawn, holder or context can fix. Read `usage.json`'s `lastError`
    before reaching for this: `can_pin` is "can MINT", not "can read the
    credential", and the two come apart exactly when the stored blob is fine.
    The mechanism described above is still the right reason for this function
    to exist; it has not been shown to have caused an outage yet.

    Same signal and same safety argument as :func:`_retire_stale_holder`.
    SIGHUP, which no holder version handles, and this caller does not release
    the socket — the descriptor stays bound here whatever the holder does.
    The next `ensure_proxy` then finds no holder and builds a fresh triad IN
    THE CALLING PROCESS, which is the point: that process is the user's shell.

    NOT gated on a fingerprint, unlike its sibling. The holder here is running
    exactly the code we ship; what is wrong with it is where it was born, and
    no version comparison can see that.
    """
    if _STAND_DOWN_SIGNAL is None:
        return False  # no SIGHUP here — see the constant
    env = os.environ if env is None else env
    if not held_by_a_holder(env=env):
        return False
    # AND THE PARENT MUST LOOK LIKE ONE. `_HELD_BY_ENV` records who spawned
    # us, which is the holder in production and the test runner under pytest.
    # `_retire_stale_holder` gets away with the variable alone because a
    # fingerprint mismatch is rare; this fires whenever the credential cannot
    # be read, which is every daemon a test starts.
    ppid = os.getppid()
    if not _parent_is_a_holder(ppid):
        return False
    try:
        os.kill(ppid, _STAND_DOWN_SIGNAL)
    except OSError:
        return False
    return True


def _orphaned_from_its_holder(env=None) -> bool:
    """Did this daemon HAVE a holder and LOSE it?

    Not the same question as `not held_by_a_holder()`, and the difference is
    the whole guard: a daemon that was never held (a bare `daemon_main`, a
    test harness) also answers "no holder", and recycling that one hands over
    forever. Only a daemon whose environment NAMES a holder can be orphaned
    from it.

    The marker outlives the holder — it is our own environment, set at spawn —
    while `getppid()` moves to init the moment the holder dies. So the two
    disagreeing IS the orphaning, and no signal handler or liveness probe is
    needed to see it.
    """
    env = os.environ if env is None else env
    return bool(env.get(_HELD_BY_ENV)) and not held_by_a_holder(env=env)


def _handed_down_listener(will_serve: bool = False) -> "socket.socket | None":
    """The listening socket our PREDECESSOR passed us, or None to bind our own.

    A separate path from :func:`_inherited_listener`, and it has to be. That
    one implements the systemd convention, where the first passed fd is
    number 3 — but `subprocess.Popen(pass_fds=...)` does NOT renumber:
    measured, a parent's fd 9 arrives as the child's fd 9 and its fd 3 is
    EBADF. A predecessor cannot use the systemd variables to say what it
    passed, so it names the number instead.

    ``_HANDDOWN_FROM_ENV`` is the same guard ``LISTEN_PID`` is, one level
    over: the variables reach every descendant, and a grandchild does NOT
    inherit the fd (Popen closes what it does not pass), so a bare number
    would name whatever that descriptor became — a log file, a pipe, another
    socket. Requiring it to have come from our own parent is what makes the
    number meaningful. Anything not a listening TCP socket is refused, and
    refusing means we bind our own port: a bad hand-down must not be able to
    take the pin down with it.
    """
    origin = os.environ.get(_HANDDOWN_FROM_ENV)
    if not origin or origin != str(os.getppid()):
        return None
    try:
        fd = int(os.environ.get(_HANDDOWN_FD_ENV, ""))
    except ValueError:
        return None
    if fd < 0:
        return None
    try:
        sock = socket.socket(fileno=fd)
    except OSError:
        return None
    try:
        if sock.type != socket.SOCK_STREAM:
            raise OSError("not a stream socket")
        # A PROBE THAT CANNOT ANSWER IS NOT A "NO". Treating that raise as "not
        # listening" refused every handover on macOS and the successor bound a
        # FRESH port, which is the stranding this whole path exists to prevent
        # (live sessions have the old port fixed at exec). `getsockname()`
        # below still proves it is a bound TCP socket on both platforms, so
        # only the redundant option is allowed to be absent.
        try:
            listening = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except OSError:
            # A CALLER THAT WILL NOT SERVE MUST NOT ACCEPT: an accept that
            # returns hands back a live client, and a holder or standby has no
            # loop to serve it. Both still need the proof, so they dial the
            # address instead of consuming from its queue.
            listening = (_accept_probe(sock) if will_serve
                         else _connect_probe(sock))
        if not listening:
            raise OSError("not listening")
        sock.getsockname()
    except OSError as exc:
        _log_lifecycle(f"ignoring the handed-down fd {fd}: {exc}")
        sock.detach()  # not ours — leave the descriptor as we found it
        return None
    return sock


def _port_answers(port: int, timeout: float = 0.5) -> bool:
    """Whether something ACCEPTS on ``port`` right now, on loopback.

    A connect, not a request: the question is whether a session dialling this
    address would be refused, and that is answered by the accept alone. Kept
    short because it runs on a teardown path — a pin must never make an exit
    slow — and treated as "nobody" on any error, since a port we cannot reach
    is one a session cannot reach either.

    SEPARATE FROM "IS ANYTHING BOUND TO IT", and the holder's squat recovery
    turns on the two disagreeing. A socket can be LISTENing with a full
    backlog and no acceptor: bound AND refusing, which is what a standby left
    by a killed holder looks like. A check that reads only one of those facts
    reports that state as its opposite.

    A SECOND COPY OF THIS EXISTED for three releases, 484 lines below, added
    without noticing this one — differing only in its default timeout, which
    is precisely the drift the host's sibling docstring warns about. Pass a
    timeout; do not write another.
    """
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _resume_serving(server) -> bool:
    """Put a stopped server back on its own port. True if it is listening again.

    ``stop()`` closes the listener but leaves the object usable, and ``start()``
    already reclaims the recorded port rather than taking a fresh one — so a
    resume is a restart of the listener, not of the process. The port matters
    more than the uptime: a running session's HTTPS_PROXY was fixed at exec, so
    coming back anywhere else is the same outage as not coming back.
    """
    try:
        server._stop = False
        server.start()
    except Exception as exc:  # noqa: BLE001 — the caller has a fallback
        _log_lifecycle(f"could not resume serving: {exc!r}")
        return False
    want = read_daemon_state(server._certdir)
    recorded = want.get("port") if isinstance(want, dict) else None
    if isinstance(recorded, int) and recorded > 0 and server.port != recorded:
        # Listening, but not where the live sessions are pointed. That is not a
        # resume, it is a second outage wearing the same log line.
        _log_lifecycle(
            f"resumed on {server.port} but sessions expect {recorded}"
        )
        return False
    return True


def daemon_main(account_num: str, email: str, certdir: Path) -> None:
    """Entry point for the detached proxy process (``-m claude_swap.pin_proxy``).

    Chains through whatever egress proxy the most recent launch recorded in
    ``upstream.json`` (corporate, another local MITM, or none), re-read per
    connection so a proxy
    that restarts on another port is followed rather than bypassed. Records
    ``proxy.json`` (port/pid/fingerprint) once listening, serves a ``/health``
    probe, and self-terminates when the last refcount holder closes the FIFO
    (idle teardown).
    """
    ClaudeAccountSwitcher = require("switcher").ClaudeAccountSwitcher

    certdir = Path(certdir)
    switcher = ClaudeAccountSwitcher()
    # NOT minted here. A daemon respawn (a fingerprint recycle, a deploy) must
    # not be able to turn the gate on: a live session's HTTPS_PROXY is fixed at
    # exec time, so a session wired before the credential existed carries a URL
    # without one and would start getting 407 on its next request — the upgrade
    # cutting off the very sessions it protects. ``apply_pin`` mints it
    # instead, so the gate arms exactly when the wiring is rewritten to carry
    # it. PinProxy only ever READS the value.
    proxy = PinProxy(
        certdir=certdir,
        pin_token_provider=make_pin_token_provider(switcher, account_num, email),
        rediscover_chain=True,
    )
    proxy.start()
    # `_OWN_FINGERPRINT`, NOT a fresh read. This record is an IDENTITY — it is
    # what `runtime_health`, a deploy check or a human answers "is the running
    # daemon on this code" from. `daemon_fingerprint()` samples the DISK, so
    # recording it here would publish what is on disk at start rather than what
    # this process loaded, and the two differ in exactly the window where the
    # question matters: a deploy landing during daemon start would make the
    # record claim the new code while we serve the old.
    #
    # Same function, opposite requirement, one line apart in intent — the
    # watchdog's disk side must be fresh, an identity must not move.
    write_daemon_state(
        certdir, proxy.port, os.getpid(), _OWN_FINGERPRINT
    )
    # A start line means the log is never empty for a daemon that ran, so
    # "no teardown line" becomes evidence of a CRASH rather than of nothing.
    _log_lifecycle(f"serving on port {proxy.port} for account {account_num}")

    # SAY WHERE WE START, BECAUSE THE VERDICT IS PER-PROCESS AND TRANSITION-ONLY.
    # `_report_deaf_bridges` logs only on CHANGE and `_last_deaf` dies with the
    # process, so after a handover the newest inbound verdict on record belongs
    # to a daemon that no longer exists. Its only caller is a request path
    # gated on a session starting or posting, so on a QUIET host the successor
    # never speaks at all and a reader cannot tell "nothing is wrong" from "the
    # live daemon has not answered yet".
    #
    # AND NOT AS A CLEAR. A fresh daemon holds no bridges, so running the
    # normal report here would print "every posting bridge holds an inbound
    # stream (0 posting)" — a vacuous truth wearing a pass. Say the count and
    # let the reader decide; a verdict arrives on the first sweep.
    try:
        _log_lifecycle(
            f"carrying {len(proxy.held_bridge_ids())} bridge(s) at start — no "
            "inbound verdict yet, the first one follows a session start or post")
    except Exception:  # noqa: BLE001 — a log must not stop a serving daemon
        pass

    # THE SERVING DAEMON OWNS THE WIRING, because nothing else was putting it
    # back. A departing daemon unwires `.claude.json` when it sees the port
    # unserved, and that check is right at the instant it runs — but on a
    # holder restart the predecessor has released and the successor has not
    # bound yet, so the port IS unserved for that instant and the wiring goes.
    # Only a LAUNCH or a `heal` wrote it, so it stayed gone: every
    # hand-launched session afterwards ran unpinned, with a healthy daemon
    # serving the port nobody was told about.
    #
    # NO-OP WHEN ALREADY CORRECT, so this costs one config read on a normal
    # start and writes nothing — the same guard `heal` uses to decide there is
    # nothing to do. Never raises: a wiring failure must not stop a daemon that
    # is otherwise serving, and the next launch or heal still repairs it.
    ensure_wired_to(proxy.port, certdir)

    fifo = refcount_fifo_path(certdir)
    if not fifo.exists():
        try:
            os.mkfifo(fifo)
        except FileExistsError:
            pass

    done = threading.Event()

    def _teardown(reason: str = "refcount") -> None:
        # Last session closed its holder (or a signal arrived) — stop serving
        # and clean up our state so a launcher never reuses a dead record.
        _log_lifecycle(f"stopping ({reason})")
        # DRAIN, because this is the only place that decides whether an upgrade
        # or a recycle costs sessions their in-flight requests. An idle daemon
        # returns from here at once.
        #
        # SHORT WHEN A HOLDER IS WAITING TO RESPAWN, for the same reason the
        # code watchdog's held exit is (see `_HELD_DRAIN_SECONDS`): a TERM
        # under a holder is a RECYCLE, and the holder cannot put the successor
        # on the socket until we are gone. Draining the full ceiling there is
        # time with the port bound and nobody behind it.
        #
        # TWO WAYS TO OWE NOTHING, and our own marker only covers one. We
        # announced a drain (the watchdog's post-ask wait), or somebody else is
        # already serving this port — which is what a holder taking the replace
        # signal leaves behind, with nothing announced here at all. Read HERE
        # rather than inside `teardown_drain_budget` so that function stays
        # pure and testable.
        cut = proxy.stop(drain=teardown_drain_budget(
            reason, held_by_a_holder(),
            handed_over=this_process_is_draining()
            or _superseded_on_the_port(certdir)))
        # THE NUMBER FROM BEFORE THE CUT. Reading it back off the proxy here
        # returns 0 always — `await_inflight` empties the set it counts.
        _log_lifecycle(f"drained, {cut} client(s) still open")
        # ``done`` must be set on EVERY exit from here: ``daemon_main`` blocks
        # on it and the signal path ends in ``os._exit(0)``, so an exception
        # escaping before it leaves the server stopped, ``.claude.json`` naming
        # a dead port, and the process alive forever holding both.
        try:
            try:
                superseded = _release_daemon_state(certdir)
            except OSError as exc:
                # The record could not be dropped, which is NOT evidence a
                # successor owns it. Treat it as "no successor" so the unwire
                # below still runs: leaving the config naming a port this
                # daemon is about to stop serving is the outage, and a stale
                # record is the smaller fault of the two.
                _log_lifecycle(f"could not release daemon state: {exc!r}")
                superseded = False
            if superseded:
                # A successor owns the state now. Unwiring here would strip the
                # config it just wrote and send every new session to no proxy
                # at all, so the departing daemon leaves the wiring alone.
                return
            # ASK THE PORT, DO NOT INFER FROM A FILE. Our own listener is
            # already closed by the drain above, so anything still answering
            # the wired address is SOMEBODY ELSE serving it — a successor that
            # came up while we were draining, or a supervisor holding the port
            # on our behalf. Unwiring then removes the config of a working pin,
            # and every session that dials during the gap gets
            # ConnectionRefused. The state-file arbitration above cannot see
            # this: a successor publishes its record and rewires only once it
            # is serving, so between our decision and its publication the files
            # say we are alone while the port says otherwise.
            if _successor_is_serving():
                _log_lifecycle(
                    f"port {_wired_port()} is still served — leaving the "
                    f"wiring alone"
                )
                return
            # Put ``.claude.json`` back the way we found it. Without this the
            # env block keeps naming the port we just stopped serving, and
            # Claude Code applies that block at boot — so EVERY session started
            # afterwards dials a dead proxy and retries forever, with every
            # proxy behind it healthy and unreachable behind it. An optional
            # feature must not be able to take the required path down with it.
            # wire_global_config(None, None) restores whatever proxy the user
            # or their launcher had before we wrote ours, which is exactly what
            # `pin --clear` already does — the call simply never ran on the
            # path where the daemon goes away by itself.
            try:
                wire_global_config(None, None)
                _log_lifecycle("unwired .claude.json — sessions fall back")
            except Exception as exc:  # noqa: BLE001
                # NAME THE FAILURE. If the unwire does not happen, every
                # session started afterwards dials a port nothing serves, and
                # that is the outage this whole path exists to prevent.
                _log_lifecycle(f"COULD NOT unwire .claude.json: {exc!r}")
        finally:
            done.set()

    # A recycle/cc-update TERM runs the same cleanup as an idle teardown.
    _install_signal_teardown(_teardown)

    threading.Thread(
        target=_watch_own_code,
        args=(proxy, account_num, email, certdir, done, _teardown),
        daemon=True,
    ).start()

    threading.Thread(
        target=watch_refcount,
        args=(fifo, _teardown),
        # The daemon's own connection count, so "is anyone using me" has an
        # answer on macOS too (/proc/net/tcp does not exist there).
        kwargs={"live_clients": proxy.live_client_count},
        daemon=True,
    ).start()
    # BOUNDED, so a signal callback actually RUNS. CPython executes a signal
    # callback on the MAIN thread only, and only when that thread next runs
    # bytecode. The kernel delivers to whichever thread has not blocked the
    # signal — its C handler there clears the pending bit and sets a flag, but
    # a main thread parked in an UNTIMED wait is never woken by a signal that
    # went elsewhere, so the flag sits set and this daemon keeps serving. Every
    # reading says "healthy process that dropped the signal":  SigCgt 0x…4000
    # (SIGTERM caught)   SigPnd 0   ShdPnd 0 threads: _accept_loop in accept(),
    # main here SIGTERM -> a worker thread : still alive after 8s SIGTERM ->
    # the process     : exited after 0.10s  In the suite this was an
    # intermittent "no successor within 3.0s" — the holder never saw an exit
    # because there was none. In production the TERM comes from `_kill_daemon`
    # (a recycle, or the orphan sweep), and that one ESCALATES: 32s later —
    # `_DRAIN_SECONDS` plus the 2s of slack — it sends SIGKILL. So the dropped
    # signal does not leave the old daemon serving; it converts an orderly
    # handover into a force-kill, with `stop(drain=…)` never entered and every
    # in-flight request cut. That is precisely the guarantee `_kill_daemon`
    # says this release makes, failing silently, and the escalation is what
    # hides it: the daemon does die, on time, so the recycle reports success.
    # 0.5 s rather than a wakeup fd: the cost is one loop iteration twice a
    # second in a process that is otherwise idle, against a selector and a
    # second teardown path to keep in step with this one.
    while not done.wait(0.5):
        pass


def wire_env(
    env: dict[str, str],
    port: int,
    ca_path: Path,
    open_refcount: bool = True,
) -> dict[str, str]:
    """Return a copy of ``env`` routed through the pin proxy.

    Sets ``HTTPS_PROXY``/``https_proxy`` to the proxy and makes Node trust our
    MITM CA. Node's ``NODE_EXTRA_CA_CERTS`` takes exactly one file, so when the
    session already trusts another CA (a corporate MITM, another local proxy)
    the two PEMs are merged into
    ``<ca dir>/ca-bundle.pem`` — never replaced.

    ``open_refcount`` controls the refcount holder. In-process callers
    (session.py, which execs claude and hands off its own fds) pass True: we
    open an inheritable write fd on the FIFO here so the exec'd claude keeps it.
    The shell path (pin-env) passes False — the SHELL must open the fd (this
    process exits immediately, so a fd we opened would close and tear the daemon
    down at once); pin-env emits the `exec {fd}<>fifo` for the shell instead.
    """
    out = dict(env)
    # Same derivation as the global config path: the CA's directory is the
    # cert dir, which holds the proxy credential.
    proxy = _proxy_url(port, Path(ca_path).parent)
    out["HTTPS_PROXY"] = proxy
    out["https_proxy"] = proxy
    # Rewrite an ALL_PROXY the caller already had; never create one. Creating
    # one here would be worse than useless: this env can be eval'd into the
    # user's SHELL (pin-env), where an ALL_PROXY we invented would send that
    # shell's git, uv and gh through an account-pinning MITM built for one
    # client.
    for key in ("ALL_PROXY", "all_proxy"):
        if key in out:
            out[key] = proxy
    # Marks this env as already pinned, so a nested launch records the proxy
    # we chain THROUGH as upstream rather than us (see _ambient_proxy).
    out["CSWAP_PIN_PORT"] = str(port)
    out["NODE_EXTRA_CA_CERTS"] = str(
        _trust_file(ca_path, env.get("NODE_EXTRA_CA_CERTS"))
    )
    # Python does not read NODE_EXTRA_CA_CERTS. Evenly across all seven
    # accounts; only the disabled one shows it, because the engine's other path
    # never re-polls it to reset the counter.
    #
    # NO SSL_CERT_FILE HERE EITHER — see the note in `wire_global_config`. The
    # python callers this was written for (the statusline nudge shelling out to
    # `cswap list`, the usage poll) are served by
    # `oauth._pin_aware_ssl_context()`, which ADDS the pin CA to a default
    # context and cannot narrow trust on any machine.

    # Attach this launch as a refcount holder: open a write fd on the FIFO and
    # mark it inheritable so the exec'd claude keeps it open for its lifetime.
    # The daemon's reader sees EOF only when every such fd closes → idle
    # teardown. O_RDWR so the open never blocks even if the daemon died.
    fifo = refcount_fifo_path(Path(ca_path).parent)
    out["CSWAP_PIN_FIFO"] = str(fifo)
    if open_refcount and fifo.exists():
        try:
            fd = os.open(str(fifo), os.O_RDWR)
            os.set_inheritable(fd, True)
            out["CSWAP_PIN_REFCOUNT_FD"] = str(fd)
        except OSError:
            pass
    return out


UPSTREAM_HOST = "api.anthropic.com"
UPSTREAM_PORT = 443


def _config_home_for_policy() -> Path:
    """Where Claude Code keeps `policy-limits.json`. A seam, so a test can
    point it somewhere that is not the developer's real config home."""
    return require("paths").get_claude_config_home()


def _active_oauth_token() -> "str | None":
    """The access token of the account cswap currently has active.

    THROUGH cswap's OWN READER, not the credentials FILE. On macOS the live
    credential lives in the Keychain and that path does not exist — so a file
    version silently did nothing on two of three machines, which is exactly
    the shape of failure the policy repair exists to end.
    """
    try:
        sw = require("switcher").ClaudeAccountSwitcher()
        raw = json.loads(sw._read_credentials() or "{}")
        return (raw.get("claudeAiOauth") or {}).get("accessToken") or None
    except Exception:  # noqa: BLE001 — never take the daemon down
        return None


def _verifying_context() -> "ssl.SSLContext":
    """A context that trusts the pin's own MITM certificate.

    THE HOST MAY NOT HAVE THE HELPER. `oauth._pin_aware_ssl_context` ships
    with a host that is still unreleased, and claude-swap is a PEER whose
    version we do not choose — the RELEASED one has no such attribute. Naming
    it unconditionally raises AttributeError inside a function whose `except`
    turns everything into `None`, so on a released host the policy repair goes
    back to being the silent no-op it was before it was fixed. Measured on CI,
    which installs exactly that host.

    We do not need the host for this. The pin ISSUES the CA in question, so it
    can add it itself; the helper is used when present only because it also
    picks up whatever else that host knows to trust.
    """
    helper = getattr(oauth, "_pin_aware_ssl_context", None)
    if helper is not None:
        try:
            return helper()
        except Exception:  # noqa: BLE001 — fall through to our own
            pass
    ctx = ssl.create_default_context()
    try:
        bundle = require("switcher").ClaudeAccountSwitcher().backup_dir \
            / "pin-proxy" / "ca-bundle.pem"
        if bundle.exists():
            ctx.load_verify_locations(cafile=str(bundle))
    except Exception:  # noqa: BLE001 — an unpinned machine has no bundle
        pass
    return ctx


def policy_limits_for(token: "str | None") -> "dict | None":
    """The org-policy document the server returns for ONE account.

    Which account is the caller's decision, and on a pinned machine it is the
    PIN's — see `sweep_policy_once`. This document carries
    `allow_remote_control`, `allow_routines` and the compliance taints, so
    asking as the wrong account applies one org's restrictions to another
    org's session.

    ``None`` when it could not be asked, which the caller must keep apart from
    an empty document — see `sweep_policy_once`.
    """
    if not token:
        return None
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/api/claude_code/policy_limits",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json",
                     "anthropic-version": "2023-06-01",
                     "anthropic-client-platform": "cli"})
        # THROUGH THE PIN, WHICH RE-SIGNS THIS HOST. The daemon's own egress is
        # wired to the pin, so this request is MITM'd with a certificate signed
        # by the pin's CA — which a default context does not trust. `grep
        # 'refreshed the org-policy cache' daemon.log` returned 0 across every
        # rotation on this host — the repair had never once run, and nothing
        # said so.
        with urllib.request.urlopen(
                req, timeout=10, context=_verifying_context()) as resp:
            doc = json.loads(resp.read().decode())
        return doc if isinstance(doc, dict) else None
    except Exception:  # noqa: BLE001 — never take the daemon down
        return None


#: Claude Code re-fetches its profile once `oauthAccount.profileFetchedAt` is a
#: day old (2.1.261 `Spe`: 86400000 ms) and writes the answer into the field
#: WHOLE, account uuid included. That fetch travels as the ACTIVE account, so
#: on a pinned machine it is the write that moves the field off the pin. A
#: spliced identity younger than this never opens that gate.
_PIN_PROFILE_MAX_AGE_S = 12 * 3600.0


def _profile_stamp_ms(ident) -> float:
    """`profileFetchedAt` as a number, or 0 when absent or unreadable."""
    v = (ident or {}).get("profileFetchedAt") if isinstance(ident, dict) else None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return 0.0
    return float(v)


def profile_identity_from(doc, now_ms=None) -> "dict | None":
    """`oauthAccount` as Claude Code writes it from `/api/oauth/profile`.

    The same keys and the same absent-vs-null rules as CC's own writer
    (2.1.261 `XQe`), because its profile gate tests these names: a field
    spelled differently here is a field CC finds missing, and a missing one
    re-opens the fetch this exists to keep closed.
    """
    if not isinstance(doc, dict):
        return None
    acct, org = doc.get("account"), doc.get("organization")
    if not isinstance(acct, dict) or not isinstance(org, dict):
        return None
    uuid = acct.get("uuid")
    if not isinstance(uuid, str) or not uuid:
        return None
    flags = org.get("cc_onboarding_flags")
    out = {
        "accountUuid": uuid,
        "hasExtraUsageEnabled": bool(org.get("has_extra_usage_enabled")),
        "ccOnboardingFlags": flags if flags is not None else {},
        "claudeCodeTrialEndsAt": org.get("claude_code_trial_ends_at"),
        "claudeCodeTrialDurationDays": org.get("claude_code_trial_duration_days"),
        "seatTier": org.get("seat_tier"),
        "profileFetchedAt": int(time.time() * 1000 if now_ms is None else now_ms),
    }
    # No `??` on CC's side for `created_at`: a server null is stored as JSON
    # `null`, not omitted, or CC's gate (`!== void 0`) reads the omission as
    # unset and re-fetches. But `acct.get(...)` cannot tell that null apart
    # from an absent key, and an absent key IS what CC's own writer produces
    # (`JSON.stringify` drops the `undefined` property) -- so the key itself
    # tracks presence in `acct`, not just its value.
    if "created_at" in acct:
        out["accountCreatedAt"] = acct.get("created_at")
    # `?? void 0` on CC's side: absent when the server sends nothing, never null.
    for key, val in (("emailAddress", acct.get("email")),
                     ("organizationUuid", org.get("uuid")),
                     ("billingType", org.get("billing_type")),
                     ("subscriptionCreatedAt", org.get("subscription_created_at"))):
        if val is not None:
            out[key] = val
    for key, val in (("displayName", acct.get("display_name")),
                     ("fullName", acct.get("full_name"))):
        if val:
            out[key] = val
    return out


def pin_profile_for(token: "str | None") -> "dict | None":
    """The pinned account's own profile in `oauthAccount` shape, or None.

    Asked with the PIN's bearer, so the stamp it carries is true and the
    fields are the pin's own -- not a copy of whatever account was live when
    the pinned slot was last the login. Same route Claude Code asks, which is
    deliberately unswapped by this proxy, so the bearer we send is the one the
    server answers for.
    """
    if not token:
        return None
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/api/oauth/profile",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json",
                     "anthropic-version": "2023-06-01",
                     "anthropic-client-platform": "cli"})
        with urllib.request.urlopen(
                req, timeout=10, context=_verifying_context()) as resp:
            doc = json.loads(resp.read().decode())
        return profile_identity_from(doc)
    except Exception:  # noqa: BLE001 — never take the daemon down
        return None


class PinProxy:
    """A CONNECT forward proxy that MITMs api.anthropic.com and swaps the
    Authorization bearer to a pinned token on the RC/Artifact routes.

    Non-anthropic CONNECTs are blind-tunnelled (optionally through the upstream
    proxy that was on HTTPS_PROXY before us). The anthropic connection is
    terminated with our leaf cert, the decrypted request is inspected, and —
    on a pinned route — its Authorization is replaced before being re-issued
    to the real upstream over TLS.
    """

    def __init__(
        self,
        certdir: Path,
        pin_token_provider: "Callable[[], str | None]",
        upstream: tuple[str, int] | None = None,
        chain_proxy: tuple[str, int] | None = None,
        host: str = "127.0.0.1",
        rediscover_chain: bool = False,
    ):
        self._certdir = Path(certdir)
        self._pin_token_provider = pin_token_provider
        # Inference-follows (opt-in; see `inference_follow_entrypoints`).
        self._inference_tokens = _ActiveTokenCache()
        self._inference_stats = _InferenceStats(self._certdir)
        self._inference_eps_logged: "frozenset[str] | None" = None
        self._inference_first_swap_logged = False
        self._inference_retry_logged_at = 0.0
        # Where the MITM'd anthropic request is really sent. Defaults to the
        # real upstream; tests point it at a fake server.
        self._upstream = upstream or (UPSTREAM_HOST, UPSTREAM_PORT)
        # A proxy to CONNECT through for egress (a corporate proxy, another
        # local MITM). Fixed when rediscover_chain is False (tests); otherwise
        # re-read from the on-disk hint per connection, so the daemon follows
        # an egress proxy that moved or came up after it did.
        self._chain = chain_proxy
        self._rediscover_chain = rediscover_chain
        self._host = host
        # Whether egress is currently bypassing the chain, and through which
        # hop when it is not — see _note_egress.
        self._egress_direct = False
        self._egress_hop: "tuple[str, int] | None" = None
        # STICKY, unlike the two above. They are the state right now, so a
        # chain that breaks and recovers reads green to every probe that
        # arrives after it — and every probe arrives after it, because nobody
        # is watching at the instant it breaks. See `direct_last`.
        self._egress_direct_last: "float | None" = None
        # DEGRADED, not abandoned — see `hop_degraded_last`. Separate from the
        # one above because falling to a LATER hop is still egress through a
        # configured proxy, so `direct` stays False and that stamp never runs.
        self._hop_degraded_last: "float | None" = None
        # The last hop fault reported, so a steadily-down hop costs one line
        # instead of one per connection — see _note_hop_unusable.
        self._hop_fault: "tuple[tuple[str, int], str] | None" = None
        # The credential a client must present on CONNECT is re-read per
        # connection, not cached here — ``_current_secret``.
        self._bundle = ensure_ca(self._certdir, UPSTREAM_HOST)
        self._server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._server_ctx.load_cert_chain(
            str(self._bundle.leaf_path), str(self._bundle.leaf_key_path)
        )
        self._srv: socket.socket | None = None
        # Per-connection upstream socket. Each MITM connection is served on
        # its own thread, so a thread-local keeps one upstream per client.
        self._local = threading.local()
        self._conn_seq = itertools.count(1)
        # Clients connected right now, in `_open_conns` — the daemon's own
        # record, because the /proc-based probe is Linux-only and its None
        # reads as "idle" on the machines that cannot answer (see
        # ``_serve_client``). No separate counter: see `live_client_count`.
        self._live_lock = threading.Lock()
        # One bridge sweep at a time. A session opening fires several calls in
        # a burst; without this each would start its own listing.
        self._bridge_sweeping = False
        self._last_bridge_sweep: float | None = None
        self._sweep_lock = threading.Lock()
        # The connections themselves, not just a count. `stop()` has to CLOSE
        # them before the process exits — see the note there on why a drained
        # request still ends in RST without this.
        self._open_conns: set = set()
        # REQUESTS IN FLIGHT, which is a different question from connections
        # open, and it is the one a drain has to ask. A connection can be open
        # for the whole session while carrying no work at all — Remote
        # Control's WebSocket is opaque after the 101 and is pumped by the
        # shared selector, not by a request thread. Counting connections made
        # the drain wait for a zero that could never arrive, so it always ran
        # to its ceiling and then cut whatever was open, including a reply that
        # had started two seconds earlier.
        # Connections that owe an answer right now — see `inflight_requests`,
        # which is the only reader, and `_owe_answer`, the only writer.
        # conn -> whether any response byte has reached that client yet.
        # A dict rather than a set so a cut can say which of the two it was;
        # see `_note_response_started`.
        self._owed: dict = {}
        # BYTES DELIVERED PER OWED CONNECTION, an instrument and nothing more.
        # Kept beside `_owed` rather than inside its value so the drain's hot
        # predicate keeps comparing a bare float. Cleared with the debt.
        self._delivered: dict = {}
        # HOW MANY WRITES CARRIED AN ANSWER rather than a keepalive. This is
        # what separates a reply still being written from one that stopped and
        # is only being kept warm — see `_is_only_keepalive`. Cleared with the
        # debt, like `_delivered`.
        #
        # WHEN CONTENT LAST REACHED THIS CLIENT — the clock `_content` counts
        # against. `now - this` is the interval `await_inflight` names as the
        # one measurement its refused stall predicate is waiting on, and it
        # only means anything PER CONNECTION: a process-wide byte rate cannot
        # produce it, because twelve replies staggered ten seconds apart look
        # busy every ten seconds while each one is silent for two minutes.
        # Seeded when the debt is taken so a reply that has sent nothing at all
        # is timed from the moment somebody started waiting.
        self._content_at: dict = {}
        # THE LONGEST SILENCE A REPLY SAT IN AND THEN FINISHED ANYWAY. High
        # water, not a snapshot, because the drain that matters most ends with
        # `_owed` EMPTY — that is what "drained clean" means — so anything read
        # off the live set at that moment is 0 by construction, an instrument
        # reporting a constant on the one branch it exists for.
        #
        # Only a COMPLETED response updates it (see `_note_reply_finished`). A
        # connection that closed mid-silence proves nothing about how long a
        # reply can be waited for, and counting it would inflate this in the
        # direction that makes a longer wait look proven safe.
        self._quiet_peak = 0.0
        # THE SAME HIGH WATER FOR BYTES. Banked only when a reply
        # COMPLETES, for the same reason as `_quiet_peak`: a reply that
        # died mid-silence proves nothing, and counting it inflates the
        # number in the direction that makes a longer wait look safe.
        self._byte_peak = 0.0
        # NEVER OBSERVED IS NOT MEASURED ZERO. A daemon that completed no reply
        # at all printed `survived 0s`, identical to one whose replies were
        # never silent — and the field exists to build a population a threshold
        # would be chosen from, so synthetic zeros drag it toward "short waits
        # are enough". Absent renders `n/a`.
        self._quiet_seen = False
        self._byte_seen = False
        # THE LONGEST GAP BETWEEN CONTENT WRITES, per connection, accumulated
        # as they happen. Cleared with the debt like its siblings.
        self._gap: dict = {}
        # THE GAP THE STALL PREDICATE ACTUALLY READS. `_gap` is between
        # CONTENT writes; `_owed_still_moving` reads the last BYTE, and a
        # keepalive is a byte. Without this the two get compared to each
        # other, and a long content gap reads as evidence about a byte
        # ceiling that it cannot speak to in either direction.
        self._byte_gap: dict = {}
        # What the server last said is CONNECTED, filled by the title sweep
        # from the listing it already pays for. None until the first sweep, and
        # None again is never treated as "nothing is connected".
        self._connected_bridges: "set[str] | None" = None
        self._stop = False
        # Wakes the title sweep out of its wait so a join costs nothing. Here
        # rather than in `start()`: a caller can drive the loop without it.
        self._sweep_wake = threading.Event()
        # Ends `_trace_tick_loop` -- set only at the end of `stop()`, never by
        # `release_listener`'s `_stop`. See the note where the thread starts.
        self._trace_tick_stop = threading.Event()
        # True when a supervisor handed us the listening socket. Then the port
        # is not ours to close — see start() and stop().
        self._inherited = False
        # The accept loop, held so a handover can JOIN it rather than merely
        # signal it: two processes accepting on one socket split the
        # connections between them, and the one that has stopped serving drops
        # its share.
        self._accept_thread: threading.Thread | None = None
        # The descriptor handed to a successor, kept only so it can be closed
        # if the spawn fails and we resume serving.
        self._handed_fd: int | None = None
        self.port = 0
        # Opt-in request tracing: CSWAP_PIN_DEBUG=<path> logs one line per
        # request (method, path, whether it matched a pinned route and was
        # swapped). CAPPED, like `daemon.log`. This wrote one line per request
        # into an uncapped append; see `_append_capped`.
        self._debug = None
        # Which path `_debug` is open on, so a re-armed trace does not keep
        # writing to the file it was armed on first.
        self._debug_for = None
        # Same pair, for CSWAP_PIN_SHAPE — see `_trace_tick`.
        self._shape = None
        self._shape_for = None
        # `_trace_tick` logs an open() failure once, not once per tick.
        self._trace_open_warned: set = set()
        # Connections carrying a subscription rather than a reply. Held
        # separately because the drain must treat them the other way round:
        # every other connection is waited for, these are let go.
        self._stream_conns: set = set()
        #: bridge id -> monotonic instant its LAST stream socket went.
        self._stream_lost: dict = {}
        # PER-BRIDGE, and initialised HERE or the accounting is dead in
        # production while every test stays green: `_note_bridge_traffic`
        # swallows its own errors by design, so a missing dict is a silent
        # no-op rather than a failure anyone would see.
        self._reset_bridge_traffic()
        # THE OBJECT THAT OWNS THE DESCRIPTOR. `wrap_socket` detaches the
        # socket it wraps, so the raw `conn` every other structure here keys
        # on has `fileno() == -1` and cannot be shut down or closed. Anything
        # that means to END a connection has to reach the TLS object.

    def start(self) -> None:
        if self._handed_fd is not None:
            # WE HANDED THIS DOWN AND NOBODY TOOK IT — the spawn failed, and
            # this is the resume. The socket never stopped listening, so there
            # is no port to reclaim and no window to lose: take the descriptor
            # back and start accepting on it again.
            fd, self._handed_fd = self._handed_fd, None
            try:
                self._srv = socket.socket(fileno=fd)
                self.port = self._srv.getsockname()[1]
            except OSError as exc:
                _log_lifecycle(f"could not take back the handed-down fd: {exc}")
                self._srv = None
            else:
                self._inherited = False
                self._start_accept_loop()
                return
        # THE ONLY CALLERS THAT SERVE. `_start_accept_loop` is right below,
        # so a client the probe has to accept is served rather than parked
        # forever. The holder and the standby adopt too and never serve.
        handed = _handed_down_listener(will_serve=True)
        if handed is not None:
            # OUR PREDECESSOR'S SOCKET, still listening. It stopped accepting
            # before it passed this down, so connections that arrived during
            # our start-up are waiting in the backlog rather than refused —
            # which is the whole 0.27s gap, closed. The port was never
            # unbound, so there is nothing to reclaim and nothing to race.
            self._srv = handed
            # OURS TO CLOSE ONLY IF NOBODY IS STILL HOLDING IT. A predecessor
            # that handed this over is on its way out, so the socket becomes
            # ours. A HOLDER is not: it is still there and will put a successor
            # on this very socket, so closing it on our way out unbinds the
            # port the holder exists to keep.
            self._inherited = held_by_a_holder()
            self.port = self._srv.getsockname()[1]
            self._start_accept_loop()
            return
        inherited = _inherited_listener(will_serve=True)
        if inherited is not None:
            # A SUPERVISOR OWNS THE PORT. It bound the socket before we existed
            # and will hold it after we exit, so the port answers whether this
            # process is starting, restarting, hung, or gone — the failure mode
            # a same-port reclaim can only recover from, never prevent.
            #
            # This is the systemd socket-activation convention (LISTEN_FDS /
            # LISTEN_PID, first fd = 3), not an agreement with any particular
            # supervisor: anything implementing it can hold our port, and we
            # name none of them.
            self._srv = inherited
            self._inherited = True
            self.port = self._srv.getsockname()[1]
            self._start_accept_loop()
            return
        self._inherited = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Reclaim the port a previous daemon recorded, when it is free.
        #
        # WHAT THE USER ASKED FOR WINS, ahead of every reclaim below. The
        # reclaim order exists to keep LIVE sessions attached across a respawn;
        # a configured port is a standing instruction about where this pin
        # serves, and honouring it only when no record happened to survive
        # would make `--set_port` do nothing on the machines that matter — the
        # ones that have been running. The cost is real and belongs to whoever
        # sets it: moving the port strands sessions whose HTTPS_PROXY was fixed
        # at exec, exactly as the note below describes. That is why nothing
        # here CHANGES the port on its own; it changes only when a human says
        # so.
        want = wanted_port(self._certdir)
        for candidate in ([want] if isinstance(want, int) and want > 0 else []) + [0]:
            try:
                self._srv.bind((self._host, candidate))
                break
            except OSError:
                continue  # taken by something else — fall through to an
                          # ephemeral port
        self._srv.listen(64)
        self.port = self._srv.getsockname()[1]
        # SAY SO WHEN A CONFIGURED PORT WAS NOT HONOURED. The fall-through
        # above is right — a pin must serve rather than refuse — but silence
        # turns "the port I set is not being used" into a mystery whose only
        # symptom is a number that does not match. Everything the reader needs
        # is the two numbers and the reason.
        asked = configured_port(self._certdir)
        if isinstance(asked, int) and asked != self.port:
            _log_lifecycle(
                f"configured port {asked} is not available — serving on "
                f"{self.port} instead"
            )
        self._start_accept_loop()

    def _start_accept_loop(self) -> None:
        """Run the accept loop on a thread we can JOIN, not merely signal.

        Kept as a handle because exactly one process may be accepting on a
        socket at a time. The kernel hands each connection to ONE of the fd
        holders that calls ``accept()``, so a predecessor still inside its
        loop dequeues connections it has already stopped serving — measured
        by a peer on a launcher that kept accepting alongside its child:
        19 of 60 requests lost in steady state, no restart involved.
        """
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        # CLEARED HERE, BEFORE THE THREAD EXISTS TO SEE IT. `release_listener`
        # sets this to wake a title thread it is about to join and never
        # clears it back — so a restart (`_resume_serving` after a handover
        # that failed to come up) used to hand the new thread a pre-set
        # event: its first wait returned instantly, the first-pass budget
        # burned to zero, and the sweep hit the wire immediately instead of
        # after its beat.
        self._sweep_wake.clear()
        self._title_thread = threading.Thread(
            target=self._title_sweep_loop, daemon=True)
        self._title_thread.start()
        # OWN THREAD, NOT `_stop`-GATED. `_trace_tick` used to run off
        # `_title_sweep_loop`'s beat, so a parking tick (a stalled trace-file
        # open) froze that thread's OTHER job, `_carry_on_login_change`, for
        # as long as it parked -- and `release_listener` setting `_stop`
        # ended the tick at a handover, right when a draining process is
        # still relaying the connections it holds and still writing to the
        # trace. Gated on its OWN event (`_trace_tick_stop`, created in
        # `__init__`), set only at the end of `stop()` (after the drain), so
        # the tick outlives `_stop` but not the process -- a `stop()` that
        # never runs used to leak this thread forever, one per proxy the
        # suite ever started.
        self._trace_tick_thread = threading.Thread(
            target=self._trace_tick_loop, daemon=True)
        self._trace_tick_thread.start()
        _provider = getattr(self, "_pin_token_provider", None)
        if getattr(_provider, "can_pin_cached", None) is not None:
            threading.Thread(target=self._warm_mint_cache, daemon=True).start()

    #: How often the daemon re-checks cloud titles. The same cadence the
    #: auto-switch engine used, kept so the API cost is unchanged — this moves
    #: the repair, it does not add a second one.
    _TITLE_SWEEP_S = 300.0

    #: The FIRST pass runs this soon after the daemon starts, not a full period
    #: later. Long enough that a burst of handovers does not put three sweeps on
    #: the wire at once; short enough that a daemon replaced every few minutes
    #: still repairs something.
    _TITLE_SWEEP_FIRST_S = 20.0

    #: How often the wait checks `live_bridge_names()` for a rename made since the wait began.
    _RENAME_CHECK_S = 10.0

    def _title_sweep_loop(self) -> None:
        """Re-check cloud titles on a cadence, because the connect hook cannot.

        THE CONNECT HOOK CANNOT SEE A TITLE THAT DOES NOT EXIST YET. The server
        renames an ACTIVE bridge from the conversation's content long after it
        was created, and `restore_titles_after_connect` has finished by then —
        its own docstring says there is no second chance, "a bridge missed here
        stays wrong until some OTHER session happens to connect".

        The periodic repair that covered this lived in
        `AutoSwitchEngine.tick()`, so THE PIN'S OWN FEATURE WAS SWITCHED OFF BY
        A COMPONENT THE PIN DOES NOT NEED. Measured: `.auto-live.lock` free
        (no live engine — the TUI's `on_unmount` releases it), the last restore
        logged 21 minutes before the bridge in question was even created, and
        that bridge then sat under two different server-written sentences. The
        archived bridges beside it were all correct, because their
        conversations had stopped and the server had stopped renaming them.

        The daemon is always running; the repair belongs here. Sleep in short
        steps so `_stop` ends the thread promptly rather than up to five
        minutes later.

        THE FIRST PASS IS EARLY, AND THAT IS NOT A DETAIL. This loop first
        slept a full interval and only then worked, which is correct only for a
        process that outlives its own period. This daemon does not: a deploy
        replaces it, and so does a holder cycling its child — MEASURED, a
        serving daemon 4.8 minutes old while titles had been wrong for over an
        hour, because every handover restarted the clock before the first sweep
        could fire. A repair that never runs is the defect this whole change
        exists to remove, reintroduced one layer down.
        """
        first = True
        while not self._stop:
            waited = 0.0
            budget = self._TITLE_SWEEP_FIRST_S if first else self._TITLE_SWEEP_S
            first = False
            try:
                names = live_bridge_names()
            except Exception:  # noqa: BLE001 — never take the sweep down
                names = None
            while waited < budget and not self._stop:
                # WAKEABLE, not a bare sleep. `release_listener` joins this
                # thread, and a poll-only wait makes that join pay up to half
                # a second on the handover path for nothing.
                self._sweep_wake.wait(0.5)
                waited += 0.5
                if this_process_is_draining():
                    continue
                # THE LOGIN CAN MOVE INSIDE THE BEAT. Claude Code watches
                # ~/.claude.json and tears a bridge off the moment the account
                # it names stops matching the pointer; this sweep is 300s
                # behind it. Measured: a login changed, two LIVE sessions were
                # torn off 3m18s later, and the beat that would have restamped
                # them was still 1m42s away.
                #
                # Gated on the file's mtime so the ordinary tick costs a stat:
                # the file is rewritten every 10-30s and the identity in it
                # almost never moves, so the parse runs only when it might
                # have. The carry itself skips records that already agree, so
                # a spurious wake writes nothing.
                #
                # `live_bridge_names()` runs here too, inside the same guard:
                # an absurd `pid` in a session record can raise something
                # `_pid_alive` does not catch, and that must not take the
                # sweep thread down any more than a login-carry failure would.
                #
                # NARROWED TO A RENAME. Comparing the whole dict woke this on
                # ANY change to the live named-bridge SET -- a second session
                # starting or an existing one exiting -- which is ordinary
                # churn, not a rename, and drove the beat to
                # `_RENAME_CHECK_S` on every such event. Only a value
                # changing under a key present BOTH before and now is a
                # rename; a key appearing or vanishing is compared from the
                # next check on, not this one.
                try:
                    self._carry_on_login_change()
                    if names is not None and waited % self._RENAME_CHECK_S == 0:
                        cur = live_bridge_names()
                        if any(cur[k] != v for k, v in names.items() if k in cur):
                            break
                        names = cur
                except Exception:  # noqa: BLE001 — never take the sweep down
                    pass
            if self._stop:
                return
            # A daemon that handed over serves the connections it still holds
            # and nothing else: the successor owns the config, the pointers
            # and the titles, and a second beat on the same files is a second
            # writer.
            if this_process_is_draining():
                continue
            try:
                self.sweep_titles_once()
            except Exception:  # noqa: BLE001 — never take the daemon down
                pass
            # ON THE SAME BEAT, and deliberately after the titles: both are
            # repairs of state a live session reads, and one API call each.
            # Separate try/except so a title failure cannot skip the policy —
            # the policy one is the difference between Remote Control working
            # and being refused machine-wide.
            try:
                self.sweep_policy_once()
            except Exception:  # noqa: BLE001 — never take the daemon down
                pass
            # AND THE POINTER, which decides whether a reattach is attempted at
            # all. A stale one sends Claude Code down the MINT path, and
            # minting is what the policy gate can refuse — so these two are the
            # halves of "Remote Control still works after the account moved".
            try:
                login = _pointer_owner(getattr(self, "_certdir", None))
                if login:
                    self.carry_live_pointers(login)
            except Exception:  # noqa: BLE001 — never take the daemon down
                pass
            # AND THE PIN'S OWN PROFILE STAMP, on the same beat. The splice
            # writes the remembered identity, and Claude Code re-fetches its
            # profile as the ACTIVE account once that stamp is a day old --
            # the write that starts every account oscillation seen here. Kept
            # younger than that from the server, as the pin, and re-asserted
            # so the live config carries it before CC's gate would open.
            # Idempotent: the splice writes only when the field moved or the
            # stamp there is older than ours.
            try:
                self._freshen_pin_identity()
                ident = remembered_pin_identity(getattr(self, "_certdir", None))
                if ident:
                    splice_config_identity(ident)
            except Exception:  # noqa: BLE001 — never take the daemon down
                pass
            # NOTHING HERE ACTS ON A PROCESS. Everything above repairs state a
            # session will read next time it looks. A session whose refusal is
            # cached in memory is not repaired by ending it: that is the user's
            # session, and the pin does not decide when one restarts. The cause
            # is a policy answer fetched while the pin was not in that
            # session's path, and that is where it is fixed.

    def _trace_tick_loop(self) -> None:
        """Run `_trace_tick` on its own 0.5s beat, until `stop()` ends it --
        see the note where this thread is started."""
        while not self._trace_tick_stop.is_set():
            try:
                self._trace_tick()
            except Exception:  # noqa: BLE001 — never take this thread down
                pass
            self._trace_tick_stop.wait(0.5)

    def _warm_mint_cache(self) -> None:
        """Populate the mint cache ONCE, off the request path and off
        `/health` -- see the note where this thread is started.

        `/health` now reads `can_pin` only from what is already cached
        (`_can_pin_from_cache`), so without this a healthy daemon reports
        it False until its first real pinned request warms the cache
        itself. ONE call, no retry: a stalled store shows up as
        `mint_stalled` on the very next `/health` peek (the read runs under
        `refresh_lock`, see `_MINT_LOCK_BOUND_S`), and a failed or slow warm
        just leaves the cache cold for the first real request to pay for
        instead.
        """
        try:
            self._pin_token_provider()
        except Exception:  # noqa: BLE001 — a warm attempt is never fatal
            pass

    def _trace_tick(self) -> None:
        """(Re)open and cap the opt-in traces off the request path.

        The only place `self._debug`/`self._shape` are opened, rotated or
        re-targeted now. `_serve_client` and the CSWAP_PIN_SHAPE writer only
        ever write to whatever this leaves open, or drop the line — see
        `_write_capped_line`. Runs on its own `_trace_tick_loop` thread, so
        this runs at worst every 0.5s, which is not on the request path.

        A line written between a re-arm (or a cap crossing) and the next tick
        is lost. Accepted: a diagnostic gap is cheaper than the proxy parking
        every request thread inside `open(2)` on it, which is the incident
        this replaces.
        """
        debug_path = trace_target(getattr(self, "_certdir", None))
        if debug_path != self._debug_for:
            self._debug, self._debug_for = None, debug_path
        if debug_path:
            self._debug = self._reopen_trace(
                "debug", debug_path, self._debug, _TRACE_MAX_BYTES)

        shape_path = os.environ.get("CSWAP_PIN_SHAPE")
        if shape_path != self._shape_for:
            self._shape, self._shape_for = None, shape_path
        if shape_path:
            self._shape = self._reopen_trace(
                "shape", shape_path, self._shape, _LOG_MAX_BYTES)

    def _reopen_trace(self, key: str, path: str, fh, cap: int):
        """Rotate and (re)open one trace handle. Only `_trace_tick` calls this.

        Never raises: an ``open()`` that fails here leaves the handle at
        ``None`` (so the request path keeps dropping the line, per
        `_write_capped_line`'s contract) and says so on stderr once per `key`,
        not once per tick — the same "once per daemon" restraint
        `_warn_unpinnable` uses, for the same reason: a tick fires every 0.5s
        and a line each would bury the signal.
        """
        try:
            if fh is not None and not fh.closed and fh.tell() > cap:
                fh.close()
                fh = None
            if fh is None or fh.closed:
                _rotate_if_over(Path(path), cap)
                fh = open(path, "a", buffering=1, encoding="utf-8",
                          errors="replace")
            return fh
        except (OSError, ValueError) as exc:
            if key not in self._trace_open_warned:
                self._trace_open_warned.add(key)
                _log_lifecycle(
                    f"the {key} trace at {path} could not be (re)opened "
                    f"({exc}); it stays off until this daemon is replaced")
            return None

    def _note_stream_end(self, bridge: str, seconds: float, closer: str) -> None:
        """One line per bridge per minute when its inbound stream ends; the
        ends the cooldown swallows are counted into the next line. A give-up
        leaves no error anywhere else: the stream just ends, repeatedly."""
        now = time.monotonic()
        led = getattr(self, "_stream_ends", None)
        if led is None:
            led = self._stream_ends = {}
        last, more = led.get(bridge, (None, 0))
        if last is not None and now - last < _STREAM_END_COOLDOWN_S:
            led[bridge] = (last, more + 1)
            return
        led[bridge] = (now, 0)
        extra = f"; {more} more in the last minute" if more else ""
        _log_lifecycle(
            f"the inbound stream for {bridge[:16]} ended after {seconds:.1f}s, "
            f"closed by the {closer}{extra}")

    def _carry_on_login_change(self) -> bool:
        """Carry immediately when the signed-in account moves, not on the beat.

        Returns whether a carry ran, so a test can assert the trigger rather
        than the schedule. Never raises: the caller is a sleep loop.
        """
        path = _config_home_for_policy().parent / ".claude.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return False
        if mtime == getattr(self, "_login_seen_mtime", None):
            return False
        login = _login_identity()
        # A READ THAT LEARNED NOTHING MUST NOT CONSUME THE GATE. Recording the
        # mtime first means one unreadable pass — the config caught mid-write,
        # a partial parse — retires that mtime for good, and the carry it owed
        # never runs. The bridge pointers then disagree with the config at the
        # next reattach, which is a fresh mint: a new name and no history.
        # Leave the gate open so the next look retries.
        if login is None:
            return False
        self._login_seen_mtime = mtime
        prev = getattr(self, "_login_seen", None)
        if login == prev:
            return False
        # NO FIRST-OBSERVATION SKIP. A `/login` made while this daemon was
        # down has no predecessor to differ from, and every deploy recycles
        # the daemon — so skipping the first tick loses exactly the case it
        # matters in. Nothing is wasted on an unchanged machine either:
        # `carry_live_pointers` already returns without writing when a
        # record's owner equals the login.
        # THE DETECTION, NOT ONLY THE OUTCOME. `carry_live_pointers` logs
        # under `if carried:`, so a pass that moves nothing is silent, and
        # that silence cannot be told from never having noticed the login.
        # This line is what dates the detection against a tear-off.
        #
        # OPT-IN, and truncated. Every other line in this log earns its place
        # on someone else's machine by being about an outage; this one is for
        # chasing a cause and would otherwise put an account identifier in a
        # third party's log for nothing. Same switch as the request trace, so
        # it turns on and off without restarting the daemon being observed.
        if trace_target(getattr(self, "_certdir", None)):
            _log_lifecycle(
                "the signed-in account moved (%s -> %s); carrying live bridge "
                "pointers now"
                % (str((prev or ("?",))[0])[:12], str(login[0])[:12]))
        self._login_seen = login
        self.carry_live_pointers(
            _pointer_owner(getattr(self, "_certdir", None)) or login)
        return True

    def carry_live_pointers(self, login: "tuple[str, str]") -> int:
        """Delegate to the module-level carry.

        A switch runs this with no daemon in the process, so the body
        cannot live on the class. Kept as a method because every
        daemon-side caller reaches it that way.
        """
        return carry_live_pointers(login)

    def clear_dead_bridge_records(self, listed: "set[str] | None") -> int:
        """Let a live session mint a new bridge when its own no longer exists.

        ``listed`` is every bridge id the server returned, whatever its
        status or connection: a disconnected or archived bridge still exists
        and its session reattaches to it, history intact. Only an id absent
        from a COMPLETE listing is a corpse.

        MEASURED across fourteen live sessions on one host — same active
        account, same pin, same restart second. Thirteen had a job record
        naming a DIFFERENT bridge than their transcript's last one: they had
        minted a replacement and moved on. One did not. Both of its stores
        named the same id, and that bridge had no worker and no event since the
        session started. It was the only session on the machine refused Remote
        Control, and every machine-wide explanation tried before this one —
        policy file, credential, org, pointer owner — was identical across all
        fourteen.

        Claude Code reads the job record for a background session, so that one
        kept trying to reattach to something that is gone. `clearBridgeSession`
        is CC's own way of writing "this conversation has no bridge", and a
        conversation with no bridge MINTS one — which is precisely what the
        other thirteen did.

        ``None`` means the listing could not be taken and NOTHING is cleared:
        every id looks dead through a failed read, and acting on that would
        wipe the bridge of every live session at once — the worst outcome here,
        from the most ordinary failure.
        """
        connected = listed
        if connected is None:
            return 0
        home = _config_home_for_policy()
        cleared = 0
        for job in _live_job_ids():
            path = home / "jobs" / job / "state.json"
            rec = _read_json(path)
            if not isinstance(rec, dict):
                continue
            bid = rec.get("bridgeSessionId")
            cse = str(bid).replace("session_", "cse_") if bid else ""
            if not bid or cse in connected:
                continue
            # A BRIDGE THAT SPOKE THROUGH THIS PIN JUST NOW IS NOT A CORPSE,
            # whatever one listing says. `connected` is a snapshot from the
            # start of the sweep; a bridge minted since, or mid-reconnect, is
            # absent from it and clearing its record makes the session mint
            # AGAIN -- measured, four records cleared in the minutes after a
            # tear-off, each a live session. The pin saw their posts.
            last = getattr(self, "_bridge_posts", {}).get(cse)
            if last is not None and time.monotonic() - last <= _DEAF_WINDOW_S:
                continue
            fresh = _read_json(path)      # re-read: their writes win on the rest
            if not isinstance(fresh, dict) or fresh.get("bridgeSessionId") != bid:
                continue
            fresh["bridgeSessionId"] = ""
            tmp = path.with_name(f".state.json.cswap-{os.getpid()}")
            try:
                tmp.write_text(json.dumps(fresh), encoding="utf-8")
                tmp.replace(path)
            except OSError:
                continue
            cleared += 1
        if cleared:
            _log_lifecycle(
                f"cleared {cleared} job record(s) naming a bridge the server no "
                f"longer has, so those sessions can mint a live one")
        return cleared

    def sweep_policy_once(self) -> bool:
        """Put the ACTIVE account's real policy answer in CC's cache file.

        WHY THE DAEMON. `/remote-control` resolves
        `Ms('allow_remote_control')` -> `Hcd()` -> that file, held in a
        per-process session cache — and Claude Code CLEARS that cache when it
        detects the signed-in account changed, so a LIVE session re-reads it
        without restarting. What it re-reads has to be right already, and the
        file is machine-wide, written with whatever account was active at fetch
        time. MEASURED: a document left by a restricted org denied Remote
        Control to every session on a host for the better part of a day while
        the server placed no restriction on the account actually in use.

        The daemon is the only process that is always running and always knows
        the active account, so keeping this honest is its job.

        A FETCH THAT FAILS CHANGES NOTHING. Absent is DENIED on the reader's
        side, so writing nothing is never the safe default, and truncating on
        an unreachable server would refuse Remote Control machine-wide.

        ASKED AS THE PIN when there is one. The file is machine-wide and every
        session reads it, and those sessions' requests go out as the pinned
        account — so the pin's answer is the one that governs them. MEASURED:
        an enterprise account carrying `allow_remote_control: {"allowed":
        false}` was made active, that denial reached this file and every live
        process's cache, and `/remote-control` refused for hours on sessions
        pinned to an account the server placed no restriction on. Two accounts
        in different orgs is the pin's whole purpose, not an edge case.
        """
        doc = policy_limits_for(
            self._pin_token_provider() or _active_oauth_token())
        if not isinstance(doc, dict):
            return False
        path = _config_home_for_policy() / "policy-limits.json"
        try:
            if path.exists() and json.loads(
                    path.read_text(encoding="utf-8")) == doc:
                return False       # already right; no write, no churn
        except Exception:  # noqa: BLE001 — unreadable counts as "replace it"
            pass
        try:
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(doc), encoding="utf-8")
            tmp.replace(path)      # atomic: no reader sees half a document
        except OSError:
            return False
        _log_lifecycle("refreshed the org-policy cache for the account "
                       "these sessions travel as")
        return True

    def revive_archived_bridges(self, sessions: list[dict], token: str) -> int:
        """Unarchive the bridges a LIVE session on this machine still holds.

        AN ARCHIVED BRIDGE UNDER A LIVE SESSION IS A BROKEN RECONNECT.
        `/remote-control` on an `active` bridge just reattaches; on an archived
        one it has to unarchive first, and that step is where it fails.
        MEASURED: thirteen live sessions on one host held `active` bridges and
        reconnected fine, the fourteenth held an `archived` one and was refused
        — the same account, the same machine, the same minute.

        OWNERSHIP COMES FROM THE REGISTRY, exactly as it does for titles: a
        bridge is in `live_bridge_names()` only because a process running HERE
        holds it — or held it, for an id recovered from the job record after a
        teardown cleared the registry copy. That widening is why this runs
        BEFORE `clear_dead_bridge_records` in the sweep and can therefore
        unarchive on one stale id, for the one pass it takes that sweep to
        write `""` over it. Reordering is not the answer: the clear keys on
        `connection_status`, which is the same row this revives.

        Another machine's archived bridge is still not ours to revive — this
        host cannot see whether that session is alive, and the pin deliberately
        makes one account hold every machine's bridges.

        Route read from the binary and confirmed against the live API:
        `POST /v1/code/sessions/{id}/unarchive` -> 200. Two plausible
        alternatives are not it — `/v1/sessions/{id}/unarchive` is 404 and
        `DELETE .../archive` is 405 — so this is the shape, not a guess.
        """
        names = live_bridge_names()
        revived = 0
        for item in sessions:
            sid = item.get("id")
            if not sid or sid not in names:
                continue
            if item.get("status") != "archived":
                continue
            if self._bridge_api(
                "POST", f"/v1/code/sessions/{sid}/unarchive", token
            ) is not None:
                revived += 1
        if revived:
            _log_lifecycle(
                f"revived {revived} archived bridge(s) a live session still holds")
        return revived

    def sweep_titles_once(self) -> int:
        """One pass: mint, list, restore. Returns how many titles were put.

        Separate from the loop so the behaviour is testable without timing,
        and so a caller that already knows something changed can run it now.
        """
        token = self._pin_token_provider()
        if not token:
            return 0            # nothing to do without the pinned identity
        sessions = self._list_bridges(token)
        if sessions is None:
            return 0            # asked and got nothing — not "nothing to fix"
        # ON THE LISTING WE ALREADY PAID FOR. Reviving an archived bridge and
        # restoring its title are two repairs of the same object, and both are
        # decided from the same rows — a second listing would buy nothing but
        # a second chance for the account to have moved underneath us.
        self.revive_archived_bridges(sessions, token)
        # ON THE SAME LISTING. `connected` is what the server says is attached
        # right now, and it feeds the deaf report only. The clear below is
        # decided on EXISTENCE: a bridge that is listed, disconnected or
        # archived, is one its session reattaches to (Claude Code unarchives
        # on reconnect) and reattaching is what keeps the conversation's
        # history. Clearing on `connected` made a torn-off session MINT on
        # its next /remote-control -- an empty duplicate beside the bridge
        # that held everything, measured on one of two sessions reconnected
        # the same way, the other still pointing at its bridge. Only a
        # COMPLETE listing may say a bridge is gone.
        self._connected_bridges = {
            r.get("id") for r in sessions
            if r.get("connection_status") == "connected" and r.get("id")}
        if getattr(self, "_listing_complete", False):
            self.clear_dead_bridge_records(
                {r.get("id") for r in sessions if r.get("id")})
        return self._restore_bridge_titles(sessions, token)

    def release_listener(self, hand_down: bool = False) -> "int | None":
        """Stop accepting, leaving open connections alone. The fd if handed down.

        The half of :meth:`stop` a handover needs FIRST. ``stop(drain=N)``
        closes the listener and then waits N seconds before returning, so the
        successor could not bind until the drain was over and the port was
        unbound for all of it — measured at 31 s on a live box, with a peer's
        request refused inside the window.

        Splitting it lets the successor take the port immediately while the
        requests already in flight here keep running; :meth:`await_inflight`
        collects them afterwards.

        ``hand_down`` goes one step further and is what closes the gap
        entirely. Closing the port and letting the successor rebind it is
        instant in the kernel (a rebind after close measured 0.0000s), but the
        successor is a fresh interpreter and takes ~50ms to reach ``bind()`` —
        and neither ``SO_REUSEADDR`` nor ``SO_REUSEPORT`` will co-bind a port
        that is still listening, so that window cannot be overlapped away.
        Measured on a live box: 6 refused requests over 0.27s per handover,
        unchanged by every drain fix. Passing the SOCKET down instead leaves
        the port bound the whole time, so arrivals queue in the backlog:
        0 refused.

        Either way this returns only once our accept loop has ENDED. A
        signalled-but-running loop would keep winning connections from a
        socket it no longer serves.
        """
        self._stop = True
        srv, self._srv = self._srv, None
        # JOIN, do not merely set the flag. The loop polls with a 0.5s
        # timeout, so it can be inside `accept()` right now — and an accept
        # that succeeds after we have handed the socket down takes a
        # connection away from the successor and drops it.
        t = getattr(self, "_accept_thread", None)
        if t is not None and t is not threading.current_thread():
            # WAKE IT, do not wait out its poll. One loopback connect makes
            # accept() return at once; the loop sees `_stop` and ends. Harmless
            # if it races the socket closing, hence the guard.
            if srv is not None:
                try:
                    with socket.create_connection(
                        srv.getsockname(), timeout=0.2
                    ):
                        pass
                except OSError:
                    pass
            t.join(timeout=5.0)
        self._accept_thread = None
        # AND THE TITLE SWEEP, which polls `_stop` every 0.5s. Best-effort:
        # a sweep inside a request carries its own timeout, and returning
        # with the thread still alive is what happens today anyway.
        self._sweep_wake.set()
        tt, self._title_thread = getattr(self, "_title_thread", None), None
        if tt is not None and tt is not threading.current_thread():
            tt.join(timeout=2.0)
        if srv is not None and hand_down:
            if self._inherited and not _orphaned_from_its_holder():
                # NOT OURS TO PASS ON. A supervisor holds this port across our
                # restarts; handing its socket to a child we do not control
                # would leave that child accepting on it after we are gone.
                #
                # UNLESS THE HOLDER IS GONE, which `_inherited` cannot know: it
                # is decided once, in `start()`, and the holder can die
                # afterwards. Refusing then answers about a holder that no
                # longer exists — and the successor's own holder finds the port
                # occupied by us.
                self._srv = srv
                return None
            fd = srv.detach()  # leave it LISTENING and open for the successor
            os.set_inheritable(fd, True)
            self._handed_fd = fd
            return fd
        self._srv = srv
        if self._srv and self._inherited and not _orphaned_from_its_holder():
            # NOT OURS TO CLOSE — a supervisor holds this port precisely so it
            # keeps answering across our restarts. And the same "unless it is
            # gone" as the hand-down above: an orphan detaching here leaves the
            # port BOUND with nobody accepting, which is worse than refused —
            # the handshake completes and the client waits. DETACH, do not just
            # drop the reference. ``detach`` gives up the object and leaves the
            # descriptor open, the same way _inherited_listener refuses a bad
            # fd without closing it.
            try:
                self._srv.detach()
            except OSError:
                pass
            self._srv = None
            return None
        elif self._srv:
            # SHUTDOWN BEFORE CLOSE.
            try:
                self._srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # never listened, or already down
            try:
                self._srv.close()
            except OSError:
                pass
            self._srv = None
        return None

    def live_stream_count(self) -> int:
        """Long-lived channels that would die with this process.

        THIS PROXY'S, not the process's. `_PUMP` is a module global driving
        every tunnel in the process, and folding it in here made one proxy
        report another's — measured on a single-process runner as 2 where 1
        was expected. The reaper wants the process-wide number and reads it
        from the marker, which is written once per process.

        Intersected with the live set: a socket object outlives its descriptor
        and the NUMBER gets reused, so the stream set alone can name a
        connection that is no longer ours.
        """
        with self._live_lock:
            return len(self._stream_conns & self._open_conns)

    def _reset_bridge_traffic(self) -> None:
        """Start the per-bridge accounting. Safe to call more than once."""
        self._bridge_posts: dict = {}
        #: bridge id -> monotonic instant of its most recent birth here:
        #: either a create THIS daemon served within the startup grace, or
        #: a pin-brokered `.../bridge` re-registration (always, and
        #: REASSIGNED on each one, since a re-registration is a new birth).
        #: A bridge inherited on a handover, with neither, never gets an
        #: entry and is judged at once. `deaf_bridges` uses this to give a
        #: just-registered bridge time to open its stream.
        self._bridge_first_post: dict = {}
        #: monotonic instant of the last `POST /v1/code/sessions` this
        #: daemon itself served, or None. Tells a bridge born here from one
        #: this daemon only inherited on a handover, which never posted a
        #: create to it at all.
        self._last_create: "float | None" = None
        # conn -> bridge id, for connections carrying that bridge's inbound
        # stream. NOT "when a stream was last opened": the stream is issued
        # once and held for the life of the session, so a recency stamp ages
        # out while the stream is still there and calls a healthy session
        # deaf. What is asked is whether one is HELD, which is live state.
        self._stream_owner: dict = {}

    def _note_bridge_traffic(self, path: str, now=None, conn=None) -> None:
        """Record that a bridge spoke, and whether it opened its ear.

        A PATH, not a request line. `_WORKER_SUBTREE` and `_BRIDGE_ID` are
        `^`-anchored to a path, so handing them "POST /v1/... HTTP/1.1" matches
        NOTHING. An earlier cut did exactly that: every dict stayed empty and
        `deaf_bridges()` answered [] on every machine, while the tests passed
        bare paths and stayed green.

        Never raises and never blocks: this sits on the request path, so a
        failure here would cost a request rather than a statistic.
        """
        try:
            is_register = _BRIDGE_REGISTER.search(path)
            if not (is_register or _WORKER_SUBTREE.search(path)
                    or _EVENT_STREAM.search(path)):
                return
            bid = _BRIDGE_ID.search(path)
            if not bid:
                return
            stamp = time.monotonic() if now is None else now
            if is_register:
                # A NEW BIRTH, so an ASSIGNMENT, not `setdefault`: a
                # re-registration replaces whatever grace an earlier life
                # of this id earned, exactly as a fresh create would.
                # `_bridge_posts` is untouched -- the register itself is
                # not a worker post, and `deaf_bridges` must still judge
                # this id only once it has actually posted.
                self._bridge_first_post[bid.group(1)] = stamp
                return
            if _EVENT_STREAM.search(path):
                if conn is not None:
                    self._stream_owner[conn] = bid.group(1)
                    # AND THE LOSS IS OVER, so the record of it goes. Keyed by
                    # bridge id it is small, but it would otherwise hold one
                    # entry for every bridge that ever lost a stream, for the
                    # life of the daemon -- the same unbounded shape that once
                    # pinned a socket object per stream here. Bounded to
                    # bridges that are deaf RIGHT NOW, which is the only
                    # population `deaf_for` is ever asked about.
                    self._stream_lost.pop(bid.group(1), None)
            else:
                # NEW TO THIS DAEMON, checked BEFORE the record below moves
                # it in: an old bridge posting again must never backdate its
                # own grace off a create that has nothing to do with it.
                is_new = bid.group(1) not in self._bridge_posts
                self._bridge_posts[bid.group(1)] = stamp
                last_create = getattr(self, "_last_create", None)
                if (is_new and last_create is not None
                        and stamp - last_create < _DEAF_STARTUP_GRACE_S):
                    self._bridge_first_post.setdefault(bid.group(1), stamp)
        except Exception:  # noqa: BLE001 — a statistic must not cost a request
            pass

    def _note_slow_request(self, method: str, path: str,
                           total_ms: float, pin_ms: float,
                           wait_ms: float | None = None) -> None:
        """Record a request that took seconds, because nothing else does.

        `daemon.log` carries lifecycle events, so a slow request leaves no
        trace in the one file a later reader has. Measured on a mac: three
        round trips of 2419/2491/2681ms out of 340 through this proxy, and
        not a line in the log for the window they happened in. A stall is
        precisely what a live claude.ai view times out on, so the thing that
        has to be visible was the one thing that was not.

        `pin_ms` is everything this proxy did BEFORE the request went
        upstream — resolving the pinned credential, the bridge bookkeeping,
        the bounded wait for a token. It is broken out because the two halves
        have opposite fixes and neither can be inferred from the total: the
        pin's own work is ours to make cheaper (the credential read alone is
        0.02ms on linux and 19.8ms on a mac, where it goes through the
        keychain), the remainder belongs to the chain below us.

        `wait_ms` SPLITS THAT REMAINDER, and it is the number that decides
        whose problem this is. It runs from the moment the whole request was
        written upstream to the moment the status line came back, so it is
        time the server had the request and had not answered. What is left
        (total - pin - wait) is our chain getting the bytes out: dialling the
        upstream, the proxy hops, the TLS.

        Without it "0ms inside the pin" is where the diagnosis stops, and it
        stopped there for hours across three sessions — ~38 slow requests an
        hour on two machines, every one of them saying only that the pin was
        not to blame. `None` when the send instant was never stamped (the
        upgrade and take-back paths do not take the normal write), and it
        prints as "unknown" rather than 0: a zero here would read as "the
        server answered instantly", which is the opposite of not knowing.

        Never raises: this runs on the request path.
        """
        floor = slow_report_ms(getattr(self, "_certdir", None))
        if floor is None or total_ms < floor:
            return
        # INFERENCE IS SUPPOSED TO TAKE SECONDS. Reporting them buried the line
        # that meant something — a `/worker/heartbeat` at 5789ms on the same
        # machine in the same window. EXACT, not a prefix: `count_tokens` lives
        # under this route and calls no model, so a slow one is still a stall.
        if path.split("?", 1)[0].rstrip("/") == "/v1/messages":
            return
        now = time.monotonic()
        last = getattr(self, "_last_slow_report", None)
        if last is not None and now - last < _SLOW_REPORT_COOLDOWN_S:
            self._slow_suppressed = getattr(self, "_slow_suppressed", 0) + 1
            return
        self._last_slow_report = now
        suppressed = getattr(self, "_slow_suppressed", 0)
        self._slow_suppressed = 0
        # THE ROUTE, NOT THE IDENTIFIERS. This log is read by people and
        # pasted into reports. The query string was the obvious carrier; the
        # WORKER routes put the bridge id in a path segment, and those are
        # the ones that actually stall — the first line this ever wrote was
        # `/v1/code/sessions/cse_01A7…/worker/events`. The segment is
        # replaced rather than truncated, because which channel stalled is
        # the whole value of the line.
        route = path.split("?", 1)[0]
        seen = _BRIDGE_ID.match(route)
        if seen:
            route = route[:seen.start(1)] + "<id>" + route[seen.end(1):]
        if wait_ms is None:
            split = "the send instant was not stamped, so the wait is unknown"
        else:
            # WHAT IS LEFT IS OURS. Naming it rather than making the reader
            # subtract is the difference between a line you act on and a line
            # you do arithmetic on at 2am.
            #
            # NAME NOTHING. This ran from after the write to the status
            # line, so it covers the server AND every hop the answer returns
            # through, and it cannot separate them. It said "waiting for the
            # server" for one release, which is an attribution wearing a
            # measurement's clothes — and a peer's direct control has since
            # shown the server was fine while that field read 1.7s. What
            # separates them lives outside this proxy.
            ours = max(0.0, total_ms - pin_ms - wait_ms)
            split = (f"{wait_ms:.0f}ms waiting for the answer, "
                     f"{ours:.0f}ms getting it out")
        more = ""
        if suppressed:
            # THE CADENCE IN THE LOG IS THIS COOLDOWN, NOT THE PHENOMENON.
            # One line a minute is a ceiling of 60 an hour, so a machine
            # reporting 34 could be having 300 — and the even spacing invites
            # exactly the periodicity argument the data cannot support.
            more = f"; {suppressed} more in the last minute"
        _log_lifecycle(
            f"a {method} to {route} took {total_ms:.0f}ms "
            f"({pin_ms:.0f}ms of it inside the pin; {split}{more}) — a live "
            f"view times out on stalls like this"
        )

    def _posting_now(self) -> int:
        """Bridges that posted inside the judging window.

        NOT `len(self._bridge_posts)`, which is every bridge this daemon has
        EVER seen and is never pruned. `deaf_bridges` filters by the window,
        so pairing its count with the cumulative total gives a ratio whose two
        halves describe different populations -- it drifts apart for the life
        of the process and reads as the fleet improving while nothing changes.
        """
        posts = getattr(self, "_bridge_posts", None) or {}
        stamp = time.monotonic()
        return sum(1 for last in posts.values()
                   if stamp - last <= _DEAF_WINDOW_S)

    def _deaf_clear_line(self, posted: int, prev) -> str:
        """The all-clear, and what it does NOT cover.

        A CLEAR IS NOT A RECOVERY FOR A BRIDGE THAT WENT QUIET. `deaf_bridges`
        judges only bridges that posted inside its window, so a deaf one
        leaves by falling silent and this line is then true of everything
        still posting and silent about it. Deafness is the one state CC
        cannot leave on its own, so a reader taking that as repaired inverts
        the fact. Whether a silent bridge recovered cannot be answered here;
        naming it is the point, not guessing it.

        What CAN be answered is whether claude.ai is still attached to one,
        and the line says so: that is what separates a silent bridge somebody
        is still looking at from one nobody is.
        """
        line = f"{DEAF_REPORT_CLEAR} ({posted} posting)"
        if not isinstance(prev, list) or not prev:
            return line
        posts = getattr(self, "_bridge_posts", None) or {}
        stamp = time.monotonic()
        gone = [b for b in prev
                if stamp - posts.get(b, -1e9) > _DEAF_WINDOW_S]
        if not gone:
            return line
        # AND WHICH OF THE SILENT ONES STILL HAS A VIEW. Whether a quiet
        # bridge recovered is still unanswerable, but whether claude.ai is
        # attached to it is not, and that is the half that decides whether a
        # popup can appear at all. `_connected_bridges` is the same set
        # `deaf_bridges` scopes itself with, so this costs no new lookup and
        # cannot disagree with the verdict above it.
        #
        # A downstream reader was doing this intersection itself, against a
        # listing it fetched separately -- two sources for one fact, and the
        # one further from the data.
        known = getattr(self, "_connected_bridges", None)
        held = None if known is None else [b for b in gone if b in known]
        if held is None:
            # UNKNOWN IS NOT "ATTACHED TO NOTHING", the same rule the verdict
            # above follows. Claiming an empty intersection off a listing that
            # never answered is how an outage reads as an all-clear.
            tail = (", and no listing was available to say which of them "
                    "claude.ai still holds")
        elif held:
            tail = (f", and claude.ai is STILL ATTACHED to {len(held)} of "
                    f"them, which is where a popup would appear: "
                    f"{' '.join(held)}")
        else:
            tail = (", and claude.ai is attached to none of them, so there is "
                    "no view for a popup to appear in")
        return (line + f" — but {len(gone)} of them stopped posting instead of "
                "recovering, so this line does not cover them and deafness is "
                f"not a state a session leaves by itself: {' '.join(gone)}"
                + tail)

    def _report_deaf_bridges(self) -> None:
        """Say which bridges post but hold no inbound stream, on CHANGE.

        `deaf_bridges` answered correctly and nothing ever asked it: no caller
        in either repo, no CLI, and a method on the daemon's own instance, so
        no other process could. It shipped dormant in three releases. A check
        nothing reaches is not a check.

        THE DAEMON LOG, because the state lives in this process and that file
        is what every monitor on this fleet already reads. Transitions only --
        a line per sweep would bury it, and the event is the set changing.

        Never raises: this is a statistic on the request path.
        """
        try:
            # THE DENOMINATOR DECIDES WHETHER THERE IS ANYTHING TO SAY. With
            # nothing recorded, `deaf_bridges` returns [] — and turning that
            # into "every posting bridge holds an inbound stream" asserts
            # health over an EMPTY population. A monitor reads that as "the
            # check ran and passed", so if the accounting breaks again (it has,
            # twice) every machine would certify health forever. Silence is the
            # honest answer to a question nothing has answered yet.
            if not (getattr(self, "_bridge_posts", None) or {}):
                # A STANDING CLAIM OUTLIVES ITS SUBJECT OTHERWISE. Silence is
                # right for a daemon that never claimed anything, and wrong
                # for one that said "N bridges are deaf" and now has nothing
                # posting: the transition record still reads deaf, and every
                # reader takes the newest transition for the current state.
                # Generic on purpose -- it does not matter whether the
                # sessions were stopped by a person, slept with the machine,
                # crashed, or were recycled by a deploy. The subject is gone,
                # so the verdict goes with it.
                prev = getattr(self, "_last_deaf", None)
                if isinstance(prev, list) and prev:
                    self._last_deaf = []
                    _log_lifecycle(
                        "%s — nothing is posting any more, so the %d bridge(s) "
                        "named there have no subject left to judge and this "
                        "withdraws that verdict rather than leaving it to "
                        "stand" % (DEAF_REPORT_CLEAR, len(prev)))
                return          # nothing posting: no claim either way
            # THE EARLY BRANCH BELOW PRINTS BEFORE THE PREDECESSOR LOOP, so it
            # has no window to drift across and takes its count here.
            posted = self._posting_now()
            # AND THE STREAMS THIS PROCESS NEVER accept()ED. A handover passes
            # the LISTENING socket down, so posts arrive here at once while
            # every established stream stays with the process that accepted it.
            # Asked from local memory alone, a successor calls every pre-
            # existing session deaf: "12 of 12" was logged four minutes into a
            # handover while five daemons were alive holding 98 connections
            # between them, the predecessor holding exactly the nine its own
            # line named as left intact. Nothing was deaf. THE UNION, NOT A
            # REFUSAL. Suppressing the report while any predecessor drains was
            # tried first and is worse: a predecessor is almost never absent
            # here — two were still serving at 93 and 134 minutes old, because
            # they stay until their channels close and a session can outlive a
            # day of recycles. That rule silences the check permanently, which
            # is the same silent-absence failure as the empty denominator
            # above, only quieter. Each draining daemon publishes what it
            # holds; this reads them.
            #
            # THE CHEAP ANSWER FIRST, AND USUALLY THE ONLY ONE NEEDED. I put
            # that on the hot path with the union and it did not belong there.
            # It is also unnecessary, because the union can only ever REMOVE
            # bridges from this list: a predecessor holding a stream makes a
            # bridge NOT deaf. So an empty local answer cannot be changed by
            # anything a predecessor holds, and there is nothing to ask.
            if not self.deaf_bridges():
                # A GRACED CLEAR IS NOT A VERDICT while the ungraced list
                # still names someone: the empty graced list came from
                # shielding a just-registered bridge, not from judging it,
                # and "every posting bridge holds a stream" over bridges
                # nobody judged is the false CLEAR the grace must never
                # produce. No claim either way; the next sweep, past the
                # grace, judges it for real.
                if self.deaf_bridges(grace=0.0):
                    return
                prev = getattr(self, "_last_deaf", None)
                if [] == prev:
                    return
                self._last_deaf = []
                _log_lifecycle(self._deaf_clear_line(posted, prev))
                return
            certdir = getattr(self, "_certdir", None)
            elsewhere: set = set()
            mute = []
            for p in (_pin_daemon_pids(certdir) if certdir else ()):
                if p == os.getpid() or not is_draining(certdir, p):
                    continue
                ids, said = draining_bridges(certdir, p)
                # A PREDECESSOR FROM BEFORE THE SIXTH LINE CANNOT BE ASKED,
                # and that is not the same as one holding nothing. Refusing
                # is right HERE and wrong as the general rule, because it
                # lasts only until the last old daemon leaves.
                (elsewhere.update(ids) if said else mute.append(p))
            now = (("mute", tuple(sorted(mute))) if mute
                   else sorted(self.deaf_bridges(elsewhere=elsewhere)))
            # RE-COUNTED BESIDE ITS OWN NUMERATOR. The loop above reads pid
            # files and asks each draining daemon what it holds -- real time,
            # during which posts keep arriving -- so the count taken before it
            # describes a smaller set than `now` does. Measured on a handover:
            # `4 of 1 bridge(s)`, a numerator above its denominator, from two
            # counts of the same set taken seconds apart.
            posted = self._posting_now()
            prev = getattr(self, "_last_deaf", None)
            if now == prev:
                return
            # SAME GUARD AS THE CHEAP BRANCH, for the same reason: a mute
            # tuple is not a clear (nothing was judged, `DEAF_REPORT_BLIND`
            # says so already), but an EMPTY `now` from the union is, and
            # must not be one while grace still hides a bridge the union
            # never got the chance to remove either.
            if not mute and not now and self.deaf_bridges(elsewhere=elsewhere,
                                                            grace=0.0):
                return
            self._last_deaf = now
            if mute:
                _log_lifecycle(
                    f"{DEAF_REPORT_BLIND} — {len(mute)} draining predecessor(s) "
                    "predate the held-bridge record, so what they are holding "
                    "cannot be asked and a local answer would name every "
                    "pre-existing session: pid "
                    + " ".join(str(p) for p in mute)
                )
            elif now:
                _log_lifecycle(
                    f"{len(now)} of {posted} bridge(s) {DEAF_REPORT_MARK} — "
                    "claude.ai can see them and messages reach the server, "
                    "but the session never receives them; only a NEW PROCESS "
                    # WITH HOW LONG, from the instant the stream went rather
                    # than from the spacing of these lines. This report runs at
                    # most once per `_BRIDGE_SWEEP_COOLDOWN_S`, so a reader
                    # timing a recovery off two of them measures the cooldown;
                    # `deaf_for` is local state and measures the bridge.
                    # UNKNOWN stays unknown -- a daemon that took the port over
                    # mid-life never saw the loss.
                    f"clears it: {' '.join(self._with_deaf_age(b) for b in now)}"
                )
            else:
                _log_lifecycle(self._deaf_clear_line(posted, prev))
        except Exception:  # noqa: BLE001 — a statistic must not cost a request
            pass

    def _with_deaf_age(self, bid: str) -> str:
        """`<id>` or `<id> (deaf 42s)` — the age only when this process saw it go."""
        age = self.deaf_for(bid)
        return bid if age is None else f"{bid} (deaf {int(age)}s)"

    def deaf_bridges(self, window: float = _DEAF_WINDOW_S, now=None,
                     elsewhere: "set | None" = None,
                     grace: "float | None" = None) -> list:
        """Bridge ids that POSTED inside ``window`` and hold no inbound stream.

        THE PAIR, as everywhere else here. Posting alone is not the signal --
        a healthy bridge posts too. A missing stream alone is not either -- a
        session that has said nothing yet has none and is fine. Deaf is the
        conjunction, and it is the state CC cannot leave on its own:
        `close()` sets state="closed" and `connect()` then returns at once,
        forever.

        The window is what stops this naming every session that ever ran: an
        ended one goes quiet and drops out on its own, with no bookkeeping to
        get wrong.

        HELD, NOT RECENTLY OPENED. The stream is issued once and kept for the
        life of the session, so a recency test ages out while the stream is
        still there. An earlier cut of this did exactly that and would have
        called every long-lived session deaf; the external 45s capture has the
        same defect and disagreed with itself three times in an hour on one
        machine (6, 9, 1).

        ``grace`` defaults to `_DEAF_STARTUP_GRACE_S`, bound HERE rather than
        in the signature, so a caller that monkeypatches the module constant
        moves this too. `grace=0.0` is the ungraced list, which
        `_report_deaf_bridges` uses to tell a shielded bridge from a real
        clear.
        """
        stamp = time.monotonic() if now is None else now
        grace = _DEAF_STARTUP_GRACE_S if grace is None else grace
        posts = getattr(self, "_bridge_posts", None)
        if not posts:
            return []
        holding = self.held_bridge_ids() | (elsewhere or set())
        # AN OUTBOUND-ONLY BRIDGE IS NOT DEAF, it never listens; see
        # `_outbound_only_bridge_ids`. Empty on this fleet today.
        holding |= _outbound_only_bridge_ids()
        # NOR IS AN EXITED SESSION'S SHUTDOWN FLUSH. Its post is real and its
        # creating process is confirmed gone, so no stream is ever coming;
        # `_dead_creator_bridge_ids` already has the positive proof, and
        # without this a session that exited stays "deaf" until the next
        # listing pass drops it from `_connected_bridges`. READ-ONLY here:
        # this runs on the request thread, where N unserialized callers
        # would share the sweep's one tmp filename. The sweep (its own
        # thread) still stamps.
        holding |= _dead_creator_bridge_ids(stamp=False)
        out = [bid for bid, last in posts.items()
               if stamp - last <= window and bid not in holding]
        # A BRIDGE THAT HAS JUST REGISTERED IS NOT YET DEAF. Its stream GET
        # follows its first post within seconds; this daemon judging it in
        # that gap is the state itself, not a loss, and no timer ever
        # retracts a transition-only report. Unmeasured only -- this daemon
        # never saw its stream go -- and shielded while its first post is
        # inside the grace.
        #
        # A MEASURED LOSS GETS THE SAME DWELL, not immediate judgment: a
        # sweep can land in the ordinary gap between a stream closing and
        # Claude Code reopening it, and `deaf_for` answers a real but
        # momentary age there (0s, measured). Shielded while that age is
        # still inside the grace; a loss still there once it passes is
        # judged exactly as before.
        first_post = getattr(self, "_bridge_first_post", None) or {}
        deaf_for = getattr(self, "deaf_for", None)

        def _too_young(bid):
            age = None if deaf_for is None else deaf_for(bid, now=stamp)
            if age is None:
                return stamp - first_post.get(bid, -1e9) < grace
            return age < grace

        out = [bid for bid in out if not _too_young(bid)]
        # AND THE SERVER MUST BE HOLDING IT. Posting without a stream has two
        # readings and our own sockets cannot separate them: a bridge that
        # LOST its ear, and one claude.ai is not attached to at all -- a
        # background job posts worker events whether or not anybody is
        # listening, and no popup follows for a bridge nobody is watching.
        # Only the first is this verdict's subject.
        #
        # Measured: 8 of 8 bridges called deaf on one host were absent from
        # the server's connected set, while that set was non-empty, so the
        # whole population was the second kind. It also explains why a host
        # running more background jobs looked worse than one running fewer.
        #
        # `None` is UNKNOWN, never "connected to nothing" -- the same rule the
        # recycle path already follows. Judging under it would call every
        # bridge on the host deaf the moment a listing fails.
        known = getattr(self, "_connected_bridges", None)
        if known is not None:
            out = [bid for bid in out if bid in known]
        return sorted(out)

    def _note_attachment(self, path: str, status_line: bytes) -> None:
        """Say whether a claude.ai attachment actually downloaded, on CHANGE.

        `/api/oauth/files/` is pinned because the file belongs to the pinned
        account, and Claude Code renders any non-200 as "could not be
        downloaded" — a message the user sees and nothing records. So the swap
        was verified in code and never in traffic, and no machine could answer
        whether an attachment had ever worked.

        THE STATUS IS CARRIED, because 403 (the swap was refused) and 404 (the
        file is not this account's) are different bugs with the same symptom.

        Never raises: a statistic must not cost a request.
        """
        try:
            if not path.startswith("/api/oauth/files/"):
                return
            parts = status_line.split(b" ")
            code = parts[1].decode("latin1", "replace") if len(parts) > 1 else "?"
            ok = code.startswith("2")
            # KEYED ON THE CODE, not on ok/not-ok: a 403 turning into a 404 is
            # a different fault and must not be swallowed as "still failing".
            state = "ok" if ok else code
            if state == getattr(self, "_last_attach", None):
                return
            self._last_attach = state
            if ok:
                _log_lifecycle(ATTACH_REPORT_OK)
            else:
                _log_lifecycle(
                    f"{ATTACH_REPORT_FAIL} — upstream answered {code}; the "
                    "user sees only 'could not be downloaded'")
        except Exception:  # noqa: BLE001 — a statistic must not cost a request
            pass

    def _note_rename(self, method: str, path: str, status_line: bytes) -> None:
        """Say whether a session rename reached its bridge, on CHANGE.

        `updateSessionTitle` PUTs with `validateStatus: (d) => d < 500`, so a
        4xx raises nothing in the CLI and the roster keeps showing the new
        name. The only party who learns the rename did not land is a PEER
        reading the stale label off a cross-session message, and by then a
        reply has gone to the wrong session. The proxy sees both the route and
        the status, so it is the only place that can say so.

        Never raises: a statistic must not cost a request.
        """
        try:
            if method != "PUT":
                return
            # EXACTLY ONE SEGMENT after the prefix: the collection mints a
            # bridge and a sub-resource is a different write, and neither is a
            # rename.
            head = path.split("?", 1)[0]
            rest = head[len("/v1/code/sessions/"):] if head.startswith(
                "/v1/code/sessions/") else None
            if not rest or "/" in rest:
                return
            parts = status_line.split(b" ")
            code = parts[1].decode("latin1", "replace") if len(parts) > 1 else "?"
            ok = code.startswith("2")
            state = "ok" if ok else code
            if state == getattr(self, "_last_rename", None):
                return
            self._last_rename = state
            if ok:
                _log_lifecycle(RENAME_REPORT_OK)
            else:
                _log_lifecycle(
                    f"{RENAME_REPORT_FAIL} — upstream answered {code}; the "
                    "roster still shows the new name and peers keep seeing "
                    "the old one")
        except Exception:  # noqa: BLE001 — a statistic must not cost a request
            pass

    def _note_bridge_superseded(self, path: str, status_line: bytes) -> None:
        """A worker POST refused with 409 is not a bridge gone quiet.

        `_note_bridge_traffic` records only the REQUEST, so a bridge the
        server has already superseded stays in `_bridge_posts` for the full
        `_DEAF_WINDOW_S` and `deaf_bridges` reports it with a line that
        claims "messages reach the server" and "only a NEW PROCESS clears
        it" — both false for one whose every worker POST comes back 409.
        `sweep_superseded_bridges` clears the same id eventually, driven by
        a listing poll, but always later than the 409 that already told us.

        Never raises: a statistic must not cost a request.
        """
        try:
            if not status_line.startswith(b"HTTP/1.1 409"):
                return
            if not _WORKER_SUBTREE.search(path) or _EVENT_STREAM.search(path):
                return
            bid = _BRIDGE_ID.search(path)
            if not bid:
                return
            b = bid.group(1)
            self._bridge_posts.pop(b, None)
            self._bridge_first_post.pop(b, None)
            stream_lost = getattr(self, "_stream_lost", None)
            if stream_lost is not None:
                stream_lost.pop(b, None)
        except Exception:  # noqa: BLE001 — a statistic must not cost a request
            pass

    def _forget_stream(self, conn) -> None:
        """Drop a stream socket and its owner, and REMEMBER WHEN.

        The three sites that ended a stream each spelled this as
        `_stream_conns.discard` + `_stream_owner.pop` -- one fact, written
        three times, and nowhere to hang the instant it happened.

        WHY THE INSTANT IS WORTH KEEPING. `deaf_bridges` answers a boolean,
        and the report reading it runs at most once per
        `_BRIDGE_SWEEP_COOLDOWN_S`. Any duration taken from the spacing of its
        log lines is therefore quantised to that interval: three "recovery
        times" were read off that spacing and one was exactly one cooldown --
        the interval reported as a recovery. The moment a stream goes is state
        this process already holds, so recording it costs no request and no
        poll, and it is the only number here that measures the bridge rather
        than our own cadence.

        ONLY WHEN THE LAST ONE GOES. A session can hold more than one stream
        socket across a reconnect; stamping on the first drop would date the
        loss from a socket that was replaced a moment later.

        The caller holds `_live_lock`, so this must not take it.
        """
        self._stream_conns.discard(conn)
        owner = getattr(self, "_stream_owner", {})
        bid = owner.pop(conn, None)
        if bid is None:
            return
        still = {owner[c] for c in (self._stream_conns & self._open_conns)
                 if c in owner}
        if bid not in still:
            self._stream_lost[bid] = time.monotonic()

    def deaf_for(self, bid: str, now=None) -> "float | None":
        """Seconds since this bridge's last stream went, or None if unknown.

        None is UNKNOWN and never 0: a daemon that took the port over mid-life
        never saw the loss, and 0 there would read as "just now".
        """
        lost = getattr(self, "_stream_lost", {}).get(bid)
        if lost is None:
            return None
        return (time.monotonic() if now is None else now) - lost

    def held_bridge_ids(self) -> set:
        """Bridges whose inbound stream THIS process is holding open.

        Its own answer only. A handover leaves every established stream with
        the process that accept()ed it, so this is a partial view by
        construction and callers that need the whole picture union it with
        `draining_bridges` of each draining predecessor.
        """
        owner = getattr(self, "_stream_owner", {})
        with self._live_lock:
            live = set(self._stream_conns & self._open_conns)
        return {owner[c] for c in live if c in owner}

    def await_inflight(self, budget: float) -> int:
        """Wait up to ``budget`` for open connections to finish, then cut them.

        A CEILING, not a wait: zero clients returns at once. Kept separate from
        releasing the port so a handover can do this while its successor is
        already accepting.

        RETURNS HOW MANY IT CUT, and the return value is the whole reason this
        signature changed. The caller logs "drained, N client(s) still open",
        and it read N from `live_client_count()` AFTER this ran — but the last
        thing this does is `_close_open_connections`, which empties the set
        that count reads. So N was 0 by construction, whatever was cut.

        Measured across all three machines' daemon logs: every non-zero value
        is from 2026-08-04/05 (`634`, `8`, `7`, `7`, `6`, `6`, `4`, `4`), and
        every value from 08-08 onward is 0 — the ordering changed in between.
        The one line that says whether a recycle cost a session anything has
        been a constant ever since, including through the night a user lost a
        response mid-stream and asked whether the pin did it. Nobody could
        answer from the log.

        A fix that deletes the evidence its own check reads turns a loud
        failure into a silent one; this hands the number back before cutting.

        AND IT SAYS SO HERE, not at the call sites. Three places drain — the
        two code-handover exits and ``_teardown``, which is the one that
        actually cut something on 2026-08-18 (a TERM under a holder, on the
        2s budget, one second after a handover began). A warning bolted onto
        the handovers would have missed exactly the event that prompted this.
        This is the only function that cuts, so it is the only place that can
        report every path, including ones written after today.
        """
        # THE SUBSCRIPTIONS ARE NOT CUT HERE, and that is deliberate. What the
        # cut did buy was a hard disconnect of the bridge's inbound stream,
        # which a session cannot reopen for itself. The tunnel wait below is
        # the other answer, and it does not cost that.
        #
        # WAIT ON REQUESTS, NOT ON CONNECTIONS. This loop asked
        # `live_client_count() == 0` and that zero is unreachable: Remote
        # Control's WebSocket is opaque after the 101, is pumped by the shared
        # selector rather than a request thread, and stays open for the whole
        # session. So the condition never held, the full budget was always
        # spent, and every recycle then cut everything open — including a
        # `/v1/messages` reply that had started moments earlier. The premise
        # was written down in this file long before the conclusion was: "Remote
        # Control's WebSocket lives as long as the session does, so the count
        # is never zero." It sat two constants above the loop that depended on
        # the opposite.
        started = time.monotonic()
        # Every drain goes through this function by construction, so a fifth
        # exit path added later is covered without anyone remembering to cover
        # it. See `announce_draining`: without it the orphan sweep TERMs a
        # predecessor that is patiently finishing its replies, one second after
        # the successor starts serving.
        done_draining = announce_draining(self._certdir, server=self)
        # PUBLISHED IMMEDIATELY, not at the first beat fifteen seconds in. The
        # sweep reads this to decide which predecessor is cheapest to reap, and
        # a recycle storm can arrive inside those fifteen seconds — a marker
        # that has not said its count yet reads as `_OWED_UNKNOWN`, which is
        # the most expensive thing to be. SNAPSHOT FIRST. `live_replies`
        # compares against this, because content delivered BEFORE the drain
        # started says nothing about whether this reply is still being written.
        #
        # AND THE DRAIN DOES NOT STOP WAITING ON A CONTENT-FREE REPLY, which
        # was asked for and refused. "No content since the drain began" is a
        # true statement about a reply whose model is THINKING: extended
        # thinking emits keepalives and no content for as long as it takes, so
        # a drain that stopped waiting on that would cut exactly the long reply
        # this whole ceiling was removed to protect. The content count decides
        # which predecessor is cheapest to REAP — a choice that is being made
        # anyway, where being wrong costs one of several — and not whether to
        # keep waiting, where being wrong costs a live answer. It becomes
        # decidable the day somebody measures the longest content-free interval
        # a live reply produces. The cut line records the inputs for that now;
        # nothing here guesses it. NO SNAPSHOT. One structure fewer to keep
        # popped at three call sites. THE PROCESS'S NUMBER, not this proxy's:
        # the marker describes the process the reaper would kill, and `_PUMP`
        # drives every tunnel in it.
        streams = self.live_stream_count() + _PUMP.live_pairs()
        if streams:
            # NAME THE BUDGET THAT BINDS THIS DRAIN, NEVER THE PROMISE ALONE.
            # "stays until they end" is true on the handover arm, whose budget
            # is infinite, and FALSE BY CONSTRUCTION on the signal arm, which
            # is capped and whose sender SIGKILLs two seconds past the cap.
            # Both printed the same sentence.
            #
            # That is how the two arms became indistinguishable in the log, and
            # the conflation reached a peer in writing: every clean drain on
            # record was a handover, the sentence above sat on all of them, and
            # "the handover is gapless by construction" was said on that
            # evidence hours before an external TERM racing a handover cut 13
            # mid-response replies at exactly the cap. The successor was
            # already serving; the promise was printed twice; neither printing
            # could keep it, because a capped clock was already running.
            #
            # A drain that CAN cut has to say so before it cuts. The cut line
            # is honest and it is too late — by then the decision a reader
            # would have made from the log has been made.
            # "AT THE START", BECAUSE THIS LINE IS PRINTED ONCE AND THE DRAIN
            # CAN RUN FOR HOURS. The number is derived now and never again, so
            # a reader arriving later takes an hours-old snapshot for the
            # current state. Measured: this line said 14 while the drain's own
            # beat, re-derived every 15s, said 1 and the socket table agreed
            # with the beat — and the gap was read as the drain waiting on
            # channels that had already left, which argued for killing a
            # process serving a live one.
            #
            # A LINE PER BEAT IS NOT THE ANSWER: it would bury the drain's real
            # events in the one file a person reads to find out why a daemon
            # died. Name the snapshot and point at the record that IS current.
            # HANDED OVER BEFORE THE WAIT, not cut after it. These are the
            # channels the wait can never outlast, and the successor is
            # already accepting on the inherited listener.
            handed = self.release_idle_streams()
            if handed:
                streams = max(0, streams - handed)
            _log_lifecycle(
                f"draining with {streams} long-lived channel(s) still open at "
                f"the start — {drain_fate(budget)}. This count is not "
                f"re-printed; `.draining-{os.getpid()}` carries the live one"
                + (f"; handed {handed} content-free stream(s) to the successor"
                   " rather than waiting out a reconnect the client was going"
                   " to make anyway" if handed else ""))
        beat_draining(self._certdir, owed=self.inflight_requests(),
                      live=self.live_replies(started),
                      quiet=self.content_free_seconds(),
                      streams=streams, bridges=self.held_bridge_ids())
        beat_at = started
        try:
            # AND THE TUNNELS. Remote Control RECEIVES over a WebSocket to the
            # ingress host the `/bridge` response names, so it is an opaque
            # tunnel `_PUMP` drives rather than a reply anyone is owed —
            # `_mitm` hands the debt back at the 101, correctly, because a
            # tunnel owes no ANSWER. It is still a live channel that dies with
            # this process.
            #
            # A HELD-OPEN STREAM DOES NOT COVER IT. That was the reasoning for
            # dropping this wait, and the fleet disproved it the same hour: pid
            # 423760 owed nothing, left at once, and took four open connections
            # with it, while pid 1452400 — which did owe — stayed and kept
            # fourteen.
            #
            # ENDS ON SILENCE. `live_pairs()` alone has no exit: a wedged peer
            # keeps its entry for ever. A tunnel quiet for the marker's own TTL
            # cannot be told from a dead one, which is the same discriminator
            # the reply wait uses. Uncapped arm only. The signal arm has a
            # supervisor counting to `_DRAIN_SECONDS + 2`, and the held arm is
            # holding the port dark.
            if budget == float("inf"):
                # A LIVE BRIDGE IS SERVED UNTIL IT ENDS, ON NO CLOCK. This
                # loop once carried a deadline that released the keepalived
                # Remote Control stream once it passed, on the reasoning that
                # waiting can never outlast a stream that never goes quiet.
                # It cannot, and that is the point: while this process holds
                # the stream the session is RECEIVING through it. Releasing it
                # turns a working channel into a deaf bridge, and Claude Code
                # rebuilds the receive side after neither an EOF nor a reset.
                #
                # The silence bound is the exit that matters and it is
                # reachable: a WEDGED peer moves no bytes, so `quiet_for`
                # crosses the TTL and the loop leaves. Only a peer still
                # talking holds this open, which is work, not a leak.
                while (_PUMP.live_pairs()
                       and _PUMP.quiet_for() <= _DRAINING_MARKER_TTL):
                    beat_draining(self._certdir,
                                  owed=self.inflight_requests(),
                                  live=self.live_replies(started),
                                  quiet=self.content_free_seconds(),
                                  streams=self.live_stream_count()
                                  + _PUMP.live_pairs(),
                                  bridges=self.held_bridge_ids())
                    time.sleep(_DRAINING_BEAT_SECONDS)
                if _PUMP.live_pairs():
                    _log_lifecycle(
                        f"leaving {_PUMP.live_pairs()} tunnel(s) quiet for "
                        f"{int(_PUMP.quiet_for())}s rather than holding this "
                        f"process open on a wedged peer — releasing them so "
                        f"each peer sees a clean EOF rather than the reset "
                        f"this process exiting would give it: "
                        f"{_PUMP.release_pairs()} released")
            if budget > 0:
                deadline = started + budget
                # THE BUDGET WAS CHOSEN BEFORE THE HANDOVER EXISTED, and the
                # three paths that share this lifecycle cannot see each other's
                # locals -- which is why `proxy.json` is the arbitration point.
                # A signal drain picks the capped arm because the port would
                # otherwise go dark. If a successor then takes the port while
                # this drain is running, that reason is gone: nothing waits on
                # this process, it accepts nothing, and it is one idle process
                # finishing replies it already owes. Exactly the condition
                # `_HANDOVER_DRAIN_SECONDS` was made infinite for.
                #
                # Measured: a TERM armed the 30s arm, twenty seconds later this
                # process's own watchdog handed over with the successor already
                # serving, and at thirty seconds the clock from before the
                # handover cut 13 mid-response replies.
                #
                # `teardown_drain_budget(handed_over=...)` means to prevent
                # this and CANNOT: `_HELD_DRAIN_SECONDS` is `_DRAIN_SECONDS`,
                # so all four combinations of its arguments return 30.0. The
                # fact has to be re-read HERE, where it can change mid-wait.
                promoted = budget == float("inf")
                # WHAT THE PREDICATE BUYS ON A CAPPED ARM, because
                # `_HELD_DRAIN_SECONDS` < `_DRAIN_STALL_SECONDS` invites the
                # reading that it buys nothing and a careful reader reached
                # exactly that. `_owed_still_moving` measures from the DEBT'S
                # last byte, not from this drain's start, so a connection
                # already silent longer than the WINDOW when the drain begins
                # breaks out at second 0 — measured. Raising the window narrows
                # that band, which is where the raise costs port-dark seconds.
                #
                # What it cannot do here is catch a connection that goes quiet
                # DURING the budget. The ceiling bounds that, and shrinking the
                # window to reach inside it is refused on measurement: byte-free
                # waits on completed replies reach 123s.
                while time.monotonic() < deadline:
                    if not self._owed_still_moving(started):
                        break
                    if not promoted and _superseded_on_the_port(self._certdir):
                        promoted = True
                        deadline = float("inf")
                        _log_lifecycle(
                            "a successor took the port while this drain was "
                            "running — dropping the wall clock so the replies "
                            "already owed can finish")
                    # SAY WE ARE STILL HERE. Without this a wait past
                    # `_DRAINING_MARKER_TTL` looks abandoned and the orphan
                    # sweep TERMs a daemon that is mid-reply, which is the
                    # 08:21:19Z line with the clock moved rather than removed.
                    now = time.monotonic()
                    if now - beat_at >= _DRAINING_BEAT_SECONDS:
                        beat_draining(
                            self._certdir, owed=self.inflight_requests(),
                            live=self.live_replies(started),
                            quiet=self.content_free_seconds(),
                            # AND THE CHANNEL COUNT, EVERY TIME. The beat
                            # REWRITES the marker, so a beat that omits this
                            # erases the one field the reaper reads to know
                            # this daemon is carrying a bridge. The first beat
                            # wrote it and this one deleted it 15s later, so
                            # the protection lasted one interval. Re-read
                            # rather than reused: a channel can end mid-drain
                            # and the marker must not overstate what a reap
                            # would cost.
                            streams=self.live_stream_count() + _PUMP.live_pairs(),
                            bridges=self.held_bridge_ids())
                        beat_at = now
                    time.sleep(0.05)
        finally:
            done_draining()
        elapsed = time.monotonic() - started
        # TWO NUMBERS, BECAUSE THEY ANSWER DIFFERENT QUESTIONS AND THIS LINE
        # USED TO CONFLATE THEM. The loop waits on OWED ANSWERS; the message
        # reported `live_client_count()`, which counts every open socket
        # including opaque tunnels that owe nobody anything.
        cut = self.inflight_requests()
        mid = self.inflight_mid_response()
        delivered = self._delivered_summary()
        # READ BEFORE `_close_open_connections`, and NOT for the reason this
        # comment first gave. That function swaps out `_open_conns` and nothing
        # else — it never touches `_owed`, `_content_at` or `_delivered`. What
        # empties those is each serving thread's `_release()` as its socket
        # dies, asynchronously, once the close lands. So the ordering is right
        # and the mechanism is a RACE, not a synchronous wipe. Naming the wrong
        # one is worse than naming none: the next reader moves the line on the
        # strength of a mechanism that does not exist.
        quiet = self._content_free_summary()
        closed = self.live_client_count()
        # THE TUNNELS TOO, AND BEFORE THE SOCKETS ARE CLOSED.
        # `_close_open_connections` reaches `_open_conns`, and a tunnel is not
        # in it: a blind CONNECT's upstream was never added, and the 101 path
        # detached its raw socket so the entry it does hold is a no-op. So
        # every drain that is not the uncapped one — a TERM, a refcount
        # teardown, the 30s held arm — used to `os._exit` with the Remote
        # Control channel still open, which is the reset this whole change
        # exists to stop, on the paths where it is most likely.
        released = _PUMP.release_pairs()
        if released:
            _log_lifecycle(
                f"released {released} tunnel(s) on the way out so each peer "
                "sees a clean EOF; a process that exits holding one gives it "
                "a reset instead, and Claude Code does not rebuild the "
                "Remote Control channel after either")
        self._close_open_connections()
        # ONE LINE PER DRAIN, ALWAYS — silence was the problem, not the noise.
        # A departure is a rare event — one line each is not noise, and it is
        # the only record that a recycle cost nothing.
        #
        # AND THE TWO OUTCOMES READ DIFFERENTLY, because they are different
        # facts. `cut` is somebody's reply ending mid-stream. `closed` alone is
        # sockets that owed nobody anything — an RC WebSocket, a keep-alive
        # between requests — and closing those costs the user nothing.
        #
        # AND THE CEILING IS NOT ALWAYS A NUMBER. `_HANDOVER_DRAIN_SECONDS` is
        # infinite, and "of a infs budget" reads as a quantity nobody can act
        # on — this is the one line a later session reads to decide whether a
        # departure cost anybody a reply, so it says which regime it ran in.
        ceiling = ("no wall-clock cap" if budget == float("inf")
                   else f"a {budget:.0f}s budget")
        if cut:
            _log_lifecycle(
                f"cut {cut} in-flight request(s) after {elapsed:.1f}s of "
                f"{ceiling} ({mid} mid-response, {cut - mid} before "
                f"headers; delivered {delivered} per reply, content-free "
                f"{quiet}; and closed {closed - cut} idle connection(s))"
            )
        else:
            # THE CLEAN BRANCH CARRIES THE HIGH WATER, NOT THE LIVE SET.
            # `drained clean` means `_owed` is empty, so `_content_free_summary`
            # here is 0 s on every clean drain there will ever be — a field
            # that cannot fail, on the one branch that matters most. See
            # `_note_reply_finished`: a reply that went quiet for N and THEN
            # delivered is the only observation that proves N was safe to wait.
            _log_lifecycle(
                f"drained clean in {elapsed:.1f}s of {ceiling} "
                f"— closed {closed} idle connection(s), none owed an answer; "
                f"longest content-free wait a completed reply survived "
                f"{f'{self._quiet_peak:.0f}s' if self._quiet_seen else 'n/a'}"
                f"; longest BYTE-free wait one survived "
                f"{f'{self._byte_peak:.0f}s' if self._byte_seen else 'n/a'}"
                f" (this is the quantity `_owed_still_moving` reads)"
            )
        return cut

    def stop(self, drain: float = 0.0) -> int:
        """Stop accepting, and optionally let in-flight requests FINISH.

        Closing the listener is instant and correct — a new connection should
        go to whoever takes the port next. The connections already open are a
        different matter: they are carrying REQUESTS, and this proxy sits on
        `HTTPS_PROXY`, so one of them is very likely a `/v1/messages` response
        streaming into a session right now.

        Measured before this existed: with the listener closed and the process
        calling ``os._exit(0)`` a moment later, a client mid-response got
        ``ConnectionResetError`` — 34 connections were open on the live daemon
        at the time. That turned "upgrade the pin" into "every session routed
        through it loses whatever it was doing", which is the thing an
        optional feature must never be able to do.

        ``drain`` is a CEILING, not a wait: the common case is zero clients and
        returns at once. A request that outlives the budget is still cut, but
        the budget exists so that the normal case — a few seconds of streaming
        — completes.
        """
        self.release_listener()
        cut = self.await_inflight(drain)
        # ONLY HERE, AFTER THE DRAIN -- `release_listener`'s `_stop` must not
        # end the tick (see the note where `_trace_tick_loop` starts): a
        # draining process still relays what it holds and still writes to
        # the trace through the whole wait this method just did.
        self._trace_tick_stop.set()
        return cut

    def _close_open_connections(self) -> None:
        """Close every open connection, write end first.

        Draining alone is not enough and the difference is not subtle:
        measured, a request that had transferred every one of its bytes STILL
        reached the client as ConnectionResetError. The data had arrived; the
        client threw it away over the reset. One ``shutdown(SHUT_WR)`` per
        connection turns that into a clean EOF.

        THE PRECONDITION IS UNREAD DATA, not merely exiting with the socket
        open — an earlier version of this docstring said the latter and it is
        wrong. Closing a socket that still has unreceived bytes in its receive
        queue MUST send RST (RFC 1122); closing an idle one sends FIN. Measured
        here, 2x2 with a control:

            unread data   teardown              client sees
            no            bare os._exit()       clean EOF (FIN)
            no            shutdown(SHUT_WR)     clean EOF (FIN)
            YES           bare os._exit()       ECONNRESET (RST)
            YES           shutdown(SHUT_WR)     clean EOF (FIN)

        A proxy meets that precondition constantly: the client keeps sending
        while we tear down, those bytes land in our receive queue, and we exit
        without reading them. The distinction matters to anyone reading this
        to decide whether their own component has the same bug — a peer
        component tested the wrong premise (an IDLE socket), correctly saw FIN
        either way, and concluded it was immune.
        """
        with self._live_lock:
            conns, self._open_conns = list(self._open_conns), set()
        for conn in conns:
            # THE RAW SOCKET, DELIBERATELY, EVEN THOUGH IT IS DETACHED.
            # `wrap_socket` detached it, so this shutdown/close pair is a no-op
            # for every MITM'd connection and the FIN-not-RST table above
            # describes something that has not happened since the MITM landed.
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def release_idle_streams(
            self, older_than: float = _CLIENT_LIVENESS_SECONDS) -> int:
        """Hand content-free streams to the successor instead of outliving them.

        WHY A DRAIN OTHERWISE NEVER ENDS. An SSE stream owes an answer for its
        whole life, so `await_inflight` waits on one for ever. Measured: a
        drain ran 3316.7s and closed one idle connection while owing nobody an
        answer. The wait protects nothing -- the successor already holds the
        listener, so a client that reconnects lands on it at once and
        `handleStreamEnd` carries `from_sequence_num`, losing no events.

        ONLY CONTENT-FREE ONES. A stream still delivering is real work and is
        left alone; this is not a cut, and the threshold is the client's own
        (see `_CLIENT_LIVENESS_SECONDS`), so every connection released here was
        already going to be dropped by the other end.

        SHUTDOWN, NOT CLOSE, and `SHUT_WR` specifically: the client sees a
        clean EOF rather than an RST even with unread bytes in our queue --
        the 2x2 in `_close_open_connections` is the measurement behind that.

        `time.monotonic`, because `_content_at` is stamped with it. Comparing
        it against a wall clock reads as ~55 years of silence and would
        release every stream on the first pass.
        """
        now = time.monotonic()
        with self._live_lock:
            victims = [c for c in (self._stream_conns & self._open_conns)
                       if now - self._content_at.get(c, now) >= older_than]
        for conn in victims:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        return len(victims)

    # -- internals ----------------------------------------------------------

    def _accept_loop(self) -> None:
        # Hold the socket, not the attribute: stop() clears ``_srv`` when a
        # supervisor owns the port (closing it there would drop the port), and
        # reading the attribute each pass would then raise AttributeError in a
        # daemon thread instead of ending the loop.
        srv = self._srv
        # A bounded wait so ``_stop`` is noticed without needing the listener
        # closed underneath us — which is the only wake-up available when the
        # socket is not ours to close.
        srv.settimeout(0.5)
        while not self._stop:
            # THE ADOPT PROBE'S CASUALTY, SERVED FIRST. It is older than
            # anything the kernel still has queued, and it has been waiting
            # since before this process existed. See `_ADOPTED_BACKLOG`.
            if _ADOPTED_BACKLOG:
                conn = _ADOPTED_BACKLOG.pop(0)
                _log_lifecycle(
                    "serving the client the adopt probe "
                    f"had to accept"
                )
            else:
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
            # A timeout on the LISTENER is inherited by every socket it
            # accepts, which would then cut a quiet-but-healthy stream. The
            # wait above is about noticing shutdown, not about the client.
            conn.settimeout(None)
            # COUNTED HERE, NOT IN THE THREAD. The exit then closed the fd with
            # the client's request unread — which the kernel MUST answer with
            # RST (see `_close_open_connections`). Microseconds when idle,
            # wider under load, which is why it showed up as an intermittent "2
            # in-flight requests cut by a planned restart" — about 1 run in 6
            # on a loaded box and never on an idle one. Counting before the
            # handoff closes the window entirely: accepted IS connected,
            # whatever the scheduler does next.
            with self._live_lock:
                self._open_conns.add(conn)
            # OWED FROM ACCEPT. The request line may still be in the kernel
            # buffer, and a client that has connected is waiting on us whether
            # or not its bytes have arrived.
            self._owe_answer(conn, True)
            threading.Thread(
                target=self._serve_client, args=(conn,), daemon=True
            ).start()

    def _should_sweep_bridges(self, method: str, path: str, now=None) -> bool:
        """Is this request a moment worth re-listing the account on?

        TWO EVENTS, because a title becomes ambiguous two ways and the create
        event only covers one:

          1. `POST /v1/code/sessions` — a NEW bridge opens beside an older
             connected one. Always sweeps; this is the original trigger.
          2. presence — an attached session checking in. Covers the case a
             create CANNOT: an older bridge ARCHIVED after the newer one
             already opened. Archiving is server-side and later, so nothing on
             the create path can ever see it.
          3. worker traffic — the same session posting events or a heartbeat.
             Same job as case 2, and the one that actually arrives. Presence
             does NOT recur: measured over a live window of 2132 requests
             across 13 attached sessions, this route saw 26 worker posts in
             its first 45 seconds and ZERO presence posts in the whole window,
             so case 2 alone left the deaf-bridge verdict only ever as fresh
             as the last create. A fleet that starts no session never re-asked
             at all.

        Rate-limited, and only cases 2 and 3 need it: a create does not recur.
        Still not a timer — a machine with no attached session posts neither,
        and this never fires.
        """
        if method != "POST":
            return False
        stamp = time.monotonic() if now is None else now
        if path == "/v1/code/sessions":
            # STAMPED HERE, not in `_note_bridge_traffic`: this is the one
            # site every create this daemon itself served passes through
            # unconditionally, and it is what tells a bridge born here from
            # one only inherited on a handover -- see `_bridge_first_post`.
            self._last_create = stamp
            return True
        if not (_PRESENCE.search(path) or _WORKER_SUBTREE.search(path)):
            return False
        last = getattr(self, "_last_bridge_sweep", None)
        if last is not None and stamp - last < _BRIDGE_SWEEP_COOLDOWN_S:
            return False
        self._last_bridge_sweep = stamp
        return True

    def _freshen_pin_identity(self) -> bool:
        """Refresh the remembered pin's profile before Claude Code's gate would.

        The remembered identity is what every splice writes, and CC re-fetches
        the profile (as the ACTIVE account, which is the write that moves the
        field off the pin) once the stamp in the live config is a day old.
        Refreshed from the server AS THE PIN, so the stamp is true and the
        fields are the pin's own. True when the file was rewritten.

        A bearer that answers as some other account is not ours to write:
        the file keeps what it has and the next beat asks again.
        """
        certdir = getattr(self, "_certdir", None)
        ident = remembered_pin_identity(certdir) if certdir is not None else None
        if not ident:
            return False
        age_s = time.time() - _profile_stamp_ms(ident) / 1000.0
        if age_s < _PIN_PROFILE_MAX_AGE_S:
            return False
        # THE ACTIVE BEARER WHEN THE PIN IS THE ACTIVE ACCOUNT. The provider
        # answers None then -- there is nothing to swap -- but that token IS
        # the pin's, and the uuid check below is what keeps a foreign answer
        # out. Same fallback `sweep_policy_once` makes.
        token = self._pin_token_provider() or _active_oauth_token()
        fresh = pin_profile_for(token) if token else None
        if not fresh or fresh.get("accountUuid") != ident.get("accountUuid"):
            # SAY WHY, or a stale stamp on one host and a fresh one on another
            # look like the same silent beat. Once an hour: the condition
            # persists across beats and the line is for a person.
            now = time.time()
            if now - getattr(self, "_freshen_warned_at", 0.0) > 3600.0:
                self._freshen_warned_at = now
                why = ("no bearer to ask with" if not token
                       else "the profile request failed" if not fresh
                       else "the bearer answers as "
                            f"{str(fresh.get('accountUuid'))[:12]}, not the pin")
                _log_lifecycle(
                    f"the pin's profile stamp is {age_s / 3600:.0f}h old and "
                    f"could not be refreshed: {why} — Claude Code re-fetches "
                    "it as the active account on the next session start")
            return False
        remember_pin_identity(certdir, {**ident, **fresh})
        _log_lifecycle("refreshed the pin's profile from the server, so the "
                       "live config stays inside Claude Code's fetch window")
        return True

    def _reassert_pin_identity(self) -> None:
        """Re-name the pin in the live config before a bridge is minted.

        THE LAUNCH RE-ASSERT DOES NOT COVER A RESTART THAT SKIPS THE LAUNCH.
        Claude Code merges ``/api/oauth/profile`` into ``oauthAccount`` with no
        guard, so while the active account differs from the pin that field
        names the active one again within minutes. Every bridge minted in the
        gap carries an owner the reattach then vetoes — measured after a forced
        update restarted the daemon outside the launch path: 12 of 13 bridges
        came back under the wrong account.

        ON THE CREATE, WHICH IS WHEN THE OWNER IS STAMPED and which does not
        recur, so this costs one read-modify-write per bridge and nothing on
        the steady-state path.
        """
        ident = remembered_pin_identity(self._certdir)
        if not ident:
            return
        try:
            splice_config_identity(ident)
            # AND EVERY SESSION ALREADY RUNNING, because the splice above moves
            # the field CC compares their pointers against. Ordered correctly
            # for the bridge being minted and not for them: theirs were stamped
            # against the pre-splice account, so each is vetoed into a fresh
            # mint on its next reattach. This is the site that fires most --
            # once per create -- so leaving it uncarried keeps producing
            # unclaimed bridges after the launch path is fixed.
            #
            # A no-op once they agree: the carry writes only on a difference,
            # so the steady-state cost is one read per live session.
            _live = _pointer_owner(self._certdir)
            if _live:
                carry_live_pointers(_live)
        except Exception:  # noqa: BLE001 — a bridge must never fail on the pin
            pass
        # VERIFY, BECAUSE THE RETURN CANNOT CARRY IT. `splice_config_identity`
        # answers False for four states and one of them — lock not taken — is
        # a skipped write its own comment says leaves the field drifted. Here
        # the owner is stamped from that field on the request being forwarded,
        # so a skipped write mints a bridge CC can refuse to reattach.
        #
        # NAME WHAT THE FIELD HOLDS, not just that it is wrong: the cause is
        # unmeasured, and a log that carries the value is what makes the next
        # occurrence a diagnosis instead of another mystery. No retry until
        # that log says which cause it is.
        live, holds = live_pin_identity_state(ident)
        if live:
            return
        _log_lifecycle(
            f"{PIN_NOT_NAMED_AT_MINT} — it holds {holds}, so the owner is "
            "stamped from that and Claude Code can refuse to reattach the "
            "bridge later. Requirement 1 breaking, at the moment it breaks")

    def _sweep_bridges_after_connect(self, token: str) -> None:
        """Sweep superseded bridges, right after this session opened one.

        THE EVENT, NOT A TIMER. A duplicate is created at exactly one moment:
        a session opens an RC bridge while an older bridge of the same name is
        still `connected`. That is when the sidebar becomes a coin flip, and
        it is the only moment worth spending an API listing on. A periodic
        sweep would wake a quiet daemon for hours to find nothing, and would
        still leave the window between ticks — the one time it matters.

        The pin sees this event for free: every RC lifecycle call is a route
        it already swaps the bearer on, so `/v1/code/sessions` succeeding IS
        the notification. Nothing polls and nothing extra is dialled.

        In a thread, and never awaited: the client's response must not wait on
        a listing, and a hanging API call must not hold a request open.
        `_bridge_sweeping` keeps a burst of session calls from starting N
        sweeps beside each other.
        """
        with self._sweep_lock:
            if self._bridge_sweeping:
                return
            self._bridge_sweeping = True

        def _run():
            try:
                self.sweep_superseded_bridges(token)
                # ...and then the OTHER direction in time. The sweep above is
                # about bridges that already exist; the restore is about the
                # one this request is creating, which cannot be in a listing
                # taken before the server answered. See
                # `restore_titles_after_connect`.
                self.restore_titles_after_connect(token)
            except Exception:  # noqa: BLE001 — never take the daemon down
                pass
            finally:
                with self._sweep_lock:
                    self._bridge_sweeping = False

        threading.Thread(target=_run, daemon=True).start()

    # Bounded, and the bound is what keeps a quiet connect cheap: three
    # listings at four seconds, then give up until the next one.
    _RESTORE_ATTEMPTS = 3
    _RESTORE_DELAY = 4.0

    def restore_titles_after_connect(self, token: str) -> int:
        """Put local names back on bridges the server titled for itself.

        SPLIT OUT OF THE SUPERSEDED SWEEP, because the two look in opposite
        directions in time and one listing cannot serve both.

        Measured 2026-08-15 on host-a. A session named `CCF` reconnected
        Remote Control at 16:55:25Z and claude.ai showed
        `host-a-serene-unicorn` from then on. Every piece was in place:

            live_bridge_names()['cse_01VHLjpz…']            == 'CCF'
            _looks_generated('host-a-serene-unicorn') is True

        so the selection would have picked it — given a listing that contained
        it. `_sweep_bridges_after_connect` fires from the REQUEST path of
        `POST /v1/code/sessions`, and its own comment says so: *"Fired on the
        request rather than the response."* That is sound for closing a
        superseded bridge, whose subject already exists, and wrong for
        restoring a title, whose subject is the bridge the request is about to
        create.

        It failed silently, too: `_restore_bridge_titles` logs only `if done:`,
        so zero restored writes nothing. The daemon log showed six restores
        that day and none after 15:46:22Z — which reads exactly like a healthy
        daemon with nothing to do. And there is no second chance, because the
        trigger is that one request: a bridge missed here stays wrong until
        some OTHER session happens to connect. That is why the name comes back
        sometimes — each of those six was fixing a PREVIOUS session's title.

        THE STOP CONDITION IS OBSERVED, NOT TIMED. Sleeping "long enough" for
        the create to land is a guess that is wrong on a slow day and wasteful
        on a fast one. This asks a question with an answer: is any bridge this
        machine believes it holds still absent from the server's listing? When
        none is, there is nothing to wait for and the loop ends — usually on
        the first pass, having spent one listing.
        """
        # Pass 0 REUSES the sweep's listing and dials nothing. The sweep ran a
        # moment ago and already restored what that listing could support, so
        # this pass exists only to answer "is anything of ours still missing" —
        # and the answer is already in hand. Everything below it is the wait
        # for a create that had not landed yet.
        _UNSET = object()
        restored = 0
        carried = getattr(self, "_sweep_listing", _UNSET)
        self._sweep_listing = _UNSET
        if carried is None:
            # The sweep asked and got nothing. Asking again immediately is the
            # extra call this loop must not make; the next connect will retry.
            return 0
        for attempt in range(self._RESTORE_ATTEMPTS):
            if attempt or carried is _UNSET:
                if attempt:
                    time.sleep(self._RESTORE_DELAY)
                sessions = self._list_bridges(token)
            else:
                sessions, carried = carried, _UNSET
            if sessions is None:
                # COULD NOT ASK IS TERMINAL, not a reason to sleep and ask
                # again — the same answer `sweep_superseded_bridges` gives one
                # screen up. Retrying here waits on the wrong thing: this loop
                # exists for a listing that SUCCEEDS and does not yet show our
                # bridge, and an unreachable API is not that. That test drives
                # a real `POST /v1/code/sessions` against a deliberately dead
                # upstream, so every listing failed and this thread sat in
                # `sleep` for 8s per request, inside the daemon's own sweep
                # guard.
                return 0
            # ACCUMULATE, NEVER RETURN ON THE FIRST SUCCESS. A pass that
            # restores something has said nothing about the bridge this connect
            # is FOR: the listing is full of other sessions, and repairing one
            # of those is the most likely outcome of pass 0 precisely because
            # those bridges have existed long enough to be listed. Returning
            # there is what kept the original defect alive after the re-listing
            # loop was built to fix it. The stop condition below is the only
            # one that answers the right question: is anything this machine
            # holds still missing from the listing? Nothing else may short-
            # circuit it.
            restored += self._restore_bridge_titles(sessions, token)
            listed = {item.get("id") for item in sessions}
            # `live_bridge_names` carries BOTH spellings and the listing only
            # ever uses `cse_`, so comparing the raw keys would always report
            # something missing and loop to the bound every single time.
            pending = {sid for sid in live_bridge_names()
                       if sid.startswith("cse_") and sid not in listed}
            if not pending:
                return restored   # nothing of ours is unaccounted for
        # Falling out means a bridge we hold never appeared within the bound.
        # Whatever WAS repaired on the way still counts, so the caller's log
        # line reports the work rather than swallowing it.
        return restored

    def _serve_client(self, conn: socket.socket) -> None:
        """``_handle_client`` with the connection counted for its lifetime.

        The daemon knows who is talking to it better than any external probe
        can, and portably: the ``/proc/net/tcp`` scan behind
        ``clients_that_arming_would_cut_off`` answers None on macOS, where it
        was then read as "nobody is connected" and let the idle watcher stop
        a daemon mid-conversation.
        """
        # ALREADY COUNTED by `_accept_loop`, before this thread existed — see
        # the comment there. This method only has to give it back.
        def _release():
            with self._live_lock:
                self._open_conns.discard(conn)
                # Or the set grows for the life of the daemon, holding a
                # socket object per finished subscription.
                # AND THE OWNER MAP WITH IT, or the set grows for the life of
                # the daemon. It belongs HERE and not in the 101-upgrade
                # branch: Remote Control's inbound is a held GET, built from
                # the API base the pin MITMs, so it arrives decrypted and ends
                # on this teardown. (An older comment here said it was a
                # blind-tunnelled WebSocket to a separate ingress host, which
                # contradicted `_EVENT_STREAM` and is not what CC does.)
                self._forget_stream(conn)
                self._owed.pop(conn, None)
                self._delivered.pop(conn, None)
                self._content_at.pop(conn, None)
                self._gap.pop(conn, None)
                self._byte_gap.pop(conn, None)

        # HANDED OVER, NOT FINISHED. A handler that turns the connection into
        # an opaque tunnel gives its thread back and passes this teardown to
        # the pump, which runs it at EOF — so the connection stays counted for
        # its whole life without a thread sitting on it.
        self._local.release = _release
        detached = False
        try:
            detached = bool(self._handle_client(conn))
        finally:
            if not detached:
                _release()
            self._local.release = None

    def _owed_still_moving(self, since: float) -> bool:
        """Is any owed connection still DELIVERING, rather than merely open?

        THE DISCRIMINATOR A DEADLINE CANNOT MAKE. Measured on host-a
        2026-08-18: a departing daemon burned its full 600s ceiling and cut 12
        replies, every one of them `mid-response` and every one of them still
        streaming when it was cut. The drain gave up on live work because a
        clock said so.

            09:02:20Z cut 12 in-flight request(s) after 600.0s of a 600s budget
                      (12 mid-response, 0 before headers)

        A wedged connection and a four-minute answer are identical to a
        deadline — which is exactly why the deadline was there. They are not
        identical to the CONNECTION: one is moving bytes and one is not. So the
        wait ends when nothing has moved for `_DRAIN_STALL_SECONDS`, and the
        budget above it becomes a backstop against a bug in this predicate
        rather than the thing that decides.

        A connection owed but not yet started (value 0.0) is measured from the
        moment its OWN debt began, not from the drain's: its request is being
        read or relayed upstream, which is real work, and an upstream that
        never answers still ages out `_DRAIN_STALL_SECONDS` after that request
        arrived, so the daemon is not held open forever either.
        """
        now = time.monotonic()
        with self._live_lock:
            # THE DEBT'S OWN CLOCK, NOT THE DRAIN'S. `release_listener` sheds
            # ARRIVALS, not requests, so a keep-alive connection can begin a
            # NEW request mid-drain — and its `_owed` stamp stays 0.0 until the
            # first response byte. Aged from the drain's start, a request that
            # arrived seconds ago reads as however long the drain has run and
            # is cut on its first evaluation. `_owe_answer` re-seeds
            # `_content_at` per request, so that is the stamp that dates the
            # debt; `since` remains the fallback for an entry already gone.
            stamps = [(stamp, self._content_at.get(conn, since))
                      for conn, stamp in self._owed.items()]
        for stamp, owed_since in stamps:
            if now - (stamp or owed_since) < _DRAIN_STALL_SECONDS:
                return True
        return False

    def live_replies(self, started: float) -> int:
        """Owed connections that have delivered CONTENT since the drain began.

        NOT 'since the debt began'. Measured on host-a 2026-08-18, the twelve
        that mattered had delivered real content in the FIRST 20 SECONDS of
        their drain and nothing but keepalives for the thirty minutes after —
        so a counter that starts at the request would call every one of them
        live. The comparison has to be against a snapshot taken when the drain
        started, which is what this takes.

        WHAT IT IS FOR: `_sweep_orphan_daemons` picks the cheapest predecessor
        to reap, and it was picking by replies OWED — where twelve corpses
        outweigh two live replies, so at the limit it preferred to kill the
        process still doing real work. This is the same question asked about
        answers instead of about debts.

        NOT USED TO CUT ANYTHING. The drain still waits on movement; see the
        comment in `await_inflight` for why "no content since the drain began"
        is not a safe reason to stop waiting.
        """
        with self._live_lock:
            return sum(1 for conn in self._owed
                       if self._content_at.get(conn, 0.0) > started)

    def _delivered_summary(self) -> str:
        """How many bytes each still-owed reply has actually delivered.

        AN INSTRUMENT, AND THE ONE THE NEXT DECISION NEEDS. `mid-response`
        says headers went out and nothing finished — it cannot separate a
        reply streaming right now from one that stopped half an hour ago,
        because a keepalive is bytes and `_owed_still_moving` counts it as
        movement. Measured on host-a 2026-08-18: twelve connections logged as
        `12 mid-response` had delivered nothing but a fixed 39-byte frame for
        thirty minutes.

        PER CONNECTION, WHICH IS THE POINT. The same night produced process-
        wide byte rates from `/proc/<pid>/io` — 490 B/s during content against
        35 B/s of heartbeat — and that separation cannot be carried to a
        per-connection rule, because nobody knew how many of the twelve the
        content was flowing on. `_StampingWriter` is the only thing in this
        system that sees bytes attributed to a connection, so the count comes
        from there and the number arrives in a log line on every machine
        instead of from somebody sampling at the right moment.

        NOTHING DECIDES ON IT YET. The reaper still sorts on replies owed and
        the drain still ends on movement; this is here to produce the
        population a threshold would have to be chosen from, which is the step
        that was skipped for every ceiling that went wrong tonight.
        """
        with self._live_lock:
            counts = sorted(self._delivered.get(c, 0) for c in self._owed)
        if not counts:
            return "0 B"
        return (f"{counts[0]}/{counts[len(counts) // 2]}/{counts[-1]} B "
                "min/med/max")

    def content_free_intervals(self) -> "list[float]":
        """Seconds since CONTENT last reached each owed client, ascending.

        THE ONE MEASUREMENT `await_inflight` NAMES AND NOBODY HAD TAKEN. Its
        refusal to stop waiting on a content-free reply ends "it becomes
        decidable the day somebody measures the longest content-free interval
        a live reply produces", and until this existed no run produced that
        number — so the refusal could never be revisited on evidence, only
        argued about.

        IT HAS TO BE PER CONNECTION, and that is why it lives here rather than
        in a sampler. A peer tried `/proc/<pid>/io` deltas with a burst
        detector; the gap it finds means "no burst on ANY reply", and twelve
        replies staggered ten seconds apart give a burst every ten seconds
        while each one is silent for two minutes. The aggregate reads twelve
        times safer than the truth, in the direction that cuts live work.
        `/proc` has no per-connection byte counter at all, so no resolution
        fixes it — the quantity is not available at that layer.

        Content, not bytes: `_is_only_keepalive` separates them by SSE event
        NAME, so an idle stream scores its true silence however many pings it
        carries.
        """
        # INSIDE THE LOCK. Sampled outside it, a concurrent content write can
        # land between the read and the acquire, making `now` older than the
        # stamp and the interval NEGATIVE — `content-free -0/-0/-0 s` on the
        # cut line, and a marker whose 4th line parses fine and reads as
        # impossible.
        with self._live_lock:
            now = time.monotonic()
            return sorted(now - self._content_at.get(c, now)
                          for c in self._owed)

    def _content_free_summary(self) -> str:
        """`content_free_intervals` as one field of the drain line."""
        gaps = self.content_free_intervals()
        if not gaps:
            return "0 s"
        return (f"{gaps[0]:.0f}/{gaps[len(gaps) // 2]:.0f}/{gaps[-1]:.0f} s "
                "min/med/max")

    def content_free_seconds(self) -> float:
        """The worst of `content_free_intervals`, for the marker's one slot."""
        gaps = self.content_free_intervals()
        return gaps[-1] if gaps else 0.0

    def _note_reply_finished(self, conn) -> None:
        """This connection's response completed. Bank the silence it survived.

        THE ONLY EVIDENCE THAT RAISES A CEILING. A cut reports what was still
        open when patience ran out, which bounds nothing: those replies never
        finished, so their silence is not known to have been survivable. A
        reply that went quiet for N seconds and THEN delivered says N was safe
        to wait, and it is the only observation that does.

        Called from `_mitm` where a response has actually been relayed, not
        from `_owe_answer`, which also fires when a connection simply closes.
        """
        with self._live_lock:
            since = self._content_at.get(conn)
            if since is None:
                return
            # BOTH KINDS OF GAP. `_gap[conn]` is the longest interval BETWEEN
            # content writes, accumulated as they happen; the term below is the
            # final one, from the last content byte to completion. A reply that
            # went quiet and then delivered, and one that went quiet and then
            # ENDED, are both evidence that a wait of that length was safe —
            # the client got its answer either way.
            #
            # A REPLY THAT DELIVERED NO CONTENT AT ALL COUNTS TOO, and that is
            # deliberate against a review finding that called it inflation. Its
            # `_content_at` is still the seed from `_owe_answer`, so a 204 or a
            # 5xx after a 30s upstream stall banks 30s. Under-reporting is the
            # direction that costs somebody an answer, and excluding these
            # would under-report.
            self._quiet_peak = max(self._quiet_peak,
                                   self._gap.get(conn, 0.0),
                                   time.monotonic() - since)
            self._quiet_seen = True
            bg = self._byte_gap.get(conn)
            if bg:
                self._byte_peak = max(self._byte_peak, bg)
                self._byte_seen = True

    def inflight_mid_response(self) -> int:
        """Of the owed requests, how many have already sent the client bytes.

        See `_note_response_started`: these are the ones a cut cannot be
        retried out of.
        """
        with self._live_lock:
            return sum(1 for stamp in self._owed.values() if stamp)

    def inflight_requests(self) -> int:
        """Connections that owe somebody an answer RIGHT NOW.

        THREE DEFINITIONS WERE TRIED AND TWO WERE WRONG. Each was measured,
        and each failure is a different unreachable zero:

          1. OPEN CONNECTIONS. An RC WebSocket is opaque after its 101 and
             lives as long as the session, so the count never fell to zero,
             every recycle paid its whole ceiling, and `os._exit` then cut
             whatever was streaming. This is the original defect.

          2. THE REQUEST/RESPONSE SPAN ONLY. Zero became reachable, and a
             client that had been accepted but had not yet sent its request
             line was invisible: the drain returned instantly and the exit
             dropped it. `case_a_planned_restart_under_a_holder_loses_nothing`
             failed at once with "1 requests connected and were never
             answered", and the log said `cut 1 in-flight request(s) after 0s`.

          3. OPEN CONNECTIONS MINUS TUNNELS. Both of the above are handled and
             a third unreachable zero appears: after a reply finishes, an
             HTTP keep-alive connection sits open and idle, still counted, so
             the drain again burns the full ceiling. Measured: `cut 1
             in-flight request(s) after 30s` with the reply long since
             delivered.

        What all three were reaching for is the thing named here: a connection
        is work while somebody is WAITING on it. That starts at accept — a
        client whose request is still in the kernel buffer is owed an answer —
        and ends when its response has been written. A keep-alive connection
        between requests is owed nothing, and a tunnel is owed nothing.
        """
        with self._live_lock:
            return len(self._owed)

    def _note_response_started(self, conn, written: int = 0,
                               content: bool = True) -> None:
        """The first response byte for this connection has gone to the client.

        THE DIFFERENCE BETWEEN AN INCONVENIENCE AND A LOSS. A request cut
        BEFORE its headers went out has sent the client nothing, so the client
        sees a dropped connection and the SDK retries — it costs a round trip.
        One cut MID-RESPONSE has already delivered part of an answer, and there
        is no retry that repairs it: that is the "API Error: Connection lost
        mid-response" a user reads.

        Reported separately because the log could not tell them apart and the
        number was therefore unusable. The sibling CCF proxy already splits
        them (`cut 4 in-flight request(s) after 5s (4 mid-response, 0 before
        headers)`), and its counts were the only ones defensible as
        user-visible while ours said "a reply MAY have ended mid-stream".

        NOT MOVED OFF `_live_lock`, and it was raised as a hot-path
        contention: this runs per `sendall`, and the lock is also taken by
        `accept`, `live_client_count`, `_owed_still_moving`,
        `inflight_requests` and `_close_open_connections`. What it holds the
        lock FOR is one dict item assignment.

        Measured on host-a 2026-08-18, a departing daemon with 24 established
        connections: ~31 bytes/s in total, one 39-byte frame roughly every
        second across the whole set. That is the shape this path actually sees
        between token bursts, and it is nowhere near contention. An unlocked
        write is not free either — the entry can be popped concurrently by
        `_owe_answer`, and resurrecting a removed connection is a leak in the
        set the drain reads. Change it when a profile shows the lock, not
        because the shape looks expensive.
        """
        with self._live_lock:
            if conn in self._owed:
                prev_byte = self._owed[conn]
                self._owed[conn] = time.monotonic()
                if prev_byte:
                    self._byte_gap[conn] = max(
                        self._byte_gap.get(conn, 0.0),
                        self._owed[conn] - prev_byte)
                self._delivered[conn] = self._delivered.get(conn, 0) + written
                if content:
                    # BANK THE GAP BEFORE OVERWRITING THE STAMP. The first
                    # version only read `now - _content_at` at COMPLETION, and
                    # `_note_reply_finished` runs one frame after the last
                    # `sendall` — so it recorded the TRAILING gap, ~0 for every
                    # reply still streaming when it ends, and threw away the
                    # long quiet in the middle that the field exists to find. A
                    # reply that pings for two minutes of extended thinking and
                    # then delivers scored zero.
                    #
                    # AND IT COULD REPORT LARGER, NOT ONLY SMALLER, which is
                    # the half that would have done damage. A reply with NO
                    # content write never moved `_content_at` off its
                    # `_owe_answer` seed, so it banked its whole REQUEST
                    # DURATION. A wrong instrument is not conservative just
                    # because its first few samples were small.
                    prev = self._content_at.get(conn)
                    if prev is not None:
                        self._gap[conn] = max(self._gap.get(conn, 0.0),
                                              self._owed[conn] - prev)
                    self._content_at[conn] = self._owed[conn]

    def _owe_answer(self, conn, owed: bool) -> None:
        """Mark a connection as owing an answer, or as having paid it.

        Called at accept (owed), when a response has been fully written
        (paid), when the next request begins (owed again), when the connection
        becomes an opaque tunnel (paid, permanently), and at close (paid).

        Idempotent by construction: a set, not a counter. A counter would have
        to be decremented exactly once per increment across four call sites and
        two exception paths, and the first version that got that wrong would
        leave the daemon believing it is forever busy — which is the same
        outcome as the bug this replaces.
        """
        with self._live_lock:
            if owed:
                # A DICT, NOT A SET, AND THE VALUE IS A TIMESTAMP. 0.0 means
                # "owed, but no response byte has gone out yet"; anything else
                # is the monotonic clock at the LAST byte written to this
                # client. One field answers both questions the drain asks —
                # has the reply started (a cut is unretryable) and is it still
                # moving (a cut is premature).
                #
                # `setdefault` so re-marking an already-owed connection cannot
                # rewind it; only paying the debt clears the entry.
                self._owed.setdefault(conn, 0.0)
                # SEEDED AT THE DEBT, not at the first content byte. A reply
                # that has sent nothing has still been silent, and for longer
                # than one that sent a token a second ago — a missing entry
                # would have to be reported as either 0 (reads as answering
                # right now) or unknown, and both hide the worst case.
                self._content_at.setdefault(conn, time.monotonic())
            else:
                self._owed.pop(conn, None)
                # THE COUNT BELONGS TO THE DEBT. A connection that has paid and
                # is waiting for its next request starts the next one at zero,
                # or a keep-alive would look busier the longer it lives.
                self._delivered.pop(conn, None)
                self._content_at.pop(conn, None)
                self._gap.pop(conn, None)
                self._byte_gap.pop(conn, None)

    def live_client_count(self) -> int:
        """How many clients are connected right now. Never None: this is a
        count the daemon keeps itself, not an inference about the OS.

        DERIVED from the open set rather than a counter beside it. They were
        two names for one fact, incremented and decremented together — and
        `_close_open_connections` empties the set without touching a counter,
        so the pair could disagree exactly when a drain had just cut
        everything. One of them had to be the answer; the set is the one that
        also says WHICH connections.
        """
        with self._live_lock:
            return len(self._open_conns)

    def _bridge_api(self, method: str, path: str, token: str, timeout: float = 30.0,
                    body: bytes | None = None):
        """One call to the sessions API, over the daemon's own egress.

        NOT THROUGH OUR OWN PORT. `/v1/code/sessions` is a PINNED ROUTE, so a
        call routed through this daemon re-enters the swap path and is
        indistinguishable from a session's own request — it overwrote the
        bearer a real retry was using, caught by
        `case_a_403_on_a_swapped_route_is_retried_unswapped`.

        NOR A PLAIN DIRECT DIAL. Measured on this host: a fresh
        `create_default_context()` to api.anthropic.com fails
        CERTIFICATE_VERIFY_FAILED, because the direct route is a TLS-inspecting
        corporate proxy. `_connect_upstream` + `_upstream_ctx` are the pair
        that already solves both — the chain walk and the trust that matches
        whichever hop answered — so this reuses them rather than becoming a
        third egress path with its own copy of the same decisions.

        None means "could not ask", NEVER "nothing there": a sweep that read a
        failed call as an empty listing would close every bridge on the
        account.
        """
        raw = None
        try:
            raw, via_loopback = self._connect_upstream()
            up = _wrap_upstream(self._upstream_ctx(via_loopback), raw, UPSTREAM_HOST)
            up.settimeout(timeout)
            framing = (
                f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                if body is not None else ""
            )
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {UPSTREAM_HOST}\r\n"
                f"Authorization: Bearer {token}\r\n"
                "anthropic-beta: oauth-2025-04-20\r\n"
                "anthropic-version: 2023-06-01\r\n"
                "Accept: application/json\r\n"
                f"{framing}"
                "Connection: close\r\n\r\n"
            )
            up.sendall(req.encode("latin1") + (body or b""))
            status_line = _read_line(up) or ""
            headers = []
            while True:
                h = _read_line(up)
                if h in ("", None):
                    break
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers.append((k.strip(), v.strip()))
            # `resp`, not `body`: rebinding the request-body parameter here is
            # harmless only because `sendall` already happened, and any future
            # retry would re-send the RESPONSE as the request.
            resp = _read_body(up, headers)
            try:
                code = int(status_line.split(" ")[1])
            except (IndexError, ValueError):
                return None
            if code >= 400:
                return None
            return json.loads(resp) if resp else {}
        except Exception:  # noqa: BLE001 — could not ask
            return None
        finally:
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass

    def _list_bridges(self, token: str):
        """Every session on the pinned account, paginated. None when it failed.

        PAGINATION IS NOT OPTIONAL: the first page is 100 of ~560 here, and a
        sweep that saw only page one would treat every later bridge as absent.
        """
        out, cursor = [], None
        # A PARTIAL LISTING IS A LISTING WITH EVERY LATER BRIDGE MISSING, and
        # a reader deciding "the server no longer has it" from one would
        # clear every live pointer past the failed page. Complete only when
        # the last page was read; a caller that acts on absence checks this.
        self._listing_complete = False
        for _ in range(40):
            path = "/v1/code/sessions?limit=100"
            if cursor:
                path += "&cursor=" + quote(cursor)
            page = self._bridge_api("GET", path, token)
            if page is None:
                return None if not out else out
            out.extend(page.get("data") or [])
            cursor = page.get("next_cursor")
            if not cursor:
                self._listing_complete = True
                break
        return out

    def _restore_bridge_titles(self, sessions: list[dict], token: str) -> int:
        """Put each live session's own name back on its bridge.

        A restart drops the RC binding, Claude Code mints a NEW cloud session,
        and it never writes the new id back — so `/rename` afterwards has no id
        to PUT to and fails silently (the client accepts anything under 500).
        The name then only exists locally while claude.ai shows whatever the
        server invented. Measured after one forced restart on this fleet:
        'Session interrupted by user' twice, six 'host-a-<word>-<word>',
        and a reconnect on another machine produced 'host-b-curious-
        torvalds' for a session called `slack`.

        The registry is the exact pairing — a name and an owning pid, with the
        bridge id from that record or, after a teardown cleared it, from the
        job record it names — so nothing here guesses from cwd, branch or
        timing.

        Renamed items are updated IN PLACE because the caller's close pass
        matches on title: leaving it reading the stale listing would decide
        against titles that are one request out of date.
        """
        # BEFORE the read, or the restore puts back a name the session's own
        # owner has already replaced — the record is what `live_bridge_names`
        # reads and the rename never reached it.
        adopt_renamed_sessions()
        names = live_bridge_names()
        if not names:
            return 0
        done = 0
        certdir = getattr(self, "_certdir", None)
        ours = _titles_we_wrote(certdir)
        for sid, want in titles_to_restore(
                sessions, names, ours, invented_bridge_names()):
            body = json.dumps({"title": want}).encode("utf-8")
            if self._bridge_api(
                "PUT", f"/v1/code/sessions/{sid}", token, body=body
            ) is None:
                continue
            _record_title(certdir, sid, want)
            for item in sessions:
                if item.get("id") == sid:
                    item["title"] = want
            done += 1
        if done:
            _log_lifecycle(
                f"restored the session name on {done} bridge(s) the "
                f"reconnect had left under a generated title"
            )
        return done

    def sweep_superseded_bridges(self, token: str) -> int:
        """Close bridges that a NEWER bridge of the same name has replaced.

        A SECOND, NARROWER PATH accepts a merely ``disconnected`` twin too,
        but only with positive local evidence THIS HOST minted it and its
        creating process has died -- see the note where it branches, below.

        FOUR CONDITIONS, ALL REQUIRED, for the path this docstring covers.
        Each alone closes something in use; the measurement that ruled each
        one out is named with it.

        1. ``connection_status == "connected"``. Only a connected bridge
           competes for a message; a disconnected one costs nothing and
           closing it would only destroy history.

        2. ``status == "archived"``. A session that merely ENDED stays
           ``active`` — 186 of them here — so ``active`` cannot mean "gone".

        3. A NEWER BRIDGE SHARES ITS TITLE. This is what makes it safe.
           ``archived`` alone is also what the user gets by archiving a
           conversation they mean to return to: of 269 archived-and-connected
           bridges here, 202 are the newest thing carrying their title, and
           closing those would delete exactly what someone put away on
           purpose. The other 67 are the shape this exists for.

        4. ``worker_status != "running"``. The server reports this for every
           machine, so it sees what local pids cannot. `idle` means nothing --
           a live session is usually idle -- so it may only SAVE a bridge,
           never condemn one.

        "NO PROCESS ON THIS MACHINE" IS DELIBERATELY NOT A CONDITION. The pin
        exists so ONE account holds every machine's bridges, so this host sees
        the other machines' sessions and cannot check their pids. It would
        have been destructive: ``host-c-inbound-demo`` and ``pinverify-host-c``
        have no process here and were both LIVE on host-c when this
        was measured. Local liveness is used only as a NEGATIVE guard — never
        close something running here — never as evidence anything is dead.

        Nor is a title shared between two LIVE bridges a reason to close
        either: two windows both named ``cswap`` that each opened RC are two
        sessions in use, and that is for the human to fix with `/rename`.
        """
        sessions = self._list_bridges(token)
        # SET EVEN WHEN THE LISTING FAILED, and that is the whole point of the
        # attribute: `None` here means "asked, got nothing", which the retry
        # must treat as terminal. Leaving it unset let the retry read "the
        # sweep never ran" and dial its own listing — one extra API call per
        # connect on precisely the path where the last one just failed.
        self._sweep_listing = sessions
        if sessions is None:
            return 0  # could not ask — certainly not "delete everything"

        # HANDED TO THE RESTORE RETRY so it does not list again a millisecond
        # later. In production the same shape is one extra API call per RC
        # connect for nothing.
        self._sweep_listing = sessions

        # RESTORE NAMES FIRST, and not as a courtesy: the close pass below
        # matches on TITLE, so a successor that never inherited its name means
        # nothing supersedes the predecessor and nothing is ever closed. That
        # is how 551 bridges accumulated here against 14 live processes — the
        # sweep's premise was false in exactly the case it was built for.
        self._restore_bridge_titles(sessions, token)

        live = _live_bridge_ids()
        # A SECOND, NARROWER ACCEPTING PATH, alongside the four conditions
        # above: a twin still merely `disconnected` (Claude Code may never
        # get around to archiving a session nobody is left to reconnect),
        # closed ONLY with POSITIVE local evidence -- a job record THIS HOST
        # wrote, naming this bridge, whose creating process has since died.
        # "No process holds it" alone is never enough: another machine's
        # sleeping bridge answers that identically, and the pin exists
        # precisely so this host cannot see that machine's pids.
        dead_creator = _dead_creator_bridge_ids()
        newest: dict[str, str] = {}
        for item in sessions:
            title = (item.get("title") or "").strip()
            if title:
                stamp = item.get("last_event_at") or ""
                if stamp > newest.get(title, ""):
                    newest[title] = stamp

        closed = 0
        for item in sessions:
            sid, title = item.get("id"), (item.get("title") or "").strip()
            if not sid or not title or sid in live:
                continue
            if (item.get("connection_status") == "connected"
                    and item.get("status") == "archived"):
                # A RUNNING WORKER IS A SESSION AT WORK, and the listing says
                # for every machine, which local pids cannot. Measured on a
                # live roster: of three bridges passing all three conditions
                # above, one was `running` and had no process here -- so the
                # three conditions alone would close a bridge another machine
                # was working on.
                # A FOURTH NEGATIVE GUARD, in the same spirit as `sid in
                # live`: `running` is evidence of life, `idle` is evidence of
                # nothing (5 of the 7 locally-live bridges were idle in that
                # same sample), so only `running` may save a bridge and
                # nothing here may condemn one. An age floor was the obvious
                # alternative and does not work: the running bridge measured
                # was 160 minutes old.
                if str(item.get("worker_status") or "").lower() == "running":
                    continue
            elif (item.get("status") == "active"
                    and item.get("connection_status") == "disconnected"
                    and sid in dead_creator):
                # THE DEAD-CREATOR PATH. Archived is deliberately excluded --
                # that is the owner's claude.ai history, kept on purpose,
                # whatever a local record says -- and `worker_status` is
                # ignored: a disconnected bridge whose creator is dead here
                # carries a stale flag, and only the dead-creator record may
                # speak for it.
                pass
            else:
                continue
            if (item.get("last_event_at") or "") >= newest[title]:
                continue  # the newest of its name — someone put this away
            # THE SUPERSEDER MUST BE ONE OF OURS. Restoring names makes titles
            # MEANINGFUL, and meaningful names repeat: this machine alone runs
            # two sessions called `rewake`, and a third on another host would
            # look, from here, like a newer bridge superseding them. `live` is
            # machine-local by design, so without this the delete pass would
            # close another machine's archived conversation on the strength of
            # a name collision.
            if not any(other["id"] in live
                       for other in sessions
                       if (other.get("title") or "").strip() == title
                       and other.get("id") != sid):
                continue
            if self._bridge_api(
                "DELETE", f"/v1/code/sessions/{sid}", token
            ) is not None:
                closed += 1
        if closed:
            _log_lifecycle(f"closed {closed} superseded remote-control bridges")
        return closed

    def _handle_client(self, conn: socket.socket) -> None:
        # A per-CONNECTION id, not a thread id: threads are pooled and reused,
        # so tagging with get_ident() made two sequential connections share a
        # tag and the log could no longer pair a request with its response —
        # which read as "this request never answered" and sent a live
        # investigation down the wrong path twice. Assigned here rather than in
        # _mitm so a blind tunnel gets one too, on the same counter.
        self._local.cid = next(self._conn_seq)
        try:
            line = _read_line(conn)
            if not line:
                conn.close()
                return
            parts = line.split(" ")
            if parts[0] == "CONNECT":
                target = parts[1] if len(parts) > 1 else ""  # host:port
                if not target.strip():
                    # An empty authority makes `_blind_tunnel` dial host "":
                    # every hop refuses it and the request ends on a direct
                    # dial that never sees a bearer, while looking exactly
                    # like a healthy tunnel. Logged, not refused — these
                    # connections already fail, and a 400 is a different
                    # failure than the one the client gets today.
                    # THE SHAPE, NOT THE LINE: this runs before any credential
                    # check and the rest of a CONNECT line is whatever the
                    # client wrote, userinfo included.
                    self._tunnel_trace(
                        "CONNECT with an unreadable authority: "
                        f"{len(parts)} token(s), {len(line)} bytes")
                # Keep the CONNECT headers rather than draining them: the
                # proxy credential arrives here and nowhere else.
                connect_headers: list[tuple[str, str]] = []
                while True:
                    h = _read_line(conn)
                    if h in ("", None):
                        break
                    if ":" in h:
                        k, v = h.split(":", 1)
                        connect_headers.append((k.strip(), v.strip()))
                # A PIN THAT IS SET IS A PIN THAT APPLIES. The gate this
                # replaces demanded a credential carried in HTTPS_PROXY, which
                # is fixed at exec. Neither is what the feature is for. `cswap
                # pin 1` means Remote Control and Artifacts belong to account
                # 1, for every session on this machine, now — not for sessions
                # launched afterwards.
                #
                # WHAT THE CREDENTIAL BOUGHT, precisely: the proxy listens on
                # loopback and the kernel does not check uid on a TCP connect,
                # so any process that can reach the port could obtain a bearer
                # for the pinned account. But the secret lives at 0600 in the
                # cert dir, so every process running AS THIS USER can read it —
                # the sandboxed tool, the npm postinstall — which is the threat
                # the docstring named. It only ever excluded a DIFFERENT login
                # on a shared host. These are single-user machines; there is no
                # such login to exclude, and the cost was the feature not
                # working.
                #
                # THE BLIND TUNNEL IS NOT GATED EITHER, and keeping it gated
                # was my error. "Do not be an open forward proxy" assumes the
                # port is reachable; this one binds 127.0.0.1 only, so the
                # population it could refuse is the same-user processes that
                # can read the 0600 secret anyway. What it actually cost: every
                # host that is NOT api.anthropic.com takes this path — git,
                # pip, npm, the auto-updater.
                host = target.rsplit(":", 1)[0]
                if host != UPSTREAM_HOST:
                    return self._blind_tunnel(target, conn)
                return self._mitm(conn)
            if len(parts) >= 2 and parts[1].startswith("/health"):
                # Local health probe (origin-form GET /health to our own port).
                # Lets a statusline/cc-update probe tell the pin proxy apart
                # from another local proxy and read the chain it forwards to.
                self._serve_health(conn)
                return
            if len(parts) >= 2 and "://" in parts[1]:
                # Absolute-form request (plain-proxy mode, no CONNECT). The
                # native auto-updater and telemetry use axios this way; dropping
                # them is what pins the "Auto-update failed" banner. NOT
                # verbatim: `claude remote-control`'s bridge client speaks this
                # form too, so `_plain_relay` takes the same swap decision the
                # MITM does. "No MITM, no swap" stood on this line for six
                # releases and is why the route table alone fixed nothing.
                self._plain_relay(line, conn)
                return
            conn.close()
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    def _current_secret(self) -> str | None:
        """The credential to require RIGHT NOW, or None to require none.

        Re-read per connection, like ``_current_chain`` does for the egress
        proxy, so a secret written under a running daemon takes effect without
        a respawn. Caching it at construction meant the gate armed on the next
        RESPAWN instead — a fingerprint recycle, a deploy, an idle teardown —
        with nothing a human would connect to the resulting 407s.

        Arming DOES cut off sessions wired before the credential existed —
        their ``HTTPS_PROXY`` is fixed at exec time and cannot be updated in
        place (measured: 67 such sessions on linux). That is unavoidable, not
        a bug to design around: nothing in a request distinguishes one of them
        from an attacker, so any rule that keeps serving them keeps the hole
        open. What matters is that it happens WHEN AN OPERATOR ASKS, in one
        step they can pair with a relaunch, instead of silently on some later
        respawn. Hence: minted by ``apply_pin``, enforced from that instant.
        """
        return read_proxy_secret(self._certdir) or None

    def _wait_for_pin_token(self, method: str, path: str, token):
        """`token`, retried briefly where a miss costs something PERMANENT.

        ONE REQUEST IS WORTH A RETRY, and only one. Everywhere else a missing
        token costs a single request billed elsewhere; on a create it gives the
        asset away for good, because the server fixes the owner there and
        offers no transfer. The usual cause is `consume-busy` — the usage
        collector holding the slot's refresh lock for an instant — so a short
        retry converts a permanent loss into a wait nobody notices. Bounded,
        and the request still goes untokened afterwards: a launch that hangs is
        worse than this fault.

        ONE PLACE, BECAUSE THE TWO CREATES ARRIVE ON DIFFERENT PATHS.
        `POST /v1/code/sessions` comes through the MITM; `claude
        remote-control`'s `POST /v1/environments/bridge` only ever arrives in
        absolute form. A wait wired to one of them is absent from the other,
        which is the same gap the route table had.

        Takes the token rather than fetching it: the MITM may already hold one
        from the sweep, and that provider re-reads the credential from disk and
        takes a cross-process lock on every call.
        """
        if token or not should_wait_for_pin(method, path) \
                or _pin_is_noop(self._pin_token_provider):
            return token
        for _ in range(_PIN_WAIT_TRIES):
            time.sleep(_PIN_WAIT_S)
            token = self._pin_token_provider()
            if token:
                return token
        _log_lifecycle(
            "a bridge was created without the pin: the token could not be "
            "minted in time, so this session belongs to the active account "
            "permanently and cannot be transferred"
        )
        return None

    def _refuse_unauthorized(self, conn: socket.socket) -> None:
        """407 a CONNECT that did not present the proxy credential.

        407 rather than a silent close so a misconfigured client says what is
        wrong instead of retrying forever against a proxy that looks dead —
        that failure mode cost a day when a dead port produced
        "ConnectionRefused, attempt 14/300" and nothing named the cause.
        """
        try:
            conn.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Basic realm="cswap-pin"\r\n'
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    def _refuse_stalled_mint(self, tls, method: str, path: str) -> bool:
        """Answer a pinned request 503 rather than queue it behind a refresh
        lock a stalled credential store may never release.

        Keeps the connection alive (``Connection: keep-alive``) like an
        ordinary reply: the swap being unavailable this once says nothing
        about the connection, and closing it would cost every OTHER request
        pipelined on it too (see ``_forward``'s note on Remote Control's
        worker connection).

        Rate-limited like ``_note_mint_busy`` and ``_note_busy_slot`` — a
        session retrying a pinned route against a stuck store would
        otherwise write one line per request.
        """
        now = time.monotonic()
        last = getattr(self, "_stall_refused_at", None)
        if last is None or now - last >= _BUSY_REPORT_COOLDOWN_S:
            self._stall_refused_at = now
            _log_lifecycle(
                f"{method} {path} refused (503): the pinned token could not "
                f"be minted within {_MINT_LOCK_BOUND_S:.0f}s -- a stalled "
                "credential store, not a broken pin"
            )
        try:
            tls.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
        except OSError:
            pass
        return True

    def _warn_unpinnable(self) -> None:
        """Say once, on stderr, that the pin is not being applied.

        The swap fails open on purpose, so nothing else marks this: requests
        keep succeeding, the daemon keeps answering /health, and the only
        visible consequence arrives later as Remote Control sessions owned by
        the wrong account with no way to transfer them. Measured: a daemon that
        could not reach its credential store served every pinned route
        unswapped and 19 sessions had to be rebuilt by hand.

        Once per daemon, not per request — a pinned session makes these calls
        continuously and a line each would bury the signal it is meant to be.
        """
        if getattr(self, "_warned_unpinnable", False):
            return
        self._warned_unpinnable = True
        # RECORD IT, do not only say it. The advice this prints — "re-run
        # `cswap pin` from a normal terminal" — cannot work on its own:
        # ensure_proxy reuses any daemon whose fingerprint matches, so the re-
        # run finds this same blind daemon and returns it. Written to the state
        # file so the NEXT ensure_proxy can see what only this process could
        # learn, and recycle instead of reusing.
        try:
            mark_daemon_unpinnable(self._certdir)
        except Exception:  # noqa: BLE001 — advisory; never break a request
            pass
        # THE HOLDER IS NOT RETIRED HERE, and the reason is measured. Doing
        # that manufactures the orphan condition on the very next tick, and the
        # orphan branch of the code watchdog has no backoff -- so a machine
        # that cannot mint rebuilt its whole triad every 31 seconds, for ever.
        # The self-heal in the watchdog already gets a fresh daemon from the
        # holder, and IT is throttled; a second, unthrottled path to the same
        # outcome is not redundancy, it is the loop.
        # BOTH getattrs. A warning on a request path must never raise, and a
        # PinProxy without a provider is reachable -- a bare construction, a
        # test double. Saying less is the failure mode to prefer here.
        why = getattr(getattr(self, "_pin_token_provider", None),
                      "blind_reason", "") or "reason unrecorded"
        try:
            sys.stderr.write(
                f"cswap pin [{why}]: "
                "the pinned account's token could not be read, so "
                "requests are going out UNPINNED. Remote Control sessions "
                "created now will belong to the active account permanently. "
                "On macOS this is usually a daemon started outside the GUI "
                "session, which cannot read the keychain; re-run `cswap pin` "
                "from a normal terminal.\n"
            )
            sys.stderr.flush()
        # Only a broken stderr — a bare `except Exception` here swallowed a
        # missing import and left the warning silently dead, which is the same
        # class of bug this warning exists to surface.
        except OSError:
            pass

    @property
    def direct_last(self) -> "float | None":
        """When this daemon last fell back to a DIRECT dial, or None.

        The one field in /health that survives the recovery. `egress` answers
        "what is egress doing", which is the wrong tense: the chain flaps back
        within seconds and every later probe reads green, so a real outage is
        invisible to everyone who was not watching at the instant it happened.

        Measured on host-b 2026-08-06 — 9901 stopped tunnelling at
        22:35:44Z, 8118 followed, the daemon went DIRECT at 22:36:46Z and was
        back on 9901 at 22:36:47Z. One second of green-again, and the whole
        incident was unreadable from that point on. This is the fifth outage
        this daemon detected and wrote to daemon.log, and the fifth nobody
        read.

        NOTE THE Z. daemon.log is UTC while claude-swap.log is local, and a
        session hunting an artifact failure read one against the other, landed
        on this outage four hours off, and published it as the cause. It was
        not. Timestamps out of this daemon are UTC — compare like with like.

        A timestamp rather than a flag: the only question a reader has is
        whether the fallback explains what they are looking at, and "it
        happened" cannot be told from an hour ago or a week ago.
        """
        return self._egress_direct_last

    @property
    def hop_degraded_last(self) -> "float | None":
        """When the walk last fell through to a hop that was not preferred.

        The sibling of :attr:`direct_last`, for the fault it does not cover.
        DIRECT means the chain was abandoned; this means the chain was USED
        with its first hop skipped — different incidents, different owners,
        and only one of them was readable after the fact.
        """
        return self._hop_degraded_last

    def _serve_health(self, conn: socket.socket) -> None:
        import json

        # Report the chain the relay would actually use, not the one this
        # daemon was constructed with — those diverge the moment the egress
        # proxy moves, and a health probe that says "no chain" while every
        # request goes through one sends the next diagnosis the wrong way.
        current = self._current_chain()
        chain = f"{current[0]}:{current[1]}" if current else None
        # Whether the pin can actually be APPLIED, not merely that a daemon is
        # up. The swap fails open by design — a request whose token cannot be
        # minted still goes out, on the disk bearer — so a daemon that cannot
        # read its own credential store serves unpinned traffic while every
        # visible signal stays green. "No token" is not the same as "cannot
        # mint one". With the pinned account already active there is
        # deliberately nothing to swap, and reporting can_pin=false there tells
        # a monitor the pin is broken on the one machine where it has nothing
        # to do.
        #
        # NEVER WAITS ON THE MINT, and never CALLS the provider at all: even
        # a free lock does not mean the provider is cheap to call -- reading
        # the pin and resolving the account are their own store accesses,
        # every one of which could be the thing that is stuck (measured: a
        # Keychain read still hung after 2d19h). This is the ONE probe every
        # monitor, `cswap pin --heal` and the installer's activation check
        # use for liveness, so a stalled store must never make it read as a
        # dead daemon. Peek the refresh lock non-blocking first; `can_pin`
        # otherwise comes only from what is already cached — see
        # `_can_pin_from_cache` and the daemon-start warm that keeps it
        # populated on a healthy daemon.
        mint_stalled_s = _mint_lock_busy(self._pin_token_provider)
        can_pin = (True if mint_stalled_s is not None
                   else _can_pin_from_cache(self._pin_token_provider))
        # WHAT EGRESS IS ACTUALLY DOING, not what it is configured to do.
        # `chain` above reports the hop the relay WOULD use, so a daemon that
        # can reach no hop and is dialling DIRECT reported exactly what a
        # healthy one did. DIRECT is not "degraded but fine" on a corporate
        # host: the direct route IS the TLS-inspecting proxy, and it answers
        # 403. Owner's count on host-a for one day: 61 DIRECT transitions, 148
        # dial-failed, 89 accepted-but-did-not-tunnel, against 238 healthy. The
        # pin detected all four outages and wrote all four to daemon.log;
        # nobody read it any of the four times. `null` until the first dial:
        # "we have not dialled yet" is not the same as "we are direct", and a
        # monitor that cannot tell them apart alarms on every daemon start.
        if self._egress_hop is not None:
            egress = f"{self._egress_hop[0]}:{self._egress_hop[1]}"
        elif self._egress_direct:
            egress = "direct"
        else:
            egress = None
        # `egress` is instantaneous; `direct_last` is the same fault in a tense
        # a later probe can still read. See :attr:`direct_last`.
        #
        # WHO HOLDS THE ADDRESS — the one question argv cannot answer. A
        # standby that ARMS becomes the holder and its argv still says
        # `--standby` forever, because argv is fixed at exec; a peer read the
        # role off it and reported an intact triad as deviating. proxy.json
        # records the DAEMON pid, which is a different process. COMPUTED HERE,
        # NEVER STORED. A recorded holder goes stale in exactly the event this
        # reports: holder dies, standby arms, and the record still names the
        # dead one until the next respawn. `held_by_a_holder` compares the
        # spawn-time marker against a LIVE `getppid()`, so the kernel owns the
        # comparand — a reused pid cannot forge it without actually being our
        # parent. `null` when nothing holds us, which is not the same as
        # "unknown": it says this address dies with this process. Reporting a
        # bare `getppid()` instead would name an unrelated process as the
        # holder of a socket it has never heard of.
        holder_pid = os.getppid() if held_by_a_holder() else None
        body = json.dumps(
            {"pin_proxy": True, "port": self.port, "chain": chain,
             # THE VERSION THE LIVE PROCESS IS RUNNING, which is not what the
             # installed package reports: a daemon survives the install that
             # replaced it, so anything reading a version off disk answers
             # about code that may not be serving. Readers deciding whether a
             # behaviour is present need this one.
             "version": _own_version(),
             "can_pin": can_pin, "egress": egress,
             "holder_pid": holder_pid,
             "direct_last": _iso_utc(self._egress_direct_last),
             "hop_degraded_last": _iso_utc(self._hop_degraded_last),
             # ADDITIVE, never a replacement for `can_pin`: whether the mint
             # check itself is currently busy behind a refresh in progress
             # (possibly stalled) rather than answered, and for how long —
             # see the note above `mint_stalled_s` is computed from.
             "mint_stalled": mint_stalled_s is not None,
             "mint_stalled_s": (round(mint_stalled_s, 1)
                                 if mint_stalled_s is not None else None)}
        )
        try:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("latin1")
                + body.encode("latin1")
            )
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _plain_relay(self, request_line: str, conn: socket.socket) -> None:
        """Forward an absolute-form proxy request through the chain (or direct).

        Rewrites the request line to origin-form and dials the target host —
        via the chain proxy if one is set (still absolute-form to it, as a
        plain proxy expects), else straight to the origin.
        """
        rl = request_line.split(" ")
        method, url = rl[0], rl[1] if len(rl) > 1 else "/"
        headers = []
        parsed: list[tuple[str, str]] = []
        while True:
            h = _read_line(conn)
            if h in ("", None):
                break
            if ":" in h:
                k, v = h.split(":", 1)
                parsed.append((k.strip(), v.strip()))
                # Never forward OUR proxy credential onward. This path relays
                # the client's headers verbatim to the chain (a cache proxy, a corporate
                # proxy), which would hand them a working credential for the
                # pinned account's proxy. It is hop-by-hop by definition
                # (RFC 9110): it authenticates to THIS proxy and stops here.
                if k.strip().lower() == "proxy-authorization":
                    continue
            headers.append(h)
        # STILL A HARD GATE here, unlike CONNECT. This path is plain-HTTP
        # forwarding to an arbitrary host: there is no bearer to withhold, so
        # "serve it unpinned" is not a weaker option — it just makes us an open
        # forward proxy. The CONNECT path could soften because refusing there
        # bought nothing the swap decision does not already buy.
        #
        # Claude Code DOES reach here: its Remote Control bridge client speaks
        # absolute form, so `claude remote-control` registers its environment
        # on this path. The refusal cannot cut those off — they carry our
        # credential — and the swap below exists because they arrive here.
        #
        # AND IT COMES BEFORE THE BODY. `_read_body` loops until the client's
        # own Content-Length is satisfied, so reading first lets an
        # unauthenticated caller hold a thread and an unbounded buffer by
        # announcing a body and sending none.
        if not _proxy_authorized(parsed, self._current_secret(),
                                 certdir=self._certdir):
            self._refuse_unauthorized(conn)
            return
        # THE BODY IS OURS TO CARRY, not `_pump`'s: anything that reads the
        # RESPONSE first deadlocks otherwise — the origin waits for
        # Content-Length bytes nobody sent while we wait for a status line.
        # The take-back needs it materialized anyway; a streamed body cannot
        # be replayed.
        body = _read_body(conn, parsed)
        # `_read_body` DECODES a chunked body, so the framing has to be
        # re-declared or the upstream reads a bodyless request — same
        # correction `_mitm` makes.
        if any(k.lower() == "transfer-encoding" and "chunked" in v.lower()
               for k, v in parsed):
            headers = [h for h in headers
                       if h.split(":", 1)[0].strip().lower()
                       not in ("transfer-encoding", "content-length")]
            headers.append(f"Content-Length: {len(body)}")
        split = urlsplit(url)
        # The scheme decides the port. Defaulting every scheme to 80 pointed
        # every https:// target at the wrong port, so those requests (the
        # auto-updater, telemetry) could not succeed at all.
        secure = split.scheme == "https"
        host, port = split.hostname, split.port or (443 if secure else 80)
        # THE SAME OWNERSHIP DECISION THE MITM MAKES, because the same routes
        # arrive here: an absolute-form request carries the identical bearer
        # and the server fixes the identical ownership from it.
        #
        # Guarded on the ORIGIN. This path forwards to an arbitrary host, and a
        # bearer belongs to the host it was minted for; rewriting one on the
        # way to somebody else's server would hand out the pinned token.
        unswapped = None      # set only when a swap actually happened
        rel = (split.path or "/") + (f"?{split.query}" if split.query else "")
        # `and secure` IS THE HALF THAT KEEPS THE TOKEN OFF THE WIRE. The host
        # guard asks WHO and says nothing about HOW, so an `http://` request to
        # the same host passes it and the direct dial then writes the pinned
        # bearer onto a bare TCP socket. The MITM path always wraps its
        # upstream, so the exposure would be this path's alone.
        if host == UPSTREAM_HOST and secure:
            ua = next((h.split(":", 1)[1].strip() for h in headers
                       if h.split(":", 1)[0].strip().lower() == "user-agent"),
                      "")
            if is_pinned_route(rel, ua):
                token = self._wait_for_pin_token(
                    method, rel, self._pin_token_provider())
                if token and any(h.split(":", 1)[0].strip().lower()
                                 == "authorization" for h in headers):
                    # ARMED ONLY WHEN THE SWAP HAPPENED. With no token nothing
                    # changed, so a second attempt would replay an identical
                    # request and double every failure.
                    unswapped = list(headers)
                    # AND `Host:` MUST AGREE WITH THE HOST WE GUARDED ON. The
                    # direct branch rewrites the line to origin form, where
                    # `Host` is the authority — so a request whose URL says
                    # upstream and whose header says somewhere else would be
                    # swapped on the URL and routed on the header.
                    headers = [
                        f"Authorization: Bearer {token}"
                        if h.split(":", 1)[0].strip().lower() == "authorization"
                        else (f"Host: {UPSTREAM_HOST}"
                              if h.split(":", 1)[0].strip().lower() == "host"
                              else h)
                        for h in headers
                    ]
                # TRACED LIKE THE MITM PATH. Untraced, a feature travelling
                # here leaves the same evidence as one that never ran.
                self._tunnel_trace(
                    f"{method} {rel} pinned=True swapped={bool(token)} "
                    "(absolute-form)")
        # Re-read like every other egress site: the daemon is constructed with
        # chain_proxy=None, so reading self._chain here meant this path ALWAYS
        # dialled the origin direct — bypassing the egress proxy on exactly the
        # traffic (auto-updater, telemetry) it was added to rescue, and hard
        # failing where there is no direct route out.
        # EVERY HOP, like the MITM path and the blind tunnel. Reading only the
        # first one meant a dead hop fell through to a dial at the ORIGIN,
        # skipping the hop behind it — and on a host with no direct route out
        # that is not a downgrade, it is a failure. This is the auto-updater's
        # and telemetry's path.
        def dial(hdrs):
            """`(socket, head)` for one attempt, or `(None, None)`."""
            for chain in self._chain_candidates():
                try:
                    sock = _dial_chain(chain, extra_ca=self._chain_ca())
                except (OSError, ssl.SSLError):
                    continue
                # A plain proxy takes the absolute-form line as-is. Our own
                # credential for the chain rides here, not the client's.
                return sock, (
                    f"{method} {url} HTTP/1.1\r\n"
                    + "\r\n".join(hdrs)
                    + "\r\n"
                    + chain.connect_headers()
                    + "\r\n"
                )
            try:
                sock = socket.create_connection((host, port), timeout=15)
                if secure:
                    # An https:// origin dialled direct needs the handshake,
                    # verified. Without it we sent cleartext HTTP at a TLS
                    # port and the request simply failed.
                    sock = _verifying_ctx().wrap_socket(sock,
                                                        server_hostname=host)
            except (OSError, ssl.SSLError):
                return None, None
            rel_path = split.path or "/"
            if split.query:
                rel_path += "?" + split.query
            return sock, (f"{method} {rel_path} HTTP/1.1\r\n"
                          + "\r\n".join(hdrs) + "\r\n\r\n")

        # A SWAP THE UPSTREAM REFUSES IS TAKEN BACK, as the MITM path already
        # does. An environment registered before the pin knew this route
        # belongs to whoever registered it, so asking as the pin gets 401 and a
        # live Remote Control dies. Nothing has reached the client yet, so the
        # request can still go again with the bearer it arrived with.
        for hdrs, retry in ((headers, unswapped is not None),
                            (unswapped, False)):
            if hdrs is None:
                break
            up, head = dial(hdrs)
            if up is None:
                conn.close()
                return
            try:
                # Connect budget only, same as the tunnel: _pump streams, and
                # a read timeout left on the socket tears down a response that
                # is merely quiet — an SSE gap or a slow origin — rather than
                # dead.
                up.settimeout(None)
                up.sendall(head.encode("latin1") + body)
                if retry:
                    code, seen = _peek_status(up)
                    if code in (401, 403, 404):
                        self._tunnel_trace(
                            f"{method} {rel} swap refused ({code}) — "
                            "retrying as it arrived (absolute-form)")
                        continue
                    if seen:
                        conn.sendall(seen)
                _pump(conn, up)
                return
            finally:
                try:
                    up.close()
                except OSError:
                    pass

    def _mitm(self, conn: socket.socket) -> bool:
        """Serve requests on this connection. True when it was HANDED OVER.

        A 101 turns the connection into an opaque stream that the shared pump
        owns from then on — so this frame must NOT close it, and its caller
        must not run the per-connection teardown that the pump will run at EOF.
        """
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # STASHED BEFORE THE WRAP, because `wrap_socket` DETACHES: after it,
        # `conn.fileno()` is -1 and the SSLSocket owns the fd. The debt is
        # keyed on this object, which is the same one `_open_conns` holds, so
        # the two stay in step.
        self._local.conn = conn
        tls = self._server_ctx.wrap_socket(conn, server_side=True)
        self._local.detached = False
        served_one = False
        try:
            while True:
                # THE DEBT BOUNDARY. `_read_line` inside then blocks until the
                # next request line arrives, and the debt is taken back up the
                # moment one does. BETWEEN, NOT BEFORE THE FIRST. Clearing it
                # here undid that for every MITM'd connection: CONNECT parsed,
                # TLS up, request on the wire, and `inflight_requests()`
                # reporting zero. The accept-time debt now survives until this
                # connection has actually answered something.
                if served_one:
                    self._note_reply_finished(conn)
                    self._owe_answer(conn, False)
                    # AND THE SUBSCRIPTION MARK ENDS WITH IT. A stream request
                    # that answered with a Content-Length (a refused auth) is
                    # a finished reply on a reusable connection; leaving the
                    # mark lets a later drain claim it and un-owe a reply that
                    # is still being written, uncounted.
                    with self._live_lock:
                        self._forget_stream(conn)
                        # THE OWNER MAP GOES WITH IT, inside that call, and
                        # here it is not merely a leak: the connection stays
                        # OPEN as keep-alive, so a stale entry makes
                        # `deaf_bridges` read this session as HOLDING a stream
                        # after its stream ended — a false negative in the
                        # check, worse than the leak.
                got_one = self._handle_one_request(tls, conn)
                self._local.up_idle_since = time.monotonic()
                served_one = True
                if not got_one:
                    break
        finally:
            if not getattr(self._local, "detached", False):
                self._drop_upstream()
                try:
                    tls.close()
                except OSError:
                    pass
        return bool(getattr(self._local, "detached", False))

    def _handle_one_request(self, tls: ssl.SSLSocket, conn=None) -> bool:
        request_line = _read_line(tls)
        if not request_line:
            return False
        # A REQUEST LINE ARRIVED, so somebody is waiting again. The debt runs
        # until this returns, which is after the response has been relayed —
        # so a streaming reply is owed for every second it streams.
        if conn is not None:
            self._owe_answer(conn, True)
            if _EVENT_STREAM.search(request_line):
                with self._live_lock:
                    self._stream_conns.add(conn)
        # PER BRIDGE, not per connection. `_stream_conns` answers "is this
        # SOCKET a stream", which is what the drain needs; this answers "does
        # this SESSION hold one", which is what a deaf bridge fails.
        # THE PATH, split the way `_handle_one_request_inner` splits it. The
        # route patterns are `^`-anchored, so a request line matches none of
        # them and the accounting silently records nothing.
        _p = request_line.split(" ")
        self._note_bridge_traffic(_p[1] if len(_p) > 1 else "/", conn=conn)
        return self._handle_one_request_inner(request_line, tls)

    def _handle_one_request_inner(self, request_line: str, tls: ssl.SSLSocket) -> bool:
        _parts = request_line.split(" ")
        method, path = _parts[0], _parts[1] if len(_parts) > 1 else "/"
        headers: list[tuple[str, str]] = []
        while True:
            h = _read_line(tls)
            if h in ("", None):
                break
            if ":" in h:
                k, v = h.split(":", 1)
                headers.append((k.strip(), v.strip()))
        body = _read_body(tls, headers)

        ua = next((v for k, v in headers if k.lower() == "user-agent"), "")
        pinned = is_pinned_route(path, ua)
        # TWO CLOCKS, because the total alone cannot say who was slow — see
        # `_note_slow_request`. `_t_pin` closes where the request leaves us.
        _t_req = _t_pin = time.monotonic()
        # OUTSIDE THE BEARER GATE, deliberately. Sweeping superseded bridges is
        # our own bookkeeping and has nothing to do with whose token a request
        # carries. Inside `if pinned:` the presence trigger was UNREACHABLE,
        # because presence is deliberately not a pinned route — so the second
        # trigger, its cooldown and its timestamp were all dead and the
        # archived-later case 0.1.139 set out to cover stayed uncovered. The
        # cooldown gates the token fetch too, so an unpinned route costs
        # nothing beyond one regex.
        #
        # ONE TOKEN PER REQUEST, AND THIS IS WHY. Moving the sweep out of the
        # bearer gate above was right, but it brought its own
        # `_pin_token_provider()` call with it — so a PINNED route that also
        # triggers a sweep fetched the same token TWICE. That provider re-reads
        # the pin and the credential from disk on every call, takes a cross-
        # process lock, and on expiry POSTs a refresh. Twice, in front of the
        # client, on the request path. Fetched once here and shared. `None` is
        # a real answer (the pin is the active account, or no usable token), so
        # it is cached in a sentinel rather than re-fetched by a falsy test.
        _tok_fetched = False
        _tok = None
        if self._should_sweep_bridges(method, path):
            # BEFORE THE SWEEP, AND THAT ORDER IS LOAD-BEARING: the carry reads
            # this same config field to decide whose pointers to restamp, so a
            # sweep run against a drifted field stamps the wrong owner — the
            # veto this exists to prevent. Same ordering as `heal`.
            if path == "/v1/code/sessions":
                self._reassert_pin_identity()
            self._report_deaf_bridges()
            _tok, _tok_fetched = self._pin_token_provider(), True
            if _tok:
                self._sweep_bridges_after_connect(_tok)
        swapped = False
        original_headers = list(headers)
        if pinned:
            token = _tok if _tok_fetched else self._pin_token_provider()
            # A STALL, NOT A FAIL-OPEN CASE. `provider()` above just gave up
            # on `refresh_lock` after `_MINT_LOCK_BOUND_S` rather than queue
            # behind a credential store that may never answer (measured: a
            # Keychain read still hung after 2d19h) -- the shape that put 104
            # requests on this daemon "before headers" with a live socket and
            # nothing serving it. Fail THIS request fast instead of joining
            # them; the fail-open path below is for a credential that was
            # actually asked and answered no.
            if token is None and getattr(
                    self._pin_token_provider, "mint_stalled", None
            ) and self._pin_token_provider.mint_stalled():
                return self._refuse_stalled_mint(tls, method, path)
            token = self._wait_for_pin_token(method, path, token)
            if token:
                headers = [
                    (k, f"Bearer {token}") if k.lower() == "authorization" else (k, v)
                    for k, v in headers
                ]
                swapped = True
                # TWO MOMENTS, not one. A create is when a NEW bridge opens
                # beside an older connected one. Sweeping on THIS instead of a
                # timer means a quiet daemon never wakes to find nothing, and
                # the fix lands when it is needed rather than up to an hour
                # later. Fired on the request rather than the response: the
                # sweep re-lists from the server anyway, so a create that fails
                # simply finds nothing new to supersede.

                # THE ONE MOMENT A DENIED SESSION BECOMES UN-DENIED, and the
                # only evidence of it. Claude Code caches the policy answer per
                # process and its `/remote-control` pre-fetch returns early
                # when a document is already cached, so a session that once
                # read a denial keeps refusing with no request on the wire.
                # This poll is the sole thing that replaces that cache, and
                # only on a 200 — a failure or a 304 re-seeds the same
                # document. Saying so here is the difference between "the fix
                # will reach it" and having watched it arrive.
                #
                # THE ONE CALL THAT CAN SAVE A LIVE BRIDGE, and until now it
                # was invisible. Claude Code asks this when the identity file
                # names an account other than the bridge's owner; our answer
                # names the PINNED account, which makes CC re-baseline rather
                # than disconnect — and it REASSIGNS the owner to that answer,
                # so every later rotation compares pin against pin. Its absence
                # is the other half of the diagnosis: a bridge that died
                # without this line never asked, and one that died after it
                # asked is a different fault entirely. The `[bridge:owner-pin]`
                # traces only exist under --debug, which no session here runs,
                # so nothing else can tell those apart.
                if path.split("?", 1)[0].rstrip("/") == "/api/oauth/validate":
                    # HOW MANY DID NOT ASK, in the same line. The absence of
                    # this line is half the diagnosis, and a bare "a session
                    # asked" cannot say whether that was one of two or one of
                    # fourteen. A rotation that tears one bridge down while
                    # ONE of fourteen asked is a different fault from one
                    # where all fourteen asked, and the counts were being
                    # reconstructed by hand afterwards from a log that never
                    # recorded the denominator.
                    try:
                        held = len(self.held_bridge_ids())
                    except Exception:  # noqa: BLE001 — a log must not cost a request
                        held = -1
                    _log_lifecycle(
                        "a session asked who its credential belongs to — "
                        "answered as the pinned account, which is what lets a "
                        "live bridge survive the account rotation"
                        + (f" (this daemon is carrying {held} bridge(s))"
                           if held >= 0 else ""))
                if path.split("?", 1)[0].rstrip("/") == \
                        "/api/claude_code/policy_limits":
                    _log_lifecycle(
                        "a session asked for its org policy — answered as the "
                        "pinned account, so a cached denial from another "
                        "account is replaced without a restart")
            else:
                # Fail-open: the request still goes, on the disk bearer. That
                # is deliberate — a pin that cannot resolve must never block
                # work — but it is silent, and silence here is expensive. A
                # Remote Control session created on this path is owned by the
                # ACTIVE account permanently; the server fixes ownership at
                # /bridge and there is no transfer. When the pinned account is
                # the active one there is nothing to swap, and warning then
                # trains the reader to disbelieve the warning (see
                # ``pin_is_noop``).
                if not _pin_is_noop(self._pin_token_provider):
                    self._warn_unpinnable()
        # INFERENCE FOLLOWS THE ACTIVE ACCOUNT, for a host that brought its own
        # login (see `inference_follow_entrypoints`). Never on a pinned route:
        # those already carry the pinned bearer, and ownership must not move.
        followed = False
        if not pinned:
            new_headers = self._inference_follow_headers(path, ua, headers)
            if new_headers is not None:
                headers = new_headers
                swapped = followed = True
        # ON THE THREAD-LOCAL, because the only place the round trip ENDS is
        # inside `_forward`'s status hook, and it takes no arguments from
        # here. One MITM connection is one thread, so there is no sharing.
        self._local.pin_ms = (time.monotonic() - _t_pin) * 1000
        self._local.t_req = _t_req
        # CLEARED PER REQUEST. One MITM connection serves many requests on the
        # same thread, so a stale stamp would time this request's wait from
        # the PREVIOUS request's send and report a wait longer than the
        # request itself.
        self._local.t_sent = None
        # THE REQUEST PATH NEVER OPENS THIS FILE. `_trace_tick` (on its own
        # `_trace_tick_loop` thread) is the only place that opens, rotates or
        # re-targets `self._debug` now; this thread only writes to whatever
        # it finds already open, or drops the line — see
        # `_write_capped_line`. Opening from here, shared by every
        # `_serve_client` thread, is what parked 342 of them inside one
        # `open(2)` call while a stalled filesystem let the rest of the daemon
        # keep working.
        if self._debug is not None:
            hdrs = " | ".join(
                f"{k}: {v[:60]}" for k, v in headers
                if k.lower() in (
                    "connection", "upgrade", "accept", "sec-websocket-key",
                    "sec-websocket-version", "cache-control", "content-type",
                )
            )
            self._debug = _write_capped_line(
                self._debug,
                f"[c{getattr(self._local, 'cid', 0)}] "
                f"{method} {path} pinned={pinned} swapped={swapped} :: {hdrs}\n",
                cap=_TRACE_MAX_BYTES,
            )

        # Opt-in: when CSWAP_PIN_SHAPE names a file, record the message-array
        # SHAPE of a /v1/messages request — role order and content-block types
        # only, never text. A 400 like "role 'system' must precede an
        # 'assistant' message or end the array" is a claim about that order,
        # and the array is assembled at send time, so it exists nowhere on disk:
        # this proxy is the only place it can be observed. Structure alone is
        # enough to locate the offending position and keeps prompt text out of
        # the log.
        if self._shape is not None and body and path.startswith("/v1/messages"):
            try:
                payload = json.loads(body)
                shape = [
                    (m.get("role"),
                     [b.get("type") for b in m["content"]]
                     if isinstance(m.get("content"), list) else "str")
                    for m in (payload.get("messages") or [])
                ]
                # SAME HANDLE DISCIPLINE as the request trace above: write to
                # whatever `_trace_tick` already opened, never open here.
                self._shape = _write_capped_line(self._shape, json.dumps({
                    "cid": getattr(self._local, "cid", 0),
                    "n": len(shape),
                    "roles": [r for r, _ in shape],
                    "head": shape[:4],
                    "tail": shape[-4:],
                    "has_output_config": any(
                        "output_config" in m for m in (payload.get("messages") or [])
                    ),
                }) + "\n")
            except Exception:
                pass

        keep = self._forward(method, path, headers, body, tls, swapped=swapped)
        if keep is _AUTH_REJECTED:
            # THE SWAP ITSELF WAS REFUSED. Send it again as it arrived. A
            # 401/403/404 is terminal to the client — SSETransport treats those
            # as permanent (M7y = new Set([401,403,404])), sets state="closed",
            # and never reconnects, so one misrouted request kills Remote
            # Control for the life of the process. That makes route
            # classification a single point of permanent failure, and no amount
            # of care in the predicate removes the risk. Retrying without the
            # swap turns "I guessed wrong about this route" into "this request
            # went out unpinned", which is the failure mode the whole module is
            # already built to tolerate.
            self._drop_upstream()
            if followed:
                self._note_inference_retry(path)
            keep = self._forward(method, path, original_headers, body, tls)
        # A client that asked to close gets closed regardless of the upstream.
        for k, v in headers:
            if k.lower() == "connection" and "close" in v.lower():
                keep = False
        return keep

    def _inference_follow_headers(self, path: str, ua: str,
                                  headers: "list[tuple[str, str]]"):
        """Headers re-billed to the active account, or None to leave them.

        Returns None whenever the swap is off, does not apply, or cannot be
        done safely — the request then goes out exactly as the host sent it.
        That is the fail-open the rest of this module uses: a re-bill that
        cannot happen must never block the work.
        """
        eps = inference_follow_entrypoints(self._certdir)
        if eps != self._inference_eps_logged:
            prev, self._inference_eps_logged = self._inference_eps_logged, eps
            self._inference_stats.note_entrypoints(eps)
        else:
            prev = eps
        # Logged on a CHANGE only, and never for a daemon that was always off:
        # most machines never enable this, and their log should not say so.
        if prev != eps and (eps or prev):
            _log_lifecycle(
                "inference-follows: "
                + (f"ON for {', '.join(sorted(eps))} — their /v1/messages bill "
                   "cswap's active account" if eps else "OFF"))
        if not is_inference_follow_route(path, ua, eps):
            return None
        token, why = self._inference_tokens.get()
        if not token:
            self._inference_stats.bump("passthrough", why)
            return None
        current = next((v for k, v in headers
                        if k.lower() == "authorization"), "")
        if current == f"Bearer {token}":
            # The host is already signed into the active account.
            self._inference_stats.bump("passthrough", "same-token")
            return None
        # x-organization-uuid names the HOST's org; Claude Code does not send
        # it on inference today, but if it ever does, a header naming one org
        # beside another org's bearer is a 403 waiting to happen.
        out = [
            (k, f"Bearer {token}") if k.lower() == "authorization" else (k, v)
            for k, v in headers
            if k.lower() != "x-organization-uuid"
        ]
        self._inference_stats.bump("swapped", stamp="lastSwapAt")
        if not self._inference_first_swap_logged:
            self._inference_first_swap_logged = True
            _log_lifecycle(
                f"inference-follows: first {ua_entrypoint(ua)} inference "
                "request re-billed to cswap's active account")
        return out

    def _note_inference_retry(self, path: str) -> None:
        """The active account refused a re-billed request; it goes out as sent.

        Invalidates the cached token (a rotation or refresh may have replaced
        it) and logs at most once per 5 minutes — a refusing account refuses
        every request, and the count is in the stats file.
        """
        self._inference_tokens.invalidate()
        self._inference_stats.bump("retriedUnswapped", stamp="lastRetryAt")
        now = time.monotonic()
        if now - self._inference_retry_logged_at >= 300:
            self._inference_retry_logged_at = now
            _log_lifecycle(
                f"inference-follows: the active account refused {path.split('?', 1)[0]} "
                "(401/403/404) — resent on the host's own bearer")

    def _forward(self, method, path, headers, body, client: ssl.SSLSocket,
                 swapped: bool = False) -> bool:
        """Relay one request upstream and stream the response back.

        Returns whether the MITM connection may carry another request. The RC
        worker pipelines heartbeat/poll/stream requests over ONE connection,
        so closing after the first turned every /remote-control into a
        reconnect loop ("Transport closed: server rejected connection") even
        though each individual route swapped correctly.

        The upstream socket is kept open across requests (one upstream
        connection per MITM connection) — reconnecting per request would make
        an SSE stream impossible to hold.
        """
        up = self._upstream_conn()
        try:
            # A WebSocket handshake must keep Connection/Upgrade even though
            # they are hop-by-hop: strip them and the server sees a plain GET
            # and answers 403 — which is exactly how RC failed through this
            # proxy. Detect the upgrade and relay those headers verbatim.
            upgrading = any(
                k.lower() == "upgrade" and v.strip() for k, v in headers
            )
            # WHO IS ASKING, on the trace line. Two callers reach this proxy
            # for the same routes -- Claude Code's own client and cswap's
            # urllib fetch -- and a decision about answering one differently
            # from the other cannot be made from a trace that records neither.
            # Truncated: the value is for telling them apart, not for reading.
            _ua = next((v.strip()[:40] for k, v in headers
                        if k.lower() == "user-agent"), "-")
            out = [f"{method} {path} HTTP/1.1".encode("latin1")]
            sent_host = False
            # _read_body decoded a chunked body, and the transfer-coding
            # header is dropped just below (hop-by-hop), so the framing has
            # to be re-declared or the upstream reads a bodyless request.
            dechunked = any(
                k.lower() == "transfer-encoding" and "chunked" in v.lower()
                for k, v in headers
            )
            for k, v in headers:
                kl = k.lower()
                if kl.startswith("proxy-"):
                    continue
                if kl in _HOP_BY_HOP and not (
                    upgrading and kl in ("connection", "upgrade")
                ):
                    continue
                if kl == "content-length" and dechunked:
                    continue  # replaced below with the decoded length
                if kl == "host":
                    v = UPSTREAM_HOST
                    sent_host = True
                out.append(f"{k}: {v}".encode("latin1"))
            if dechunked:
                out.append(f"Content-Length: {len(body or b'')}".encode("latin1"))
            if not sent_host:
                out.append(f"Host: {UPSTREAM_HOST}".encode("latin1"))
            up.sendall(b"\r\n".join(out) + b"\r\n\r\n" + (body or b""))
            # THE INSTANT THE SERVER OWNS IT. Everything after this and before
            # the status line is the server's; everything before it is ours.
            # Cleared first so a request that takes the retry path cannot be
            # timed against the previous attempt's send.
            self._local.t_sent = time.monotonic()
            self._trace_upgrade = upgrading
            if upgrading:
                # 101 turns the connection into an opaque byte stream (RC's
                # WebSocket): relay the handshake response, then pump both
                # directions until either side closes. Nothing further on this
                # connection is HTTP, so the request loop must end.
                if _relay_upgrade(up, client):
                    # 101 = OPAQUE FROM HERE. Nothing further on this
                    # connection is HTTP, so the thread that carried the
                    # handshake has no work left: hand both sockets to the
                    # shared selector and give it back. This is the Remote
                    # Control WebSocket, which stays open for the whole
                    # session — the single longest-lived thing the pin holds.
                    self._local.up = None  # the pump owns it now
                    # STOPS BEING WORK HERE. From the 101 on, this connection
                    # carries no request the daemon can finish — it is two
                    # sockets being copied into each other for the life of the
                    # session. A drain that counts it waits for a zero that
                    # never arrives, pays its whole ceiling on every recycle,
                    # and then cuts whatever else was open. It is still an OPEN
                    # connection and is still closed on teardown; it is simply
                    # not something to wait for.
                    #
                    # A TUNNEL OWES NOTHING. Nobody is waiting on a reply here
                    # — two sockets are being copied into each other for the
                    # life of the session. This is the RC WebSocket, and it is
                    # the connection that made the original zero unreachable.
                    _c = getattr(self._local, "conn", None)
                    if _c is not None:
                        self._owe_answer(_c, False)
                        # AND IT IS NO LONGER OURS TO CLOSE. The mark is set
                        # from the request LINE and the upgrade is decided by
                        # the client's `Upgrade:` header, so both can be true
                        # at once — and from here the socket belongs to the
                        # pump. A drain closing it makes epoll drop the fd
                        # silently: no event, `_close_pair` never runs, and the
                        # connection stays in every map for the life of the
                        # daemon.
                        with self._live_lock:
                            # AND THE OWNER MAP. Keyed on the same object; the
                            # two are one fact and must be dropped together.
                            self._forget_stream(_c)
                    release = getattr(self._local, "release", None)
                    _m = _STREAM_ROUTE.search(path or "")
                    _bridge = _m.group(1) if _m else None
                    _t0 = time.monotonic()

                    def _release_tunnel(closed_by=None):
                        if release:
                            release()
                        if _bridge:
                            self._note_stream_end(
                                _bridge, time.monotonic() - _t0,
                                "upstream" if closed_by is up else
                                "client" if closed_by is client else "unknown")
                    _release_tunnel._wants_closer = True

                    _pump_detached(up, client, _release_tunnel)
                    self._local.detached = True
                    return False
                self._drop_upstream()
                return False
            # COUNTED BY THE CALLER, around the whole request — see
            # `_handle_one_request`. Counting only from here reported zero for
            # a request still being read or written upstream, and the drain
            # then cut it "after 0s".
            _conn = getattr(self._local, "conn", None)
            return _relay_response(
                up, client, getattr(self._local, "cid", 0),
                reject_on_auth_error=swapped,
                # THE RELAY SEES THE STATUS AND THE CALLER SEES THE ROUTE, and
                # a spurious stream 404 needs both to be recognised.
                path=path,
                certdir=getattr(self, "_certdir", None),
                # THE MOMENT A CUT STOPS BEING RETRYABLE. Before this fires the
                # client has received nothing and the SDK retries; after it,
                # part of an answer is already delivered.
                on_headers=(
                    lambda n, c: self._note_response_started(_conn, n, c))
                if _conn is not None else None,
                # THE CALLER IS THE ONLY ONE THAT KNOWS THE PATH, and the relay
                # is the only one that sees the status. Neither can report an
                # attachment outcome alone.
                #
                # AND THE TRACE RIDES THE SAME HOOK. `_relay_response` writes
                # its `<-` line to `_TRACE` only, which is opened once at
                # import from an env var and so is off on a daemon that is
                # already serving. The `trace-to` file switch — the only one
                # reachable during an incident — showed every request and not
                # one response. `_tunnel_trace` writes both targets and this
                # method can reach it, so no new plumbing is needed.
                #
                # THE STATUS LINE IS ALSO WHERE A STALL ENDS, and it is the
                # only place it can be timed. Time to the first byte is the
                # number that means the same thing for both.
                on_status=lambda st: (
                    self._note_attachment(path, st),
                    self._note_rename(method, path, st),
                    self._note_bridge_superseded(path, st),
                    self._tunnel_trace(
                        f"    <- {st.decode('latin1', 'replace').strip()}"
                        f"  {method} {path}  ua={_ua}"),
                    self._note_slow_request(
                        method, path,
                        (time.monotonic() - getattr(
                            self._local, "t_req", time.monotonic())) * 1000,
                        getattr(self._local, "pin_ms", 0.0),
                        wait_ms=(
                            (time.monotonic() - self._local.t_sent) * 1000
                            if getattr(self._local, "t_sent", None) is not None
                            else None)),
                ),
                # A HEAD response carries the headers of the GET it mirrors,
                # Content-Length included, but no body — only the request
                # method says so.
                method=method,
            )
        except (OSError, ssl.SSLError):
            self._drop_upstream()
            return False

    def _upstream_conn(self) -> ssl.SSLSocket:
        """The live upstream TLS socket for this MITM connection, dialing on
        first use. Reused across requests so keep-alive and SSE work."""
        up = getattr(self._local, "up", None)
        if up is not None and not self._upstream_reusable(up):
            self._drop_upstream()
            up = None
        if up is None:
            # The context must describe the socket we ACTUALLY got, not the
            # chain we hoped for. _connect_upstream falls back to a direct
            # dial when the recorded chain is unreachable, and _upstream_ctx
            # re-reading the (still loopback) hint would then hand a
            # CERT_NONE context to a real internet connection carrying
            # account bearers.
            raw, via_loopback = self._connect_upstream()
            up = _wrap_upstream(
                self._upstream_ctx(via_loopback), raw, UPSTREAM_HOST
            )
            self._local.up = up
            self._local.up_idle_since = time.monotonic()
        return up

    def _upstream_reusable(self, up) -> bool:
        """A kept upstream socket is reused only while young and quiet: idle
        past ``_UPSTREAM_IDLE_REUSE_S`` it is presumed closed by the hop, and
        one with bytes pending while nothing was asked for is being closed."""
        since = getattr(self._local, "up_idle_since", None)
        if since is None or time.monotonic() - since > _UPSTREAM_IDLE_REUSE_S:
            return False
        try:
            readable, _, _ = select.select([up], [], [], 0)
        except (OSError, ValueError):
            return False
        return not readable

    def _drop_upstream(self) -> None:
        up = getattr(self._local, "up", None)
        if up is not None:
            try:
                up.close()
            except OSError:
                pass
            self._local.up = None

    def _upstream_ctx(self, via_loopback: bool) -> ssl.SSLContext:
        """TLS context for the hop to the real api.anthropic.com.

        When we chain through a LOOPBACK proxy (any local MITM), that
        hop re-signs api.anthropic.com with its own CA whose path we can't know
        portably — and it terminates on localhost, having itself verified the
        real upstream. So we skip cert verification for a loopback chain,
        exactly as the real client (Node) does by trusting that CA blindly.
        For a direct dial or a remote proxy, full verification stays on:
        system roots (real cert) + our own CA (test fakes) + any corp CA on
        NODE_EXTRA_CA_CERTS.

        ``via_loopback`` is reported by the dial that actually happened, never
        re-derived from the hint. Reading the hint independently meant an
        unreachable loopback chain fell back to a DIRECT dial while this still
        answered CERT_NONE — an unverified connection to the real
        api.anthropic.com carrying account bearers, i.e. MITM-able exactly
        when the local chain is down.
        """
        if via_loopback:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        # Our own CA too, so a test's fake upstream verifies.
        return _verifying_ctx(self._bundle.ca_path)

    def _chain_ca(self) -> "Path | None":
        """The egress proxy's own CA, as recorded beside the proxy address.

        ``write_upstream_hint`` records it precisely so a later launch that
        cannot see the proxy's environment can still verify it. The daemon is
        one of those launches — it is spawned from whatever shell ran
        ``cswap pin``, which normally has no ``NODE_EXTRA_CA_CERTS`` — so
        without this the recorded CA was never consulted and an ``https://``
        corporate proxy failed verification against the public roots alone.
        """
        ca = read_upstream_ca(self._certdir)
        return Path(ca) if ca else None

    def _current_chain(self) -> tuple[str, int] | None:
        """The egress proxy to CONNECT through, re-read per connection.

        Not a snapshot: a local egress proxy can restart on another port, or
        come up only after this daemon did. Binding the chain once at spawn
        would leave the daemon bypassing it — and where that proxy is the only
        route out, bypassing it is a hard failure, not a performance note.
        ``rediscover_chain=False`` keeps tests explicit.
        """
        # Returned RAW; every consumer runs it through _as_chain, which they
        # must anyway — `_chain` is also assigned directly and this method is
        # stubbed outright in tests, so normalizing here covers neither.
        if not self._rediscover_chain:
            return self._chain
        return read_upstream_hint(self._certdir)

    def _connect_upstream(self) -> tuple[socket.socket, bool]:
        """Dial the upstream (through the chain when there is one).

        Returns ``(socket, via_loopback)``. The flag says how the socket was
        REALLY obtained, because the chain can be unreachable and the dial
        silently becomes direct — and the TLS context must follow the path
        taken, not the path recorded (see :meth:`_upstream_ctx`).

        The 15s budget covers CONNECTING only. It is cleared before the socket
        carries requests, because ``create_connection``'s timeout stays on the
        socket and would then apply to every read — and the Remote Control
        inbound channel is a LONG POLL that deliberately holds its response
        open until the phone/web sends something. With the timeout left on,
        that poll died every 15s and no inbound message ever reached the CLI,
        while heartbeats (which answer at once) kept succeeding — so the
        session looked healthy and was silently deaf.
        """
        # A HOP THAT IS RESTARTING IS NOT A HOP THAT IS GONE. A refused dial
        # costs this walk nothing, so waiting out that second is nearly free.
        #
        # WHY WAIT AT ALL, when there is already a DIRECT fallback: on the
        # machine this outage happened to, DIRECT is the corporate TLS-
        # inspecting proxy. Falling through to it saves one second and sends
        # the request through an inspector for as long as the hop is away.
        # Holding briefly keeps the chain the user configured. BOUNDED, and
        # small. It is not a retry ladder — the hop's own restart is already
        # bounded (its maintainer killed the holder three times in a row:
        # process count unchanged, one replacement per death, no accumulation),
        # so a ladder here would only add a busy loop neither side intended.
        #
        # NOTHING TO WAIT FOR IF THERE IS NO HOP. The grace exists for a hop
        # that is RESTARTING; an empty candidate list means this host has no
        # chain at all, and `_walk_chain_once` returns None instantly forever.
        # The constant's comment already claimed this ("a host with no chain at
        # all never enters this loop"); the code did not implement it, and the
        # comment was the half being believed.
        candidates = self._chain_candidates()
        if candidates:
            deadline = time.monotonic() + _CHAIN_HEAL_GRACE_S
            while True:
                sock = self._walk_chain_once()
                if sock is not None:
                    return sock
                if time.monotonic() >= deadline:
                    break
                time.sleep(_CHAIN_HEAL_POLL_S)
        # Every hop is still unusable after the grace period (or there was
        # never a hop): fall through to the unchained dial, which is what this
        # method has always ended in.
        sock = _dial_with_no_chain(self._upstream)
        sock.settimeout(None)
        self._note_egress(direct=True, configured=bool(candidates))
        return sock, False

    def _walk_chain_once(self) -> "tuple[socket.socket, bool] | None":
        """One pass over the chain. The socket and its loopback flag, or None
        when no hop was usable this time round."""
        candidates = self._chain_candidates()
        for i, chain in enumerate(candidates):
            # A HOP THAT REFUSES AND A HOP THAT WILL NOT DIAL ARE ONE EVENT.
            # A dial that raises OSError, a CONNECT answered non-200, and a
            # hop that accepts and never answers all mean the same thing:
            # this hop is not usable, so try the one behind it. A cache proxy
            # that is RESTARTING produces the second and third shapes — its
            # listener is up before its proxy logic is.
            try:
                raw = _dial_chain(chain, extra_ca=self._chain_ca())
            except OSError as exc:
                # NAME WHY, even though the reaction is the same. "the hop
                # refused" and "the hop answered and was wrong" are one
                # decision here and two DIFFERENT FAULTS to whoever runs that
                # hop: the first says its port was down, the second says its
                # port was up and its logic was not. Collapsing them left the
                # log unable to tell a supervisor that kept the port alive
                # from one that never ran — which is the whole claim such a
                # supervisor makes.
                self._note_hop_unusable(chain.address, f"dial failed: {exc!r}")
                continue
            try:
                raw.sendall(
                    f"CONNECT {self._upstream[0]}:{self._upstream[1]} HTTP/1.1\r\n"
                    f"Host: {self._upstream[0]}:{self._upstream[1]}\r\n"
                    f"{chain.connect_headers()}\r\n".encode("latin1")
                )
                status = _read_line(raw)
                while True:
                    h = _read_line(raw)
                    if h in ("", None):
                        break
            except OSError:
                status = None
            if not _connect_ok(status):
                self._note_hop_unusable(
                    chain.address,
                    "accepted but did not tunnel: "
                    + (f"CONNECT -> {status!r}" if status else "no reply"),
                )
                try:
                    raw.close()
                except OSError:
                    pass
                continue
            raw.settimeout(None)
            # PREFERENCE, not identity. `_chain_candidates` returns the re-read
            # current chain FIRST and recorded next-hops behind it, so index 0
            # is the hop that should have carried this. Anything else means the
            # preferred one did not, which is the degradation nothing recorded.
            self._note_egress(direct=False, hop=chain.address,
                              preferred=(i == 0))
            return raw, chain.host in _LOOPBACK
        # NO HOP ANSWERED THIS PASS. The caller decides whether that is final:
        # a hop mid-restart refuses for ~1s and then serves again, so the
        # direct dial belongs after a grace period, not here. `candidates`
        # being empty (no chain configured at all) is still the caller's
        # distinction to make — see `_note_egress(configured=...)`.
        return None

    def _note_hop_unusable(self, hop: "tuple[str, int]", why: str) -> None:
        """Log WHY a hop was skipped, once per (hop, reason) transition.

        The walk falls through an unusable hop silently and carries on, so the
        only trace is which hop ended up carrying the request. That is not
        enough to attribute a failure: a hop whose PORT is dead and a hop that
        answers and refuses to tunnel are the same fall-through here and
        opposite faults for whoever runs it. One of them is what a supervisor
        holding that port exists to prevent; the other it cannot touch.

        Deduplicated on the transition like :meth:`_note_egress`, so a hop
        that is steadily down costs one line rather than one per connection.
        """
        state = (hop, why)
        if state == self._hop_fault:
            return
        self._hop_fault = state
        _log_lifecycle(f"hop {hop[0]}:{hop[1]} unusable — {why}")

    def _note_egress(
        self,
        *,
        direct: bool,
        hop: "tuple[str, int] | None" = None,
        configured: bool = True,
        preferred: bool = True,
    ) -> None:
        """Log egress path changes; silence means the path is unchanged.

        A launch must never be blocked, so no hop reachable degrades to a
        direct dial rather than failing. That downgrade is invisible from the
        outside: requests keep succeeding and the session looks pinned while
        egress has left the path the user configured.

        WHICH HOP is part of the same question. The walk falls through a dead
        hop silently, so a request carried by the second hop and one carried by
        the first are indistinguishable in the log — an observer had to infer
        it afterwards from the TLS issuer. Record the transition only, so a
        steady chain still costs nothing per connection.

        ``configured`` SEPARATES "NOTHING IS SET UP" FROM "NOTHING ANSWERED",
        which used to be one sentence. On a host with no corporate proxy and
        no cache proxy there is no chain to walk, so a direct dial is the only
        thing a pin can do and it is the NORMAL path. Saying "no chain hop
        reachable, bypassing the configured proxy chain" there is false twice
        — nothing was unreachable, and there is no configured chain to bypass
        — and it is the STEADY STATE on such a machine, so a reader seeing it
        alone calls a healthy host degraded. The two need opposite responses:
        one is "go look at your egress proxy", the other is "this is how this
        machine is".
        """
        state = None if direct else hop
        if direct == self._egress_direct and state == self._egress_hop:
            return
        self._egress_direct, self._egress_hop = direct, state
        if direct and not configured:
            _log_lifecycle(
                "egress direct — no proxy chain is configured on this host"
            )
        elif direct:
            # Stamped HERE and not in the branch above: a host with no chain
            # configured is not falling back from anything, and stamping its
            # steady state would leave it reporting a permanent fault.
            self._egress_direct_last = time.time()
            _log_lifecycle(
                "egress DIRECT — no chain hop reachable, bypassing the "
                "configured proxy chain"
            )
        else:
            # DEGRADED IS STILL A FAULT, and until now it was the only one with
            # no tense a later probe could read. `direct_last` exists because a
            # chain flaps back within seconds and every probe after that reads
            # green; a fall-through to a later hop does exactly the same and
            # was left out only because the sticky record was built for DIRECT
            # and never generalised. One second, and afterwards nothing on the
            # box said it happened.
            if not preferred:
                self._hop_degraded_last = time.time()
            where = f"{hop[0]}:{hop[1]}" if hop else "the proxy chain"
            _log_lifecycle(f"egress via {where}"
                           + ("" if preferred else " — DEGRADED, the preferred "
                              "hop did not carry this"))

    def learn_next_hop(self) -> None:
        """Ask the recorded hop what IT chains through, and record the answer.

        THE RECORD HAS TO BE ABLE TO GROW AFTER THE LAUNCH THAT MADE IT.
        `_probe_next_hop` runs at hint-writing time and nowhere else, and
        `cswap pin --ensure` — what an rc hook calls before every `claude` —
        routes to `heal`, which never re-stamps the hint. So the only chance
        to learn the outer hop was a launch that happened while the inner one
        was answering. Miss it once and the chain is single-hop for good.

        MEASURED here, and it was the steady state, not a transient:

            upstream.json  {"proxy": "http://127.0.0.1:9901", "ca": ...}
            written 2026-08-04 01:32, no "next" key a day later
            live probe of 9901 -> http://127.0.0.1:8118

        When 9901 died the walk had one hop and fell to DIRECT — and DIRECT on
        this host is the corporate TLS inspector, which answers 403 "Access
        restricted by network policy". The answer was one HTTP request away
        the whole time.

        ASKED WHILE THE HOP IS HEALTHY, which is both the only moment the
        answer can be trusted and the only moment it is free: a dead hop
        cannot say what is behind it, and that is exactly when it is needed.

        Never raises and never blocks a request: `_probe_next_hop` is loopback
        only with a 1s budget, and this runs on the daemon's own timer, not on
        a connection.
        """
        recorded = _read_upstream(self._certdir, "proxy")
        if not recorded:
            return
        nxt = _probe_next_hop(recorded)
        # A PROBE THAT COULD NOT ASK IS NOT AN ANSWER OF "NONE" — the same
        # rule `write_upstream_hint` states. Writing "" on a hop that is down
        # would erase a next hop learned while it was up, at the moment it
        # matters most.
        if not nxt or nxt == _read_upstream(self._certdir, "next"):
            return
        # A HOP THAT NAMES US IS A LOOP, NOT A NEXT HOP. A looped proxy neither
        # answers nor exits — it appears here as "accepted but did not tunnel:
        # no reply".
        if self._is_me(nxt):
            _log_lifecycle(
                f"{recorded} names this daemon as its upstream — refusing to "
                f"record a loop"
            )
            return
        write_upstream_hint(
            self._certdir, recorded, read_upstream_ca(self._certdir), next_hop=nxt,
        )
        _log_lifecycle(f"learned the hop behind {recorded}: {nxt}")

    def _is_me(self, value) -> bool:
        """Whether ``value`` names this daemon's own address.

        A hop we would dial back into. Loopback only — a remote proxy on our
        port number is a different machine and perfectly legitimate.

        Takes a URL string OR an already-parsed hop, because the two callers
        differ: `learn_next_hop` holds what `/health` reported (a string) and
        `_chain_candidates` holds `_Chain`s. `_as_chain` accepts a tuple, not
        a URL — splatting a string into it makes `_Chain(*"http://…")`, which
        is a TypeError, so the string has to be parsed first.
        """
        hop = parse_upstream_proxy(value) if isinstance(value, str) \
            else _as_chain(value)
        if hop is None or not self.port:
            return False
        return hop.host in _LOOPBACK and hop.port == self.port

    def _chain_candidates(self) -> list[_Chain]:
        """The hops to try, in order. The re-read one first (it is the most
        current), then whatever a launch recorded behind it.

        A HOP NAMING US IS DROPPED HERE TOO, not only at learning time. The
        record outlives the process that wrote it, so a chain learned during a
        polluted window — or written by a version without the guard above,
        which is every version already on disk today — would keep pointing at
        this daemon after the hop itself was repaired.
        """
        chain = _as_chain(self._current_chain())
        hops = [chain] if chain else []
        for hop in _chain_hops(self._certdir):
            if hop not in hops:
                hops.append(hop)
        kept = [h for h in hops if not self._is_me(h)]
        if len(kept) != len(hops):
            self._note_hop_unusable(
                (self._certdir.name, self.port),
                "a recorded hop names this daemon — dropped, it is a loop",
            )
        return kept

    @staticmethod
    def _tunnel_is_open(up: socket.socket):
        """The tunnel if it is actually carrying, None if it is already EOF.

        A CONNECT 200 means the proxy ACCEPTED the request, not that it reached
        the host: a filtering proxy answers optimistically and dials afterwards, closing
        the socket when that dial fails. Look for a closed read end — no client
        byte has been sent yet, so a readable socket here can only mean EOF.
        Never blocks: a healthy idle tunnel has nothing to read and reports not
        ready, which is exactly the "open" answer.

        Reads rather than peeks, because ``MSG_PEEK`` is not available on
        every socket this receives: ``ssl.SSLSocket.recv`` rejects ANY non-zero
        flag with ``ValueError`` — which is not an ``OSError``, so the except
        below could not catch it and it escaped to the connection handler.
        An ``https://`` chain therefore did not merely fail this check, it
        killed the connection AND the direct-dial rescue this check exists to
        trigger. The byte a read consumes is pushed back via :class:`_Prefixed`
        so the caller's stream is unchanged; the socket is returned rather
        than a bool for exactly that reason.
        """
        try:
            ready, _, _ = select.select([up], [], [], 0.35)
            if not ready:
                return up  # nothing to read == still open, the normal case
            first = up.recv(1)
            return _Prefixed(up, first) if first else None
        except (OSError, ValueError):
            return None

    def _tunnel_trace(self, line: str) -> None:
        """Write one tunnel line to whichever traces are on.

        TWO TARGETS, DELIBERATELY. `_TRACE` is opened once at import from
        `CSWAP_PIN_DEBUG` and cannot be turned on afterwards; the `trace-to`
        file can be armed on a daemon that is already serving. Only the second
        is reachable during an incident, and it was the one this path did not
        write to — so an armed trace showed every route CC sends and nothing
        about the channel it receives on.
        """
        text = f"[c{getattr(self._local, 'cid', 0)}] {line}\n"
        if _TRACE is not None:
            try:
                _TRACE.write(text)
                _TRACE.flush()
            except (OSError, ValueError):
                pass
        debug_path = trace_target(getattr(self, "_certdir", None))
        if debug_path:
            # SAME HANDLE DISCIPLINE as the request path: let go rather than
            # close on a re-arm, because these fields are touched from every
            # connection thread without a lock.
            if debug_path != self._debug_for:
                self._debug, self._debug_for = None, debug_path
            self._debug = _append_capped(
                debug_path, text, self._debug, cap=_TRACE_MAX_BYTES)

    def _blind_tunnel(self, target: str, conn: socket.socket) -> None:
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s else 443
        # Trace the tunnel too. Remote Control receives over a WebSocket to the
        # ingress host the /bridge response names — NOT api.anthropic.com — so
        # it lands here, not in the MITM. Logging only the MITM made an absent
        # inbound channel look identical to a healthy one: the routes CC sends
        # (worker/events, heartbeat) were all 200 in the trace while the
        # channel CC *receives* on left no line at all.
        self._tunnel_trace(
            f"CONNECT {target} tunnelled (no pin: bearer never seen)")
        up = None
        # EVERY HOP, not just the first. Remote Control RECEIVES over a
        # WebSocket to the ingress host the /bridge response names, which is
        # not api.anthropic.com and therefore lands here: with the hop missed,
        # the session keeps heartbeating and posting through the MITM at 200
        # while nothing sent from claude.ai arrives. Try each hop, but never
        # let the chain be the only answer. A filtering proxy (per-domain
        # forwards, a corporate MITM) may refuse the ingress host outright, and
        # closing here made that refusal invisible.
        for chain in self._chain_candidates():
            try:
                up = _dial_chain(chain, extra_ca=self._chain_ca())
                up.sendall(
                    f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                    f"{chain.connect_headers()}\r\n".encode("latin1")
                )
                status = _read_line(up)
                while True:
                    h = _read_line(up)
                    if h in ("", None):
                        break
                if not _connect_ok(status):
                    # Refused BY this hop (not a transport failure). Try the
                    # hop behind it; a direct dial is what happens only when
                    # none of them will carry it.
                    self._tunnel_trace(
                        f"chain refused {target} "
                        f"({(status or '').strip()}) — next hop")
                    up.close()
                    up = None
                    continue
            except OSError:
                up = None
                continue
            break
        if up is not None and (carrying := self._tunnel_is_open(up)) is None:
            # A 200 is not proof the chain reached the host. a filtering proxy
            # answers CONNECT optimistically and only then dials; when that
            # dial fails it closes, so the tunnel is EOF the instant we look.
            # Trusting the status alone made Remote Control silently deaf —
            # everything Claude Code SENDS still went through the MITM path at
            # 200 while the receive channel was a dead socket.
            self._tunnel_trace(
                f"chain answered 200 but the tunnel to {target} was already "
                f"EOF — dialling direct")
            up.close()
            up = None
        elif up is not None:
            up = carrying  # the peeked byte, pushed back in front of the stream
        if up is None:
            try:
                up = socket.create_connection((host, port), timeout=15)
            except OSError:
                conn.close()
                return
        # Connect budget only — a tunnel is long-lived by definition, and a
        # read timeout left on it would tear down an idle-but-healthy stream.
        up.settimeout(None)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # A TUNNEL OWES NOTHING, AND THIS IS THE PATH THE RC WEBSOCKET TAKES.
        # The connection was marked OWED at accept, and until this line existed
        # it stayed owed for its entire life — so `inflight_requests()` could
        # never reach zero on any machine that had ever connected Remote
        # Control, and every drain paid its full ceiling exactly as it did
        # before the drain was "fixed".
        #
        # THE FIX LANDED ON THE OTHER PATH. `_mitm` clears the debt at its 101
        # handover, and that is where I put it. But this function's own
        # docstring says where RC actually goes: "Remote Control receives over
        # a WebSocket to the ingress host the /bridge response names — NOT
        # api.anthropic.com — so it lands here, not in the MITM." The premise
        # was written down twelve lines up from the code that needed it.
        _c = getattr(self._local, "conn", None) or conn
        self._owe_answer(_c, False)
        release = getattr(self._local, "release", None)

        def _release_tunnel():
            if release:
                release()

        # DETACHED: nothing after the 200 is ours to parse, so the thread that
        # built the tunnel has no work left. It hands the pair to the shared
        # selector along with its own teardown and returns.
        _pump_detached(conn, up, _release_tunnel)
        return True


_TRACE = (
    open(os.environ["CSWAP_PIN_DEBUG"], "a")
    if os.environ.get("CSWAP_PIN_DEBUG")
    else None
)

class _AuthRejected:
    """Sentinel: the upstream refused the SWAPPED credential, nothing sent.

    Distinct from True/False, which both mean "the client already has its
    response". This says the opposite — the client has received NOTHING and
    the caller must retry.
    """

    __slots__ = ()

    def __bool__(self) -> bool:  # never mistaken for "keep the connection"
        return False


_AUTH_REJECTED = _AuthRejected()

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "upgrade",
}

# The response path parses raw bytes, and `b"transfer-encoding" in
# {str, ...}` is silently False — so that filter did nothing at all and
# every hop-by-hop header was relayed verbatim. It went unnoticed because
# the one case anybody would have caught (chunked) is the one case where
# forwarding the header happens to be RIGHT: we relay the chunk framing
# byte-for-byte, so it really is our hop's encoding too. The others
# (Keep-Alive, TE, Upgrade) describe the upstream's connection, not ours.
_HOP_BY_HOP_BYTES = {k.encode("latin1") for k in _HOP_BY_HOP}


def _read_line(sock) -> str | None:
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            return None if not buf else buf.decode("latin1")
        if b == b"\n":
            if buf.endswith(b"\r"):
                buf.pop()
            return buf.decode("latin1")
        buf += b


def _read_body(sock, headers) -> bytes:
    """The request body, decoded.

    Recognizing only ``Content-Length`` read ZERO bytes from a
    ``Transfer-Encoding: chunked`` request while the forwarder stripped the
    transfer-coding header (it is hop-by-hop), so the upstream received a
    bodyless request — every chunked message or artifact upload silently lost
    its payload.

    The body is materialized whole either way, which the retry path already
    requires: a swap the upstream refuses is re-sent unswapped, and a
    streamed body could not be replayed.
    """
    length = 0
    chunked = False
    for k, v in headers:
        kl = k.lower()
        if kl == "content-length":
            try:
                length = int(v)
            except ValueError:
                length = 0
        elif kl == "transfer-encoding" and "chunked" in v.lower():
            chunked = True
    if chunked:
        # Content-Length is ignored when a transfer-coding is present
        # (RFC 9112 §6.3), so decode and let the forwarder re-frame.
        return _read_chunked_body(sock)
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return bytes(body)


def _read_chunked_body(sock) -> bytes:
    """Decode a chunked request body to bytes, trailers discarded."""
    body = bytearray()
    while True:
        line = _read_line(sock)
        if line in ("", None):
            return bytes(body)
        try:
            size = int(line.split(";")[0].strip() or "0", 16)
        except ValueError:
            return bytes(body)
        if size == 0:
            # Consume the trailer section so the socket is left at the start
            # of the next request rather than mid-frame.
            while True:
                t = _read_line(sock)
                if t in ("", None):
                    break
            return bytes(body)
        need = size
        while need > 0:
            chunk = sock.recv(min(65536, need))
            if not chunk:
                return bytes(body)
            body += chunk
            need -= len(chunk)
        _read_line(sock)  # the CRLF terminating this chunk


def _peek_status(up) -> "tuple[int | None, bytes]":
    """`(status code or None, the bytes read)` for the head of a response.

    Read so a refused swap can be taken back before anything reaches the
    client. THE BYTES COME BACK EVEN WHEN THE CODE DOES NOT: they are already
    off the socket and `_pump` will never see them again, so discarding them
    on an unparsable status line truncates the response instead of relaying
    something we merely could not classify.
    """
    buf = bytearray()
    while b"\r\n" not in buf and len(buf) < 8192:
        try:
            chunk = up.recv(4096)
        except (OSError, ssl.SSLError):
            return None, bytes(buf)
        if not chunk:
            break
        buf += chunk
    # DRAIN THE TLS BUFFER BEFORE HANDING BACK. `_pump` selects on the SOCKET,
    # and one TLS record can decrypt to more than the read above consumed — so
    # bytes already decrypted and waiting are invisible to its selector and the
    # response stalls until the client's own timeout. Its docstring says so;
    # a byte-at-a-time read here reproduced it exactly.
    pending = getattr(up, "pending", None)
    while pending and pending():
        try:
            more = up.recv(65536)
        except (OSError, ssl.SSLError):
            break
        if not more:
            break
        buf += more
    line = bytes(buf).split(b"\r\n", 1)[0].split(b" ")
    if len(line) < 2 or not line[1].isdigit():
        return None, bytes(buf)
    return int(line[1]), bytes(buf)


def _relay_upgrade(up: ssl.SSLSocket, client: ssl.SSLSocket) -> bool:
    """Relay an upgrade handshake response verbatim; True when it was a 101.

    Headers pass through untouched (Connection/Upgrade included — the client
    needs them to accept the switch), and any bytes already read past the
    header terminator are forwarded so no frame is lost.
    """
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        try:
            chunk = up.recv(65536)
        except (ConnectionResetError, ssl.SSLError, OSError):
            chunk = b""
        if not chunk:
            return False
        buf += chunk
    if _TRACE is not None:
        _TRACE.write(
            "    <-UPGRADE "
            + bytes(buf).split(b"\r\n\r\n")[0].decode("latin1", "replace")[:400]
            + "\n"
        )
        _TRACE.flush()
    client.sendall(bytes(buf))
    return buf.split(b"\r\n", 1)[0].split(b" ")[1:2] == [b"101"]


def _status_has_no_body(status_line: bytes, method: str | None) -> bool:
    """Whether RFC 9110 says this response cannot carry a body.

    These are exactly the responses that legitimately arrive with neither
    Content-Length nor Transfer-Encoding, so without this they read as
    "close-delimited" and the relay blocks on recv until the upstream hangs
    up — which a keep-alive server never has to do.
    """
    if method and method.upper() == "HEAD":
        return True
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return False
    try:
        code = int(parts[1])
    except ValueError:
        return False
    # 205 Reset Content is also required to carry no content (RFC 9110
    # §15.3.6). 1xx is deliberately NOT here: an interim response is not the
    # final one, and treating it as complete would leave the real status in
    # the upstream buffer for the next request to read — a desync. It gets
    # its own handling in _relay_response.
    return code in (204, 205, 304)


def _is_interim(status_line: bytes) -> bool:
    """A 1xx: an INTERIM response, to be forwarded and then read past."""
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return False
    try:
        return 100 <= int(parts[1]) < 200
    except ValueError:
        return False


class _Prefixed:
    """A socket with bytes pushed back in front of it.

    Reading a response head can consume the start of the NEXT one; a socket
    has no unread, so the leftover travels here instead.
    """

    def __init__(self, sock, prefix: bytes):
        self._sock = sock
        self._buf = bytearray(prefix)

    def recv(self, n: int) -> bytes:
        if self._buf:
            out, self._buf = bytes(self._buf[:n]), bytearray(self._buf[n:])
            return out
        return self._sock.recv(n)

    def __getattr__(self, name):
        return getattr(self._sock, name)


# The SSE events that are KEEPALIVE rather than answer. Named, not sized: a
# keepalive is a keepalive because the protocol calls it one, and no threshold,
# rate or frame width has to be guessed.
#
# FAILS SAFE BY CONSTRUCTION: the test is "is EVERY event in this chunk a
# keepalive", so an event name we do not know counts as CONTENT and the drain
# keeps waiting. A protocol change makes this conservative, never lethal. The
# opposite phrasing — "does this chunk contain a known content event" — would
# cut a live reply the day Anthropic adds an event type.
_SSE_KEEPALIVE_EVENTS = (b"ping",)


def _is_only_keepalive(data: bytes) -> bool:
    """Does this chunk carry SSE events and nothing but keepalives?

    False for anything else at all, including a chunk with no `event:` line —
    a plain JSON body, a chunk split mid-line, the tail of a data payload.
    Only a chunk that is unambiguously all-keepalive answers True.
    """
    seen = False
    for line in data.split(b"\n"):
        if not line.startswith(b"event:"):
            continue
        seen = True
        if line[6:].strip() not in _SSE_KEEPALIVE_EVENTS:
            return False
    return seen


class _StampingWriter:
    """A client socket that reports every write, and is otherwise itself.

    ONE METHOD, because `sendall` is the only thing the relay path calls on the
    client — checked rather than assumed. Everything else falls through, so a
    future caller reaching for another method gets the real socket's behaviour
    instead of an AttributeError.
    """

    __slots__ = ("_sock", "_note")

    def __init__(self, sock, note):
        self._sock = sock
        self._note = note

    def send_head(self, data):
        """The response head: movement, never content.

        THE HEAD GOES THROUGH THIS WRITER TOO, and classifying it as content
        would make every response look like it had delivered an answer from
        its first byte — a rule that ships, looks like a fix, and never fires.
        It still stamps, because a head reaching the client IS the connection
        moving.
        """
        self._note(len(data), False)
        return self._sock.sendall(data)

    def sendall(self, data):
        # NOTE FIRST, SEND SECOND. A stamp after a blocking `sendall` records
        # when the write COMPLETED, and a slow client is exactly the case where
        # that gap matters — the drain would see the connection as stale for
        # the whole time it was busy delivering to it.
        #
        # AND HOW MUCH, not only that something moved. This count is what makes
        # that distinction possible; nothing decides on it yet.
        self._note(len(data), not _is_only_keepalive(data))
        return self._sock.sendall(data)

    def __getattr__(self, name):
        return getattr(self._sock, name)


#: A 404 on the Remote Control event stream that the SESSION DID NOT EARN.
#: `GET /v1/code/sessions/<id>/worker/events/stream` came back 404 on four
#: sessions whose other worker routes were answering 200 seconds either side of
#: it -- one of them a `PUT /worker` that succeeded on the same id right after.
#: The server had not lost those sessions.
#:
#: It costs the whole session anyway. The client treats 404 here as permanent
#: (`M7y = {401,403,404}`), so `Sr()` sends `end_session` to the child and the
#: person reads "Remote Control disconnected -- session not found (code 404)"
#: and has to reconnect by hand. A 5xx cannot do that: `validateStatus: f<500`
#: keeps it away from the flag-setter entirely, and the retry predicate takes
#: `>= 500`, so the client simply asks again.
#:
#: So relay it as 503 while the pin can still SEE the session working, and let
#: it through untouched once it cannot. Liveness is read off traffic already
#: crossing this hop -- no probe, no extra request.
_STREAM_LIVE_SECONDS = 90.0
#: A 404 that arrives while THIS HOP is failing is not a verdict either.
#:
#: `_stream_404_is_spurious` reads liveness off worker traffic that crossed this
#: hop and answers False when there is no evidence. Safe while the transport
#: works; inverted when it does not, because the traffic stops BECAUSE the hop
#: is down -- the evidence is absent for the very reason the guard should fire,
#: and the 404 then ends the session permanently.
#:
#: Only 5xx arms this. A 404 must not, or one spurious 404 would excuse every
#: later one.
_HOP_TROUBLE_SECONDS = 120.0
_hop_trouble_at = 0.0
_hop_trouble_lock = threading.Lock()


def _note_hop_trouble(status_line: bytes) -> None:
    """Record that this hop just returned a transport-shaped failure."""
    if not status_line.startswith(b"HTTP/1.1 5"):
        return
    global _hop_trouble_at
    with _hop_trouble_lock:
        _hop_trouble_at = time.time()


def _hop_recently_failed() -> bool:
    with _hop_trouble_lock:
        at = _hop_trouble_at
    if not at:
        return False
    return 0 <= (time.time() - at) <= _HOP_TROUBLE_SECONDS
_STREAM_ROUTE = re.compile(r"/v1/code/sessions/([^/?]+)/worker/events/stream")
_WORKER_ROUTE = re.compile(r"/v1/code/sessions/([^/?]+)/worker")
_worker_alive: dict[str, float] = {}
_worker_alive_lock = threading.Lock()
#: WHERE THE EVIDENCE LIVES, AND IT CANNOT BE THIS PROCESS'S MEMORY. A
#: long-held stream stays with the DEPARTING daemon for the whole drain while
#: its session's heartbeats move to the successor, so the process holding the
#: doomed connection is structurally unable to see that its session is alive.
#: An in-memory map answers "no evidence" for exactly the population this
#: guard exists for. Measured: a stream 404 on a session whose heartbeats were
#: 41s old, declined, during a drain that ran 2110s.
#:
#: WALL CLOCK, NOT `monotonic`: two processes read this file and monotonic
#: clocks are not comparable across them.
_ALIVE_FILE = "worker-alive.json"
#: One write per session per interval. This sits on the request path, and a
#: heartbeat every ~33s does not need a write every time.
_ALIVE_WRITE_EVERY = 10.0


def _alive_path(certdir) -> "Path | None":
    return Path(certdir) / _ALIVE_FILE if certdir else None


def _alive_load(certdir) -> dict:
    p = _alive_path(certdir)
    if p is None:
        return {}
    try:
        got = json.loads(p.read_text())
    except (OSError, ValueError):
        return {}
    return got if isinstance(got, dict) else {}


def _note_worker_status(path: str | None, status_line: bytes,
                        certdir=None) -> None:
    """Remember when a session last had a worker route answer 2xx.

    Recorded in this process AND in a file every daemon can read, because the
    daemon that will be asked is not always the one that saw the answer.
    """
    m = _WORKER_ROUTE.search(path or "")
    if m is None or not status_line.startswith(b"HTTP/1.1 2"):
        return
    sid, now = m.group(1), time.time()
    with _worker_alive_lock:
        last = _worker_alive.get(sid, 0.0)
        _worker_alive[sid] = now
        if len(_worker_alive) > 256:
            # One entry per session this daemon has ever relayed for, so it
            # grows for as long as the process lives. Anything past the window
            # can never satisfy the check again.
            for k, seen in list(_worker_alive.items()):
                if now - seen > _STREAM_LIVE_SECONDS:
                    del _worker_alive[k]
        if now - last < _ALIVE_WRITE_EVERY:
            return
    p = _alive_path(certdir)
    if p is None:
        return
    shared = _alive_load(certdir)
    shared[sid] = now
    # MERGED, NOT OVERWRITTEN: the departing daemon and its successor both
    # write here. A lost update costs one entry and fails toward "no
    # evidence", which is the direction that lets the 404 through.
    shared = {k: v for k, v in shared.items()
              if isinstance(v, (int, float)) and now - v <= _STREAM_LIVE_SECONDS}
    try:
        tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(shared))
        os.replace(tmp, p)      # atomic, so a reader never sees a torn file
    except OSError:
        pass


def _stream_404_is_spurious(path: str | None, certdir=None) -> bool:
    """Whether a 404 on this path contradicts what ANY daemon just saw.

    False whenever there is no evidence either way. That direction is the safe
    one: with no evidence the 404 goes through and the client behaves exactly
    as it does today.

    The NEWER of this process's memory and the shared file wins. Memory alone
    is blind during a handover; the file alone lags by up to the write
    interval.
    """
    m = _STREAM_ROUTE.search(path or "")
    if m is None:
        return False
    sid, now = m.group(1), time.time()
    with _worker_alive_lock:
        seen = _worker_alive.get(sid)
    shared = _alive_load(certdir).get(sid)
    if isinstance(shared, (int, float)):
        seen = shared if seen is None else max(seen, shared)
    if seen is None:
        return False
    # A future stamp is clock skew, not evidence of anything; bound it both
    # ways so a corrupt entry cannot mark a session alive forever.
    return -_STREAM_LIVE_SECONDS <= (now - seen) <= _STREAM_LIVE_SECONDS


def _relay_response(
    up: ssl.SSLSocket,
    client: ssl.SSLSocket,
    cid: int = 0,
    reject_on_auth_error: bool = False,
    method: str | None = None,
    on_headers=None,
    on_status=None,
    path: str | None = None,
    certdir=None,
) -> bool:
    """Stream one upstream response to the client; return whether the
    connection may be reused for another request.

    Response framing decides where this response ends, which is what makes
    keep-alive possible at all:

    - ``Content-Length``: exactly that many body bytes.
    - ``Transfer-Encoding: chunked``: until the terminating zero-length chunk.
    - neither (SSE / ``text/event-stream``, or a close-delimited body): pipe
      until EOF, then the connection is spent.

    Bytes are forwarded as they arrive, so an SSE stream reaches the client
    event-by-event instead of being buffered whole.
    """
    # EVERY WRITE, NOT JUST THE FIRST. `on_headers` began as "the reply has
    # started", which the drain needed to tell a retryable cut from a lost one.
    # It now also answers "is this reply still MOVING", and that question has
    # to be asked of every byte rather than the first — so the client is
    # wrapped once here and the body loops, the chunked pipe and anything added
    # later stamp by construction, because they write through the object they
    # were handed.
    #
    # THE ALTERNATIVE IS THE BUG THIS FILE KEEPS REPEATING: stamping at each
    # `sendall` site is the same shape as clearing the drain debt at `_mitm`'s
    # handover and not at `_blind_tunnel`'s, which is where Remote Control
    # actually goes. One place, or it will be missed.
    if on_headers is not None:
        client = _StampingWriter(client, on_headers)

    def _send_head(payload: bytes) -> None:
        """Write the response head. Kept because the branches read better with
        a name on this, not because it is where the stamping happens."""
        send = getattr(client, "send_head", None)
        (send or client.sendall)(payload)

    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        try:
            chunk = up.recv(65536)
        except (ConnectionResetError, ssl.SSLError, OSError):
            chunk = b""
        if not chunk:
            break
        buf += chunk
    head, sep, rest = bytes(buf).partition(b"\r\n\r\n")
    if not sep:
        return False
    lines = head.split(b"\r\n")
    status_line = lines[0] if lines and lines[0] else b"HTTP/1.1 502 Bad Gateway"
    # Nothing has reached the client yet, so a swap the upstream refused can
    # still be taken back. 401/403/404 are the three the client treats as
    # permanent; anything else is the origin's own answer and belongs to it.
    if reject_on_auth_error and any(
        status_line.startswith(b"HTTP/1.1 " + c) for c in (b"401", b"403", b"404")
    ):
        if _TRACE is not None:
            _TRACE.write(
                f"[c{cid}]     <- {status_line.decode('latin1', 'replace')}"
                " (swap refused — retrying unswapped)\n"
            )
            _TRACE.flush()
        return _AUTH_REJECTED
    _note_worker_status(path, status_line, certdir)
    _note_hop_trouble(status_line)
    if (status_line.startswith(b"HTTP/1.1 404")
            and _STREAM_ROUTE.search(path or "")
            and (_stream_404_is_spurious(path, certdir)
                 or _hop_recently_failed())):
        if _TRACE is not None:
            _TRACE.write(
                f"[c{cid}]     <- {status_line.decode('latin1', 'replace')}"
                " (session still answering — relayed as 503 so the client"
                " retries instead of ending)\n"
            )
            _TRACE.flush()
        status_line = b"HTTP/1.1 503 Service Unavailable"
    if _TRACE is not None:
        _TRACE.write(
            f"[c{cid}]     <- "
            f"{status_line.decode('latin1', 'replace')}\n"
        )
        _TRACE.flush()
    # AFTER THE TAKE-BACK, deliberately. A swap the upstream refused returns
    # above and is retried unswapped, so reporting here would name a failure
    # the user never saw. This is the status that reaches the client.
    if on_status is not None:
        try:
            on_status(status_line)
        except Exception:  # noqa: BLE001 — never let a statistic break a reply
            pass
    out = [status_line]
    length: int | None = None
    chunked = False
    keep = not status_line.startswith(b"HTTP/1.0")
    bodyless = _status_has_no_body(status_line, method)
    interim = _is_interim(status_line)
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        kl = k.strip().lower()
        vl = v.strip().lower()
        if kl == b"content-length":
            try:
                length = int(v.strip())
            except ValueError:
                length = None
        elif kl == b"transfer-encoding" and b"chunked" in vl:
            chunked = True
        elif kl == b"connection" and b"close" in vl:
            keep = False
        if kl in _HOP_BY_HOP_BYTES:
            continue
        out.append(line)
    if chunked:
        # Transfer-Encoding is hop-by-hop, so the loop above drops it — but
        # _pipe_chunked relays the chunk-size lines VERBATIM. Announcing no
        # framing while sending chunk syntax leaves the client to read
        # "1a\r\n" as body bytes, or to wait for a close that a keep-alive
        # upstream never sends. This IS our hop's encoding: re-declare it.
        out.append(b"Transfer-Encoding: chunked")
    if keep and not interim and this_process_is_draining():
        # A DEPARTING DAEMON STOPS TAKING NEW WORK, and until this line it did
        # not. `release_listener` stops accepting new CONNECTIONS; nothing
        # stopped accepting new REQUESTS on the keep-alives it already holds.
        #
        # NOTHING IS CUT. This reply completes normally; the header only says
        # "do not send me another". The client then opens a fresh connection,
        # which lands on the successor through the shared listener, so sessions
        # migrate one completed reply at a time and one that is still thinking
        # is untouched until its answer arrives.
        #
        # IT DOES NOT END THE DRAIN and is not meant to: a reply that never
        # completes still holds, exactly as it must. This stops new work
        # entering a departing process, which is the half that stranded people.
        keep = False
    if not keep:
        # Connection is hop-by-hop too, and `close` was read into `keep` and
        # then dropped — so the proxy was about to close while the client
        # still believed the connection reusable. Its next request then died
        # on a dead socket instead of opening a new one. (Before
        # _HOP_BY_HOP_BYTES the filter compared bytes to a str set and never
        # matched, so the header was forwarded by accident and this was
        # accidentally right.) Re-declare it for OUR hop, as with chunked.
        out.append(b"Connection: close")
    if interim:
        # An interim (1xx) response is followed by the real one on the same
        # connection. Returning here delivered the 103 as though it were the
        # answer and left the 200 in the buffer, so the next request read a
        # stale response. Forward it and loop for the final status.
        _send_head(b"\r\n".join(out) + b"\r\n\r\n")
        # `client` IS ALREADY THE WRAPPER by the time we get here, so the
        # recursion must not ask for a second one: passing both the wrapped
        # socket and the callback nested a `_StampingWriter` per interim
        # response, and every write then walked the chain stamping once per
        # layer. Two 103 Early Hints gave three. The stamp is already in the
        # chain — one wrapper per response is the whole point of wrapping at
        # the top rather than at each `sendall` site.
        if rest:
            # Bytes already read past this head belong to the next response;
            # they cannot be pushed back, so hand them to the recursion.
            return _relay_response(
                _Prefixed(up, rest), client, cid,
                reject_on_auth_error=reject_on_auth_error, method=method,
                on_headers=None, path=path, certdir=certdir,
            )
        return _relay_response(
            up, client, cid,
            reject_on_auth_error=reject_on_auth_error, method=method,
            on_headers=None, path=path, certdir=certdir,
        )
    if bodyless:
        # 204/304 (and 1xx) carry no body by definition and commonly send
        # neither Content-Length nor Transfer-Encoding. Falling through to
        # the close-delimited branch would block on recv until the upstream
        # closes — which a keep-alive server need not ever do — and the
        # client's request just hangs.
        _send_head(b"\r\n".join(out) + b"\r\n\r\n" + rest)
        return keep
    _send_head(b"\r\n".join(out) + b"\r\n\r\n" + rest)

    if chunked:
        return _pipe_chunked(up, client, bytearray(rest)) and keep
    if length is not None:
        remaining = length - len(rest)
        while remaining > 0:
            try:
                chunk = up.recv(min(65536, remaining))
            except (ConnectionResetError, ssl.SSLError, OSError):
                return False
            if not chunk:
                return False
            client.sendall(chunk)
            remaining -= len(chunk)
        return keep
    # No framing: body runs to EOF (SSE and close-delimited replies).
    while True:
        try:
            chunk = up.recv(65536)
        except (ConnectionResetError, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        client.sendall(chunk)
    return False


def _pipe_chunked(up: ssl.SSLSocket, client: ssl.SSLSocket, buf: bytearray) -> bool:
    """Forward a chunked body verbatim until the terminating 0-length chunk.

    Parses only enough to find the end of the body (so the next response on
    this connection starts at the right offset); every byte is relayed as-is.
    """
    while True:
        while b"\r\n" not in buf:
            try:
                chunk = up.recv(65536)
            except (ConnectionResetError, ssl.SSLError, OSError):
                return False
            if not chunk:
                return False
            client.sendall(chunk)
            buf += chunk
        line, _, tail = bytes(buf).partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return False
        need = size + 2  # chunk data + trailing CRLF
        buf = bytearray(tail)
        while len(buf) < need:
            try:
                chunk = up.recv(65536)
            except (ConnectionResetError, ssl.SSLError, OSError):
                return False
            if not chunk:
                return False
            client.sendall(chunk)
            buf += chunk
        buf = bytearray(buf[need:])
        if size == 0:
            return True


def _drain_ready(src) -> bytes:
    """Everything readable right now, TLS buffer included.

    One TLS record can decrypt to more than a single ``recv`` returns, and a
    selector sees the SOCKET, not the SSL buffer — so bytes already decrypted
    and waiting are invisible to it. Measured: after a recv returning 10
    bytes, 90 more sat in the buffer while the selector reported not-readable.
    A long poll or SSE stream through such a tunnel stalls on data that has
    already arrived.
    """
    data = src.recv(65536)
    pending = getattr(src, "pending", None)
    while data and pending and pending():
        more = src.recv(65536)
        if not more:
            break
        data += more
    return data


class _PumpLoop:
    """ONE selector thread for EVERY tunnel, instead of one thread each.

    THE MEASURED PROBLEM. A connection spends almost its whole life here —
    a CONNECT tunnel is opaque from the 200 onward, and a WebSocket upgrade
    turns the MITM into the same thing — and it used to hold an OS thread for
    that entire time. Counted from outside the process, hop wedged:

        idle          4 threads
         50 conns ->  54 threads
        150 conns -> 154 threads
        300 conns -> 304 threads

    Exactly 1:1, which is how a dead upstream produced 27,491 threads and
    44,121 FDs in 40 minutes and took a 48-core box to load 16,483: the
    retry count IS the thread count. A ceiling was tried and removed — it
    turns the 257th retry into a refused connection and leaves the coupling.

    The multiplexing was always here; `_pump` already ran a selector over its
    two sockets. It just ran one per connection. Registering every pair with
    ONE selector is the same code with the thread removed, which is what an
    event loop would give and what the peer proxy in this chain measured on
    its own side: 84 connections, 11 threads, flat.

    NOT asyncio, deliberately. This module speaks blocking sockets in 53
    places — TLS MITM, CONNECT tunnels, the chain walk, fd hand-down — and
    every one of them carries a measurement that would have to be re-proved
    against a coroutine rewrite. The property the outage needs is "a
    connection is not a thread", and that is this class.
    """

    def __init__(self):
        # When any tunnel last moved a byte. The drain reads it to tell a
        # tunnel carrying a session from one whose peer has wedged.
        self._last_move = 0.0
        self._kind: dict = {}
        self._sel = selectors.DefaultSelector()
        self._peer: dict = {}
        # Bytes accepted from one side that the other has not taken yet.
        self._pending: dict = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        # A self-pipe so `add` wakes the selector instead of waiting out its
        # timeout: a tunnel registered a moment after `select()` blocked would
        # otherwise sit idle for the whole poll, which is a stall the client
        # sees as a hang.
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._sel.register(self._wake_r, selectors.EVENT_READ)

    @staticmethod
    def can_take(sock) -> bool:
        """Whether this socket can live in a non-blocking selector at all.

        `_TLSInTLS` (an https:// chain hop, TLS inside TLS) implements only
        sendall/recv/pending/settimeout/gettimeout/fileno/close — no
        `setblocking`, and no way to drive its handshake from a readiness
        callback. `add` used to call `setblocking(False)` on it and raise
        AttributeError, which is not in the except tuple: the exception
        escaped `_handle_one_request`'s `except (OSError, ssl.SSLError)` and
        killed the connection. Behind a TLS egress proxy that is Remote
        Control's inbound WebSocket dying on every launch, and it left two
        stale entries in `_peer` on the way out.

        Callers fall back to the blocking `_pump` for these, which costs a
        thread and is what every version before the shared selector did.
        """
        return callable(getattr(sock, "setblocking", None))

    def quiet_for(self) -> float:
        """Seconds since any tunnel last moved a byte, 0.0 if none ever has."""
        with self._lock:
            last = self._last_move
        return (time.monotonic() - last) if last else 0.0

    def reset_for_tests(self) -> None:
        """Forget every tunnel. TEST ISOLATION ONLY.

        This object is a module global, so in a single-process test run one
        case's leftover pairs are visible to the next — measured on the macOS
        runner as one proxy reporting another's tunnels, and as a drain waiting
        out the marker TTL on a tunnel it did not own. A daemon has exactly one
        `_PUMP` and never wants this.
        """
        with self._lock:
            self._peer.clear()
            self._pending.clear()
            self._last_move = 0.0

    def live_pairs(self, kind: str | None = None) -> int:
        """How many tunnels this selector is driving, or how many of `kind`.

        The drain asks. A tunnel is deliberately un-owed — it is not a reply
        anybody is waiting for — but it IS a live channel, and a process that
        exits while pumping one takes it down.
        """
        with self._lock:
            if kind is None:
                return len(self._peer) // 2
            return sum(1 for s in self._peer
                       if self._kind.get(s, "tunnel") == kind) // 2

    def release_pairs(self, kind: str | None = None) -> int:
        """Let the driven tunnels of `kind` go, and say how many.

        SHUT_WR, NOT CLOSE, and on BOTH sides: each peer sees a clean EOF
        rather than the RST it would get when this process exits with the
        sockets still open. That is the same policy `release_idle_streams`
        uses for SSE, and the 2x2 in `_close_open_connections` is the
        measurement behind preferring it.

        THE PAIR LEAVES THE MAP FIRST, or the shutdown is undone by the next
        byte: a released socket still registered keeps being relayed, the
        `send` onto its shut peer raises EPIPE, and `_close_pair` then closes
        WITHOUT shutdown — which is the RST this method exists to avoid. It
        also keeps `live_pairs()` honest, and the reaper reads that number to
        decide which predecessor is cheapest to kill.

        BOTH SIDES, because a tunnel has no client/upstream asymmetry here --
        `add` takes an unordered pair and `_peer` maps each to the other. Half
        a shutdown leaves the other end waiting on a socket nobody will write
        to again.

        THIS IS NOT A HANDOVER. The successor cannot inherit a live connection
        (no `SCM_RIGHTS` anywhere in this tree), so the channel ends here
        whatever we do. What this buys is WHEN: beside the recycle that caused
        it, rather than whenever the peer happens to stop talking.
        """
        with self._lock:
            socks = [s_ for s_ in self._peer
                     if kind is None or self._kind.get(s_, "tunnel") == kind]
            for s_ in socks:
                self._peer.pop(s_, None)
                self._kind.pop(s_, None)
                self._pending.pop(s_, None)
                try:
                    self._sel.unregister(s_)
                except (KeyError, ValueError, OSError):
                    pass
        for s_ in socks:
            try:
                s_.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        return len(socks) // 2

    def add(self, a, b, on_close=None, kind: str = "tunnel") -> None:
        """Take over a pair of sockets. Returns AT ONCE.

        `on_close` runs when the tunnel ends — it is where the caller's own
        teardown goes, because the caller no longer has a thread to run it on.

        `kind` SEPARATES TWO POPULATIONS THAT LOOK IDENTICAL HERE. Every host
        that is not the upstream takes a blind CONNECT — git, pip, npm, the
        auto-updater — and lands in this same map beside the one Remote
        Control WebSocket. They need opposite treatment on a drain: a bulk
        transfer is real work and must be waited out, while the bridge is
        keepalived and never goes quiet, so waiting on it cannot end. Only the
        101 path passes `bridge`.
        """
        with self._lock:
            self._last_move = time.monotonic()
            self._kind[a] = self._kind[b] = kind
            self._peer[a] = (b, on_close)
            self._peer[b] = (a, on_close)
            for s in (a, b):
                try:
                    s.setblocking(False)
                    self._sel.register(s, selectors.EVENT_READ)
                except (OSError, ValueError, KeyError):
                    self._close_pair(a, b, on_close)
                    return
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, daemon=True)
                self._thread.start()
        try:
            self._wake_w.send(b"\0")
        except OSError:
            pass

    def _flush(self, dst, on_close) -> None:
        """Send what we can, keep the rest, and watch for writability.

        Registering EVENT_WRITE only while there is a backlog: a socket that
        is always writable would otherwise wake the selector on every pass
        and turn the loop into a spin.
        """
        with self._lock:
            buf = self._pending.get(dst, b"")
        while buf:
            try:
                sent = dst.send(buf)
            except (BlockingIOError, ssl.SSLWantWriteError):
                break
            except OSError:
                with self._lock:
                    peer = self._peer.get(dst)
                    self._pending.pop(dst, None)
                    if peer is not None:
                        self._close_pair(dst, peer[0], peer[1])
                return
            buf = buf[sent:]
        with self._lock:
            if buf:
                self._pending[dst] = buf
                try:
                    self._sel.modify(
                        dst, selectors.EVENT_READ | selectors.EVENT_WRITE
                    )
                except (KeyError, ValueError, OSError):
                    pass
            else:
                self._pending.pop(dst, None)
                try:
                    self._sel.modify(dst, selectors.EVENT_READ)
                except (KeyError, ValueError, OSError):
                    pass

    def _close_pair(self, a, b, on_close, closed_by=None) -> None:
        # CALLER HOLDS THE LOCK. It mutates `_peer`, and the run loop now
        # takes the lock only around the map — so each call site wraps it
        # rather than the method taking a second, non-reentrant acquire.
        for s in (a, b):
            self._peer.pop(s, None)
            self._kind.pop(s, None)
            try:
                self._sel.unregister(s)
            except (KeyError, ValueError):
                pass
            try:
                s.close()
            except OSError:
                pass
        if on_close is not None:
            try:
                if getattr(on_close, "_wants_closer", False):
                    on_close(closed_by)
                else:
                    on_close()
            except Exception:  # noqa: BLE001 — never take the loop down
                pass

    def _run(self) -> None:
        while True:
            for key, events in self._sel.select(timeout=60):
                src = key.fileobj
                # A BACKLOG DRAINING is not a read. `_flush` registered this
                # socket for writability because its peer had bytes waiting;
                # handle that first and fall through, since a socket can be
                # both readable and writable in the same pass.
                if events & selectors.EVENT_WRITE:
                    with self._lock:
                        entry = self._peer.get(src)
                    self._flush(src, entry[1] if entry else None)
                    if not (events & selectors.EVENT_READ):
                        continue
                if src is self._wake_r:
                    try:
                        self._wake_r.recv(65536)
                    except OSError:
                        pass
                    continue
                # THE LOCK COVERS THE MAP, NOT THE I/O. Holding it across the
                # write re-coupled every tunnel to every other one: a single
                # peer that stops reading blocks this one thread inside
                # `sendall` WHILE HOLDING the lock `add` also takes, so no
                # other tunnel moves a byte and no new tunnel can register.
                # That is the "one bad connection stalls everything" property
                # this class removed from the thread count, put back as a
                # global mutex — and a peer that stops reading is exactly what
                # the outage produced.
                with self._lock:
                    entry = self._peer.get(src)
                if entry is None:
                    continue
                dst, on_close = entry
                try:
                    data = _drain_ready(src)
                except (BlockingIOError, ssl.SSLWantReadError):
                    continue  # nothing decrypted yet — wait for more
                except OSError:
                    data = b""
                if not data:
                    with self._lock:
                        self._close_pair(src, dst, on_close, closed_by=src)
                    continue
                # NEVER BLOCK THIS THREAD. It carries every tunnel, so a
                # peer that stops reading would stall all of them — releasing
                # the lock was not enough, because the stall is the THREAD,
                # not the mutex. `send` reports how much it took; the rest is
                # buffered and flushed when the selector says `dst` is
                # writable. A blocking `sendall` here reintroduced the exact
                # coupling this class removed.
                with self._lock:
                    # A BYTE MOVED. Stamped where bytes are CONFIRMED and not
                    # at the top of the select loop: the wake pipe fires on
                    # this daemon's own bookkeeping, and a stamp there is a
                    # heartbeat the drain would read as traffic.
                    self._last_move = time.monotonic()
                    self._pending[dst] = self._pending.get(dst, b"") + data
                self._flush(dst, on_close)


_PUMP = _PumpLoop()


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Shuttle bytes both ways until either side closes, BLOCKING.

    OWNS ITS OWN SELECTOR, deliberately: this is what runs for a socket the
    shared `_PumpLoop` cannot drive, so routing it back through `_PUMP.add`
    re-enters the very call that refused it. It did, for one release —
    `_pump` was rewritten as `add` plus an Event, which made the `can_take`
    fallback raise the same AttributeError it existed to avoid.

    A blocking selector needs only `fileno()`, which `_TLSInTLS` has; it is
    `setblocking` it lacks. That is why every version before the shared loop
    carried an https:// chain hop without noticing.

    Costs a thread. Prefer :func:`_pump_detached` on any path that can give
    its thread back.

    Drains each side's TLS buffer before going back to `select`. One TLS
    record can decrypt to more than a single `recv` returns, and select sees
    the SOCKET, not the SSL buffer — so bytes already decrypted and waiting
    are invisible to it. Measured: after a recv returning 10 bytes, 90 more
    sat in the buffer while the selector reported not-readable.
    """

    def _drain(src) -> bytes:
        data = src.recv(65536)
        pending = getattr(src, "pending", None)
        while data and pending and pending():
            more = src.recv(65536)
            if not more:
                break
            data += more
        return data

    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ)
    sel.register(b, selectors.EVENT_READ)
    try:
        while True:
            for key, _ in sel.select(timeout=60):
                src = key.fileobj
                dst = b if src is a else a
                data = _drain(src)
                if not data:
                    return
                dst.sendall(data)
    except (OSError, ssl.SSLError):
        return
    finally:
        sel.close()
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def _pump_detached(a: socket.socket, b: socket.socket, on_close=None,
                   kind: str = "bridge") -> None:
    """Hand a tunnel to the shared selector and RETURN.

    This is where the thread is given back. A tunnel is opaque from the 200
    onward and lives for as long as the session does, so the thread that set
    it up has nothing left to do — it was only holding the connection open.
    `on_close` carries whatever teardown that frame would have run.

    A socket the selector cannot drive (see `_PumpLoop.can_take`) keeps the
    thread instead: correctness first, and it is what every version before
    the shared selector did for every connection.
    """
    if not (_PumpLoop.can_take(a) and _PumpLoop.can_take(b)):
        try:
            _pump(a, b)
        finally:
            if on_close is not None:
                try:
                    on_close()
                except Exception:  # noqa: BLE001
                    pass
        return
    _PUMP.add(a, b, on_close, kind)


if __name__ == "__main__":  # pragma: no cover — exercised as a subprocess
    import sys as _sys

    if _sys.argv[1:2] == [_HOLDER_MODULE_ARG]:
        holder_main(_sys.argv[3], _sys.argv[4], Path(_sys.argv[5]),
                    port=int(_sys.argv[2]))
    elif _sys.argv[1:2] == [_STANDBY_MODULE_ARG]:
        standby_main(_sys.argv[2], _sys.argv[3], Path(_sys.argv[4]))
    else:
        daemon_main(_sys.argv[1], _sys.argv[2], Path(_sys.argv[3]))
