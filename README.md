# cswap-pin

Keep Claude Code's **Remote Control** and **Artifacts** on one account while
inference keeps following [`cswap`](https://github.com/realiti4/claude-swap)'s
account swap.

## The problem

cswap swaps the on-disk credential, so *everything* follows the swap —
including two things that are not inference and that you usually want to stay
put:

- **Remote Control** — a session's owner is fixed at creation by whichever
  bearer created it. Swap accounts and the phone/web loses the session; stale
  "ghost" sessions pile up on the old account.
- **Artifacts** — owned by the publishing bearer. After a swap a republish
  403s and the artifact "disappears" from the account you are logged into.

Claude Code resolves all of these through one credential accessor and has no
per-operation token selector, so splitting auth *per operation inside one
session* means intercepting the requests.

## How it works

A local MITM forward proxy that swaps the `Authorization` bearer on exactly
the routes whose server-side ownership is decided by it, and passes everything
else — `/v1/messages` above all — through untouched.

```
claude session
  HTTPS_PROXY ─► cswap pin proxy ──► (whatever HTTPS_PROXY was already set) ──► api.anthropic.com
                   swaps bearer on: /v1/code/sessions*, /v1/sessions/*,
                                    /v1/environments, /v1/environments/bridge*,
                                    /v1/environments/<env>/bridge/reconnect,
                                    /api/frame/*, /v1/ultrareview/*
                   passes through:  /v1/messages, /api/oauth/usage, everything else
                   NEVER swapped:   .../worker/*, .../client/presence,
                                    /v1/environments/<env>/work/*, ?beta=true
```

Inference keeps billing whichever account cswap has swapped onto. Only the
claude.ai-side assets are pinned.

### Remote Control has two front doors, and they own sessions differently

| you run | it creates | ownership route |
|---|---|---|
| `/remote-control` in the REPL | a bridge on the current session | `POST /v1/code/sessions/<id>/bridge` |
| `claude remote-control` | an ENVIRONMENT this machine offers | `POST /v1/environments/bridge` |

The second family is easy to miss, because `remote-control` is the
subcommand's name while the ownership it creates travels on a path that does
not contain it. Pin only the first and `claude remote-control` registers every
machine on whichever account is currently active — with nothing reporting a
fault, because nothing is failing. The machine is simply absent from the
pinned account's browser.

**A pinned route is only swapped on a path that reads the bearer, and there
are two.** The MITM terminates a `CONNECT` and inspects each request inside
it; the other forwards absolute-form requests (`POST https://host/path`),
which is plain-proxy form. Remote Control's bridge client speaks the second,
so adding its routes to the table changes nothing until that path swaps too.
Both now take the same decision from the same predicate, and both write a line
saying what they decided — an untraced path leaves exactly the evidence a
feature that is not running leaves.

A swap the upstream REFUSES (401/403/404) is taken back and the request goes
again with the bearer it arrived with. That is what lets an environment
registered before the pin knew this route keep working instead of dying on its
next poll.

Three exceptions inside the pinned prefixes are worth naming, because all
three were learned by breaking them:

- **`/worker/*`** carries the session's own channel credential, not an OAuth
  bearer. Swapping it makes the server reject every worker call and leaves
  Remote Control in a reconnect loop.
- **`/client/presence`** is *registration*, not ownership: it tells the server
  which process is attached and should receive events. Swapped, the server
  registers the pinned account while the process actually listening belongs to
  the active one — so inbound has nobody to reach. It returns `200` either way,
  which is what made it hard to find.
- **`/v1/environments/<env>/work/*`** is the same shape as `/worker/*`, one
  path over. In the bridge client every OAuth call goes through one wrapper
  that reads the account's access token — register, deregister,
  `bridge/reconnect`, archive — while `poll`, `ack`, `stop` and `heartbeat`
  each take a token as an *argument* and send whatever the caller hands them.
  Measured against an environment this proxy had just registered: the register
  answered fine swapped, and the very next `work/poll` on that same
  environment answered `401` swapped and `200` unswapped. Ownership is still
  the pin's, because the register is; the work queue is simply not an
  ownership route.

`?beta=true` under `/v1/environments` is excluded for a different reason: it
is a second product (the managed-agents SDK) sharing the path space with a
credential this proxy has never looked at. Swapping an `Authorization` nobody
has read is the mistake `/worker` already measured.

### A wrong guess cannot cost you a session

Route classification used to be a single point of *permanent* failure. Claude
Code treats `401/403/404` as terminal — its SSE transport sets `state="closed"`
and never reconnects — so one misrouted swap ended that session's Remote
Control for the life of the process (measured: 26 such responses severed four
sessions that were still running hours later).

Since 0.1.1 the proxy holds the response before any byte reaches the client,
and when the *swap* is what was refused it re-sends the request exactly as it
arrived. "Wrong about this route" degrades to "this request went out unpinned",
which is the failure mode everything else here is already built to tolerate.

### Keeping a session's bridge when the account rotates

Swapping the bearer is only half of it. Claude Code also writes a *pointer* —
naming the bridge, the sequence to resume at, and the account it believes it is
— and on the next launch compares that recorded account against
`~/.claude.json`'s `oauthAccount`. A mismatch is a veto:

```
reattach vetoed: the credential store account changed since this conversation's
pointer was persisted — minting fresh, history channels suppressed
```

The comparison is against the account cswap currently has **active**, never
against the pin. And Claude Code stamps the pointer with its own login, not
with the bearer this proxy swapped in — so under a perfectly working pin the
bridge belongs to the pinned account while the pointer names whichever account
happened to be active. Rotate once between two runs and the veto strands a
bridge that was reattachable the whole time. Measured on one machine: **14 of
14** live sessions held a pointer that disagreed with the login. What follows
from that — veto, fresh mint, history suppressed — is Claude Code's code path
as read at 2.1.233, not a second measurement and not documentation: none of
this is documented anywhere, it is decompiled. Nobody relaunched all fourteen
to watch it happen.

So since 0.1.81 the pin restamps the pointer of sessions that are **not
running** with the account that is live right now, and the pointer then agrees
with the login by construction. Two hooks, because neither covers the other's
sessions:

| hook | reached by | timing |
| --- | --- | --- |
| `heal` | `cswap pin --ensure`, the rc hook before every hand-launched `claude` | backgrounded by the rc file, so it can lose the race against the launch it precedes |
| `ensure_proxy` | `cswap run`, and a hand-typed `cswap pin <n>` | synchronous, before `execvpe` — but it runs with the DEFAULT profile's environment, so on `cswap run <account>` it sweeps that profile, not the isolated one it is about to launch |

Losing that race costs the current launch and nothing else: the pointer a pass
misses is restamped by the next launch on the machine, and a session that gets
vetoed once still ends up with a working bridge — just a new one.

**Restamped, not blanked.** Removing the owner also clears the veto, and it is
the more obvious move, but the same branch decides something else:

```js
if (!He) { He = Qe.id, Oe = Qe.seq;
           if (!Ir || !hzs()) Ke = true;      // Ir = owner matches the login
           … `${Ke ? "reattach-or-fail" : "fresh-mint fallback"}` }
```

No owner means no match means **reattach-or-fail, with the fresh-mint fallback
switched off** — so a pointer naming a bridge that has since been deleted (by
another machine's sweep, by `/cleanup-rc`, from claude.ai) leaves that session
with no Remote Control at all. A *matching* owner keeps the fallback, which
makes a wrong guess cost exactly what it costs today: a new bridge. That is why
nothing here has to prove which account owns a bridge, and why there is no
cache to go stale.

The `hzs()` in that condition is a server-side feature gate whose `true` is a
client default, so the fallback is Anthropic's to keep rather than something
this package can guarantee. Removing the owner loses it unconditionally;
matching loses it only if that gate is ever turned off.

**Two stores, and the live one is not the obvious one.** The pointer lives in
`~/.claude/jobs/<jobId>/state.json` when `CLAUDE_JOB_DIR` is set and in the
transcript's last `bridge-session` record otherwise. A session that has been
both keeps a stale transcript record forever — 12 of 13 live sessions here are
background jobs whose transcript record disagrees with their job record.

**What it restores is the bridge, not the backfill.** `noHistoryBackfill` is
copied through, and `if (Qe.noHistoryBackfill) le = true` runs on the reattach
branch too, so a pointer carrying it reattaches with history channels still
suppressed — 12 of 12 job records here carry it, and Claude Code ORs it forward
so it never clears. The session keeps the same conversation and the same
sequence position instead of starting over on a new bridge.

That `le` also skips Claude Code's own title derivation (the block is
`else if (!le)`), so the name does not come back from CC either — it comes from
this package: the daemon's sweep puts each session's local name on its bridge
whenever the server has invented one, which is what `titles_to_restore` is for
and what 0.1.80 shipped. Restamping and title restore are two halves of the
same outcome, and neither replaces the other.

Nothing here clears the flag. Doing that would push transcript history to the
server, which is not this proxy's call to make — and a draft that wrote the
flag ON, to preserve a suppression on a branch that turns out to be unreachable
at launch, would have cost every ownerless pointer its messages and its name,
permanently. It was removed.

## Install

The pin is an optional extra of claude-swap, not a standalone tool: it reads
cswap's account store, rewrites the config cswap already manages, and the
`cswap pin` command itself lives in the host. Installing `cswap-pin` on its own
does nothing useful.

**The extra is not on PyPI yet, and the obvious line does not fail — it
warns.** `claude-swap` 0.25.0 publishes only the `menubar` extra, so this
installs a host with no pin in it and exits 0. Measured on a clean macOS HOME:

```console
$ uv tool install 'claude-swap[pin]'
warning: The package `claude-swap==0.25.0` does not have an extra named `pin`
Installed 2 executables: claude-swap, cswap
$ cswap pin
cswap: error: unrecognized arguments: pin
```

Until a host release carries it, install from the branch that does. Measured
the same way, on a HOME with nothing but `claude` on PATH — no proxy, no CA
bundle, no other wiring:

```bash
uv tool install "claude-swap[pin] @ git+https://github.com/codeslake/claude-swap@feat/pin-package-seam"
```

```console
$ cswap --version
cswap 0.26.0b1
$ cswap pin
No cloud account pinned
```

Once the host release lands, the plain form is the one to use — and the line
above keeps working, so there is no rush to change it:

```bash
uv tool install 'claude-swap[pin]'
```

`pipx` should take the same arguments, but this was verified with `uv` only.

**On a machine running claude-swap from a checkout, keep it editable.** The
command above installs the PyPI release and replaces whatever was there, extras
included — so running it against an editable install both downgrades the host
and drops `cswap_pin` from the tool env. The daemon already running survives
(its code is in memory) but every successor it spawns dies with
`ModuleNotFoundError`, which is invisible until something tries to restart it:

```bash
uv tool install --force --editable '.[pin]'     # from the checkout
```

### Upgrading a machine that is already serving

Nothing to do. Install the new version; the running daemon notices its own
code changed and replaces itself, on the same port, without dropping anything.
Measured across a real code change on a live daemon: **68,168 requests, 0
refused, 0 reset, 0 unanswered**, same port, new pid.

**`refused=0` on its own is not that claim**, and it is worth saying because
this package spent several releases believing it was. The port is held by a
process that outlives the daemon, so during a handover it stays bound and
every arrival queues in the backlog: a probe that only counts
`ConnectionRefusedError` is structurally incapable of failing, however long
nobody is behind the socket. One machine drained for 30 seconds that way —
`refused=0` the whole time, and 30 requests died on a 3s timeout with no
reply. The numbers above count a request that connects and is never answered
as a failure, which is what it is to a session.

This used to need a procedure, and a procedure is not an answer — a deploy is
not something someone follows, it is whatever the running code does. Two
machines taught that: both moved their port mid-upgrade (53749 → 54264,
36301 → 45357) and stranded every session that had the old number baked in at
exec, because the successor came up with no holder above it. Every spawn now
lands under one.

## Use

**An account has to exist first.** The pin points at one of cswap's managed
accounts by number, so on a machine that has none, the first command in this
section is the one that fails:

```console
$ cswap pin 2
Error: Account-2 does not exist
$ cswap list
No accounts are managed yet.
No active Claude account found. Please log in first.
```

Log in with `claude` and let cswap pick the account up (`cswap list` shows the
numbers), then:

```bash
cswap pin 2          # RC / artifacts / ultrareview → account 2
cswap pin            # show the current pin
cswap pin --clear    # remove it
```

The pinned account is re-read per request, so `cswap pin <other>` takes effect
under a live daemon — no session restart. The one thing a re-pin cannot move is
a Remote Control session that is **already open**: the server fixed its owner
when it was created, so reconnecting inside it is what mints a new one under
the new pin.

## The port

Nothing is hardcoded. The first daemon binds port `0` — the OS picks — and
records what it got in `<cswap-backup>/pin-proxy/proxy.json`. Later starts try
to reclaim that number and fall back to another ephemeral port if anything else
already holds it, so a port you are using is never taken from you.

Reclaiming matters because a running session's `HTTPS_PROXY` is fixed when it
execs: coming back on a different port would leave that session dialling an
address nothing answers, and its requests would then go out *unpinned* rather
than fail loudly.

### The port outlives the daemon

The socket is bound by a **holder** — a process that never serves a request.
It binds, starts the daemon, and waits. The daemon accepts on that inherited
descriptor, so there is no relay and no extra hop: the connection the client
makes is the connection the daemon serves.

That is what makes a crash survivable. A planned restart already keeps the
port (the outgoing daemon hands its socket down), but a `kill -9`, an OOM
kill or a segfault skips every cooperative step — and an unowned port is
permanent for a live session, whose `HTTPS_PROXY` was fixed at exec.
Measured: **twelve `kill -9`s** of the daemon while four clients hammered the
port — **6,388 requests, 0 refused**, same port throughout, a new pid each
time. The 41 resets in that run are the killed daemon's own in-flight
requests, which a crash must cost; a *planned* restart costs none.

The reason it is zero rather than small is that the holder never releases the
socket between children. It binds once and keeps it; each daemon accepts on
the inherited descriptor. So there is no re-acquire to lose, and a connection
arriving mid-crash waits in the kernel's backlog instead of being refused. A
supervisor that closes and rebinds has a window there by construction, however
narrow — a peer measured 1 refusal in 40 requests on that shape.

The holder reads the daemon's exit rather than guessing:

| exit | meaning | what the holder does |
| :-- | :-- | :-- |
| `0` | idle teardown — it meant to go | release the port, do not respawn |
| `75` | `SIGTERM` under a holder: a redeploy | restart at once, same socket |
| other | killed or crashed | restart on a 0.25s → 5s ladder |

`CSWAP_PIN_SELF_HEAL=off` turns every automatic replacement off — the holder's
restart above and the self-upgrade below — for when you are debugging the
daemon and a respawner fighting you is worse than a dead port. `cswap pin
--heal` and a launch still repair, because those are you asking.

`CSWAP_PIN_EXIT_WITH_PARENT=1` makes the holder die when the process that
started it dies. **Do not set this.** A holder is meant to outlive its
launcher — `cswap pin` spawns it and exits, a shell backgrounds it and the
shell exits — so with this on, a normal launch loses the port within a couple
of seconds and every session wired to it is stranded. It exists for a test
runner: a `SIGKILL`ed pytest otherwise leaves holders behind (151 of them,
9.17 GiB, measured), and the suite sets it for the one case that asserts that
cleanup.

Two opt-in traces, both off unless you name a file:

```bash
CSWAP_PIN_DEBUG=/tmp/pin.log     # one line per request
CSWAP_PIN_SHAPE=/tmp/shape.log   # the message-array shape of each request body
```

And an opt-in slow-request report, off unless you name a threshold in
milliseconds. It writes to `daemon.log`, so it stays silent until asked —
always-on it produced about 38 lines an hour on one fleet, which is noise in
the file people read to find out why a daemon died.

It goes in the same `settings.json` section `cswap pin <email>` already
writes, so there is no new path to remember:

```json
"remoteControl": { "pinnedEmail": "you@example.com", "debugSlowMs": 1500 }
```

Edit it while the daemon serves; it is re-read within seconds. Restarting the
daemon is the one act guaranteed to hide an intermittent stall, so a switch
that needed a restart would be useless for this. `CSWAP_PIN_SLOW_MS` wins for
a deployment that would rather set it in the environment.

Each line splits the round trip three ways — inside the pin, waiting for the
server, and getting the request out through the chain — because the total
alone cannot say whose problem a stall is. The route is logged without its
query string or session id.

`CSWAP_PIN_LISTEN_FD` and `CSWAP_PIN_LISTEN_FROM` also appear in a daemon's
environment. They are how a process hands its listening socket to the next
one, written by the parent at spawn — not settings, and setting them by hand
makes a daemon adopt a descriptor that is not the one it was given.

A redeploy is the same story from the other side. Under a holder the daemon
does not hand its socket to a successor — it exits `75` and lets the holder
put the new code on the socket it already owns. Handing the port out of the
holder is what left one machine's pin unwired for 76 minutes while every
component reported healthy.

A daemon that is NOT under a holder still hands its socket down, and the
successor it starts gets a holder that **adopts** that socket rather than
binding a fresh one. There is no race to lose: the descriptor is already bound
and listening. That is what makes the first upgrade onto this version safe as
well as every one after it.

### A daemon that outlives its holder gets a new one

A holder can die without taking its daemon with it, and nothing looks wrong
afterwards: the daemon already holds the socket, so the port keeps answering.
What is gone is the property above — every spawn lands under a holder — so the
*next* death takes the port down for good.

The daemon notices by asking a question it was already able to answer. Its
`CSWAP_PIN_HELD_BY` names the holder that started it, and an orphan is
reparented to init, so the marker and `getppid()` disagree the moment the
holder dies. Nothing signal-specific: a `SIGHUP`, a `SIGQUIT`, a segfault and a
targeted kill all land the same way. It then hands over exactly as a code
change would, and the successor's holder adopts the socket.

Measured, under load across the whole orphaning: **110,188 requests, 0 refused,
0 reset**, same port, one holder afterwards.

### When the holder and its daemon die together

The two rows above both leave *something* alive that can put the port back. The
row neither covers is both going at once — `cswap` fully off, an OOM kill that
takes the process group, a machine being torn down. The descriptor is closed by
the kernel with the last process holding it, and a session's `HTTPS_PROXY` was
fixed at exec, so it has no way to learn the address moved. Measured with both
gone: **198 of 199 ConnectionRefused**, permanently.

**On Linux, killing the holder alone is already this row.** The daemon is
spawned to exit with its parent (`PR_SET_PDEATHSIG`, and see
`CSWAP_PIN_EXIT_WITH_PARENT`), so the kernel takes it down with the holder and
the descriptor closes with them both. macOS has no equivalent primitive, so
there the daemon outlives its holder still holding the socket and its own
watchdog puts a fresh holder back. Same command, same lineage shape, measured
the same day: **147 probes / 0 unanswered on a Mac, 232 of 241 refused on
Linux**. Anything reasoning about "the holder dies but the daemon survives" is
reasoning about Darwin.

The signal matters as much as the target, and in the same direction:
`SIGTERM` leaves the holder able to run its teardown — drain the daemon, hand
the socket down — while `SIGKILL` denies it exactly that. The handler *is* the
handover.

So a third process holds the same descriptor and does nothing with it. It is
spawned detached (its own session, so a `ctrl-C` or a group-delivered `TERM`
aimed at the holder misses it) and it **never accepts** — CPython only accepts
when you call `accept()`, so a listening socket can be held in silence. That is
what makes this a dormant holder rather than a relay: it forwards no bytes, so
none of the byte-shuffling failures a relay has to get right exist here.

`CSWAP_PIN_STANDBY_FROM` carries the pid it was born under. It acts only when
**both** are true:

- `getppid()` no longer reads that pid — *not* `== 1`, which never happens on a
  subreaper host (`systemd --user`); a standby that never arms while still
  holding the descriptor makes the address accept-and-hang, strictly worse than
  refusing.
- the daemon `proxy.json` names is gone — `kill(pid, 0)`, microseconds and no
  socket — **and** one 250ms probe to the port gets **no byte back**. The
  recorded pid is asked first because it is the cheapest and most direct
  evidence there is: silence is only a *proxy* for "nothing accepts", and a
  loaded daemon can stay silent longer than any window worth waiting. Any byte
  counts and the status is ignored — a live daemon answers `407` and a peer's
  carrying relay answers `503`, and both mean "somebody is behind this socket".

Either condition alone is wrong: while the holder lives it is already respawning
its own daemon, and a silent port during an ordinary daemon crash is a gap the
holder closes by itself (measured: 407 of 408 requests served across a daemon
`SIGKILL`, max time-to-first-byte 6.3ms).

When it does act it does not serve traffic — it puts a holder back on the
descriptor it was already holding, and requests that arrived meanwhile are
waiting in the backlog of a socket that never stopped listening.

**What it cannot preserve is the connections the dead daemon had already
accepted.** Those bytes are in a process that no longer exists and no successor
can produce them. Measured with a peer's instrument — sampling a real session's
ESTABLISHED connections every 200ms across the kill — the session's connections
drop to zero and are re-made about 851ms later. What survives is the *address*,
which is the part a session cannot relearn, and that is the whole point:
`HTTPS_PROXY` was fixed at exec, so a client that retries finds a listener
instead of the 198-of-199 ConnectionRefused above.

So **"zero requests lost" is a claim about a retrying client, not about
connection continuity**, and elapsed time cannot tell the two apart — a reset
that is re-made in under a second looks identical to no reset at all. The
upgrade path above is the stronger one: there the socket is handed on, so
connections are never reset in the first place.

**Only `SIGHUP` releases it.** `SIGTERM` and `SIGINT` are ignored outright:
`TERM` is what a supervisor, a `systemctl stop` or a stray `pkill` sends, and
that is exactly when the sessions still need the address. A peer on this design
measured their graceful path as *more destructive than `kill -9`* for want of
that distinction. `PortHolder.stop()` — a deliberate release — sends the
`SIGHUP` itself, so releasing the port really releases it.

## Hosts that bring their own login (Claude Desktop)

Everything above assumes inference already follows cswap, and for the `claude`
CLI it does: it reads the Keychain cswap swaps. **Claude Desktop's Code tab
does not.** It spawns its bundled CLI with the app's own login in
`CLAUDE_CODE_OAUTH_TOKEN`, and under a desktop entrypoint Claude Code ignores
any settings `env` entry naming a variable the host set at spawn — so no
configuration reaches it. Desktop bills the account the app is signed into,
and after a rotation it is the one client left on "Weekly limit reached".

Its traffic still comes through this proxy, and its User-Agent names the
entrypoint (`claude-cli/<ver> (external, claude-desktop)`). So, opt-in, the
proxy can re-bill it: list the entrypoints in `inference-follows` in the pin's
directory, one per line.

```bash
echo claude-desktop > ~/.claude-swap-backup/pin-proxy/inference-follows   # on
rm ~/.claude-swap-backup/pin-proxy/inference-follows                      # off
```

The file is re-read every 2 seconds, so it reaches a daemon that is already
serving. `CSWAP_PIN_INFERENCE_FOLLOWS=claude-desktop` (comma-separated) wins
over the file, like `CSWAP_PIN_DEBUG` over `trace-to`.

What it does, for a listed entrypoint only:

- `/v1/messages` and `/v1/messages/count_tokens` get the active account's
  bearer — cswap's own Keychain reader, cached 30 seconds, so a rotation is
  picked up within that. Nothing else moves: ownership routes keep the pin,
  and `/api/oauth/*`, usage and profile calls keep the host's own login.
- A token within a minute of expiry is not used, and the proxy never refreshes
  one (refresh tokens are single-use; the CLI keeps the Keychain copy fresh).
- A swap the account refuses (401/403/404) is resent on the host's own bearer,
  the same fail-open the pinned routes use.

Counters land in `inference-follows.json` beside it — `swapped`,
`retriedUnswapped`, `passthrough` by reason, `lastSwapAt`, `lastRetryAt` — and
`daemon.log` records the switch turning on or off, the first re-billed request
of each daemon, and refusals (at most one line per five minutes).

## Falling through a dead hop

The pin dials through whatever egress proxy the machine already has, and that
proxy usually has one behind it. When a hop dies the request has to reach the
hop *behind* it — falling through to a direct dial is not "no proxy" on a
machine whose direct route is a TLS-inspecting corporate proxy, it is a `403`.

So the pin asks each hop what it chains through, **while that hop is still
answering** — the only moment the answer can be trusted, and the only moment it
is free. Measured on one machine: the record named a single hop for a day while
that hop's own `/health` had been naming the next one the entire time, because
the question was only ever asked at launch. When the inner hop died, a chain
that could have stepped one hop out went direct instead.

## A connection is not a thread

An upstream that accepts and never answers used to cost one OS thread per
connection, and a client that retries forever opens them faster than they
drain. Measured on a 48-core box: **27,491 threads / 44,121 FDs in 40
minutes**, load 16,483, rescued by hand.

Connections are multiplexed on one selector instead. Measured with
`tools/thread_probe.py`, idle CONNECT tunnels against a local upstream:

| open tunnels | before | after |
| --: | --: | --: |
| 50 | 55 threads | 5 |
| 150 | 155 threads | 5 |
| 300 | 305 threads | 5 |

A ceiling was tried first and removed: it turns the 257th retry into a
refused connection and leaves the coupling in place.

### Asking for a specific port

```bash
cswap pin --get_port          # what it is serving right now (for scripts)
cswap pin --set_port 41234    # serve there from the next daemon start
cswap pin --set_port 0        # back to dynamic: the kernel picks
```

A port you set outranks the reclaim above — it is a standing instruction,
where the reclaim is only about keeping live sessions attached. It takes
effect on the next daemon start, not immediately: moving the port under a
running session would strand it, since its `HTTPS_PROXY` was fixed at exec.

If the port you asked for is taken, the pin serves on another one rather than
refusing to start, and says so in `pin-proxy/daemon.log`.

**`CSWAP_PIN_PORT` is not a setting.** The pin writes it into `.claude.json`
as its own marker and Claude Code applies that block at boot, so inside a
pinned session it already holds the running daemon's port. Exporting it
changes nothing; use `--set_port`.

## Requirements

- Python 3.10+
- [`claude-swap`](https://github.com/realiti4/claude-swap) — a peer, not a
  dependency: this package is loaded *by* it (see `src/cswap_pin/_host.py` for
  the exact surface it borrows)
- `cryptography` (installed automatically) for the MITM CA

## Running the tests

Against the **released** host, which is what CI gates on:

```bash
S="$(mktemp -d)" && HOME="$S" XDG_DATA_HOME="$S/.local/share" \
  uv run --with pytest --with pytest-xdist --with cryptography \
         --with claude-swap \
         python -m pytest tests -q -m "not needs_host_seam"
```

Against your **claude-swap checkout**, which also runs the seam tests:

```bash
S="$(mktemp -d)" && HOME="$S" XDG_DATA_HOME="$S/.local/share" \
  uv run --with pytest --with pytest-xdist --with cryptography \
         --with-editable /path/to/claude-swap \
         python -m pytest tests -q
```

Measured, both: 114 passed / 6 skipped for the first, 115 / 6 for the second.
The extra one is `TestAutoViewPinBadge` — it reads a seam that only exists in a
host new enough to have it, so it is `@pytest.mark.needs_host_seam` and CI
excludes it by marker rather than skipping it silently.

**`--with claude-swap` (or `--with-editable`) is not optional.** Five test
files import the HOST, and `claude-swap` is deliberately absent from
`[dependency-groups] dev` — listing it there made `uv run` unresolvable and
took the publish workflow down with it (the reason sits beside the group in
`pyproject.toml`). So the host arrives on the command line or not at all.
Without it the suite does not fail, it **errors**: 14 collection errors,
`ModuleNotFoundError: No module named 'claude_swap'`.

`--with pytest-xdist` is not optional either: `addopts` carries `-n 4`, and a
pytest without xdist refuses the flag rather than ignoring it.

**Redirect `HOME` and `XDG_DATA_HOME`.** The suite drives real cert dirs,
daemon state and config wiring; a run against your own `HOME` will rewrite
`~/.claude.json`, publish a test CA into `~/.claude/ca-trust.d/`, and touch
the account store. `tests/conftest.py` redirects all of it per test, but the
env vars are the belt to that suspenders — they are what the child processes
the suite spawns obey.

**`pytest-xdist` is required, not optional.** `addopts = "-n 4"` in
`pyproject.toml` runs the suite on 4 workers (12.2s → ~5.0s, measured; more
workers do not help — the floor is the single longest test). A pytest without
xdist refuses the flag rather than ignoring it, so the suite will not start.

For a serial repro of a failure, add `-n 0`: xdist gives no live output and
truncates tracebacks it cannot attribute to a worker.

**Do not split a heavy test class to parallelise it.** It looks like free
speed — splitting the 24-case port class halved its 12.7s — and it crashes a
worker instead, 3 runs of 3, reported as `received keyboard-interrupt`. The
cause is in xdist's own shutdown, not in this suite: `execnet`'s
`_terminate_execution` gives a worker's execution pool **5 seconds** to drain
and then runs `os.kill(os.getpid(), 2)  # send ourselves a SIGINT`
(`gateway_base.py:1245`, measured with `sigwaitinfo` — `si_pid` is the worker
itself and `si_code` is `SI_USER`). Two spawn-heavy classes on one worker
exceed that budget, so the worker interrupts itself mid-run and the class
never reports at all — it does not even appear in `--durations`.

The 5s is hardcoded, so nothing here can raise it. Both halves pass in
isolation (7.60s and 5.74s); together on one worker they do not.

One pytest test runs many `case_*` methods (`run_cases` in `conftest.py`), so
113 collected tests carry 350 cases. A failure names both: `Class::case_name`.

## Why a separate package

Upstream did not want a MITM proxy shipped inside claude-swap itself and asked
for a companion distribution exposed through an optional extra. See
[realiti4/claude-swap#198](https://github.com/realiti4/claude-swap/issues/198).

## Trust

The proxy generates its own CA to re-sign `api.anthropic.com` and names it in
`NODE_EXTRA_CA_CERTS`. Node accepts exactly one file there, so an existing CA
(a corporate MITM, another local proxy) is **merged**, never replaced —
otherwise the session silently loses trust in every host the other proxy
re-signs.

**The proxy does not authenticate its callers, deliberately.** It listens on
`127.0.0.1` only, so the population it could turn away is other processes
running *as you* — and an earlier version did exactly that, with a secret file
in the cert dir. That defended against nobody: any process able to reach the
port could also read a `0600` file in your own home. What it did cost was real,
because a session's `HTTPS_PROXY` is fixed when it execs and cannot be updated
in place: arming the credential instantly `407`'d every session that had
started before it existed.

So the honest boundary is the loopback interface plus your user account, not a
credential. If you share a machine with logins you do not trust, do not run
this — the pinned account's token is reachable by anything that can reach the
port.

## License

MIT
