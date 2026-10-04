# cswap-pin

Keep Claude Code's **Remote Control** and **Artifacts** on one account while
inference keeps following [`cswap`](https://github.com/realiti4/claude-swap)'s
account swap.

## Quick start

1. Install (the commit is tagged `pin-install-85764e7`):

   ```bash
   uv tool install --force --python 3.12 \
     "claude-swap[pin] @ git+https://github.com/codeslake/claude-swap@85764e77dc63c02f35caffdf64ddcc5cc61ea0dd" \
     --with cswap-pin==0.1.311
   ```

2. `cswap pin N`, N being an account from `cswap list`. If you reach the
   internet through a proxy, pin with it exported:
   `HTTPS_PROXY=http://127.0.0.1:<port> cswap pin N`.
3. Run `cswap pin --ensure >/dev/null 2>&1 &` on every `claude` launch: as this
   one line in `~/.bashrc` or `~/.zshrc` for hand launches, and in your
   `CLAUDE_CODE_PROCESS_WRAPPER` script too if you use one.

   ```bash
   claude() { (cswap pin --ensure >/dev/null 2>&1 &); command claude "$@"; }
   ```

If it breaks: `cswap pin --clear`. Everything below is reference.

## Before you start, and if it breaks

Pinning rewrites files Claude Code reads at startup (every one is listed under
[What the pin writes](#what-the-pin-writes)). This is the full way back.

**`cswap pin --clear` is the undo**, and it works even when the `cswap-pin`
package is broken or gone. It:

- removes the `env` keys the pin added to `.claude.json` (`HTTPS_PROXY`,
  `https_proxy`, `ALL_PROXY`, `NODE_EXTRA_CA_CERTS`, `CSWAP_PIN_PORT`) and puts
  back any value they replaced, so a proxy you had set before comes back;
- points `oauthAccount` in the same file back at the account you are logged in
  as;
- drops the pin record from cswap's `settings.json`, unless that file is
  shared across machines (below).

It prints `Unpinned the cloud account` (or `No cloud account pinned`) and exits
0. When Claude Code is holding the config lock it says `re-run once it frees
up` and exits 1; run it again.

**A settings file shared across machines.** When `<data>/settings.json` is a
symlink (for example into a dotfiles repo that several machines link), the pin
record in it belongs to all of them, so `--clear` unpins THIS machine only. It
unwires `.claude.json`, leaves the shared record alone and writes
`<data>/pin-cleared`; the other machines keep their pin, and so does the shared
file you commit. `cswap pin <account>` removes `pin-cleared` and pins this
machine again. With no pin recorded there is nothing to keep, so `--clear`
writes no `pin-cleared` and a pin recorded later from another machine reaches
this one. `cswap pin --clear --everywhere` drops the shared record, for
every machine that links it. A `cswap pin <account>` that fails puts the shared
record, and this machine's `pin-cleared`, back as they were. This needs a claude-swap that has the matching
support; with an older one `--clear` drops the record from the shared file as
before.

What it does not undo:

- `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` are deleted from
  that `env` block whenever the pin wires it, and no copy is kept, because each
  of them replaces a trust store instead of adding to it. Set them again
  yourself if you had them.
- The proxy keeps running. A session that is already open had the pin's port
  fixed in its environment when it started, so it keeps going through the
  proxy, now unpinned, and stopping the proxy would cut it. So stop the proxy
  (below) once the last pinned session has closed.

**By hand, when `cswap` itself will not run.** `<data>` below is cswap's data
directory: `~/.local/share/claude-swap` on Linux (`$XDG_DATA_HOME/claude-swap`
when that is set), `~/.claude-swap-backup` on macOS.

1. Find the receipt for your config: `<data>/pin-wiring/<key>.json`, where
   `<key>` is the first 16 hex digits of the SHA-256 of the config's absolute
   path.

   ```bash
   printf %s "$HOME/.claude.json" | sha256sum | cut -c1-16    # macOS: shasum -a 256
   ```

2. In `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` if you use that),
   delete from `env` every key the receipt lists under `_cswapPinWiredKeys`,
   then add back every key and value under `_cswapPinWiredKeysSaved`. An older
   cswap-pin kept those two keys at the top level of `.claude.json` instead;
   if they are there, use them and then delete them.
3. Delete the receipt.
4. Only now, delete `pinnedEmail` and `pinnedOrganizationUuid` under
   `remoteControl` in `<data>/settings.json`. The order matters: while the
   wiring is still there, the next `cswap pin --ensure` rebuilds a missing
   record from it.
5. If `oauthAccount` in `.claude.json` still names the pinned account, switch
   to (or log in as) the account you want; that rewrites it.

**Stopping the proxy**, once no session started under the pin is still open
(each one would lose its connection):

```bash
pkill -HUP  -f 'cswap_pin.proxy --standby'     # the standby ignores TERM and INT
pkill -TERM -f 'cswap_pin.proxy --hold-port'   # the holder stops its daemon, then frees the port
pgrep -f cswap_pin.proxy                       # should print nothing
```

The standby goes first because a standby whose holder is gone puts a new holder
back on the port (see [When the holder and its daemon die
together](#when-the-holder-and-its-daemon-die-together)). A pid still listed
afterwards is a daemon running without a holder; `kill` it.

**Removing it completely.** `--clear` undoes the pin; these also remove what
you and the pin added around it:

1. Take out the `cswap pin --ensure` line (the rc `claude()` function, a
   launcher or `CLAUDE_CODE_PROCESS_WRAPPER` script), and the `~/.zshenv` block
   or `BASH_ENV` file from [Trust](#trust) if you added one.
2. Run `cswap pin --clear`. With `CLAUDE_CONFIG_DIR` set there are two
   configs, `~/.claude.json` and `$CLAUDE_CONFIG_DIR/.claude.json`, each with
   its own receipt; `--clear` clears both when `CLAUDE_CONFIG_DIR` is exported
   in its own environment, and only `~/.claude.json` from a shell without it.
3. Stop the proxy as above, once the last pinned session has closed.
4. Delete `ca-trust.d/cswap-pin.pem` under `~/.claude` (and under
   `$CLAUDE_CONFIG_DIR`) if it is there, and `<data>/pin-proxy/`. The pin's CA
   is a full CA (`CA:TRUE`, no name constraints) and its private key stays in
   `pin-proxy/ca.key` until you delete it.

**Back to upstream claude-swap.** Run `cswap pin --clear` first, while this
build is still installed: upstream has no `cswap pin` and nothing that removes
a wiring. Then reinstall from PyPI, naming the release you want:

```bash
uv tool install --force --python 3.12 claude-swap==<version>    # e.g. 0.26.0
```

## Prerequisites

- **macOS or Linux.** The pin needs POSIX file locks and FIFOs; on Windows
  `cswap pin` refuses.
- **Not root, unless inside a container.** As root outside one, `cswap pin`
  refuses to run, and `cswap pin --ensure` exits 0 having done nothing.
- **[uv](https://docs.astral.sh/uv/)**, and **git** for uv to fetch the host
  from GitHub. `pipx` should take the same arguments, but this was verified
  with `uv` only.
- **Python 3.12 or newer** for the tool. That is claude-swap's floor;
  `cswap-pin` on its own accepts 3.10, but it never runs on its own. uv can
  supply one (see [Install](#install)).
- **Claude Code, logged in with a claude.ai (OAuth) account that cswap
  manages**: `cswap list` has to show it. An API-key account cannot be pinned,
  because Remote Control and Artifacts need an OAuth bearer.
- **If you reach the internet through a proxy**: its URL, exported as
  `HTTPS_PROXY` in the shell where you run `cswap pin N`. See
  [Proxy chains](#proxy-chains).
- **If anything on that path re-signs TLS** (a local caching or inspecting
  proxy, a corporate TLS inspector): its CA certificate as a PEM file,
  exported as `NODE_EXTRA_CA_CERTS` in the same shell.

## Install

The pin is an optional extra of claude-swap, not a standalone tool: it reads
cswap's account store, rewrites the config cswap already manages, and the
`cswap pin` command itself lives in the host. Installing `cswap-pin` on its own
does nothing useful.

**The extra is not on PyPI.** `claude-swap` 0.26.0 publishes only the
`menubar` extra, so `uv tool install 'claude-swap[pin]'` installs a host with
no pin in it and exits 0 with a warning. Install the host from the fork that
carries the extra, at a fixed commit, with this package beside it:

```bash
uv tool install --force --python 3.12 \
  "claude-swap[pin] @ git+https://github.com/codeslake/claude-swap@85764e77dc63c02f35caffdf64ddcc5cc61ea0dd" \
  --with cswap-pin==0.1.311
```

```console
$ cswap --version
cswap 0.27.0b1
$ cswap pin
No cloud account pinned
```

- **A commit, not a branch.** The fork's `integration` branch is force-pushed,
  so a branch name installs whatever it points at that day. The commit above
  is tagged `pin-install-85764e7`, so it stays fetchable after `integration`
  is force-pushed; the URL keeps the full SHA because a tag can move. When you
  upgrade, change the commit and the `cswap-pin` version together; the pair
  above is the one this README was checked against, and the next verified
  pair is announced here.
- **`--python 3.12`**, because claude-swap needs 3.12 or newer and without the
  flag uv takes whichever interpreter it finds first. Under a narrowed `PATH`
  that was a 3.11, and the install failed. With the flag uv uses a 3.12 it
  finds, or downloads one (under `env -i` it downloaded 3.12.14 and the line
  above installed cleanly). Any 3.12+ works: `--python 3.13`, or a path to an
  interpreter.
- **Already have claude-swap as a uv tool?** If its interpreter is 3.12 or
  newer, reuse it, so whatever already runs `cswap` keeps the same runtime:

  ```bash
  grep -E '^(home|version_info)' "$(uv tool dir)/claude-swap/pyvenv.cfg"
  ```

  and pass `--python <home>/python3`.
- **`cryptography`** (for the pin's CA) is installed into the tool's own
  environment as a dependency of `cswap-pin`. A uv tool never uses the system
  Python or its packages, so there is nothing to install there.
- **`--force`** replaces an existing `claude-swap` tool, whatever it was
  installed from.

**Do not run a plain `uv tool install 'claude-swap[pin]'` over this**,
including the one `cswap pin` prints when it cannot import `cswap-pin`. With
`--force` it replaces the fork with PyPI's 0.26.0, which has no pin (measured:
`cswap 0.26.0`, and a warning that there is no extra named `pin`). Without
`--force` it keeps the installed fork but rewrites the tool's record of where
it came from to PyPI, so a later upgrade comes from there. `cswap upgrade` on
its own is safe: it runs `uv tool upgrade claude-swap`, which keeps the pinned
commit (measured: `Nothing to upgrade`).

**Do not run a plain `uv tool install claude-swap` over it either**, the line
a bootstrap script usually carries. Measured with uv 0.12.18 over the install
line above: it exits 0, keeps the fork's code (`cswap 0.27.0b1`), rewrites the
tool's record to PyPI's `claude-swap`, and uninstalls `cswap-pin` and
`cryptography` from the tool. The pin can then no longer respawn its daemon,
and the first `cswap pin --ensure` that finds the daemon dead removes the
wiring. Re-install only with the `git+...@<sha>` line, and make a bootstrap
script install claude-swap only when it is missing:

```sh
[ -d "$(uv --color never tool dir)/claude-swap" ] || uv tool install -q claude-swap
```

`--color never` because uv colours even piped output when `FORCE_COLOR` is set,
and Claude Code sessions export it; the path then carries escape codes and the
test never matches.

**On a machine running claude-swap from a checkout, keep it editable.** Any
`uv tool install --force` replaces the tool, extras included, so pointing one
at an editable install swaps your checkout out, and a line without the `pin`
extra also drops `cswap_pin` from the tool env. The daemon already running
survives (its code is in memory) but every successor it spawns dies with
`ModuleNotFoundError`, which is invisible until something tries to restart it:

```bash
uv tool install --force --python 3.12 --editable '.[pin]'     # from the checkout
```

### Upgrading a machine that is already serving

Nothing to do beyond the install line with the new commit and version; the
running daemon notices its own code changed and replaces itself, on the same
port, without dropping anything.
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

## Proxy chains

The pin is one more hop in front of whatever your machine already uses to
reach `api.anthropic.com`:

```
claude ──► pin (127.0.0.1:<port>) ──► first hop ──► next hop ──► api.anthropic.com
```

It learns the chain from the environment of the command that pins, `cswap pin
N` (and `cswap run`). Export these there:

- `HTTPS_PROXY` (or `https_proxy`): the **first** hop, as a URL. `http://`,
  `https://` and `http://user:password@host:port` all work.
- `NODE_EXTRA_CA_CERTS`: the CA certificate (a PEM file) of a hop that
  re-signs TLS.

What it learned goes into `upstream.json`, in the directory `cswap pin
--get_certdir` prints (the first successful pin creates it):

| key | holds | learned from |
| :-- | :-- | :-- |
| `proxy` | the first hop | `HTTPS_PROXY` / `https_proxy` when you pinned |
| `ca` | that hop's CA | `NODE_EXTRA_CA_CERTS` when you pinned |
| `next` | the hop behind the first one | the first hop's own `GET /health`, asked when you pin and again later by the running daemon. Only a loopback `http://` hop is asked, and only a JSON answer naming its `https_proxy` counts |

The daemon re-reads this file on every connection, so an edit takes effect
without a restart. The `ca` is merged with the pin's own CA into
`ca-bundle.pem`, and that bundle is the `NODE_EXTRA_CA_CERTS` the pin hands
Claude Code, so a session trusts both.

**An unset variable never clears the record.** `cswap pin` usually runs in a
plain shell that cannot see the proxy a launcher gives Claude Code, so a
missing `HTTPS_PROXY` keeps what an earlier pin recorded. To take a hop out,
edit `upstream.json` and set `proxy` (and `next`) to `""`.

Ports below are examples (8118 is privoxy's default):

| your chain | export before `cswap pin N` | `upstream.json` then holds | when a hop dies |
| :-- | :-- | :-- | :-- |
| none: direct to the internet | nothing (`unset HTTPS_PROXY https_proxy`) | an empty `proxy` | nothing to fall through; the pin dials direct |
| privoxy, or any plain forwarding proxy | `HTTPS_PROXY=http://127.0.0.1:8118` | `proxy`; no `next`, since privoxy answers `/health` with a 400 | `503` until it is back; set `CSWAP_PIN_ALLOW_DIRECT=1` only when direct internet works, to dial direct instead |
| a local TLS-intercepting proxy that dials out itself | `HTTPS_PROXY=http://127.0.0.1:<its port>` and `NODE_EXTRA_CA_CERTS=<its CA>` | `proxy`, `ca` | `503` until it is back; set `CSWAP_PIN_ALLOW_DIRECT=1` only when direct internet works, to dial direct instead |
| a local intercepting proxy that reports its upstream on `/health`, in front of privoxy | the same two, for the intercepting proxy: the first hop, not privoxy | `proxy`, `ca`, and `next` (privoxy) once the intercepting proxy's `/health` names it | falls through to privoxy; `503` only while both are down |
| any other TLS-intercepting hop: a corporate inspector, a remote proxy | `HTTPS_PROXY=<its URL>`, and `NODE_EXTRA_CA_CERTS=<its root CA>` unless your system trust store already has it | `proxy`, `ca`; no `next`, because only loopback hops are asked | `503` until it is back |

**`next` is learned only from the first hop's `/health`.** It is recorded
only when that hop's `GET /health` returns JSON naming its `https_proxy`. A
generic intercepting proxy has no such endpoint, so in front of privoxy it
leaves no `next`, and a dead first hop gives `503` instead of falling through.
Then set `next` in `upstream.json` by hand (e.g.
`"next": "http://127.0.0.1:8118"`); it survives re-pins, because a pin that
learns no `next` keeps the recorded one.

**A dead hop is never bypassed silently.** The pin tries `proxy`, then `next`,
for 2.5 s, then answers Claude Code `503 Service Unavailable` with
`Retry-After: 2`, and Claude Code retries. While any hop is recorded it does
not fall back to a direct dial: where only the proxy may reach the internet, a
direct dial fails, and on the network this was measured on it answered 403,
which Claude Code shows as "Please run /login". If a direct dial from your
machine does reach the internet, `CSWAP_PIN_ALLOW_DIRECT=1` in the daemon's
environment restores the direct fallback (see [The port](#the-port)). With no
hop recorded at all, direct is simply the route. [Falling through a dead
hop](#falling-through-a-dead-hop) says why `next` is asked while the first hop
still answers.

**A chain recorded outer-first is fixed by a re-pin.** If the first pin ran
from a shell exporting the outer egress proxy, `upstream.json` holds it as
`proxy` and the cache proxy in front of it is skipped. Re-pin with `cswap pin
N` from the shell that exports the inner cache proxy: when that hop reports
its own upstream as `https_proxy` on `GET /health`, and the recorded hop
answers that request with a 4xx, the pin re-records the chain inner first.
Only a re-pin, or a `cswap run`, from that shell does this; `--ensure` and
`heal` never re-stamp the record.

**Which certificates the pin itself checks.** Through a loopback hop the pin
does not verify `api.anthropic.com`'s certificate: it trusts the local hop, the
same way Claude Code trusts that hop's CA. Through a remote hop, or direct, it
verifies against the system trust store plus the `NODE_EXTRA_CA_CERTS` in its
own environment, which it inherits from whatever started it: `cswap pin N`,
`cswap run`, or `cswap pin --ensure`. So for a remote intercepting hop whose CA
is not in the system store, export `NODE_EXTRA_CA_CERTS` in all three places,
the launch hooks in [Launching `claude`](#launching-claude) included.

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

Log in with `claude`, add that account with `cswap add` (`cswap list` shows
the numbers), then, in a shell that exports your chain (see [Proxy
chains](#proxy-chains)):

```bash
cswap pin 2          # RC / artifacts / ultrareview → account 2
cswap pin            # show the current pin
cswap pin --state    # OK / NOT-OK / UNKNOWN on stdout, the detail on stderr, exit 0
cswap pin --clear    # remove it
```

The pinned account is re-read per request, so `cswap pin <other>` takes effect
under a live daemon — no session restart. The one thing a re-pin cannot move is
a Remote Control session that is **already open**: the server fixed its owner
when it was created, so reconnecting inside it is what mints a new one under
the new pin.

## Launching `claude`

`cswap pin N` writes the pin into `.claude.json`, which Claude Code applies at
startup, so every `claude` started afterwards goes through the pin with no
wrapper. What can go stale is the daemon behind that address: a crash, a
reboot, an upgrade that lost a dependency. `cswap pin --ensure` repairs it
before a launch. It restarts a dead daemon on the same port or, if it cannot,
removes the wiring so the session starts unpinned instead of dialling a port
nothing answers. It prints nothing, always exits 0, and does nothing when no
pin is set.

**The trigger is every `claude` launch**, in whatever every launch passes
through: a shell function for hand launches, and the script
`CLAUDE_CODE_PROCESS_WRAPPER` names, so the daemon and background sessions
Claude Code spawns itself are covered too. That is what the maintainers' own
hosts run.

**Run it in the background, never in front of the launch.** It returns in
about 70 ms when nothing is pinned (measured; that is interpreter start-up) and
is cheap on a healthy pin (a state read and one loopback connect). With a dead
daemon it can take tens of seconds: up to 10 s waiting for the spawn lock, up
to 10 s for a new daemon to come up, then up to three 1 s probes of the old
port before it unwires. A launch that starts before it finishes uses whatever
wiring was there; a daemon that comes back comes back on the same port, so
that session picks it up.

`cswap run N` needs none of this: it repairs the pin itself before it execs
Claude Code.

### Interactive shells

The same line works in `~/.zshrc` and in `~/.bashrc`:

```bash
claude() { (cswap pin --ensure >/dev/null 2>&1 &); command claude "$@"; }
```

The subshell keeps the background job out of your shell's job table, so there
are no `[1] Done` lines.

### Unattended launchers

A bot, a daemon, a systemd unit, a cron job or a `CLAUDE_CODE_PROCESS_WRAPPER`
script reads no rc file, so put the line in the launcher, before it execs
Claude Code:

```sh
#!/bin/sh
cswap pin --ensure >/dev/null 2>&1 &
exec "$@"        # or: exec claude ...
```

A daemon that `--ensure` starts inherits this launcher's environment. It needs
`cswap` on the launcher's `PATH` (`uv tool dir --bin` prints where uv put it)
and, if your chain needs them, the same `NODE_EXTRA_CA_CERTS` and
`CSWAP_PIN_ALLOW_DIRECT` you pin with.

**Not from a systemd service's `ExecStart`.** A daemon that `--ensure` starts
there joins that unit's cgroup, and with the default `KillMode=control-group`
it dies when the unit stops, freeing the port every pinned session is wired
to. Run the line from a launcher that is not a service's `ExecStart`, and
after the first pin check where the holder runs:

```bash
pgrep -f '[c]swap_pin.proxy --hold-port'    # the holder's pid
cat /proc/<pid>/cgroup                    # a last component ending in .service is that unit's
```

### A settings `env` overrides the pin

Claude Code applies the `env` block of `.claude.json` first and then the `env`
of every settings file on top of it: user, project, local and managed (read in
Claude Code 2.1.287). So an `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY` or
`NODE_EXTRA_CA_CERTS` in any `settings.json` replaces the pin's value, and
nothing says so: requests skip the pin, or the session stops trusting the
pin's CA and every pinned request fails TLS. Keep proxy and CA variables out of
settings files. Export them where you pin instead; the pin chains through the
proxy and merges the CA for you.

## What the pin writes

`<data>` is cswap's data directory (see [Before you
start](#before-you-start-and-if-it-breaks)); `cswap pin --get_certdir` prints
`<data>/pin-proxy`.

| where | what | after `cswap pin --clear` |
| :-- | :-- | :-- |
| `~/.claude.json` `env` (`$CLAUDE_CONFIG_DIR/.claude.json` when that is set) | sets `HTTPS_PROXY`, `https_proxy` and `ALL_PROXY` to the pin's loopback address, `NODE_EXTRA_CA_CERTS` to the pin's CA (or to `ca-bundle.pem` when a hop's CA is merged in) and `CSWAP_PIN_PORT` to its port; deletes `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` | the five removed and whatever they replaced restored; the three deleted stay deleted |
| `~/.claude.json` `oauthAccount` | the pinned account's identity, re-asserted by every `--ensure` | the account you are logged in as |
| `<data>/pin-wiring/<key>.json` | the receipt: `_cswapPinWiredKeys` (what was set), `_cswapPinWiredKeysSaved` (what that replaced), `writtenBy` | emptied |
| `<data>/settings.json`, `remoteControl` | `pinnedEmail`, `pinnedOrganizationUuid` (a `debugSlowMs` you add there is yours and is left alone) | the two pin keys dropped; when the file is a symlink (shared across machines) they are left alone unless you add `--everywhere` |
| `<data>/pin-cleared` | written only by a `--clear` on a symlinked `settings.json` that records a pin: this machine reads the shared record as "nothing pinned" while it exists. Needs the matching claude-swap | removed by `cswap pin <account>` and by `--clear --everywhere` |
| `<data>/pin-proxy/` | the CA and its keys, `ca-bundle.pem`, `upstream.json`, `proxy.json` (port and pid), `port.hint`, `settings.json` (from `--set_port`), `daemon.log`, locks and a FIFO | left in place |
| `~/.claude/ca-trust.d/cswap-pin.pem` (under `$CLAUDE_CONFIG_DIR` when that is set) | a copy of the pin's CA, for a launcher that builds one trust bundle from that directory. That is a launcher convention, not Claude Code's: with no such launcher nothing reads it | left in place |
| `~/.claude/jobs/<id>/state.json`, and a transcript's `bridge-session` record | the account in the bridge pointer of a session that is not running, restamped (see [Keeping a session's bridge when the account rotates](#keeping-a-sessions-bridge-when-the-account-rotates)) | not touched |

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

`CSWAP_PIN_ALLOW_DIRECT=1` restores the old fall-through to a DIRECT dial when
every configured hop is unusable. Off by default since 0.1.251: on the network
it was measured on, the direct route is a corporate TLS-inspecting proxy,
which answers 403 "Access restricted by network policy" to API and Remote
Control requests, and Claude Code renders that as "Please run /login" (measured
2026-09-07, 49 direct dials in 22 minutes, one fleet-wide login wave). That is
one network's behaviour: set the opt-in only when a direct dial from your
machine reaches the internet. Without
the opt-in the pin answers `503 Service Unavailable` with `Retry-After: 2` and
logs `egress REFUSED` once per outage; the client retries, nothing is asked to
log in. A host with no chain configured is unaffected and dials direct as
before. The daemon reads the opt-in from ITS OWN environment, fixed at exec,
so a running daemon never sees a later export: set it in the shell that starts
the next daemon (`export CSWAP_PIN_ALLOW_DIRECT=1; cswap pin --heal`).

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

It goes in the section `cswap pin <email>` already writes in cswap's own
`settings.json` (`~/.local/share/claude-swap/settings.json` on Linux,
`~/.claude-swap-backup/settings.json` on macOS), so there is no new path to
remember:

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

Counters land in `inference-follows.<pid>.json` beside it (one per daemon, so a
handover does not reset them; a dead daemon's file is pruned after a week) — `swapped`,
`retriedUnswapped`, `passthrough` by reason, `lastSwapAt`, `lastRetryAt` — and
`daemon.log` records the switch turning on or off, the first re-billed request
of each daemon, and refusals (at most one line per five minutes).

## Usage from inference replies (`ratelimits.json`)

Every `/v1/messages` reply carries the account's quota in
`anthropic-ratelimit-unified-{5h,7d}-{utilization,reset,status}` — the same
numbers `/api/oauth/usage` serves, without its `user:profile` scope or its own
~30 requests/hour budget. The proxy files the latest of those headers per
bearer in `ratelimits.json` in the pin's directory, keyed by the first 24 hex
characters of the bearer's sha256 (never the token), written by a background
thread every 5 seconds and merged newest-wins across daemons. Readings older
than 8 days are dropped. It is passive: no request is ever added.

The matching claude-swap fork reads it for setup-token slots (which cannot
call the usage endpoint at all) and as autoswitch's fallback when the active
account's usage endpoint is unreadable.

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

See [Prerequisites](#prerequisites). [`claude-swap`](https://github.com/realiti4/claude-swap)
is a peer, not a dependency: this package is loaded *by* it (see
`src/cswap_pin/_host.py` for the exact surface it borrows), which is why
`cswap-pin` itself declares Python 3.10+ while the pair needs 3.12+.
`cryptography` (installed automatically) is for the MITM CA.

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

**A remote proxy that intercepts TLS needs its CA.** When the pin chains
through a proxy, `cswap pin N` makes one CONNECT to `api.anthropic.com` through
it with the trust the daemon uses. If that proxy re-signs with a CA the pin was
never given, it prints a line starting `PINNED REQUESTS WILL FAIL` with the fix:
export the proxy's CA in `NODE_EXTRA_CA_CERTS` and re-run `cswap pin N`. The pin
is set either way, and the daemon already serving picks the CA up on its next
connection. A proxy that does not answer is reported, not fatal. A loopback
proxy's certificate is not checked, because the daemon does not verify the
origin through one.

**Replace-class CA variables are handed back.** `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` each replace a trust store, so the pin
never writes them and removes them from the `env` block of `.claude.json` while
it is wired. The values it removed are kept in the wiring receipt, and
`cswap pin --clear` puts them back.

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

**Every shell a session starts inherits the pin.** Claude Code applies the
`env` block of `.claude.json` to its own process, so every child it starts,
Bash-tool shells included, inherits `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`,
`NODE_EXTRA_CA_CERTS` and `CSWAP_PIN_PORT`. The child's HTTPS then goes through
the proxy, which re-signs only `api.anthropic.com` and tunnels every other host
untouched. The trust it hands the child is wider than that: the CA is a full CA
(`CA:TRUE`) with no name constraints, so a Node child reading
`NODE_EXTRA_CA_CERTS` accepts a certificate that CA signs for any host. A
settings file's `env` is applied after that block and wins over it; see [A
settings `env` overrides the pin](#a-settings-env-overrides-the-pin).

To take a session's Bash-tool shells off the pin, put this in `~/.zshenv`,
which zsh reads for every shell, the Bash tool's non-interactive `zsh -c`
included:

```bash
if [[ -n ${CLAUDECODE-} && ${HTTPS_PROXY-} == *[/@]127.0.0.1:${CSWAP_PIN_PORT-} ]]; then
  [[ ${all_proxy-} == *[/@]127.0.0.1:$CSWAP_PIN_PORT ]] && unset all_proxy
  unset HTTPS_PROXY https_proxy ALL_PROXY NODE_EXTRA_CA_CERTS
fi
```

It fires only in a Claude Code child whose proxy is this pin's own loopback
port, so a corporate `HTTPS_PROXY` in any other shell is left alone, and Claude
Code itself stays pinned, since the `unset` runs in the child only. A lowercase
`all_proxy` is the pin's only when a `cswap` launch pointed one you already had
at it, hence its own test. A child Claude Code starts without zsh, such as a
stdio MCP server, keeps all of it. The `unset` also removes what the pin was
carrying for the child: the upstream proxy the pin chains through and, when
`NODE_EXTRA_CA_CERTS` is a merged bundle, the CA merged into it. On a network
that needs its own proxy or CA, export your own `HTTPS_PROXY` and
`NODE_EXTRA_CA_CERTS` after the `unset`.

The lines themselves are valid bash too; what differs is where they go. Claude
Code runs a Bash-tool command as `<your shell> -c`, without `-l` once it has a
shell snapshot (read in 2.1.287), and a `bash -c` reads no startup file except
the one `$BASH_ENV` names. So with bash, save the lines to a file and export
`BASH_ENV` pointing at it in the environment you start `claude` from. Measured
for zsh only.

**Accept Claude Code's trust dialog in your home directory by hand.** Trust
accepted in your home directory does not persist (Claude Code keeps it per
session by design), so a process started there, such as Claude Code's
background daemon or a background session, evaluates Remote Control as an
anonymous user and `/remote-control` can disappear. Set
`projects["<your home directory>"].hasTrustDialogAccepted` to `true` in
`~/.claude.json` yourself. This is Claude Code's behaviour, not the pin's.

## License

MIT
