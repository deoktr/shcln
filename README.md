# shcln

shcln is a shell history cleaner that removes passwords, tokens, and other
sensitive entries from your shell history. It aims to work on both workstations
and servers.

Supports bash and zsh history files.

## Why clean history automatically?

Anything typed at the prompt: passwords, API tokens, database URLs with
credentials, private keys pasted inline, bearer headers; ends up on disk,
readable by every program ran as the same user.

Shell history is a high-value target for supply chain attackers. Recent
incidents involving malicious npm, PyPI, and VS Code marketplace packages have
shipped payloads that exfiltrate developer credentials and local configuration,
including shell history.

Manual cleanup does not scale and is easy to forget.

Running `shcln` on a regular schedule, for example from a systemd user timer, a
cron job, or at shell startup, keeps the window of exposure short without
requiring you to remember to do it manually.

## Install

Pre-built binaries are published with each GitHub release.

Pick the target for your platform (the releases page lists all of them):

| Target                       | Platform             |
| ---------------------------- | -------------------- |
| `x86_64-unknown-linux-gnu`   | Linux x86_64, glibc  |
| `x86_64-unknown-linux-musl`  | Linux x86_64, static |
| `aarch64-unknown-linux-gnu`  | Linux ARM64, glibc   |
| `aarch64-unknown-linux-musl` | Linux ARM64, static  |
| `x86_64-apple-darwin`        | macOS Intel          |
| `aarch64-apple-darwin`       | macOS Apple silicon  |

The musl builds are statically linked, which makes them a good fit for servers
and minimal containers.

Download and install the binary:

```bash
# pick the target for your host
export TARGET="shcln-x86_64-unknown-linux-gnu"

curl -fsSL -O "https://github.com/deoktr/shcln/releases/latest/download/${TARGET}"
install -m 0755 "${TARGET}" ~/.local/bin/shcln
```

Make sure `~/.local/bin` is on your `PATH`, for example by appending this to
`~/.bashrc` or `~/.zshrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then check the install:

```bash
~/.local/bin/shcln --version
```

### Verify a release

Release binaries carry a
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation,
signed keyless via [Sigstore](https://www.sigstore.dev/) and recorded in
GitHub's attestation store. This proves the binary was built by this repo's CI
inside GitHub Actions, and ties it to the exact commit and workflow.

After downloading a binary, verify it with the GitHub CLI:

```bash
gh attestation verify "${TARGET}" --owner deoktr
```

A successful check prints `Verification succeeded` and confirms the artifact was
built by the `deoktr/shcln` GitHub Actions workflow.

### From source

Build and install with Cargo:

```bash
cargo install --git https://github.com/deoktr/shcln --locked
```

## Usage

Preview which entries would be removed, without touching the history files:

```bash
shcln --dry-run
```

Clean the history files:

```bash
shcln
```

Removed entries are counted, not printed, so a run scheduled by systemd or cron
does not copy the secrets it removes into the journal. Pass `--print-removed`
when running interactively to see the matched text and the rule that matched it.

A history file with nothing to remove is left untouched: it is not rewritten and
its modification time does not change.

### Run on a schedule with systemd

Create a user service at `~/.config/systemd/user/shcln.service`:

```ini
[Unit]
Description=Clean shell history with shcln

[Service]
Type=oneshot
ExecStart=%h/.local/bin/shcln
```

Then a matching timer at `~/.config/systemd/user/shcln.timer`:

```ini
[Unit]
Description=Run shcln hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now shcln.timer
```

### Run on a schedule with cron

Edit your user crontab with `crontab -e` and add:

```cron
# clean shell history every hour
0 * * * * $HOME/.local/bin/shcln >/dev/null
```

### Run at shell startup

For bash, append to `~/.bashrc`:

```bash
# clean the history left by previous sessions, in the background
command -v shcln >/dev/null 2>&1 && ( shcln >/dev/null 2>&1 & )
```

For zsh, append to `~/.zshrc`:

```bash
# clean the history left by previous sessions, in the background
command -v shcln >/dev/null 2>&1 && ( shcln >/dev/null 2>&1 & )
```

The startup hook runs on every new shell. That is usually what you want, but on
a machine where shells are opened in bursts, a timer avoids the extra runs.

## Prevention

Cleaning removes secrets after the fact. Not recording them in the first place
is cheaper.

For bash, in `~/.bashrc`:

```bash
# a command starting with a space is not saved
HISTCONTROL=ignorespace

# also drop commands that look like they carry a secret
HISTIGNORE='*password=*:*token=*:*secret=*:*api_key=*'
```

For zsh, in `~/.zshrc`:

```zsh
# a command starting with a space is not saved
setopt HIST_IGNORE_SPACE

# also drop commands that look like they carry a secret
HISTORY_IGNORE='(*password=*|*token=*|*secret=*|*api_key=*)'
```

## Alternatives

- [shellclear](https://github.com/rusty-ferris-club/shellclear)

## TODO

- Add end-to-end tests with output verification to ensure all secrets are
  removed
- Output hashed secrets to be able to compare to a database, in order to revoke 
  them if needed, must first ensure the actual secret is correctly selected in 
  regex

## License

shcln is licensed under the [MIT license](./LICENSE).
