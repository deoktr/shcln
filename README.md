# shcln

Shell history cleaner (shcln), removes passwords, tokens, and other sensitive entries from shell history.

This project aims to work on both workstations and servers.

Supports bash, and zsh history files.

## Why clean history automatically?

Anything typed at the prompt, like passwords, API tokens, database URLs with credentials, private keys pasted inline, bearer headers; ends up on disk, readable by any other program.

Shell history is a high-value target for supply chain attackers, recent incidents involving malicious npm, PyPI, and VS Code marketplace packages have included payloads that exfiltrate it to attacker-controlled servers.

Manual cleanup does not scale and is easy to forget.

Running `shcln` on a regular schedule, for example from a systemd user timer, a cron job, or a shell logout hook, keeps the window of exposure short without requiring you to remember to do it manually.

## Install

Installation from CI pre-built releases.

First select the target based on your host, check releases for the full list:

```bash
# Linux x86_64
export TARGET="shcln-x86_64-unknown-linux-gnu"
# macOS AArch64
export TARGET="shcln-aarch64-apple-darwin"
```

Download and install:

```bash
# download the binary
curl -fsSL -O "https://github.com/deoktr/shcln/releases/latest/download/${TARGET}"

# install for your user
chmod 755 "${TARGET}"
mv "${TARGET}" ~/.local/bin/shcln

# test install
shcln --version
```

### Verify a release

Release binaries carry a [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation, signed keyless via [Sigstore](https://www.sigstore.dev/) and recorded in GitHub's attestation store. This proves the binary was built by this repo's CI inside GitHub Actions, and matches it to the exact build.

After downloading a binary, verify it with the GitHub CLI:

```bash
gh attestation verify "${TARGET}" --owner deoktr
```

A successful check prints `Verification succeeded` and confirms the artifact was built by the `deoktr/shcln` GitHub Actions workflow.

### From Source

Installation from source:

```bash
cargo install --git https://github.com/deoktr/shcln
```

## Usage

Run keeping a back-up of the original history file in case you want to roll-back:

```bash
shcln --keep-tmp
```

### Run on a schedule with systemd

Create a user service at `~/.config/systemd/user/shcln.service`:

```ini
[Unit]
Description=Clean shell history with shcln

[Service]
Type=oneshot
ExecStart=%h/.local/bin/shcln
```

And a matching timer at `~/.config/systemd/user/shcln.timer`:

```ini
[Unit]
Description=Run shcln hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

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
0 * * * * $HOME/.local/bin/shcln >/dev/null 2>&1
```

### Run on shell logout

For bash, append to `~/.bash_logout`:

```bash
command -v shcln >/dev/null 2>&1 && shcln >/dev/null 2>&1
```

For zsh, append to `~/.zlogout`:

```bash
command -v shcln >/dev/null 2>&1 && shcln >/dev/null 2>&1
```

## Alternatives

- [shellclear](https://github.com/rusty-ferris-club/shellclear)

## TODO

- Add end-to-end tests with output verification to ensure all secrets are removed

## License

shcln is licensed under [MIT](./LICENSE).
