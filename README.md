# shcln

Shell history cleaner (shcln), remove password and other sensitive entries from shell history.

This project aims to work on both workstations and servers.

Supports bash, and zsh history files.

## Install

Installation from CI pre-build releases.

First select the target based on your host, check releases for full list:

```bash
# Linux x86_64
export TARGET="shcln-x86_64-unknown-linux-gnu"
# macOS AArch64
export TARGET="shcln-aarch64-apple-darwin"
```

Download and install:

```bash
# download and verify
curl -fsSL -O https://github.com/deoktr/shcln/releases/latest/download/${TARGET}.tar.gz
curl -fsSL -O https://github.com/deoktr/shcln/releases/latest/download/${TARGET}.sha256
sha256sum -c "${TARGET}.sha256"

# install
tar -xzf "${TARGET}.tar.gz"
chmod 755 shcln
mv shcln ~/.local/bin/shcln

# clean
rm shcln "${TARGET}.sha256" "${TARGET}.tar.gz"

# verify install
shcln --version
```

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

## Alternatives

- [shellclear](https://github.com/rusty-ferris-club/shellclear)

## TODO

- Update README.md to explain why it's important to clean history automatically
- Add end-to-end tests with output verification to ensure all secrets are removed

## License

shcln is licensed under [MIT](./LICENSE).
