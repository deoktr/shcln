# shcln

Shell history cleaner (shcln), remove password and other sensitive entries from shell history.

This project aims to work on both workstations and servers.

Supports bash, and zsh history files.

## Install

Installation:

```bash
curl -fsSL https://github.com/deoktr/shcln/releases/latest/download/install.sh | sh
```

## Usage

Run keeping a back-up of the original history file in case you want to roll-back:

```bash
shcln --keep-tmp
```

## Alternatives

- [shellclear](https://github.com/rusty-ferris-club/shellclear)

## TODO

- Support for other shells: fish, nushell, tcsh, ksh
- Package with Nix
- Update README.md to explain why it's important to clean history automatically
- Add end-to-end tests with output verification to ensure all secrets are removed

## License

shcln is licensed under [MIT](./LICENSE).
