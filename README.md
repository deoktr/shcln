# shcln

Shell history cleaner (shcln), remove password and other sensitive entries from shell history.

This project aims to work on both workstations and servers.

Supports bash, and zsh history files.

## Usage

Build:

```bash
cargo build --release
```

Run:

```bash
./target/release/shcln
```

## Alternatives

- [shellclear](https://github.com/rusty-ferris-club/shellclear)

## TODO

- Support for other shells: fish, nushell, tcsh, ksh
- Add CI to release
- Package with Nix
- Update README.md to include installation
- Update README.md to explain why it's important to clean history automatically
- Add end-to-end tests with output verification to ensure all secrets are removed

## License

shcln is licensed under [MIT](./LICENSE).
