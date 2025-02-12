# shcln

Shell history cleaner, remove password and other sensitive entries from shell history.

This project aims to work on both workstations and servers.

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

- Configure matches, add match list (to remove) and exclude list (to keep)
- Add a dry run mode
- Generate a report with stats
- Support for zsh, it's history is encoded in metafield format: <https://www.zsh.org/mla/users/2011/msg00154.html>
- Clean and remove temp file on error
- Option to prompt the user for deletes
- Option to replace the secret with "X" instead of deleting the line
- Support for other shells: zsh, nushell, tcsh, ksh
- Log only the hash of the secret to be able to compare it to a list and revoke it if needed

## License

shcleaner is licensed under [MIT](./LICENSE).
