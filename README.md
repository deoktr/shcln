# shcln

Shell history cleaner, remove password and other sensible command arguments from shell history.

Features:

- Low memory usage with buffered I/O streams.

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

- Keep same owner and permissions on history file
- Create a CLI
- Configure file locations
- Configure matches, add match list (to remove) and exclude list (to keep)
- Add a dry run mode
- Generate a report with stats
- Support for zsh
- Clean and remove temp file on error
- Option to prompt the user for deletes
- Remove old commands, either with date (if available) or with size
- Error messages
- Option to replace the secret with "X" instead of deleting the line
- Support for other shells: zsh, nushell, tcsh, ksh
- Log only the hash of the secret to be able to compare it to a list and revoke it if needed
- Windows and powershell compatible

## License

shcleaner is licensed under [MIT](./LICENSE).
