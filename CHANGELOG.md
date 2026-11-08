# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

## [0.7.1] - 2026-11-08

### Added

- Add new patterns

## [0.7.0] - 2026-10-24

### Added

- Add `--dry-run` flag, printing what would be removed without modifying anything on disk
- Add `--print-removed` flag to print removed entries while writing to disk

### Changed

- Update to leave a history file with nothing to remove completely untouched, no write and no mtime change

### Removed

- Remove `--keep-tmp` flag, the temporary backup file is now always deleted after cleaning

### Fixed

- Fix a bug where non-UTF-8 lines where deleted in bash history
- Changed history replacement to be atomic
- Fix a bug where a run killed hard enough to skip its cleanup (`SIGKILL`, `SIGTERM`, power cut) left its temporary file behind, the next run now sweeps temporary files older than a minute

## [0.6.4] - 2026-10-20

### Changed

- Refactor release CI to make it cleaner

## [0.6.3] - 2026-10-19

### Changed

- Pin CI actions to specific commits
- Release CI for ARM run on `ubuntu-26.04-arm`

### Fixed

- Concurrency issue in release CI

## [0.6.2] - 2026-10-19

### Added

- Add SLSA build provenance attestation for releases

## [0.6.1] - 2026-10-18

### Added

- Add musl builds for Linux targets to the release CI
- Build release binaries with `cargo auditable` so they embed their dependency tree and can be scanned for known vulnerabilities

## [0.6.0] - 2026-10-18

### Changed

- Refactor source
- Upgrade dependencies
- Update the release CI
