# Contributing to risu-rs

Thank you for your interest in contributing to **risu-rs**!
This document outlines the process for setting up your environment and submitting patches.

## Prerequisites

- Install the latest [Rust toolchain](https://www.rust-lang.org/tools/install).
- Ensure `cargo`, `rustfmt`, and `clippy` are available in your `PATH`.

## Building

Use Cargo, Rust's package manager, to build the project:

```bash
cargo build
```

## Testing

Run the test suite before submitting changes:

```bash
cargo test
```

Some tests require database backends. See the `README.md` for details on configuring `DATABASE_URL`.

## Linting and formatting

Format and lint code prior to committing:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

## Submitting changes

1. Fork the repository and create your branch from `main`.
2. Make your changes with clear, descriptive commit messages.
3. Ensure all tests pass and code is formatted.
4. Open a Pull Request describing your changes and referencing any relevant issues.

Thanks again for contributing!
