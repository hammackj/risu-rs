# Installation Guides

## Prerequisites
- Install Rust via [`rustup`](https://rustup.rs/).
- Ensure `~/.cargo/bin` is on your `PATH` so the `cargo` and `risu-rs` commands are available.

## Build from source
```bash
git clone https://github.com/example/risu-rs.git
cd risu-rs
cargo build --release
```

## Install locally
```bash
cargo install --path .
```
This places the compiled binary in `~/.cargo/bin/`.
