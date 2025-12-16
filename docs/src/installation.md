# Installation

### Homebrew (macOS)

```bash
brew tap edneedham/cred
```

```bash
brew install edneedham/cred/cred
```

### Quick install (shell)

```bash
curl -fsSL https://raw.githubusercontent.com/edneedham/cred/main/scripts/install.sh | sh -s
```

### Install with Cargo:

```bash
cargo install cred
```

### Pre-built binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/edneedham/cred/releases).

Available binary targets:

-   `cred-vX.Y.Z-aarch64-apple-darwin` - macOS Apple Silicon
-   `cred-vX.Y.Z-x86_64-apple-darwin` - macOS Intel
-   `cred-vX.Y.Z-x86_64-unknown-linux-gnu` - Linux x86_64
-   `cred-vX.Y.Z-x86_64-pc-windows-msvc.exe` - Windows

Make the binary executable and move it to your PATH:

```bash
chmod +x cred-*
sudo mv cred-* /usr/local/bin/cred
```

Check installation:

```bash
cred --version
```