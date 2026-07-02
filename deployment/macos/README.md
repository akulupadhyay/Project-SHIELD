# macOS Deployment

Build this folder on macOS, not Windows.

Recommended artifacts:

```text
Secure Portable Vault.app
SecurePortableVault-macOS-aarch64-apple-darwin.dmg
SecurePortableVault-macOS-aarch64-apple-darwin.app.zip
```

From the repository root on a Mac:

```bash
./deployment/macos/build.sh
```

On Apple Silicon such as an M3 MacBook Air, the script builds `aarch64-apple-darwin`. On Intel macOS, it builds `x86_64-apple-darwin`.

End users do not need Rust, Cargo, Node, Vite, or internet access to run the packaged app. macOS provides the system webview runtime.

Unsigned/unnotarized builds may be blocked by Gatekeeper. For distribution outside your own machine, use Apple Developer ID signing and notarization.

The vault creates runtime files beside the `.app` bundle on first launch:

```text
vault-data/
signed-device-manifest.json
```
