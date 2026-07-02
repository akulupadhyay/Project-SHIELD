# Windows Portable Folder

Run `SecurePortableVault-Windows.exe` from this folder.

For fully offline systems that do not already have Microsoft WebView2 installed, this folder must also contain:

```text
WebView2FixedRuntime/
```

Build that folder from the repository root with:

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File .\deployment\build-windows.ps1 -FixedRuntimePath "C:\Path\To\Extracted\Microsoft.WebView2.FixedVersionRuntime"
```

Runtime vault files are created beside the EXE:

```text
vault-data/
signed-device-manifest.json
```

Do not pre-seed another user's vault-data into this folder unless you intentionally want to move that exact vault state.
