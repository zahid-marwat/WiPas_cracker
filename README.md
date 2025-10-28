# WiPas Desktop Scanner

WiPas Desktop Scanner is a lightweight Windows GUI that shells out to `netsh` to list nearby Wi-Fi networks. Click **Scan Wi-Fi Networks** to refresh the list, then click any entry to view detailed information (signal strength, authentication, encryption, and BSSIDs).

## Requirements

- Windows 10 or later (because it relies on `netsh`)
- Python 3.8+ available on your `PATH` (`python` or `py` command)

## Project Layout

- `wifi_scanner.py` – Tkinter application that parses `netsh wlan show networks` output.
- `start.bat` – Launch script that finds Python, runs the GUI, and keeps the project self-contained.
- `vendor_defaults.json` – Mapping of vendor OUIs (first three bytes of a BSSID) to lists of candidate default passwords.
- `.gitignore` – Ignores Python caches, virtual environments, and editor settings.
- `todo.md` – Task list used while iterating on the project.

## Running the App

From a PowerShell (or Command Prompt) window in the project directory run:

```powershell
./start.bat
```

The script finds `python`/`py`, launches `wifi_scanner.py`, and opens the GUI. If the script reports that Python is missing, install it from [python.org](https://www.python.org/downloads/) or add your Python installation to `PATH`.

## Notes

- The scan results are based on the current `netsh` output; the command may require Wi-Fi to be enabled.
- Some SSIDs may appear as `<Hidden SSID>` when the network is broadcast without a name.
- `netsh` can take a couple of seconds to respond; the app disables the scan button until results arrive.
- When you select a network, the app looks up vendor-specific default passwords from `vendor_defaults.json`, reads the stored Wi-Fi credential (via `netsh wlan show profile ... key=clear`), and reports if any default matches.
- Reading stored Wi-Fi keys requires the profile to exist on your machine and usually administrator privileges. If the key cannot be read, the status bar explains why.
- Customize `vendor_defaults.json` with additional OUIs and password guesses as needed. Use uppercase hex pairs separated by colons (e.g., `AA:BB:CC`).
