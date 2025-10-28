import json
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox
from typing import Any, Dict, List, Optional


class WifiScannerApp:
    """Simple Windows Wi-Fi scanner GUI using `netsh` output."""

    DEFAULTS_FILE = "vendor_defaults.json"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("WiPas Desktop Scanner")
        self.root.geometry("520x400")

        self.status_var = tk.StringVar(value="Press scan to discover nearby Wi-Fi networks.")

        self.scan_button = tk.Button(root, text="Scan Wi-Fi Networks", command=self.start_scan)
        self.scan_button.pack(fill=tk.X, padx=12, pady=(12, 6))

        self.status_label = tk.Label(root, textvariable=self.status_var, anchor="w", justify=tk.LEFT)
        self.status_label.pack(fill=tk.X, padx=12)

        self.listbox = tk.Listbox(root, height=15)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=12, pady=(6, 12))
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        self.network_details: List[Dict[str, Any]] = []  # parsed network dictionaries aligned with listbox indices
        self.vendor_defaults = self._load_vendor_defaults()

    def start_scan(self) -> None:
        """Kick off a background scan triggered by the Scan button."""
        self.scan_button.config(state=tk.DISABLED)
        self.status_var.set("Scanning for networks...")
        self.listbox.delete(0, tk.END)
        self.network_details.clear()
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self) -> None:
        try:
            process = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8",
                errors="ignore",
            )
            networks = self._parse_netsh_output(process.stdout)
            self.root.after(0, self._populate_results, networks)
        except FileNotFoundError:
            self.root.after(0, self._handle_error, "`netsh` command not found. This tool only works on Windows.")
        except subprocess.CalledProcessError as exc:
            self.root.after(0, self._handle_error, f"Failed to run scan (exit code {exc.returncode}).")

    def _handle_error(self, message: str) -> None:
        self.status_var.set(message)
        self.scan_button.config(state=tk.NORMAL)

    def _populate_results(self, networks: List[Dict[str, Any]]) -> None:
        if not networks:
            self.status_var.set("No Wi-Fi networks found. Try scanning again.")
        else:
            self.status_var.set("Tap a network to view details.")

        self.network_details = networks
        for entry in networks:
            ssid = entry.get("ssid", "<Hidden SSID>")
            auth = entry.get("authentication", "Unknown")
            signal = entry.get("signal", "?")
            self.listbox.insert(tk.END, f"{ssid} ({auth})  Signal: {signal}")

        self.scan_button.config(state=tk.NORMAL)

    def _parse_netsh_output(self, output: str) -> List[Dict[str, Any]]:
        networks: List[Dict[str, Any]] = []
        current: Optional[Dict[str, Any]] = None

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("SSID "):
                if current:
                    networks.append(current)
                parts = line.split(":", 1)
                ssid_value = parts[1].strip() if len(parts) > 1 else ""
                current = {"ssid": ssid_value or "<Hidden SSID>"}
            elif current is not None:
                if line.lower().startswith("authentication"):
                    current["authentication"] = line.split(":", 1)[1].strip()
                elif line.lower().startswith("signal"):
                    current["signal"] = line.split(":", 1)[1].strip()
                elif line.lower().startswith("encryption"):
                    current["encryption"] = line.split(":", 1)[1].strip()
                elif line.lower().startswith("bssid "):
                    current.setdefault("bssids", []).append(line.split(":", 1)[1].strip())

        if current:
            networks.append(current)

        return networks

    def on_select(self, event: tk.Event) -> None:
        selection = event.widget.curselection()
        if not selection:
            return
        index = selection[0]
        if index >= len(self.network_details):
            return

        details = self.network_details[index]
        ssid = details.get("ssid", "<Hidden SSID>")
        auth = details.get("authentication", "Unknown")
        encryption = details.get("encryption", "Unknown")
        bssids = "\n".join(details.get("bssids", [])) or "N/A"
        signal = details.get("signal", "?")

        message = (
            f"SSID: {ssid}\n"
            f"Authentication: {auth}\n"
            f"Encryption: {encryption}\n"
            f"Signal: {signal}\n"
            f"BSSIDs:\n{bssids}"
        )
        messagebox.showinfo("Network details", message)

        if not self.vendor_defaults:
            self.status_var.set("No vendor defaults configured; edit vendor_defaults.json to add entries.")
            return

        self.status_var.set(f"Checking default passwords for {ssid}...")
        threading.Thread(target=self._check_vendor_defaults, args=(ssid, details), daemon=True).start()

    def _load_vendor_defaults(self) -> Dict[str, List[str]]:
        defaults_path = Path(self.DEFAULTS_FILE)
        if not defaults_path.exists():
            sample = {
                "00:11:22": ["admin", "admin123"],
                "BC:5F:F4": ["password", "12345678"],
                "DEFAULT": ["admin", "password", "12345678"]
            }
            defaults_path.write_text(json.dumps(sample, indent=4), encoding="utf-8")
            return sample

        try:
            data = json.loads(defaults_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            messagebox.showwarning("Config error", f"Failed to parse {defaults_path.name}: {exc}")
            return {}

        sanitized: Dict[str, List[str]] = {}
        for key, value in data.items():
            if not isinstance(value, list):
                continue
            sanitized[key.upper()] = [str(item) for item in value]
        return sanitized

    def _check_vendor_defaults(self, ssid: str, details: Dict[str, Any]) -> None:
        candidates: List[str] = []
        prefixes = self._extract_vendor_prefixes(details)
        for prefix in prefixes:
            candidates.extend(self.vendor_defaults.get(prefix, []))

        if not candidates:
            candidates.extend(self.vendor_defaults.get("DEFAULT", []))

        if not candidates:
            self.root.after(0, lambda: self.status_var.set("No default passwords configured for this network."))
            return

        stored_password = self._get_saved_password(ssid)
        if stored_password is None:
            self.root.after(0, lambda: self.status_var.set("Stored Wi-Fi password unavailable. Run as admin and ensure the network profile exists."))
            return

        for password in candidates:
            if stored_password == password:
                self.root.after(0, lambda pwd=password: self._report_match(ssid, pwd))
                return

        self.root.after(0, lambda: self.status_var.set("No vendor defaults matched the stored password."))

    def _extract_vendor_prefixes(self, details: Dict[str, Any]) -> List[str]:
        prefixes: List[str] = []
        bssids = details.get("bssids", [])
        for bssid in bssids:
            normalized = bssid.upper().replace("-", ":")
            parts = normalized.split(":")
            if len(parts) >= 3:
                prefixes.append(":".join(parts[:3]))
        return prefixes

    def _get_saved_password(self, ssid: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "profile", f'name="{ssid}"', "key=clear"],
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8",
                errors="ignore",
            )
        except subprocess.CalledProcessError:
            return None

        for raw_line in result.stdout.splitlines():
            if "Key Content" in raw_line:
                parts = raw_line.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
        return None

    def _report_match(self, ssid: str, password: str) -> None:
        self.status_var.set(f"Match found for {ssid}: {password}")
        messagebox.showinfo("Password match", f"Matched default password for {ssid}:\n{password}")


def main() -> None:
    if sys.platform != "win32":
        print("This tool only runs on Windows.", file=sys.stderr)
        return

    root = tk.Tk()
    app = WifiScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
