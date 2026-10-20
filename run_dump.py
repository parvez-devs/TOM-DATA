#!/usr/bin/env python3
"""Run the existing TOM script without changing its banner, menu or dump functions."""
import argparse
import os
import runpy
from getpass import getpass
from pathlib import Path

from hub_client import HubClient, HubError, HubRestricted, login_from_hub


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("script", nargs="?", default="newd.py")
    parser.add_argument("--clear-local-pause", action="store_true")
    args = parser.parse_args()
    url = os.environ.get("HUB_URL") or input("Hub HTTPS URL: ").strip()
    token = os.environ.get("HUB_CLIENT_TOKEN") or getpass("Hub client token (hidden): ").strip()
    hub = HubClient(url, token)
    if args.clear_local_pause:
        hub.clear_local_pause()
        print("Local pause cleared after hub review.")
        return
    path = Path(args.script)
    if not path.is_file():
        raise HubError("Place your existing full TOM script at the supplied path")
    namespace = runpy.run_path(str(path), run_name="tom_dump_module")
    account_class, menu = namespace.get("auth"), namespace.get("menu")
    if not isinstance(account_class, type) or not callable(menu):
        raise HubError("Script must expose its existing auth class and menu function")
    account_class.check = lambda self: login_from_hub(self, hub)
    # Prevent a legacy menu from bypassing the vault through auth.login.
    account_class.login = account_class.check
    menu()


if __name__ == "__main__":
    try:
        main()
    except (HubError, HubRestricted) as exc:
        print(f"  [!] {exc}")
        raise SystemExit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nStopped.")
