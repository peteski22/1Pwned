"""Handles all interactions with the 1Password (op) CLI.

This module provides a generator to stream `LoginItem` objects
fetched from the `op` command-line tool.
"""

import json
import subprocess
import sys
from collections.abc import Generator
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LoginItem:
    """An immutable, declarative data structure for a 1Password Login.

    Attributes:
        id: The 1Password item UUID.
        title: The title of the login item.
        username: The username, if one is present.
        password: The password. This will not be None, as items without passwords are not yielded.
        url: The primary URL, if one is set.
    """

    id: str
    title: str
    username: str | None
    password: str
    url: str | None


def _run_op(cmd: list[str]) -> str:
    """Internal wrapper for running `op` (1password CLI) commands and handling errors.

    Args:
        cmd: A list of string arguments for the `subprocess.run` call,
            e.g., ["op", "item", "list"].

    Returns:
        The UTF-8 decoded string from the command's stdout.

    Raises:
        subprocess.CalledProcessError: If the `op` command returns a non-zero exit code.
        This is caught and re-raised to be handled by the caller.
    """
    try:
        p = subprocess.run(cmd, check=True, capture_output=True)
        return p.stdout.decode("utf-8")
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if e.stderr else str(e)
        print(f"Error running `op` command {' '.join(cmd)}: {stderr}", file=sys.stderr)
        raise  # Re-raise the exception to be handled by the caller


def _parse_login_item(item_json: dict[str, Any]) -> LoginItem | None:
    """Parses the raw JSON dictionary from `op item get` into a LoginItem.

    This function attempts to find the password, username, and primary URL
    from the item's field and URL lists.

    Args:
        item_json: The dictionary parsed from the `op item get ...` JSON
            output.

    Returns:
        A populated `LoginItem` object if a password is found, or `None`
        if no password field exists (as it cannot be checked).
    """
    try:
        item_id = item_json["id"]
        title = item_json.get("title", "unknown-title")

        fields = item_json.get("fields", [])

        # Declarative way to find the first matching field
        password = next((f.get("value") for f in fields if f.get("id") == "password"), None)

        # We can't check an item with no password, so return None
        if not password:
            print(f"[WARN] {title} ({item_id}): No password field found.", file=sys.stderr)
            return None

        username = next((f.get("value") for f in fields if f.get("id") == "username"), None)
        if not username:
            print(f"[WARN] {title} ({item_id}): No username field found.", file=sys.stderr)

        urls = item_json.get("urls", [])
        primary_url = next((u.get("href") for u in urls if u.get("primary")), None)

        return LoginItem(
            id=item_id,
            title=title,
            username=username,
            password=password,
            url=primary_url,
        )
    except (KeyError, TypeError) as e:
        print(f"Error parsing item JSON for item ID {item_json.get('id')}: {e}", file=sys.stderr)
        return None


def stream_login_items() -> Generator[LoginItem, None, None]:
    """Streams all Login items from 1Password, fetching details for each.

    This first lists all item summaries, then gets the full JSON for
    each item one by one, parsing and yielding it.

    This is memory-efficient as it doesn't load all full items at once.

    Yields:
        LoginItem: A `LoginItem` object for each item that has a password.

    Raises:
        subprocess.CalledProcessError: If the initial `op item list`
            command fails.
        json.JSONDecodeError: If the `op item list` output is not valid JSON.
    """
    print("Fetching list of Login items from 1Password...")
    list_out = _run_op(["op", "item", "list", "--categories", "Login", "--format", "json"])
    item_summaries = json.loads(list_out)

    total = len(item_summaries)
    if total == 0:
        print("No Login items found.")
        return

    print(f"Found {total} Login items. Fetching details...")

    for i, summary in enumerate(item_summaries, start=1):
        item_id = summary.get("id")
        if not item_id:
            print(f"[WARN] Skipping item {i}/{total}: No ID in summary.", file=sys.stderr)
            continue

        # This print to stderr will be overwritten by `print_compromised`
        # print(f"Checking item {i}/{total} ({summary.get('title', '...')})...", end="\r", file=sys.stderr)
        # sys.stderr.flush()

        try:
            detail_out = _run_op(["op", "item", "get", item_id, "--format", "json"])
            item_json = json.loads(detail_out)

            login_item = _parse_login_item(item_json)

            if login_item:
                yield login_item

        except subprocess.CalledProcessError:
            print(f"\n[WARN] Skipping item {item_id}: Error fetching item JSON.", file=sys.stderr)
            continue
        except json.JSONDecodeError:
            print(f"\n[WARN] Skipping item {item_id}: Error decoding item JSON.", file=sys.stderr)
            continue

    print("\nDone fetching all item details.", file=sys.stderr)
