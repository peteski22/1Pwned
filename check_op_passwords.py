#!/usr/bin/env python3
"""Stream-check 1Password Login items against HaveIBeenPwned pwned-passwords.

This script composes functionality from:
- op_client: Handles all 1Password CLI interaction.
- hibp_checker: Handles all HIBP API interaction.
"""

import json
import logging
import subprocess
import sys
import time

from hibp_checker import (
    HIBPError,
    HIBPRateLimitError,
    check_pwned_hash,
    hash_password,
)
from op_client import LoginItem, stream_login_items

SLEEP_BETWEEN = 0.1  # seconds between HIBP API calls

logger = logging.getLogger(__name__)  # Get a logger for this module


def print_compromised(item: LoginItem, count: int):
    """Prints a compromised password notification to STDOUT.

    This remains a `print` function because it is the script's primary
    data output, not a log message.
    """
    # Clear the stderr progress line written by the logger
    print(" " * 80, end="\r", file=sys.stderr)

    # Print to stdout
    print(f"[PWNED] {count:>6} | {item.id} | {item.title} | {item.username} | {item.url}")
    sys.stdout.flush()


def main():
    """Main orchestration function.

    Connects the stream of login items to the pwned password checker and prints pwned results.
    """
    # Configure logging to go to stderr
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )

    pwned_count = 0
    checked_count = 0

    try:
        for item in stream_login_items():
            checked_count += 1
            try:
                hashed_pass = hash_password(item.password)
                count = check_pwned_hash(hashed_pass)

                if count > 0:
                    print_compromised(item, count)
                    pwned_count += 1

            except HIBPRateLimitError as e:
                logger.error(f"Rate limited by HIBP. Aborting. {e}")
                break  # Stop processing
            except HIBPError as e:
                logger.error(f"HIBP Check failed for {item.title}: {e}")
                # Continue to the next item
            except Exception as e:
                logger.error(f"Unexpected error checking {item.title}: {e}")

            # Be a good citizen to the HIBP API
            time.sleep(SLEEP_BETWEEN)

    except subprocess.CalledProcessError:
        logger.critical("Error running `op`. Make sure you're signed in.")
        sys.exit(2)
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.critical(f"Failed to decode JSON from 1Password: {e}")
        sys.exit(3)

    logger.info(f"Check complete. Checked {checked_count} items. Found {pwned_count} compromised passwords.")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
