#!/usr/bin/env python3
"""Create or replace a SentinelUEBA API user."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from src.auth import create_user
from src.service_config import ServiceSettings
from src.storage import connect_database


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("--role", choices=["admin", "analyst"], default="analyst")
    parser.add_argument("--database", type=Path, default=None)
    args = parser.parse_args()
    password = getpass.getpass("Password (minimum 10 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        parser.error("Passwords do not match")
    database_path = args.database or ServiceSettings.from_environment().database_path
    with connect_database(database_path) as connection:
        create_user(connection, args.username, password, args.role)
    print(f"Created {args.role} user {args.username}")


if __name__ == "__main__":
    main()
