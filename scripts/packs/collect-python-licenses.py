from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import shutil
from pathlib import Path


PACKAGE = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)(?:\s|\\|;|$)")
LICENSE_NAME = re.compile(r"^(?:licen[cs]e|copying|notice)(?:[._-].*)?$", re.IGNORECASE)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()
    arguments.out.mkdir(parents=True, exist_ok=False)

    expected = {}
    for line in arguments.lock.read_text(encoding="utf-8").splitlines():
        match = PACKAGE.match(line)
        if match:
            expected[normalize(match.group(1))] = match.group(2)

    records = []
    for name, locked_version in sorted(expected.items()):
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        actual_version = distribution.version
        if actual_version != locked_version:
            raise SystemExit(f"installed version mismatch for {name}: {actual_version}")
        copied = []
        for relative in distribution.files or ():
            if not LICENSE_NAME.match(Path(relative).name):
                continue
            source = Path(distribution.locate_file(relative)).resolve()
            if not source.is_file():
                continue
            destination_directory = arguments.out / name
            destination_directory.mkdir(exist_ok=True)
            destination = destination_directory / Path(relative).name
            if destination.exists():
                continue
            shutil.copyfile(source, destination)
            copied.append(str(destination.relative_to(arguments.out)).replace("\\", "/"))
        if not copied:
            raise SystemExit(f"no license file found for {name}")
        records.append({"name": name, "version": actual_version, "files": copied})

    (arguments.out / "index.json").write_text(
        json.dumps({"schemaVersion": 1, "packages": records}, indent=2) + "\n",
        encoding="utf-8",
    )


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


if __name__ == "__main__":
    main()
