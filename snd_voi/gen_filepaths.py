#!/usr/bin/env python3
from datetime import datetime, timezone
import json
from pathlib import Path

EXCLUDED_FILES = {
	".gitkeep",
	"files.json",
	Path(__file__).name,
}
EXCLUDED_DIRS = {}

base_dir = Path(".")
root_files = []
categories = {}
total = 0

for path in sorted(base_dir.rglob("*")):
	if not path.is_file():
		continue
	if any(part in EXCLUDED_DIRS for part in path.parts):
		continue
	if path.name in EXCLUDED_FILES:
		continue

	rel_path = path.relative_to(base_dir)
	total += 1

	if len(rel_path.parts) == 1:
		root_files.append(rel_path.name)
	else:
		top_dir = rel_path.parts[0]
		categories.setdefault(top_dir, []).append({
			"name": rel_path.stem,
			"path": rel_path.as_posix(),
		})

manifest = {
	"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
	"total_files": total,
	"root_files": root_files,
	"categories": categories,
}

Path("files.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(f"Generated files.json ({total} files)")
