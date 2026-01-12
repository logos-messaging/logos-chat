import std/os

# all vendor subdirectories
for dir in walkDir(thisDir() / "vendor"):
  if dir.kind == pcDir:
    switch("path", dir.path)
    switch("path", dir.path / "src")
