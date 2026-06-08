"""C2DETECT command-line interface."""
from cognis_core import build_cli
from c2detect.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc detection",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
