"""
stratix.cli
===========
Command-line entry points for the STRATIX SDK.

© 2026 Intelligent Consulting BV. All rights reserved.
Author: Suzanne Natalie Button, Director, Intelligent Consulting BV
First published: 26 February 2026
"""

import argparse
import json
import sys

from stratix.validator import StratixValidator
from stratix.mappers import get_mapper


def validate_cli():
    parser = argparse.ArgumentParser(
        description="Validate a STRATIX event JSON file against the schema specification."
    )
    parser.add_argument("file", help="Path to event JSON file")
    parser.add_argument("--no-strict", action="store_true",
                        help="Disable strict mode (suppress optional field warnings)")
    args = parser.parse_args()

    with open(args.file) as f:
        event = json.load(f)

    strict = not args.no_strict
    result = StratixValidator(strict=strict).validate(event)
    print(result)
    sys.exit(0 if result.valid else 1)


def map_cli():
    parser = argparse.ArgumentParser(
        description="Map a vendor-schema event to a STRATIX-normalised event."
    )
    parser.add_argument("--schema", required=True,
                        choices=["ecs", "cim", "asim", "modbus", "dnp3", "opc-ua"],
                        help="Source schema to map from")
    parser.add_argument("--input",  required=True, help="Path to input event JSON file")
    parser.add_argument("--output", required=True, help="Path to write STRATIX output JSON")
    parser.add_argument("--asset-id",       default="unknown")
    parser.add_argument("--purdue-level",   type=int, default=1)
    parser.add_argument("--data-residency", default="BE")
    args = parser.parse_args()

    with open(args.input) as f:
        event = json.load(f)

    mapper = get_mapper(args.schema)

    # OT mappers accept additional keyword arguments
    ot_schemas = {"modbus", "dnp3", "opc-ua"}
    if args.schema in ot_schemas:
        stratix_event = mapper.map(
            event,
            asset_id=args.asset_id,
            purdue_level=args.purdue_level,
            data_residency=args.data_residency,
        )
    else:
        stratix_event = mapper.map(event)

    with open(args.output, "w") as f:
        json.dump(stratix_event, f, indent=2)

    print(f"✅ Mapped [{args.schema.upper()}] → STRATIX  →  {args.output}")


def registry_cli():
    parser = argparse.ArgumentParser(
        description="Query the STRATIX Registry."
    )
    parser.add_argument("action", choices=["search", "stats"],
                        help="Action to perform")
    parser.add_argument("--domain",       default=None)
    parser.add_argument("--sector",       default=None)
    parser.add_argument("--nis2-aligned", action="store_true", default=None)
    parser.add_argument("--dora-aligned", action="store_true", default=None)
    args = parser.parse_args()

    from stratix.registry import StratixRegistry
    registry = StratixRegistry()

    if args.action == "stats":
        print(json.dumps(registry.stats(), indent=2))
    elif args.action == "search":
        results = registry.search(
            domain=args.domain,
            sector=args.sector,
            nis2_aligned=args.nis2_aligned if args.nis2_aligned else None,
            dora_aligned=args.dora_aligned if args.dora_aligned else None,
        )
        for r in results:
            print(f"  {r.name} v{r.version} [{r.domain}] — {r.status}")
        if not results:
            print("  No extensions found matching your criteria.")
