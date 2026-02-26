# Contributing to STRATIX SDK

Thank you for your interest in contributing to the STRATIX ecosystem.

## What You Can Contribute

- **New vendor mappers** — additional source schema adapters (e.g. QRadar, Cribl, Wazuh)
- **Sector registry extensions** — domain-specific schema extensions for the STRATIX Registry
- **Bug fixes and test coverage** — improvements to existing validator or mapper logic
- **Documentation** — usage examples, integration guides, translations

## What Is Not Open for Contribution

The STRATIX core schema specification — the four extension layers, controlled vocabularies,
and field definitions — is governed exclusively by Intelligent Consulting BV. Proposals to
modify the core schema should be submitted as issues for consideration by the maintainers.

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-mapper-name`
3. Write your code and tests (maintain >90% test coverage)
4. Run: `pytest && ruff check . && mypy stratix/`
5. Open a Pull Request with a clear description

## Copyright

All contributions must include the Apache 2.0 licence header. By submitting a contribution
you agree that it will be licensed under Apache 2.0 and that Intelligent Consulting BV
retains the right to include it in the STRATIX SDK.

## Code of Conduct

Be professional, constructive, and respectful. This project serves the European
cybersecurity and critical infrastructure community.
