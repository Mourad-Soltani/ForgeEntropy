# ForgeEntropy

Offline CLI for forging and auditing high-entropy secrets.

**Built by Mourad.Soltani**

## What you get

- Generate strong passwords / API keys with configurable charset and length
- Audit any secret for Shannon entropy and policy compliance
- Crack-time estimates (simplified model)
- JSON output for scripting
- Zero external dependencies (Python stdlib only)
- Health tests included

## Requirements

- Python 3.8+

## How to run in 30 seconds

```bash
# From the unzipped directory
python -m forgeentropy.cli generate --length 32 --json
python -m forgeentropy.cli audit "your-secret-here" --min-entropy 80
python -m unittest discover -s tests -v
```

## License

MIT — see LICENSE
