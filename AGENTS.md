# Repository Guidelines for Codex

This project uses Python. The following conventions help ensure consistent contributions across Codex repositories.

## Environment Setup
If dependencies from `requirements.txt` are missing, create a virtual environment and install them:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Scripts should run with Python 3.8 or later.

## Testing
After any change, verify the main script still executes:

```bash
python3 dns_inspectah.py example.com
```

## Coding Standards
- Follow PEP 8 guidelines. If `black` or `flake8` are available, run them before committing.
- Provide docstrings for all public functions and classes.
- Use descriptive variable names and keep functions small.
- Prefer cross-platform compatible code.

## Documentation
- Write clear commit messages summarizing your changes.
- Reference modified files in PR summaries using line citations.
- Update `README.md` when adding features or configuration options.

## Contributing
Keep these instructions up to date when repository conventions change.
