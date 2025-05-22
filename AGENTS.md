# Repository Guidelines for Codex

## Testing
Run the following command after making changes:

```bash
python3 dns_inspectah.py example.com
```

The script depends on packages listed in `requirements.txt`. If they are not installed, create a virtual environment and run:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Documentation
Use descriptive commit messages and cite relevant files in PR summaries.
