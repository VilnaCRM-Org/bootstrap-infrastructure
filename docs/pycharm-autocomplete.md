# PyCharm Autocomplete for the Pulumi Project

This guide explains how to wire up a local virtual environment so PyCharm can
offer reliable autocomplete for the Pulumi stack. The runtime experience still
happens inside Docker, but PyCharm needs a local interpreter with the project
dependencies indexed to power the editor.

## 1. Create the virtual environment

Decide where you want the interpreter to live:

- `pulumi/.venv` keeps the environment alongside the Pulumi sources.
- `.venv` at the repository root works just as well if you already use that
  convention.

Run the commands below from the repository root, replacing `pulumi/.venv` with
`.venv` if you prefer the top-level location.

```bash
python3 -m venv pulumi/.venv
# Activate the environment (run the line that matches your shell):
#   macOS/Linux:        source pulumi/.venv/bin/activate
#   Windows PowerShell: pulumi\.venv\Scripts\Activate
#   Windows cmd:        pulumi\.venv\Scripts\activate.bat
pip install --upgrade pip
pip install "pulumi>=3.138,<4" "pulumi-aws>=7.0,<8" black flake8 pre-commit
deactivate
```

If the virtual environment already exists and you want to refresh the
dependencies, reactivate it (`source pulumi/.venv/bin/activate`,
`source .venv/bin/activate`, `pulumi\.venv\Scripts\Activate`,
`.venv\Scripts\Activate`, `pulumi\.venv\Scripts\activate.bat`, or
`.venv\Scripts\activate.bat`) and rerun the `pip install …` line.

## 2. Point PyCharm at the new interpreter

1. Open PyCharm.
2. Go to `Settings → Project: infrastructure-template → Python Interpreter`.
3. Click the gear icon → `Add…` → `Existing environment`.
4. Browse to the interpreter you created—e.g. `pulumi/.venv/bin/python` (macOS/Linux),
   `pulumi\.venv\Scripts\python.exe` (Windows), `.venv/bin/python`, or `.venv\Scripts\python.exe`—select
   the path that matches your OS, and apply the change.

PyCharm immediately indexes the environment and enables autocomplete for the
Pulumi SDKs, AWS provider, and the helper tooling (Black, Flake8, Pre-commit).

## 3. Verify autocomplete works

Open `pulumi/__main__.py` in PyCharm and start typing `pulumi.` or
`pulumi_aws.`. You should see completion suggestions for the available modules
and resources. If completions are missing, click the interpreter selection in
the status bar once more to ensure the `pulumi/.venv` interpreter is active for
the project, then re-trigger indexing via **File → Invalidate Caches / Restart…**.

## 4. Keep the environment current

- Whenever `pulumi/pyproject.toml` changes, rerun the `pip install …` command so
  the virtual environment mirrors the project dependencies.
- Delete and recreate the virtual environment if you switch Python versions
  locally.
- The `.venv` folders stay out of version control; each developer should create
  it on their machine following the steps above.
