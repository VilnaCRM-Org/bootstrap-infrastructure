# PyCharm Autocomplete with the Docker Workspace

This repository ships with a Docker environment that already contains the Pulumi
CLI, the Python SDKs, and linting tools. You can point PyCharm at this container
to obtain autocomplete without installing Python packages locally. A fallback
local virtual environment workflow is included for developers who prefer to keep
an interpreter on disk.

## 1. Build and start the Docker workspace

1. Install the latest versions of Docker Desktop (or Docker Engine) and Docker
   Compose.
2. From the repository root, build the container and start it in the background:

   ```bash
   make start
   ```

   The compose file defines a single service named `pulumi`. It mounts the
   repository into `/workspace` inside the container.

3. (Optional) To drop into a shell inside the running container, use:

   ```bash
   make sh
   ```

   This is helpful if you want to verify that the Pulumi CLI and Python packages
   are available (`pulumi version`, `python -c "import pulumi"`).

## 2. Attach PyCharm to the Docker interpreter (recommended)

1. Launch PyCharm and open the project.
2. Navigate to `Settings → Project: bootstrap-infrastructure → Python Interpreter`.
3. Click the gear icon → `Add…` → select **Docker Compose**.
4. In the dialog:
   - Choose the repo's `docker-compose.yml`.
   - Set **Service** to `pulumi`.
   - Leave the working directory as `/workspace`.
   - Ensure the Python interpreter path is `/home/dev/.venvs/bootstrap-infrastructure/bin/python`.
5. Click **OK**, then **Apply**. PyCharm connects to the running container,
   indexes the interpreter, and autocomplete should light up immediately.

PyCharm remembers the interpreter selection. If it shows as "not connected",
start the container again (`make start`) and PyCharm will reconnect. If the
workspace refuses to start, run `make doctor` before debugging Docker or Compose
manually.

## 3. Optional: local virtual environment fallback

If you cannot use Docker on your machine, you can still create a local virtual
environment mirroring the container dependencies. Keep it outside the checkout
so bind mounts and file watches never hide or replace the interpreter that
Pulumi Automation uses.

```bash
export UV_PROJECT_ENVIRONMENT="${HOME}/.venvs/bootstrap-infrastructure"
uv venv --seed "${UV_PROJECT_ENVIRONMENT}"

# macOS/Linux
uv sync --all-groups

# Windows PowerShell
$env:UV_PROJECT_ENVIRONMENT="$HOME/.venvs/bootstrap-infrastructure"; uv venv --seed $env:UV_PROJECT_ENVIRONMENT; uv sync --all-groups

# Windows cmd.exe
set UV_PROJECT_ENVIRONMENT=%USERPROFILE%\\.venvs\\bootstrap-infrastructure && uv venv --seed %UV_PROJECT_ENVIRONMENT% && uv sync --all-groups
```

When adding the interpreter in PyCharm, select the explicit environment path:

- macOS/Linux: `${HOME}/.venvs/bootstrap-infrastructure/bin/python`
- Windows PowerShell: `$env:USERPROFILE\\.venvs\\bootstrap-infrastructure\\Scripts\\python.exe`
- Windows cmd.exe: `%USERPROFILE%\\.venvs\\bootstrap-infrastructure\\Scripts\\python.exe`

## 4. Verify autocomplete

Open (or create) a Pulumi program file, for example `pulumi/__main__.py`, and
type `pulumi.` or `pulumi_aws.`. You should see resource suggestions. If
completions fail to appear:

- Confirm the interpreter (Docker or local venv) is selected in the PyCharm
  status bar.
- Rebuild the Docker image if dependencies changed:

  ```bash
  make build
  make start
  ```

- Use **File → Invalidate Caches / Restart…** in PyCharm to trigger re-indexing.

## 5. Stop the workspace

When you are done, you can stop the container:

```bash
make down
```

This removes the running containers for the current workspace. Rebuild with
`make build` if you need a fresh image afterward.
