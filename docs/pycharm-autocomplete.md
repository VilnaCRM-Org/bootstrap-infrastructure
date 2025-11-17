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
   docker compose up --build -d
   ```

   The compose file defines a single service named `pulumi`. It mounts the
   repository into `/workspace` inside the container.

3. (Optional) To drop into a shell inside the running container, use:

   ```bash
   docker compose exec pulumi bash
   ```

   This is helpful if you want to verify that the Pulumi CLI and Python packages
   are available (`pulumi version`, `python -c "import pulumi"`).

## 2. Attach PyCharm to the Docker interpreter (recommended)

1. Launch PyCharm and open the project.
2. Navigate to `Settings → Project: infrastructure-template → Python Interpreter`.
3. Click the gear icon → `Add…` → select **Docker Compose**.
4. In the dialog:
   - Choose the repo's `docker-compose.yml`.
   - Set **Service** to `pulumi`.
   - Leave the working directory as `/workspace`.
   - Ensure the Python interpreter path is `/opt/pulumi-venv/bin/python`.
5. Click **OK**, then **Apply**. PyCharm connects to the running container,
   indexes the interpreter, and autocomplete should light up immediately.

PyCharm remembers the interpreter selection. If it shows as "not connected",
start the container again (`docker compose up -d`) and PyCharm will reconnect.

## 3. Optional: local virtual environment fallback

If you cannot use Docker on your machine, you can still create a local virtual
environment mirroring the container dependencies. Choose where you want it to
live:

- `pulumi/.venv` keeps the interpreter alongside prospective Pulumi code.
- `.venv` at the repository root works equally well.

Run the commands below from the repository root (replace `pulumi/.venv` with
`.venv` if you pick the root location).

```bash
python -m venv pulumi/.venv
# Activate the environment (run the line that matches your shell):
#   macOS/Linux:        source pulumi/.venv/bin/activate
#   Windows PowerShell: pulumi\.venv\Scripts\Activate
#   Windows cmd:        pulumi\.venv\Scripts\activate.bat
pip install --upgrade pip
pip install "pulumi>=3.138,<4" "pulumi-aws>=7.0,<8" black flake8 pre-commit
deactivate
```

When adding the interpreter in PyCharm, select the relevant path:

- macOS/Linux: `pulumi/.venv/bin/python` or `.venv/bin/python`
- Windows (PowerShell/cmd): `pulumi\.venv\Scripts\python.exe` or `.venv\Scripts\python.exe`

## 4. Verify autocomplete

Open (or create) a Pulumi program file, for example `pulumi/__main__.py`, and
type `pulumi.` or `pulumi_aws.`. You should see resource suggestions. If
completions fail to appear:

- Confirm the interpreter (Docker or local venv) is selected in the PyCharm
  status bar.
- Rebuild the Docker image if dependencies changed:

  ```bash
  docker compose build pulumi
  ```

- Use **File → Invalidate Caches / Restart…** in PyCharm to trigger re-indexing.

## 5. Stop the workspace

When you are done, you can stop the container:

```bash
docker compose down
```

This removes the running container but keeps the built image for the next
session. Use `docker compose down --rmi all` if you also want to remove the
image.
