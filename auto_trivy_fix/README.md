# auto_trivy_fix

Automated helper to scan a Docker image with Trivy, attempt to patch the Dockerfile (base image and package pins),
rebuild the image, and produce a report.

## Requirements
- Linux/macOS/Windows with:
  - Python 3.9+
  - `docker` CLI installed and you have permission to build images
  - `trivy` CLI installed (https://github.com/aquasecurity/trivy)

Install Python deps:
```bash
python -m pip install -r requirements.txt
```

## Usage

The main entry point is `autofix.py`. You can run it with the following environment variables:

- `IMAGE_NAME`: The name of the Docker image to scan and fix (e.g., `python:3.9-slim`).
- `DOCKERFILE_PATH`: The path to the Dockerfile to patch (e.g., `example/Dockerfile`).
- `BUILD_CONTEXT`: The build context for the `docker build` command (defaults to the directory of the Dockerfile).

Example:
```bash
export IMAGE_NAME="my-app:1.0"
export DOCKERFILE_PATH="app/Dockerfile"
python auto_trivy_fix/autofix.py
```

The script will generate a `final_report.json` file with the results of the fix.

### Internet Search for Fixes

The script includes an experimental feature to search for fixes online for vulnerabilities that do not have a `fixed_version` provided by Trivy. This feature uses Google search to find potential fixes. Please note that the accuracy of this feature is not guaranteed, and the suggested fixes should be reviewed carefully.

## Dependency Vulnerability Fixing

The `dependency_fix.py` script can be used to automatically fix vulnerabilities in Python `requirements.txt` files.

### Usage

You can run the script with the following environment variable:

- `REQUIREMENTS_PATH`: The path to the `requirements.txt` file to fix (e.g., `example/app/requirements.txt`).

Example:
```bash
export REQUIREMENTS_PATH="my_project/requirements.txt"
python auto_trivy_fix/dependency_fix.py
```

The script will scan the `requirements.txt` file for vulnerabilities using `pip-audit` and automatically update the file with the fixed versions of the vulnerable packages.

### JavaScript Projects

The `js_dependency_fix.py` script can be used to automatically fix vulnerabilities in JavaScript projects that use `npm`.

#### Usage

You can run the script with the following environment variable:

- `PROJECT_PATH`: The path to the JavaScript project directory (e.g., `js_example`).

Example:
```bash
export PROJECT_PATH="my_js_project"
python auto_trivy_fix/js_dependency_fix.py
```

The script will run `npm audit` to find vulnerabilities and then run `npm install` to update the vulnerable packages to the fixed versions. This will update the `package.json` and `package-lock.json` files.
