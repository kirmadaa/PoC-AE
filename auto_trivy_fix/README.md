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
