# Traefik ACME Cleaner

An ACME Certificate Cleanup Script for Traefik.

This script performs cleanup operations on the Traefik `acme.json` file by removing expired, invalid, and optionally unused certificates. It also generates a markdown report summarising the analysis.

**Container Image:** [`ghcr.io/aperim/traefik-acme-cleanup`](https://ghcr.io/aperim/traefik-acme-cleanup)

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Environment Variables](#environment-variables)
  - [Examples](#examples)
- [Docker Usage](#docker-usage)
  - [Running the Container](#running-the-container)
  - [User and Group IDs](#user-and-group-ids)
  - [Overriding the Default Command](#overriding-the-default-command)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

## Features

- **Certificate Cleanup**: Removes expired and invalid certificates from Traefik's `acme.json` file.
- **Unused Certificates**: Optionally removes certificates that are not in use by Traefik routers.
- **Markdown Report**: Generates a detailed markdown report summarising the certificate analysis.
- **Traefik API Integration**: Fetches in-use domains directly from Traefik's API for accurate analysis.
- **Flexible Configuration**: Configure behaviour via command-line arguments or environment variables.
- **Docker Support**: Run the script effortlessly inside a Docker container with configurable user IDs.

## Prerequisites

- **Python**: Version 3.20 or higher.
- **Traefik API Credentials**: Access to the Traefik dashboard API.
- **Access to `acme.json`**: The script needs read and write permissions to Traefik's `acme.json` file.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/aperim/traefik-acme-cleaner.git
   cd traefik-acme-cleaner
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   **Note**: It's recommended to use a virtual environment.

## Configuration

The script can be configured using environment variables or command-line arguments.

### Required Environment Variables

- `TRAEFIK_DASHBOARD_URL`: URL to the Traefik dashboard API endpoint (e.g., `http://localhost:8080/api`).
- `TRAEFIK_DASHBOARD_USERNAME`: Username for Traefik dashboard authentication.
- `TRAEFIK_DASHBOARD_PASSWORD`: Password for Traefik dashboard authentication.

### Optional Environment Variables

- `TRAEFIK_ACME_FILE`: Path to the `acme.json` file. Default is `acme.json` in the current directory.
- `ACME_CLEANUP_UNUSED`: Set to `true` to include unused certificates in the cleanup. Default is `false`.
- `ACME_CLEANUP_DOIT`: Set to `true` to perform the cleanup. If `false`, the script runs in simulation mode. Default is `false`.
- `CLEANUP_REPORT`: Path to the markdown report file. Default is `./REPORT.md`.

## Usage

Run the script using Python:

```bash
python acme_cleanup.py [options]
```

### Command-Line Options

- `--include-unused`: Include unused certificates in the removal process.
- `--doit`: Perform the cleanup; otherwise, the script runs in simulation mode.
- `--report PATH`: Specify the path to the markdown report file.

### Environment Variables

Environment variables can be used instead of command-line arguments:

- `ACME_CLEANUP_UNUSED`: Equivalent to `--include-unused`.
- `ACME_CLEANUP_DOIT`: Equivalent to `--doit`.
- `CLEANUP_REPORT`: Equivalent to `--report`.

### Examples

1. **Simulate Cleanup and Generate Report**:

   ```bash
   python acme_cleanup.py --report ./cleanup_report.md
   ```

2. **Perform Actual Cleanup**:

   ```bash
   python acme_cleanup.py --doit
   ```

3. **Include Unused Certificates in Cleanup**:

   ```bash
   python acme_cleanup.py --doit --include-unused
   ```

4. **Using Environment Variables**:

   ```bash
   export TRAEFIK_DASHBOARD_URL="http://localhost:8080/api"
   export TRAEFIK_DASHBOARD_USERNAME="your_username"
   export TRAEFIK_DASHBOARD_PASSWORD="your_password"
   export ACME_CLEANUP_DOIT="true"
   python acme_cleanup.py
   ```

## Docker Usage

The script is available as a Docker image for ease of use.

### Pulling the Docker Image

Pull the image from GitHub Container Registry:

```bash
docker pull ghcr.io/aperim/traefik-acme-cleanup:latest
```

### Running the Container

Run the container with the necessary environment variables and volume mounts:

```bash
docker run --rm \
  -e TRAEFIK_ACME_FILE="/data/acme.json" \
  -e TRAEFIK_DASHBOARD_URL="http://traefik:8080/api" \
  -e TRAEFIK_DASHBOARD_USERNAME="your_username" \
  -e TRAEFIK_DASHBOARD_PASSWORD="your_password" \
  -e ACME_CLEANUP_DOIT="true" \
  -v /path/to/your/acme.json:/data/acme.json \
  -v /path/to/output/report:/data \
  ghcr.io/aperim/traefik-acme-cleanup
```

- **Mount the `acme.json` File**: Ensure that the `acme.json` file is mounted inside the container at the path specified by `TRAEFIK_ACME_FILE`.
- **Mount the Output Directory**: If you want to save the report outside the container, mount the directory where the report will be saved.

### User and Group IDs

To match file permissions with your host system, you can specify the user and group IDs:

- `PUID`: User ID to run the application as (default `1000`).
- `PGID`: Group ID to run the application as (default `1000`).

**Example**:

```bash
docker run --rm \
  -e PUID=1001 \
  -e PGID=1001 \
  -e TRAEFIK_ACME_FILE="/data/acme.json" \
  -e TRAEFIK_DASHBOARD_URL="http://traefik:8080/api" \
  -e TRAEFIK_DASHBOARD_USERNAME="your_username" \
  -e TRAEFIK_DASHBOARD_PASSWORD="your_password" \
  -e ACME_CLEANUP_DOIT="true" \
  -v /path/to/your/acme.json:/data/acme.json \
  ghcr.io/aperim/traefik-acme-cleanup
```

### Overriding the Default Command

You can override the default command to run a shell or another command within the container:

```bash
docker run --rm -it \
  -v /path/to/your/data:/data \
  ghcr.io/aperim/traefik-acme-cleanup /bin/sh
```

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**: Create a fork of the repository on GitHub.

2. **Create a Feature Branch**:

   ```bash
   git checkout -b feature/my-new-feature
   ```

3. **Commit Your Changes**:

   ```bash
   git commit -am 'Add my new feature'
   ```

4. **Push to the Branch**:

   ```bash
   git push origin feature/my-new-feature
   ```

5. **Create a Pull Request**: Open a pull request on GitHub.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Author

- **Troy Kelly** - [troykelly](https://github.com/troykelly) - <troy@aperim.com>

---
