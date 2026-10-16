# Escal8

**A standalone Bash-based Linux privilege-escalation enumeration tool.**

Escal8 helps security researchers, penetration testers, and CTF players identify potential Linux privilege-escalation opportunities through system enumeration and security checks.

Escal8 is **read-only by design**. It gathers information and reports potential security issues without attempting exploitation or privilege escalation.

## Features

- **System enumeration** — OS, kernel, users, groups, and system configuration.
- **Privilege checks** — sudo rules, SUID/SGID binaries, Linux capabilities, and Polkit.
- **Filesystem analysis** — writable files and directories, cron jobs, ACLs, permissions, and mount options.
- **Process and service discovery** — running processes, services, systemd timers, and deleted files.
- **Network enumeration** — interfaces, routes, listening services, and network-related configuration.
- **Credential exposure checks** — selected credential-file metadata, shell history, SSH configuration, and sudo-session metadata.
- **Container and infrastructure checks** — container runtimes, NFS, cloud identity metadata, and common DevOps configuration paths.
- **Kernel and software context** — kernel hardening information and installed software inventory.
- **Structured reporting** — severity-based findings and check-coverage summaries.
- **Multiple output formats** — terminal output, text reports, JSON, and HTML.
- **Flexible execution** — quick profiles and individually selected checks.
- **Portable distribution** — a standalone Bash script for transfer to Linux targets.

## Quick Start

### 1. Get Escal8

Clone the repository:

```bash
git clone https://github.com/pr0m7x90/escal8.git
cd escal8
```

### 2. Build the standalone script

```bash
chmod +x build.sh
./build.sh
```

The generated script will be available at `dist/escal8.sh`.

### 3. Run Escal8

Full enumeration:

```bash
bash dist/escal8.sh
```

Quick enumeration:

```bash
bash dist/escal8.sh --profile quick --no-color
```

Run selected checks:

```bash
bash dist/escal8.sh --checks suid,sudo,cron
```

Show help:

```bash
bash dist/escal8.sh --help
```

List available checks:

```bash
bash dist/escal8.sh --list-checks
```

## Reports

Generate a text report:

```bash
bash dist/escal8.sh --quiet -o report.txt
```

Generate a JSON report:

```bash
bash dist/escal8.sh --format json --output report.json
```

Generate an HTML report:

```bash
bash dist/escal8.sh --format html --output report.html
```

Reports include findings and relevant check-coverage information. Review the results in the context of the target system rather than treating individual indicators as proof of exploitability.

## Severity Levels

Escal8 uses the following finding classifications:

| Severity | Meaning |
|---|---|
| `CRITICAL` | A potentially critical security issue requiring immediate investigation |
| `HIGH` | A potentially serious security issue |
| `MEDIUM` | A security concern requiring contextual review |
| `LOW` | A lower-priority security concern |
| `INFO` | Informational system or configuration data |
| `OK` | A check ran without identifying a concern |
| `SKIP` | A check could not assess the relevant item |
| `FAILED` | An unexpected internal check error occurred |

These classifications help prioritize investigation. They do not independently prove that a system is exploitable.

## Check Coverage

Escal8 distinguishes between checks that completed, were skipped, failed, or were not requested.

This distinction matters: a skipped check does not mean the target is secure. Missing utilities, insufficient permissions, container restrictions, or inaccessible resources can limit enumeration.

## Project Structure

The tree below uses ASCII characters to avoid character-encoding issues in rendered Markdown.

```text
escal8/
|-- .gitignore
|-- build.sh
|-- README.md
|-- src/
|   |-- 00_header.sh
|   |-- 01_colors.sh
|   |-- 02_utils.sh
|   |-- 03_args.sh
|   `-- ... check modules
|-- dist/
|   `-- escal8.sh
`-- tests/
    |-- escal8.bats
    |-- run_tests.sh
    |-- run_chroot_tests.sh
    `-- fixtures/
```

The `src/` directory contains the maintainable source modules. `build.sh` combines them into the standalone distributable script in `dist/escal8.sh`.

## Build and Test

Build Escal8 and run the regression suite:

```bash
./build.sh
bash tests/run_tests.sh
```

If Bats is installed, run the Bats test suite:

```bash
bats tests/escal8.bats
```

The optional chroot integration tests require a suitable Linux environment, root privileges, and support for operations such as `chroot` and `mknod`:

```bash
sudo bash tests/run_chroot_tests.sh
```

Run ShellCheck when available:

```bash
shellcheck -s bash src/*.sh
shellcheck -s bash dist/escal8.sh
```

A test suite that skips an integration test has not fully validated that test. Check the test output and your environment before relying on a validation result.

## Portability

Escal8 is written in Bash and designed for Linux environments with varying sets of installed utilities.

- Bash is required.
- Optional utilities are checked before use where applicable.
- Missing dependencies may cause individual checks to be skipped.
- The tool does not need a mandatory Python, Node.js, or Rust runtime on the target.
- Escal8 does not perform network requests or phone home.

Coverage depends on the target environment, available utilities, permissions, and environment restrictions.

## Security Notice

Escal8 is an enumeration tool, not an exploitation framework. Findings are potential security indicators that should be verified manually.

Enumeration coverage depends on the target operating system, available utilities, permissions, and environment restrictions. Escal8 does not guarantee the discovery of every privilege-escalation path.

**Use Escal8 only on systems you own or have explicit authorization to assess.**

## Development Status

Escal8 is under active development. Contributions, bug reports, test cases, and suggestions for additional enumeration checks are welcome.
