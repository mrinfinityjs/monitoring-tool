# Terminal Network Monitoring Tools

A comprehensive, terminal-based network monitoring tool written in Node.js. It provides real-time latency and status monitoring for TCP/TLS endpoints, along with a suite of interactive commands for on-the-fly network diagnostics, including port scanning, IP information lookup, and remote server command execution via SSH.

## Screenshot

![Terminal](https://github.com/mrinfinityjs/monitoring-tool/blob/main/image.jpg?raw=true) 

## Features

-   **Real-time Monitoring**: Continuously checks endpoints using ICMP (ping) and TCP port connections.
-   **TLS/SSL Validation**: Monitors TLS certificate validity and logs any changes to the certificate hash.
-   **Dynamic Configuration**: Add, remove, or disable hosts on-the-fly by editing the `monitor.json` file. The tool automatically reloads the configuration.
-   **Interactive Diagnostics**:
    -   **Port Scanning**: Use the `map` command to run an Nmap scan on any host.
    -   **IP Information**: Use the `info` command to get reverse DNS, ASN, and geographic location for any IP.
    -   **Remote Execution**: Use the `ssh` command to run commands on pre-configured servers.
-   **Persistent Logging**: Keeps a running log of events and a historical record of all seen SSL certificates.
-   **Responsive Terminal UI**: Built with `blessed`, providing a clean, scrollable, and interactive interface.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

1.  **Node.js**: Version 16.x or newer is recommended.
2.  **Nmap**: The `map` command relies on the Nmap command-line tool.
    -   **Debian/Ubuntu**: `sudo apt update && sudo apt install nmap`
    -   **CentOS/RHEL**: `sudo yum install nmap`
    -   **macOS (Homebrew)**: `brew install nmap`

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd <repository-directory>
    ```

2.  **Install dependencies:**
    This command will read the `package.json` file and install all required Node.js packages.
    ```bash
    npm install
    ```

3.  **Set up your configuration:**
    Create a `monitor.json` file in the project's root directory. You can use the example below as a starting point.

## Configuration (`monitor.json`)

The application is controlled by a `monitor.json` file. Here is a breakdown of all the available options.

### Global Configuration

These settings are defined at the top level of the JSON file.

| Key                      | Type    | Description                                                                 | Default |
| ------------------------ | ------- | --------------------------------------------------------------------------- | ------- |
| `log_to_file`            | Boolean | If `true`, all events will be logged to a file.                             | `false` |
| `log_file_path`          | String  | The path to the log file.                                                   | `monitor.log` |
| `log_max_size_mb`        | Number  | The maximum size of the log file in MB before it's truncated.               | `10`    |
| `disabled_show_total_time` | Number  | The duration in seconds to keep a disabled server visible in the UI.      | `300`   |
| `total_display_alerts`   | Number  | The maximum number of alerts to show in the alert log window.               | `10`    |

### Server Configuration (`servers` array)

The `servers` key holds an array of objects, where each object represents a host to monitor.

| Key                    | Type    | Description                                                                 | Required |
| ---------------------- | ------- | --------------------------------------------------------------------------- | -------- |
| `name`                 | String  | A unique, human-readable name for the endpoint.                             | **Yes**  |
| `address`              | String  | The hostname (e.g., `google.com`) or IP address to monitor.                 | **Yes**  |
| `port`                 | Number  | The TCP port to check.                                                      | **Yes**  |
| `enabled`              | Boolean | Set to `false` to temporarily disable monitoring for this host.             | **Yes**  |
| `port_ping_frequency`  | Number  | The interval in seconds for performing TCP port checks.                     | **Yes**  |
| `icmp_ping_frequency`  | Number  | The interval in seconds for performing ICMP pings.                          | **Yes**  |
| `icmp_pings_per_check` | Number  | The number of ICMP pings to send in each check to calculate an average.     | No       |
| `check_tls`            | Boolean | If `true`, performs a TLS handshake to check the certificate.               | No       |
| `ssh_user`             | String  | The username for SSH connections (for the `ssh` command).                   | No       |
| `ssh_host`             | String  | The hostname/IP for SSH connections. Can differ from `address`.             | No       |
| `ssh_key`              | String  | The absolute path to the private SSH key file.                              | No       |

### Example `monitor.json`

```json
{
  "log_to_file": true,
  "log_file_path": "monitor.log",
  "log_max_size_mb": 10,
  "total_display_alerts": 15,
  "servers": [
    {
      "name": "Google DNS (TLS)",
      "address": "dns.google",
      "port": 853,
      "check_tls": true,
      "port_ping_frequency": 60,
      "icmp_ping_frequency": 60,
      "icmp_pings_per_check": 3,
      "enabled": true
    },
    {
      "name": "Cloudflare DNS",
      "address": "1.1.1.1",
      "port": 53,
      "check_tls": false,
      "port_ping_frequency": 30,
      "icmp_ping_frequency": 30,
      "enabled": true
    },
    {
      "name": "My LAN Server (SSH)",
      "address": "192.168.1.10",
      "port": 22,
      "enabled": true,
      "port_ping_frequency": 15,
      "icmp_ping_frequency": 15,
      "check_tls": false,
      "ssh_user": "myuser",
      "ssh_host": "192.168.1.10",
      "ssh_key": "/home/user/.ssh/id_rsa"
    }
  ]
}
```

## Running the Application

To start the monitoring tool, run the following command from your project directory:

```bash
npm start
```
*(This assumes you have a `"start": "node netmon.js"` script in your `package.json`).*

Alternatively, you can run the script directly:

```bash
node netmon.js
```

## Interactive Commands

Type commands into the `>` prompt at the bottom of the screen and press Enter.

| Command                     | Description                                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------- |
| `map <target>`              | Runs an Nmap scan (`nmap -Pn`) against a target. The target can be a partial name from the config, a hostname, or an IP. |
| `info <target>`             | Looks up DNS, rDNS, ASN, and GeoIP information for a target.                                            |
| `ssh <match>:<command>`     | Executes a shell command on a remote server. Finds a server from the config where `<match>` is part of its name or `ssh_host`. |
| `enable --name "..." --host "..."` | Adds a new server to the `monitor.json` file. Other options can be provided.                      |
| `disable --name "..."`      | Sets `"enabled": false` for the specified server in `monitor.json`.                                     |
| `disable --name "..." --delete` | Permanently removes the specified server from `monitor.json`.                                           |
| `clear`                     | Clears the alert log window.                                                                            |
| `help` or `cmd`             | Displays a list of available commands.                                                                  |
| `exit` or `quit`            | Shuts down the application gracefully. (You can also use `Ctrl+C`).                                     |

## Logging Files

The application generates two log files in the project directory:

-   `monitor.log`: A plain-text log of all status changes and events that appear in the "Alerts & Events" window.
-   `ssl-verified.json`: A structured JSON log containing the full details of every unique SSL certificate encountered by the monitor. This is useful for historical tracking and auditing certificate changes.

## Core Dependencies

-   [blessed](https://github.com/chjj/blessed): For the interactive terminal user interface.
-   [ping](https://github.com/danielkrainas/node-ping): For ICMP ping functionality.
-   [node-ssh](https://github.com/steelbrain/node-ssh): For executing remote commands via SSH.
-   [node-nmap](https://github.com/jas-/node-nmap): A wrapper for the Nmap command-line tool.
-   [axios](https://github.com/axios/axios): For making HTTP requests to the GeoIP API.
