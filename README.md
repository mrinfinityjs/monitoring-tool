# Network Monitor Dashboard (Shane Britt, 2025)

This is a Node.js TUI (Terminal User Interface) tool that continuously monitors a list of servers defined in a JSON file. It provides a static, auto-updating dashboard in your terminal and can log important events to a file.

## Features

-   **Live Dashboard**: A clean, static display that updates in place.
-   **TCP Port Check**: Tracks the success/failure ratio and the time of the last failure.
-   **ICMP Ping Check**: Measures latency and tracks min/max/avg times.
-   **Status Coloring**: Latency is color-coded based on configurable thresholds.
-   **File Logging**: Logs critical events like TCP failures and latency alerts to a file.
-   **Log Rotation**: Automatically clears the log file when it reaches a configured size limit to prevent disk space issues.

## Setup

1.  **Install Node.js**: Ensure you have a recent version of Node.js installed.
2.  **Install Dependencies**: Open your terminal in the project directory and run:
    ```bash
    npm install
    ```

## Configuration (`monitor.json`)

The `monitor.json` file is an object containing global settings and an array of servers to monitor.

### Global Configuration

-   `log_to_file` (boolean): `true` to enable file logging, `false` to disable.
-   `log_file_path` (string): The name and path of the log file (e.g., `"monitor.log"`).
-   `log_max_size_mb` (number): The maximum size of the log file in megabytes. When the file exceeds this size, it will be cleared.

### Server Configuration (`servers` array)

Each object in the `servers` array has the following properties:

#### Required Properties:

*   `name` (string): A unique, human-readable name for the server.
*   `address` (string): The hostname (`google.com`) or IP address (`8.8.8.8`).
*   `port` (number): The TCP port to check.
*   `port_ping_frequency` (number): The interval in seconds between each TCP port check.
*   `icmp_ping_frequency` (number): The interval in seconds between each batch of ICMP pings.
*   `icmp_pings_per_check` (number): The number of pings to send in each ICMP check batch.

#### Optional Display Properties:

*   `good_display_ms` (number): Latency at or below this value (in ms) will be colored **Green**. (Default: 50)
*   `alert_display_ms` (number): Latency at or above this value will be colored **Yellow**. (Default: 150)
*   `critical_display_ms` (number): Latency at or above this value will be colored **Red**. (Default: 300)

## Running the Tool

To start the monitor, run the following command from the project directory:

```bash
npm start


## License

MIT Public license, you're free tp use this however you wish.
