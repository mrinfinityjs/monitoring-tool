import fs from 'fs/promises';
import net from 'net';
import dns from 'dns/promises';
import ping from 'ping';
import { performance } from 'perf_hooks';

const CONFIG_FILE = 'monitor.json';
const RENDER_INTERVAL_MS = 500; // How often to redraw the screen

// --- ANSI Escape Codes for Colors & TUI ---
const colors = {
    reset: "\x1b[0m",
    bright: "\x1b[1m",
    dim: "\x1b[2m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    grey: "\x1b[90m",
};
const cursor = {
    hide: "\x1b[?25l",
    show: "\x1b[?25h",
    clearScreen: "\x1b[2J",
    toTop: "\x1b[H",
};

// --- State and Config Management ---
let CONFIG = {}; // Will hold global config like logging
const serverStates = new Map();
let serverConfigs = []; // Will hold the array of servers

/**
 * Logs a message to the configured log file, handling rotation.
 * @param {string} message The message to log.
 */
async function logToFile(message) {
    if (!CONFIG.log_to_file) {
        return; // Logging is disabled
    }
    const logEntry = `[${new Date().toISOString()}] ${message}\n`;
    const { log_file_path, log_max_size_mb } = CONFIG;

    try {
        // Check file size for rotation
        try {
            const stats = await fs.stat(log_file_path);
            const maxSizeInBytes = log_max_size_mb * 1024 * 1024;
            if (stats.size > maxSizeInBytes) {
                await fs.truncate(log_file_path, 0); // Clear the file
                await fs.appendFile(log_file_path, `[${new Date().toISOString()}] LOG ROTATED: File size exceeded ${log_max_size_mb}MB.\n`);
            }
        } catch (error) {
            // If file doesn't exist (ENOENT), it's fine. We'll create it.
            if (error.code !== 'ENOENT') throw error;
        }

        // Append the new log entry
        await fs.appendFile(log_file_path, logEntry);
    } catch (error) {
        // Log to console if file logging fails, so the error isn't silent
        console.error(`\n[FATAL LOGGING ERROR] Could not write to log file ${log_file_path}:`, error.message);
    }
}

/**
 * A utility to format time differences in a human-readable "ago" format.
 */
function formatTimeAgo(timestamp) {
    if (!timestamp) return 'N/A';
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ago`;
}

/**
 * Renders the entire dashboard to the console.
 */
function renderDisplay() {
    let output = `${cursor.toTop}${cursor.clearScreen}`;
    output += `${colors.bright}--- Network Monitor Dashboard (Updated: ${new Date().toLocaleTimeString()}) ---\n\n${colors.reset}`;

    for (const server of serverConfigs) {
        const state = serverStates.get(server.name);
        if (!state) continue;

        const ipPort = state.ip ? `${state.ip}:${server.port}` : 'resolving...';
        const avg = state.icmp.avg !== null ? `${state.icmp.avg.toFixed(1)}ms` : 'N/A';
        const min = state.icmp.min !== null ? `${state.icmp.min.toFixed(1)}ms` : 'N/A';
        const max = state.icmp.max !== null ? `${state.icmp.max.toFixed(1)}ms` : 'N/A';
        const tcpRatio = `${state.tcp.success}:${state.tcp.fail}`;
        const lastFail = formatTimeAgo(state.tcp.lastFailTimestamp);
        
        let color = colors.reset;
        if (state.status === 'CRITICAL') color = colors.red;
        else if (state.status === 'ALERT') color = colors.yellow;
        else if (state.status === 'GOOD') color = colors.green;
        else if (state.status === 'UNREACHABLE' || state.status === 'SETUP_FAIL') color = colors.grey;

        output += `${color}${server.name.padEnd(22)} [${ipPort.padEnd(21)}] `;
        output += `Avg: ${avg.padEnd(8)} Min: ${min.padEnd(8)} Max: ${max.padEnd(9)} `;
        output += `TCP-S/F: ${tcpRatio.padEnd(7)} Last Fail: ${lastFail.padEnd(10)}`;
        output += `${colors.reset}\n`;
    }

    output += `\n${colors.dim}Monitoring ${serverConfigs.length} servers. Log file: ${CONFIG.log_to_file ? CONFIG.log_file_path : 'disabled'}. Press Ctrl+C to exit.${colors.reset}`;
    process.stdout.write(output);
}

/**
 * Performs a TCP port "ping".
 */
function checkTcpPort(server, ip) {
    const state = serverStates.get(server.name);
    const socket = new net.Socket();
    socket.setTimeout(5000);

    const fail = (reason) => {
        state.tcp.fail++;
        state.tcp.lastFailTimestamp = Date.now();
        logToFile(`[${server.name}] TCP FAILED: Could not connect to ${ip}:${server.port}. Reason: ${reason}`);
        socket.destroy();
    };

    socket.on('connect', () => {
        state.tcp.success++;
        socket.destroy();
    });
    socket.on('error', (err) => fail(err.message));
    socket.on('timeout', () => fail('Connection timed out'));
    socket.connect(server.port, ip);
}

/**
 * Performs an ICMP ping check.
 */
async function checkIcmpPing(server, ip) {
    const state = serverStates.get(server.name);
    try {
        const res = await ping.promise.probe(ip, { times: server.icmp_pings_per_check });
        const oldStatus = state.status;

        if (!res.alive) {
            if (oldStatus !== 'UNREACHABLE') {
                logToFile(`[${server.name}] ICMP STATUS CHANGE: Host became UNREACHABLE.`);
            }
            state.status = 'UNREACHABLE';
            return;
        }

        const avgLatency = parseFloat(res.avg);
        state.icmp.min = state.icmp.min === null ? parseFloat(res.min) : Math.min(state.icmp.min, parseFloat(res.min));
        state.icmp.max = state.icmp.max === null ? parseFloat(res.max) : Math.max(state.icmp.max, parseFloat(res.max));
        state.icmp.avg = avgLatency;

        const { good_display_ms = 50, alert_display_ms = 150, critical_display_ms = 300 } = server;
        let newStatus = 'OK';
        if (avgLatency >= critical_display_ms) newStatus = 'CRITICAL';
        else if (avgLatency >= alert_display_ms) newStatus = 'ALERT';
        else if (avgLatency <= good_display_ms) newStatus = 'GOOD';

        if (newStatus !== oldStatus && (newStatus === 'ALERT' || newStatus === 'CRITICAL')) {
            logToFile(`[${server.name}] ICMP STATUS CHANGE: ${oldStatus} -> ${newStatus}. Avg Latency: ${avgLatency.toFixed(1)}ms`);
        }
        state.status = newStatus;
    } catch (error) {
        state.status = 'UNREACHABLE';
    }
}

/**
 * Main function to start the monitoring tool.
 */
async function main() {
    console.log('Initializing network monitor...');

    try {
        const fileContent = await fs.readFile(CONFIG_FILE, 'utf-8');
        CONFIG = JSON.parse(fileContent);
        serverConfigs = CONFIG.servers;
        if (!serverConfigs || !Array.isArray(serverConfigs)) {
            throw new Error('Config file must be an object with a "servers" array.');
        }
    } catch (error) {
        console.error(`FATAL: Could not read or parse ${CONFIG_FILE}. Error: ${error.message}`);
        process.exit(1);
    }
    
    for (const server of serverConfigs) {
        serverStates.set(server.name, {
            ip: null,
            status: 'PENDING',
            tcp: { success: 0, fail: 0, lastFailTimestamp: null },
            icmp: { min: null, max: null, avg: null },
        });
    }

    for (const server of serverConfigs) {
        const state = serverStates.get(server.name);
        try {
            const { address: ip } = await dns.lookup(server.address);
            state.ip = ip;
            state.status = 'OK';
            if (server.port && server.port_ping_frequency > 0) {
                checkTcpPort(server, ip);
                setInterval(() => checkTcpPort(server, ip), server.port_ping_frequency * 1000);
            }
            if (server.icmp_ping_frequency > 0 && server.icmp_pings_per_check > 0) {
                checkIcmpPing(server, ip);
                setInterval(() => checkIcmpPing(server, ip), server.icmp_ping_frequency * 1000);
            }
        } catch (error) {
            state.status = 'SETUP_FAIL';
            state.ip = 'resolve-failed';
            logToFile(`[${server.name}] SETUP FAILED: Could not resolve hostname "${server.address}". Error: ${error.message}`);
        }
    }
    
    process.stdout.write(cursor.hide);
    const displayInterval = setInterval(renderDisplay, RENDER_INTERVAL_MS);

    process.on('SIGINT', () => {
        clearInterval(displayInterval);
        process.stdout.write(cursor.toTop + cursor.clearScreen + cursor.show);
        console.log('Network monitor stopped.');
        process.exit(0);
    });
}

main();
