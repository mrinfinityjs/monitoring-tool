import fs from 'fs/promises';
import net from 'net';
import dns from 'dns/promises';
import ping from 'ping';

// --- Constants ---
const CONFIG_FILE = 'monitor.json';
const RENDER_INTERVAL_MS = 500; // How often to redraw the screen
const CONFIG_REFRESH_INTERVAL_MS = 3000; // How often to check for config changes

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
let CONFIG = {}; // Holds the entire contents of monitor.json
const serverStates = new Map(); // Holds live data for each server
const serverTimers = new Map(); // Stores setInterval IDs for each server's checks

/**
 * Logs a message to the configured log file, handling rotation.
 * @param {string} message The message to log.
 */
async function logToFile(message) {
    if (!CONFIG.log_to_file) {
        return; // Logging is disabled
    }
    const logEntry = `[${new Date().toISOString()}] ${message}\n`;
    const { log_file_path, log_max_size_mb = 10 } = CONFIG;

    try {
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
        await fs.appendFile(log_file_path, logEntry);
    } catch (error) {
        console.error(`\n[FATAL LOGGING ERROR] Could not write to log file ${log_file_path}:`, error.message);
    }
}

/**
 * Formats a timestamp into a human-readable "ago" string.
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

    const disabledShowTimeMs = (CONFIG.disabled_show_total_time || 300) * 1000;

    for (const server of (CONFIG.servers || [])) {
        const state = serverStates.get(server.name);
        if (!state) continue; // Skip if state isn't initialized yet

        // Hide disabled servers after the configured time has passed
        if (!server.enabled && state.disabledTimestamp) {
            if ((Date.now() - state.disabledTimestamp) > disabledShowTimeMs) {
                continue;
            }
        }
        
        const ipPort = state.ip ? `${state.ip}:${server.port}` : 'resolving...';
        const avg = state.icmp.avg !== null ? `${state.icmp.avg.toFixed(1)}ms` : 'N/A';
        const min = state.icmp.min !== null ? `${state.icmp.min.toFixed(1)}ms` : 'N/A';
        const max = state.icmp.max !== null ? `${state.icmp.max.toFixed(1)}ms` : 'N/A';
        const tcpRatio = `${state.tcp.success}:${state.tcp.fail}`;
        
        let color, statusText;
        if (!server.enabled) {
            color = colors.red;
            statusText = 'DISABLED';
        } else {
            color = colors.reset;
            if (state.status === 'CRITICAL') color = colors.red;
            else if (state.status === 'ALERT') color = colors.yellow;
            else if (state.status === 'GOOD') color = colors.green;
            else if (state.status === 'UNREACHABLE' || state.status === 'SETUP_FAIL') color = colors.grey;
            statusText = formatTimeAgo(state.tcp.lastFailTimestamp);
        }

        output += `${color}${server.name.padEnd(22)} [${ipPort.padEnd(21)}] `;
        output += `Avg: ${avg.padEnd(8)} Min: ${min.padEnd(8)} Max: ${max.padEnd(9)} `;
        output += `TCP-S/F: ${tcpRatio.padEnd(7)} Last Fail: ${statusText.padEnd(10)}`;
        output += `${colors.reset}\n`;
    }
    output += `\n${colors.dim}Config reloads automatically. Press Ctrl+C to exit.${colors.reset}`;
    process.stdout.write(output);
}

// --- Monitoring Core Functions ---
function checkTcpPort(server, ip, state) {
    const socket = new net.Socket();
    socket.setTimeout(5000);
    const fail = (reason) => {
        state.tcp.fail++;
        state.tcp.lastFailTimestamp = Date.now();
        logToFile(`[${server.name}] TCP FAILED on ${ip}:${server.port}. Reason: ${reason}`);
        socket.destroy();
    };
    socket.on('connect', () => { state.tcp.success++; socket.destroy(); });
    socket.on('error', (err) => fail(err.message));
    socket.on('timeout', () => fail('Timeout'));
    socket.connect(server.port, ip);
}

async function checkIcmpPing(server, ip, state) {
    try {
        const res = await ping.promise.probe(ip, { times: server.icmp_pings_per_check || 1 });
        const oldStatus = state.status;
        if (!res.alive) {
            if (oldStatus !== 'UNREACHABLE') logToFile(`[${server.name}] ICMP STATUS: Host became UNREACHABLE.`);
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

async function startMonitoring(server) {
    if (serverTimers.has(server.name)) return; // Already running

    const state = serverStates.get(server.name);
    state.disabledTimestamp = null; // Clear any previous disabled timestamp

    try {
        const { address: ip } = await dns.lookup(server.address);
        state.ip = ip;
        if(state.status === 'SETUP_FAIL' || state.status === 'PENDING') state.status = 'OK';

        const timers = {};
        if (server.port && server.port_ping_frequency > 0) {
            const runCheck = () => checkTcpPort(server, ip, state);
            runCheck();
            timers.tcp = setInterval(runCheck, server.port_ping_frequency * 1000);
        }
        if (server.icmp_ping_frequency > 0) {
            const runCheck = () => checkIcmpPing(server, ip, state);
            runCheck();
            timers.icmp = setInterval(runCheck, server.icmp_ping_frequency * 1000);
        }
        serverTimers.set(server.name, timers);
    } catch (error) {
        state.status = 'SETUP_FAIL';
        state.ip = 'resolve-failed';
        logToFile(`[${server.name}] SETUP FAILED: Could not resolve "${server.address}". Error: ${error.message}`);
    }
}

function stopMonitoring(serverName) {
    if (!serverTimers.has(serverName)) return;

    const timers = serverTimers.get(serverName);
    clearInterval(timers.tcp);
    clearInterval(timers.icmp);
    serverTimers.delete(serverName);

    const state = serverStates.get(serverName);
    if (state && !state.disabledTimestamp) {
        state.disabledTimestamp = Date.now();
    }
}

/**
 * Reads the config file and starts/stops monitors as needed.
 */
async function syncMonitors() {
    let newConfig;
    try {
        const fileContent = await fs.readFile(CONFIG_FILE, 'utf-8');
        newConfig = JSON.parse(fileContent);
    } catch (error) {
        logToFile(`ERROR: Could not read or parse ${CONFIG_FILE}. No changes will be applied.`);
        return;
    }
    CONFIG = newConfig;

    const currentServerNames = new Set(CONFIG.servers.map(s => s.name));
    const previousServerNames = new Set(serverStates.keys());

    // Stop monitoring for servers that were removed or are now disabled
    for (const name of previousServerNames) {
        if (!currentServerNames.has(name)) {
            stopMonitoring(name);
            // We don't delete from serverStates immediately to allow for the graceful disable display
        }
    }

    // Start or update monitoring for all servers in the config
    for (const server of CONFIG.servers) {
        if (!serverStates.has(server.name)) {
            serverStates.set(server.name, {
                ip: null, status: 'PENDING', disabledTimestamp: null,
                tcp: { success: 0, fail: 0, lastFailTimestamp: null },
                icmp: { min: null, max: null, avg: null },
            });
        }

        if (server.enabled) {
            startMonitoring(server);
        } else {
            stopMonitoring(server.name);
        }
    }
}

async function main() {
    console.log('Initializing network monitor...');
    
    await syncMonitors(); // Initial load
    
    // Start periodic sync and render loops
    const syncInterval = setInterval(syncMonitors, CONFIG_REFRESH_INTERVAL_MS);
    const displayInterval = setInterval(renderDisplay, RENDER_INTERVAL_MS);
    
    // Graceful exit
    process.stdout.write(cursor.hide);
    process.on('SIGINT', () => {
        clearInterval(syncInterval);
        clearInterval(displayInterval);
        serverTimers.forEach(timers => {
            clearInterval(timers.tcp);
            clearInterval(timers.icmp);
        });
        process.stdout.write(cursor.toTop + cursor.clearScreen + cursor.show);
        console.log('Network monitor stopped.');
        process.exit(0);
    });
}

main();
