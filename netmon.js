import fs from 'fs/promises';
import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import ping from 'ping';
import blessed from 'blessed';
import dns from 'dns/promises';
import { performance } from 'perf_hooks';

// --- Constants ---
const CONFIG_FILE = 'monitor.json';
const SSL_LOG_FILE = 'ssl-verified.json';
const RENDER_INTERVAL_MS = 1000;
const CONFIG_REFRESH_INTERVAL_MS = 5000;

// --- State and Config Management ---
let CONFIG = {};
const serverStates = new Map();
const serverTimers = new Map();
const alertQueue = [];

// --- UI Elements ---
const screen = blessed.screen({ smartCSR: true, title: 'Network Monitor' });
const serverList = blessed.box({ top: 0, left: 0, width: '100%', height: '70%-1', scrollable: true, alwaysScroll: true, keys: true, vi: true, mouse: true, border: { type: 'line' }, label: ' Monitored IP Endpoints ', tags: true });
const alertLog = blessed.log({ top: '70%', left: 0, width: '100%', height: '30%-1', border: { type: 'line' }, label: ' Alerts & Events ', scrollable: true, alwaysScroll: true, keys: true, vi: true, mouse: true, tags: true });
const inputBox = blessed.textbox({ bottom: 0, left: 0, height: 1, width: '100%', inputOnFocus: true, style: { fg: 'white', bg: 'blue' }, prompt: '> ' });

// --- System & UI Functions ---
function shutdown() {
    serverTimers.forEach(timers => { clearInterval(timers.main); clearInterval(timers.icmp); });
    screen.destroy();
    process.exit(0);
}

function setupUI() {
    screen.append(serverList);
    screen.append(alertLog);
    screen.append(inputBox);
    inputBox.on('submit', (text) => { handleCommand(text); inputBox.clearValue(); screen.render(); inputBox.focus(); });
    screen.key(['escape', 'q', 'C-c'], () => shutdown());
    screen.key(['tab'], () => screen.focusNext());
    screen.key(['S-tab'], () => screen.focusPrevious());
    logAlert('SYSTEM', `Welcome! Type 'cmd' for commands, or 'exit' (or press Ctrl+C) to quit.`);
    inputBox.focus();
    screen.render();
}

// --- Logging & Alerting ---
function logAlert(serverName, message) {
    const timestamp = new Date().toLocaleTimeString();
    const entry = `{grey-fg}[${timestamp}]{/grey-fg} {bold}${serverName}:{/bold} ${message}`;
    alertQueue.push(entry);
    const maxAlerts = CONFIG.total_display_alerts || 10;
    while (alertQueue.length > maxAlerts) { alertQueue.shift(); }
    alertLog.setContent(alertQueue.join('\n'));
    alertLog.setScrollPerc(100);
    logToFile(`${serverName}: ${message}`);
}

async function logToFile(message) {
    if (!CONFIG.log_to_file) return;
    const cleanMessage = message.replace(/{[^{}]+}/g, '');
    const logEntry = `[${new Date().toISOString()}] ${cleanMessage}\n`;
    try {
        const stats = await fs.stat(CONFIG.log_file_path).catch(() => ({ size: 0 }));
        if (stats.size > (CONFIG.log_max_size_mb || 10) * 1024 * 1024) await fs.truncate(CONFIG.log_file_path, 0);
        await fs.appendFile(CONFIG.log_file_path, logEntry);
    } catch (e) { /* silent fail */ }
}

// --- Command Handling ---
async function handleCommand(command) {
    const [cmd, ...args] = command.trim().split(/\s+/);
    const argString = args.join(' ');
    const parseArgs = (s) => { const o = {}; (s.match(/--[a-zA-Z_]+(\s+".*?"|\s+\S+)/g) || []).forEach(m => { const [k, ...v] = m.slice(2).split(/\s+/); o[k] = v.join(' ').replace(/"/g, ''); }); return o; };
    const parsedArgs = parseArgs(argString);
    switch (cmd.toLowerCase()) {
        case 'cmd': case 'help':
            logAlert('CMD', "Commands: {yellow-fg}enable, disable, cmd/help, clear, exit{/}"); break;
        case 'exit': case 'quit': shutdown(); break;
        case 'clear': alertQueue.length = 0; alertLog.setContent(''); break;
        case 'enable':
            try {
                if (!parsedArgs.name || !parsedArgs.host) throw new Error("`--name` and `--host` are required.");
                const [address, port] = parsedArgs.host.split(':');
                const newServer = { name: parsedArgs.name, address, port: parseInt(port), enabled: true, check_tls: parsedArgs.check_tls === 'true', port_ping_frequency: parseInt(parsedArgs.port_ping_frequency || 15), icmp_ping_frequency: parseInt(parsedArgs.icmp_ping_frequency || 10), icmp_pings_per_check: parseInt(parsedArgs.icmp_pings_per_check || 3) };
                let conf = JSON.parse(await fs.readFile(CONFIG_FILE, 'utf-8'));
                if (conf.servers.some(s => s.name === newServer.name)) throw new Error(`Server name "${newServer.name}" exists.`);
                conf.servers.push(newServer);
                await fs.writeFile(CONFIG_FILE, JSON.stringify(conf, null, 2));
                logAlert('CMD', `{green-fg}Enabled: ${newServer.name}{/}`);
            } catch (e) { logAlert('CMD ERROR', `{red-fg}${e.message}{/}`); } break;
        case 'disable':
            try {
                if (!parsedArgs.name) throw new Error("`--name` is required.");
                let conf = JSON.parse(await fs.readFile(CONFIG_FILE, 'utf-8'));
                const i = conf.servers.findIndex(s => s.name === parsedArgs.name);
                if (i === -1) throw new Error(`Server "${parsedArgs.name}" not found.`);
                if (argString.includes('--delete')) { conf.servers.splice(i, 1); logAlert('CMD', `{yellow-fg}Deleted: ${parsedArgs.name}{/}`); }
                else { conf.servers[i].enabled = false; logAlert('CMD', `{yellow-fg}Disabled: ${parsedArgs.name}{/}`); }
                await fs.writeFile(CONFIG_FILE, JSON.stringify(conf, null, 2));
            } catch (e) { logAlert('CMD ERROR', `{red-fg}${e.message}{/}`); } break;
        default: if (cmd) logAlert('CMD', `Unknown cmd: '${cmd}'.`);
    }
}

// --- Monitoring Core ---
async function updateSslLog(serverConfig, ip, cert) {
    let sslLog = {};
    try { sslLog = JSON.parse(await fs.readFile(SSL_LOG_FILE, 'utf-8')); } catch (e) { }
    const certPEM = `-----BEGIN CERTIFICATE-----\n${Buffer.from(cert.raw).toString('base64')}\n-----END CERTIFICATE-----`;
    const hash = crypto.createHash('sha512').update(certPEM).digest('hex');
    const uniqueName = `${serverConfig.name} (${ip})`;
    if (!sslLog[uniqueName]) sslLog[uniqueName] = [];
    if (!sslLog[uniqueName].some(entry => entry.id === hash)) {
        sslLog[uniqueName].push({ id: hash, entry_date: new Date().toISOString(), subject: cert.subject, issuer: cert.issuer, valid_from: cert.valid_from, valid_to: cert.valid_to, certificate: certPEM });
        await fs.writeFile(SSL_LOG_FILE, JSON.stringify(sslLog, null, 2));
    }
}

function updateStatusBasedOnLatency(state, latency) {
    const { originalConfig } = state;
    let newStatus = 'GOOD';
    if (latency >= (originalConfig.critical_display_ms || 500)) newStatus = 'CRITICAL';
    else if (latency >= (originalConfig.alert_display_ms || 250)) newStatus = 'ALERT';
    if ((newStatus === 'ALERT' || newStatus === 'CRITICAL') && state.status !== newStatus) {
        logAlert(state.displayName, `{yellow-fg}HIGH LATENCY: ${latency.toFixed(1)}ms{/yellow-fg}`);
    }
    if (state.status !== 'CRITICAL') { state.status = newStatus; }
}

function checkTls(serverConfig, ip, state) {
    const startTime = performance.now();
    const socket = tls.connect(serverConfig.port, ip, { servername: net.isIP(serverConfig.address) ? undefined : serverConfig.address, rejectUnauthorized: false }, () => {
        state.connTime = performance.now() - startTime;
        updateStatusBasedOnLatency(state, state.connTime);
        const cert = socket.getPeerCertificate(true);
        if (!cert || Object.keys(cert).length === 0) {
            state.status = 'TLS_FAIL'; state.sslInfo = 'No Cert';
            socket.destroy(); return;
        }
        state.sslInfo = 'OK'; // Simplified success status
        const certPEM = `-----BEGIN CERTIFICATE-----\n${Buffer.from(cert.raw).toString('base64')}\n-----END CERTIFICATE-----`;
        const newHash = crypto.createHash('sha512').update(certPEM).digest('hex');
        if (state.sslHash && state.sslHash !== newHash) {
            state.status = 'CRITICAL'; logAlert(state.displayName, `{red-bg}CRITICAL: SSL certificate hash changed!{/}`);
        }
        state.sslHash = newHash;
        updateSslLog(serverConfig, ip, cert);
        socket.destroy();
    });
    socket.on('error', (err) => { state.status = 'TLS_FAIL'; state.sslInfo = 'FAIL'; state.connTime = null; socket.destroy(); });
    socket.setTimeout(8000, () => { state.status = 'TLS_FAIL'; state.sslInfo = 'Timeout'; state.connTime = null; socket.destroy(); });
}

function checkTcpPort(serverConfig, ip, state) {
    const startTime = performance.now();
    const socket = new net.Socket();
    socket.setTimeout(5000);
    socket.on('connect', () => {
        state.connTime = performance.now() - startTime;
        updateStatusBasedOnLatency(state, state.connTime);
        state.tcp.success++;
        socket.destroy();
    });
    socket.on('error', (err) => { state.tcp.fail++; logAlert(state.displayName, `{red-fg}TCP FAIL: ${err.message}{/}`); socket.destroy(); });
    socket.on('timeout', () => { state.tcp.fail++; logAlert(state.displayName, `{red-fg}TCP FAIL: Timeout{/}`); socket.destroy(); });
    socket.connect(serverConfig.port, ip);
}

async function checkIcmpPing(serverConfig, ip, state) {
    const probeOptions = { times: serverConfig.icmp_pings_per_check || 1, ipv6: state.ipFamily === 6 };
    try {
        const res = await ping.promise.probe(ip, probeOptions);
        if (!res.alive) {
            if (state.status !== 'UNREACHABLE') logAlert(state.displayName, `Host became UNREACHABLE.`);
            state.status = 'UNREACHABLE'; return;
        }
        const avgLatency = parseFloat(res.avg);
        updateStatusBasedOnLatency(state, avgLatency);
        state.icmp.avg = avgLatency;
    } catch (e) { /* silent fail */ }
}

function startMonitoring(target) {
    const { uniqueId, ip, ipFamily, originalConfig } = target;
    if (serverTimers.has(uniqueId)) return;

    const displayName = `${originalConfig.name} (${ipFamily === 6 ? 'v6' : 'v4'})`;
    serverStates.set(uniqueId, {
        uniqueId, ip, ipFamily, displayName, originalConfig,
        status: 'PENDING', disabledTimestamp: null, sslHash: null, sslInfo: null,
        tcp: { success: 0, fail: 0 }, icmp: { avg: null }, connTime: null
    });

    const timers = {};
    const checkFunc = originalConfig.check_tls ? checkTls : checkTcpPort;

    if (originalConfig.port && originalConfig.port_ping_frequency > 0) {
        const runCheck = () => {
            const currentState = serverStates.get(uniqueId);
            if (currentState && !currentState.disabledTimestamp) {
                checkFunc(originalConfig, ip, currentState);
            }
        };
        runCheck();
        timers.main = setInterval(runCheck, originalConfig.port_ping_frequency * 1000);
    }
    if (originalConfig.icmp_ping_frequency > 0) {
        const runIcmp = () => {
            const currentState = serverStates.get(uniqueId);
            if (currentState && !currentState.disabledTimestamp) {
                checkIcmpPing(originalConfig, ip, currentState);
            }
        };
        runIcmp();
        timers.icmp = setInterval(runIcmp, originalConfig.icmp_ping_frequency * 1000);
    }
    serverTimers.set(uniqueId, timers);
}

function stopMonitoring(uniqueId) {
    if (!serverTimers.has(uniqueId)) return;
    const timers = serverTimers.get(uniqueId);
    clearInterval(timers.main);
    clearInterval(timers.icmp);
    serverTimers.delete(uniqueId);
    const state = serverStates.get(uniqueId);
    if (state) state.disabledTimestamp = Date.now();
}

// --- Main Loop and Sync ---
function renderDisplay() {
    const lines = [];
    const disabledShowTimeMs = (CONFIG.disabled_show_total_time || 300) * 1000;
    const sortedStates = Array.from(serverStates.values()).sort((a, b) => a.displayName.localeCompare(b.displayName));

    for (const state of sortedStates) {
        if (state.disabledTimestamp && (Date.now() - state.disabledTimestamp) > disabledShowTimeMs) continue;
        const port = state.originalConfig.port;
        let latencyString;
        if (state.icmp.avg !== null) {
            latencyString = `${state.icmp.avg.toFixed(1)}ms (ICMP)`;
        } else if (state.connTime !== null) {
            latencyString = `${state.connTime.toFixed(1)}ms (TCP)`;
        } else {
            latencyString = 'Checking...';
        }
        const ssl = state.originalConfig.check_tls ? `SSL: ${state.sslInfo || 'Checking...'}` : '';
        let color = 'white';
        if (state.disabledTimestamp) color = 'red';
        else if (state.status === 'CRITICAL' || state.status === 'TLS_FAIL') color = 'red';
        else if (state.status === 'ALERT') color = 'yellow';
        else if (state.status === 'GOOD' || state.status === 'OK') color = 'green';
        else if (state.status === 'UNREACHABLE' || state.status === 'SETUP_FAIL') color = 'grey';
        let line = `{${color}-fg}${state.displayName.padEnd(25)} [${state.ip.padEnd(39)}:${String(port).padEnd(5)}] Latency: ${latencyString.padEnd(15)} ${ssl.padEnd(15)}{/${color}-fg}`;
        if (state.disabledTimestamp) line += `{red-bg} STOPPED {/}`;
        lines.push(line);
    }
    serverList.setContent(lines.join('\n'));
    screen.render();
}

async function syncMonitors() {
    let newConfig;
    try { newConfig = JSON.parse(await fs.readFile(CONFIG_FILE, 'utf-8')); } catch (e) { return; }
    CONFIG = newConfig;
    const allTargetMonitors = new Map();
    for (const server of CONFIG.servers) {
        if (!server.enabled) continue;
        const resolutions = await Promise.allSettled([
            dns.resolve4(server.address).catch(() => []), dns.resolve6(server.address).catch(() => [])
        ]);
        let ipsV4 = resolutions[0].status === 'fulfilled' ? resolutions[0].value : [];
        let ipsV6 = resolutions[1].status === 'fulfilled' ? resolutions[1].value : [];
        if (net.isIP(server.address) === 4) ipsV4.push(server.address);
        else if (net.isIP(server.address) === 6) ipsV6.push(server.address);
        new Set(ipsV4).forEach(ip => { allTargetMonitors.set(`${server.name}-${ip}`, { uniqueId: `${server.name}-${ip}`, ip, ipFamily: 4, originalConfig: server }); });
        new Set(ipsV6).forEach(ip => { allTargetMonitors.set(`${server.name}-${ip}`, { uniqueId: `${server.name}-${ip}`, ip, ipFamily: 6, originalConfig: server }); });
    }
    const runningMonitorIds = new Set(serverTimers.keys());
    for (const runningId of runningMonitorIds) { if (!allTargetMonitors.has(runningId)) { stopMonitoring(runningId); } }
    for (const target of allTargetMonitors.values()) { if (!runningMonitorIds.has(target.uniqueId)) { startMonitoring(target); } }
}

// Start the application
function main() {
    setupUI();
    syncMonitors();
    setInterval(syncMonitors, CONFIG_REFRESH_INTERVAL_MS);
    setInterval(renderDisplay, RENDER_INTERVAL_MS);
}

main();
