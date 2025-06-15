import fs from 'fs/promises';

const CONFIG_FILE = 'monitor.json';

function parseArgs(args) {
    const options = {};
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            options[key] = args[i + 1];
            i++; // Skip the value
        }
    }
    return options;
}

async function main() {
    const args = parseArgs(process.argv.slice(2));

    if (!args.name || !args.host) {
        console.error('Error: --name and --host arguments are required.');
        console.log('Example: node netmon-add.js --name "My Web Server" --host "example.com:443" --icmp_ping_frequency 15');
        process.exit(1);
    }

    const [address, portStr] = args.host.split(':');
    if (!address || !portStr) {
        console.error('Error: --host format must be <address>:<port>');
        process.exit(1);
    }

    const newServer = {
        name: args.name,
        address: address,
        port: parseInt(portStr, 10),
        port_ping_frequency: parseInt(args.port_ping_frequency || 15, 10),
        icmp_ping_frequency: parseInt(args.icmp_ping_frequency || 10, 10),
        icmp_pings_per_check: parseInt(args.icmp_pings_per_check || 3, 10),
        enabled: true,
    };

    try {
        const fileContent = await fs.readFile(CONFIG_FILE, 'utf-8');
        const config = JSON.parse(fileContent);

        // Check for duplicates
        if (config.servers.some(s => s.name === newServer.name)) {
            console.error(`Error: A server with the name "${newServer.name}" already exists.`);
            process.exit(1);
        }

        config.servers.push(newServer);
        await fs.writeFile(CONFIG_FILE, JSON.stringify(config, null, 2));
        console.log(`Success! Server "${newServer.name}" added to ${CONFIG_FILE}.`);

    } catch (error) {
        console.error(`Error processing ${CONFIG_FILE}:`, error.message);
        process.exit(1);
    }
}

main();
