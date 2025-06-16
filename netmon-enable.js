import fs from 'fs/promises';

const CONFIG_FILE = 'monitor.json';

/**
 * A more robust argument parser that handles quoted values.
 * @param {string[]} processArgs - The arguments from process.argv.slice(2)
 * @returns {object} A key-value map of arguments.
 */
function parseArgs(processArgs) {
    const options = {};
    for (let i = 0; i < processArgs.length; i++) {
        const arg = processArgs[i];
        if (!arg.startsWith('--')) continue;

        const key = arg.slice(2);
        const nextArg = processArgs[i + 1];

        if (nextArg && !nextArg.startsWith('--')) {
            options[key] = nextArg.replace(/^"|"$/g, ''); // Handles quoted strings
            i++; // Skip the value argument
        } else {
            options[key] = true; // Treat flags without values as booleans
        }
    }
    return options;
}

/**
 * Tries to convert string values to their appropriate types (number, boolean).
 * @param {string} value The string value to convert.
 * @returns {string|number|boolean} The converted value.
 */
function autoType(value) {
    if (typeof value !== 'string') return value;

    if (!isNaN(value) && !isNaN(parseFloat(value))) {
        return parseFloat(value);
    }
    if (value.toLowerCase() === 'true') {
        return true;
    }
    if (value.toLowerCase() === 'false') {
        return false;
    }
    return value;
}


async function main() {
    const args = parseArgs(process.argv.slice(2));

    if (!args.name || !args.host) {
        console.error('Error: --name and --host arguments are required.');
        console.log('Example: node netmon-enable.js --name "My Server" --host "domain.com:22" --ssh_user "dev" --ssh_key "./keys/dev.key"');
        process.exit(1);
    }

    // Separate host and port
    const [address, portStr] = args.host.split(':');
    if (!address || !portStr) {
        console.error('Error: --host format must be <address>:<port>');
        process.exit(1);
    }

    // Base object
    const newServer = {
        name: args.name,
        address: address,
        port: parseInt(portStr, 10),
        enabled: true,
    };

    // Dynamically add all other provided flags
    for (const key in args) {
        if (key !== 'name' && key !== 'host') {
            newServer[key] = autoType(args[key]);
        }
    }
    
    // Set defaults if not provided
    if (newServer.port_ping_frequency === undefined) newServer.port_ping_frequency = 15;
    if (newServer.icmp_ping_frequency === undefined) newServer.icmp_ping_frequency = 10;


    try {
        const fileContent = await fs.readFile(CONFIG_FILE, 'utf-8');
        const config = JSON.parse(fileContent);

        const serverIndex = config.servers.findIndex(s => s.name === newServer.name);
        if (serverIndex !== -1) {
            console.log(`Server "${newServer.name}" already exists. Updating it.`);
            // Merge new properties into the existing server config
            config.servers[serverIndex] = { ...config.servers[serverIndex], ...newServer };
        } else {
            console.log(`Adding new server "${newServer.name}".`);
            config.servers.push(newServer);
        }

        await fs.writeFile(CONFIG_FILE, JSON.stringify(config, null, 2));
        console.log(`Success! ${CONFIG_FILE} updated.`);

    } catch (error) {
        console.error(`Error processing ${CONFIG_FILE}:`, error.message);
        process.exit(1);
    }
}

main();
