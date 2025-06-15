import fs from 'fs/promises';

const CONFIG_FILE = 'monitor.json';

function parseArgs(args) {
    const options = {};
    let hasDeleteFlag = false;
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            if(key === 'delete') {
                hasDeleteFlag = true;
                continue;
            }
            options[key] = args[i + 1];
            i++; // Skip the value
        }
    }
    return { ...options, delete: hasDeleteFlag };
}

async function main() {
    const args = parseArgs(process.argv.slice(2));

    if (!args.name && !args.host) {
        console.error('Error: --name or --host argument is required to identify the server.');
        console.log('Example (disable): node netmon-disable.js --name "My Web Server"');
        console.log('Example (delete):  node netmon-disable.js --host "example.com:443" --delete');
        process.exit(1);
    }

    try {
        const fileContent = await fs.readFile(CONFIG_FILE, 'utf-8');
        const config = JSON.parse(fileContent);
        
        let serverIndex = -1;

        if (args.name) {
            serverIndex = config.servers.findIndex(s => s.name === args.name);
        } else if (args.host) {
            const [address, portStr] = args.host.split(':');
            const port = parseInt(portStr, 10);
            serverIndex = config.servers.findIndex(s => s.address === address && s.port === port);
        }

        if (serverIndex === -1) {
            console.error('Error: No matching server found.');
            process.exit(1);
        }
        
        const serverName = config.servers[serverIndex].name;

        if (args.delete) {
            config.servers.splice(serverIndex, 1);
            console.log(`Success! Server "${serverName}" has been deleted from ${CONFIG_FILE}.`);
        } else {
            config.servers[serverIndex].enabled = false;
            console.log(`Success! Server "${serverName}" has been disabled in ${CONFIG_FILE}.`);
        }
        
        await fs.writeFile(CONFIG_FILE, JSON.stringify(config, null, 2));

    } catch (error) {
        console.error(`Error processing ${CONFIG_FILE}:`, error.message);
        process.exit(1);
    }
}

main();
