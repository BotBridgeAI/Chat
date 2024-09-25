const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const https = require('https');
const path = require('path');
const cors = require('cors');
const axios = require("axios");

const db = require('./db');

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Use the cors middleware
//app.use(cors({ origin: 'https://tigert2173.github.io/EFRO/EFROAIBETA.html' }));
// Enable CORS for all routes
app.use(cors());

const SECRET_KEY = 'your_secret_key_here'; // Replace with your secret key

// Middleware to check authentication
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Unauthorized');
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).send('Unauthorized');
        req.user = decoded;
        next();
    });
};
// Middleware to check superadmin role
const checkSuperAdmin = (req, res, next) => {
    if (req.user.role !== 'superadmin') return res.status(403).send('Forbidden');
    next();
};
// Demote Admin (Super Admin only)
app.post('/admin/demote/:id', authenticate, checkSuperAdmin, (req, res) => {
    const { id } = req.params;
    db.run('UPDATE users SET role = ? WHERE id = ?', ['user', id], function (err) {
        if (err) return res.status(500).send(err.message);
        if (this.changes === 0) return res.status(404).send('User not found');
        res.send({ message: 'User demoted to regular user successfully' });
    });
});

// Middleware to check admin role
const checkAdmin = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).send('Forbidden');
    next();
};

// Get All Users (Admin only)
app.get('/admin/users', authenticate, checkAdmin, (req, res) => {
    db.all('SELECT id, username, role FROM users', [], (err, rows) => {
        if (err) return res.status(500).send(err.message);
        res.send(rows);
    });
});
// Route to check user role
app.get('/admin/check-role', authenticate, (req, res) => {
    // Check if req.user is defined
    if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' }); // User not authenticated
    }

    // Check the user's role
    if (req.user.role === 'admin' || req.user.role === 'superadmin') {
        return res.json({ role: req.user.role });
    } else {
        return res.status(403).json({ error: 'Forbidden: Insufficient permissions' }); // Not an admin
    }
});

// Promote User to Admin (Admin only)
app.post('/admin/promote/:id', authenticate, checkAdmin, (req, res) => {
    const { id } = req.params;
    db.run('UPDATE users SET role = ? WHERE id = ?', ['admin', id], function (err) {
        if (err) return res.status(500).send(err.message);
        if (this.changes === 0) return res.status(404).send('User not found');
        res.send({ message: 'User promoted to admin successfully' });
    });
});

// User Registration
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).send(err.message);
        db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hash, 'user'], function (err) {
            if (err) return res.status(500).send(err.message);
            res.status(201).send({ id: this.lastID });
        });
    });
});

// User Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(401).send('Invalid credentials');
        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) return res.status(401).send('Invalid credentials');
            const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY);
            res.send({ token });
        });
    });
});

// Add API Link
app.post('/api-links', authenticate, (req, res) => {
    const { api_url, api_name } = req.body;
    db.run('INSERT INTO api_links (user_id, api_url, api_name) VALUES (?, ?, ?)', [req.user.id, api_url, api_name], function (err) {
        if (err) return res.status(500).send(err.message);
        res.status(201).send({ id: this.lastID });
    });
});

// Get User's API Links
app.get('/api-links', authenticate, (req, res) => {
    db.all('SELECT id, api_url, api_name FROM api_links WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).send(err.message);
        res.send(rows);
    });
});

// Get All API Links
app.get('/admin/api-links', (req, res) => {
    db.all('SELECT id, api_url, api_name FROM api_links', [], (err, rows) => {
        if (err) return res.status(500).send(err.message);
        res.send(rows);
    });
});

// Update API Link
app.put('/api-links/:id', authenticate, (req, res) => {
    const { id } = req.params;
    const { api_url, api_name } = req.body;
    db.run('UPDATE api_links SET api_url = ?, api_name = ? WHERE id = ? AND user_id = ?', [api_url, api_name, id, req.user.id], function (err) {
        if (err) return res.status(500).send(err.message);
        if (this.changes === 0) return res.status(403).send('Forbidden');
        res.send({ message: 'API link updated successfully' });
    });
});

// // Delete API Link
// app.delete('/api-links/:id', authenticate, (req, res) => {
//     const { id } = req.params;
//     db.run('DELETE FROM api_links WHERE id = ? AND user_id = ?', [id, req.user.id], function (err) {
//         if (err) return res.status(500).send(err.message);
//         if (this.changes === 0) return res.status(403).send('Forbidden');
//         res.send({ message: 'API link deleted successfully' });
//     });
// });

// Route to delete an API link (requires user to own the API or admin privileges)
app.delete('/api-links/:id', authenticate, checkAdmin, async (req, res) => {
    const apiLinkId = req.params.id;
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';

    try {
        // Check if the API link belongs to the user or if the user is an admin
        const apiLink = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM api_links WHERE id = ?', [apiLinkId], (err, row) => {
                if (err) return reject(err);
                resolve(row);
            });
        });

        if (!apiLink) {
            return res.status(404).send('API link not found');
        }

        if (apiLink.user_id !== userId && !isAdmin) {
            return res.status(403).send('Forbidden');
        }

        // Delete the API link
        db.run('DELETE FROM api_links WHERE id = ?', [apiLinkId], function (err) {
            if (err) {
                console.error('Error executing SQL query:', err.message);
                return res.status(500).send('Internal Server Error');
            }
            if (this.changes === 0) {
                return res.status(404).send('API link not found');
            }
            res.send('API link deleted successfully');
        });
    } catch (err) {
        res.status(500).send('Internal Server Error');
    }
});

// Public API to List Available Links
app.get('/public/api-links', (req, res) => {
    db.all('SELECT id, api_url, api_name FROM api_links', [], (err, rows) => {
        if (err) return res.status(500).send(err.message);
        res.send(rows);
    });
});






// =========================== \\
// Initialize servers array and message queue
let servers = [];
const messageQueue = [];

// Function to fetch and update servers from the API
async function updateServers() {
    try {
        const response = await axios.get('https://api.botbridge.net/admin/api-links');
        if (!response.data || !Array.isArray(response.data)) {
            throw new Error('Invalid data format from API.');
        }
        response.data.forEach(api => {
            const existingServer = servers.find(s => s.url === api.api_url);
            if (existingServer) {
                existingServer.url = api.api_url;
                existingServer.benchmarkSpeed = existingServer.benchmarkSpeed;
            } else {
                servers.push({
                    url: api.api_url,
                    busy: false,
                    down: true,
                    benchmarkSpeed: null,
                    benchmark: true,
                });
            }
        });
        servers = servers.filter(server => response.data.some(api => api.api_url === server.url));
        await checkAllServerStatuses();
    } catch (error) {
        console.error('Error fetching server links:', error);
    }
}

// Function to send the user's request to the selected server
async function sendMessageToServer(server, reqBody, res) {
    server.busy = true; // Mark the server as busy
    // Variable to track if the stream has started
    let streamStarted = false;

    // Timer to monitor if the stream hasn't started within 10 seconds
    const streamTimeout = setTimeout(async () => {
        if (!streamStarted) {
            console.warn(`Stream from ${server.url} didn't start within 60 seconds. Checking server status...`);

            // Check server status if the stream hasn't started
            await checkServerStatus(server);

            if (!server.down) {
                console.log(`Server ${server.url} is up. Marking as not busy.`);
                server.busy = false; // Mark the server as not busy
            } else {
                console.error(`Server ${server.url} is down.`);
               // res.status(500).send({ error: 'Server failed to start streaming.' });
            }
        }
    }, 60000); // 60 seconds timeout

    try {
        const response = await axios({
            method: 'post',
            url: server.url + "/v1/chat/completions",
            data: reqBody, // Send the entire request body
            responseType: 'stream', // Ensure we can handle streaming response
            headers: {
                'Content-Type': 'application/json' // Set content type for the request
            }
        });

        // When the stream starts
        response.data.on('data', () => {
            if (!streamStarted) {
                streamStarted = true; // Stream has started
                clearTimeout(streamTimeout); // Clear the 10-second timeout monitor
                console.log(`Stream from ${server.url} has started.`);
            }
        });

        // Pipe the response stream from the server to the response stream to the client
        response.data.pipe(res);

        // Handle stream end and reset server state
        response.data.on('end', () => {
            console.log(`Stream from ${server.url} ended.`);
            server.busy = false; // Mark the server as free
            res.end(); // End the response to the client
            // Increment the generation count
            server.generations = (server.generations || 0) + 1;
        });

        // Handle stream errors
        response.data.on('error', (err) => {
            console.error(`Error in response stream from ${server.url}: ${err.message}`);
            server.busy = false; // Free the server in case of error
            //res.status(500).send({ error: 'Error in response stream' });
        });

    } catch (error) {
        console.error(`Error sending message to ${server.url}: ${error.message}`);
        server.busy = false; // Mark the server as free on error
        server.down = true; // Mark the server as down
        //res.status(500).send({ error: `Server ${server.url} failed.` });
    }
}



// Function to check server status
async function checkServerStatus(server) {
    const testPrompt = {
        model: "gpt-3.5-turbo",
        messages: [{ role: "user", content: "." }],
        max_tokens: 1,
    };
        try {
            const response = await axios.post(server.url + "/v1/chat/completions", testPrompt);
            const benchmarkSpeed = response.headers['openai-processing-ms'];
            server.benchmarkSpeed = benchmarkSpeed ? `${benchmarkSpeed} ms` : 'N/A';
            server.down = false;
            console.log(`${server.url} is up. Benchmark Speed: ${server.benchmarkSpeed}`);
            server.benchmark = false;
        } catch (error) {
            server.down = true;
            server.busy = false;
            server.benchmarkSpeed = 'N/A';
            console.log(`${server.url} is down.`);
        } finally {
            server.busy = false; // Always set busy state to false at the end
        }
   return;
}

// Function to periodically check all server statuses
async function checkAllServerStatuses() {
    for (const server of servers) {
        if (server.down || server.benchmark && !server.busy) {
            await checkServerStatus(server);
        }
    }
    console.log('Servers updated:', servers);
}

// Load balancer logic to find the next available server
function getAvailableServer() {
    return servers.find((server) => !server.busy && !server.down);
}

const MAX_RETRIES = 45; // Maximum retries before failing

// Function to process messages in the queue
async function processQueue(retryCount = 0) {
    if (messageQueue.length === 0) return; // Exit if the queue is empty

    const availableServer = getAvailableServer();
    if (!availableServer) {
        if (retryCount >= MAX_RETRIES) {
            console.log('Max retries reached. Sending failure response to the client.');
            const { reqBody, res } = messageQueue.shift(); // Get the next message from the queue
            sendFailureResponse(res, `Failed to process after ${MAX_RETRIES} attempts. You were first in queue and a server could not be found after ${MAX_RETRIES} seconds to generate a response...`);
            return; // Exit after sending failure response
        }

        console.log('No available servers, retrying in 1 second...');
        setTimeout(() => processQueue(retryCount + 1), 1000); // Retry after 1 second
        return;
    }

    const { reqBody, res } = messageQueue.shift(); // Get the next message from the queue
    console.log(`Processing message. Queue length: ${messageQueue.length}`);

    try {
        await sendMessageToServer(availableServer, reqBody, res);
        retryCount = 0; // Reset retry count after a successful request
    } catch (error) {
        console.log(`Error processing message: ${error.message}. Re-queuing.`);
        messageQueue.unshift({ reqBody, res }); // Put the message back in the front of the queue
    }

    processQueue(0); // Continue processing without retry count
}

// Function to send a failure response back to the client
function sendFailureResponse(res, message) {
    // Send failure response to the client
    res.status(500).send({
        status: 'failed',
        message: message
    });
}


// API endpoint to handle user messages
app.post("/api/send", async (req, res) => {
    const reqBody = req.body;

    if (!reqBody) {
        return res.status(400).send({ error: "Request body is missing." });
    }

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Transfer-Encoding', 'chunked');

    messageQueue.push({ reqBody, res });
    console.log(`Message added to queue. Queue length: ${messageQueue.length}`);

    // Start processing the queue if it's not already running
    if (messageQueue.length === 1) {
        processQueue();
    }
});

// API endpoint to get server statuses
app.get("/api/servers-status", (req, res) => {
    res.json(servers);
});

// Endpoint to mark a server as not new
app.post('/api/re-benchmark', (req, res) => {
    const url = req.query.url;

    if (!url) {
        return res.status(400).send({ error: 'Server URL is required.' });
    }

    const server = servers.find(s => s.url === url);
    if (server) {
        server.benchmark = false;
        checkServerStatus(server).then(() => {
            res.send({ message: 'Server marked as not new and benchmark completed.' });
        }).catch(err => {
            res.status(500).send({ error: 'Failed to check server status.' });
        });
    } else {
        res.status(404).send({ error: 'Server not found.' });
    }
});

// API endpoint to get the number of jobs in the queue
app.get('/api/queue-status', (req, res) => {
    res.json({ queueLength: messageQueue.length });
});

// API endpoint to get the number of servers not down
app.get('/api/servers-not-down', (req, res) => {
    const notDownCount = servers.filter(server => !server.down).length;
    res.json({ notDownCount });
});

// API endpoint to get the number of servers not down
app.get('/api/servers-listed', (req, res) => {
    const listedCount = servers.length;
    res.json({ listedCount });
});

// API endpoint to get the number of servers not down
app.get('/api/servers-down', (req, res) => {
    const downCount = servers.filter(server => server.down).length;
    res.json({ downCount });
});

// Endpoint to mark a server as not busy
app.post('/api/mark-server-not-busy', (req, res) => {
    const { url } = req.query;
    const server = servers.find(s => s.url === url);
    if (server) {
        server.busy = false;
        res.status(200).send('Server marked as not busy');
    } else {
        res.status(404).send('Server not found');
    }
});
async function benchmarkFreeServers(percentage = 0.25) {
    // Get a list of servers that are not down and not busy
    const freeServers = servers.filter(server => !server.down);

    if (freeServers.length === 0) {
        console.log('No free servers available for benchmarking.');
        return;
    }

    // Determine the number of servers to benchmark based on the percentage
    const numServersToBenchmark = Math.ceil(freeServers.length * percentage);

    // Shuffle the array of free servers randomly
    for (let i = freeServers.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [freeServers[i], freeServers[j]] = [freeServers[j], freeServers[i]];
    }

    // Select the calculated number of servers to benchmark
    const randomServers = freeServers.slice(0, numServersToBenchmark);

    for (const server of randomServers) {
        await checkServerStatus(server);
    }

    console.log(`Randomly selected ${numServersToBenchmark} servers updated:`, randomServers);
}
// Start the server
// Start the server
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Load balancer running on port ${PORT}`);
    updateServers(); // Initial update
    setInterval(updateServers, 10000); // Update every 100 seconds
    setInterval(benchmarkFreeServers, 600000); // Check random selection of servers to benchmark every 10 min
    //setInterval(checkServerHealth, 5000);
});

//app.listen(3000, () => console.log('Server running on port 3000'));
// Load SSL Certificate and Private Key
const sslOptions = {
    key: fs.readFileSync('certs/private.key.pem'),
    cert: fs.readFileSync('certs/domain.cert.pem')
};

// Create HTTPS server
https.createServer(sslOptions, app).listen(443, () => {
    console.log('HTTPS Server running on port 443');
});
