const express = require('express');
const path = require('path'); // Built-in Node.js module for working with file paths

const app = express();

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Start the server on port 80
const port = 80;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
