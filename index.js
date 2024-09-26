const express = require("express");
const path = require("path");
const { Pool } = require("pg"); // Import the Pool constructor
const { DATABASE_URL, SECRET_KEY } = process.env;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors"); // Import cors
require("dotenv").config();

const app = express();
app.use(cors()); // Enable cors
app.use(express.json());

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Function to get PostgreSQL version (for testing)
async function getPostgresVersion() {
  try {
    const client = await pool.connect();
    const response = await client.query("SELECT version()");
    console.log("PostgreSQL version:", response.rows[0].version);
    client.release();
  } catch (err) {
    console.error("Error getting PostgreSQL version:", err);
  }
}
getPostgresVersion();

// User Signup Endpoint
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = await pool.connect();
    const hashedPassword = await bcrypt.hash(password, 12); // Hash password

    try {
      const userResult = await client.query(
        "SELECT * FROM users WHERE username = $1",
        [username],
      );

      if (userResult.rows.length > 0) {
        return res.status(400).json({ message: "Username already exists" });
      }

      await client.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [username, hashedPassword],
      );
      res.status(201).json({ message: "User created successfully" });
    } catch (err) {
      console.error("Error inserting user:", err);
      res.status(500).json({ message: "Internal server error" });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Error connecting to database:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
//LOGIIN
app.post('/login', async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [req.body.username]);

    const user = result.rows[0];

    if (!user) return res.status(400).json({ message: "Username or password incorrect" });

    const passwordIsValid = await bcrypt.compare(req.body.password, user.password);
    if (!passwordIsValid) return res.status(401).json({ auth: false, token: null });

    var token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: 86400 });
    res.status(200).json({ auth: true, token: token });
  } catch (error) {
    console.error('Error: ', error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});
// Simple endpoint to test the server (you can remove this later)
app.get("/", (req, res) => res.sendFile(path.join(__dirname + "/index.html")));

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
