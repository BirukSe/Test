import express from 'express';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables

const app = express();

// Database connection
const db = new pg.Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

db.connect()
    .then(() => console.log("Database connected successfully"))
    .catch(err => console.error("Database connection error:", err));

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Register route
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await db.query(
            'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
            [name, email, hashedPassword]
        );

        const user = result.rows[0];
        res.status(201).json({ message: "User created successfully", user });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: "User creation failed", details: error.message });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
        res.json({ message: "Login successful", token });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: "Login failed" });
    }
});

// Post creation route
app.post('/api/posts', async (req, res) => {
    const { title, text } = req.body;

    if (!title || !text) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const result = await db.query(
            'INSERT INTO posts (title, text) VALUES ($1, $2) RETURNING *',
            [title, text]
        );

        const post = result.rows[0];
        res.status(201).json({ message: "Post created successfully", post });
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ error: "Post creation failed", details: error.message });
    }
});

// Get all posts
app.get('/api/posts', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM posts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ error: "Failed to fetch posts", details: error.message });
    }
});

// Export the app for Vercel
export default app;
