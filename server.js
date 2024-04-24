const express = require('express');
const bodyParser = require('body-parser');
const {Client} = require ('pg');
const bcrypt = require('bycrypt');
const jwt = require('jsonwebtoken');
require ('dotenv').config();
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 4001;


// PostgreSQL connection configuration
const client = new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432, // Default PostgreSQL port
    ssl: {
        rejectUnauthorized: false, // Set to false if using self-signed certificates
        // You may need to provide other SSL options such as ca, cert, and key
        // Example:
        // ca: fs.readFileSync('path/to/ca-certificate.crt'),
        // cert: fs.readFileSync('path/to/client-certificate.crt'),
        // key: fs.readFileSync('path/to/client-certificate.key')
    },
});

app.use(bodyParser.json());
app.use(cors());
// Connect to PostgreSQL database
client.connect()
    .then(() => console.log('Connected to PostgreSQL'))
    .catch(error => console.error('Error connecting to PostgreSQL:', error));

// Helper function to hash passwords
const hashPassword = async(password) => {
    const saltRounds = 10;
    return bcrypt.hash(password,saltRounds);
};
// Helper function to compare passwords
const comparePassWords = async(plainPassword,hashedPassword) => {
    return bcrypt.compare(plainPassword,hashedPassword);
};

const generateToken = (userId) => {
    return jwt.sign({ userId},process.env.JWT_SECRET,{expiresIn: '1h'});
};

// middleware to verify JWT token
const verifyToken = (req,res,next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if(!token) {
        return res.status(401).json({sucess:false,error:'Unauthorized: No token provided'})
     }
     jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });
        }
        req.userId = decoded.userId;
        next();
    });
};