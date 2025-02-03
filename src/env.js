const dotenv = require('dotenv');

dotenv.config();

module.exports = {
    DB_URL: process.env.DATABASE_URL,
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN
};