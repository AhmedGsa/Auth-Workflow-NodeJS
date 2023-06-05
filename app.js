const express = require('express');
require('dotenv').config();
require('express-async-errors');
const connectDB = require('./db/connect');
const cookieParser = require('cookie-parser');
const authRouter = require('./routes/auth');
const app = express();
// middleware
app.use(express.json());
app.use(cookieParser());
// routes
app.use('/api/v1/auth', authRouter);

const port = process.env.PORT;
const start = async () => {
    try {
        await connectDB(process.env.MONGO_URI);
        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    } catch (error) {
        console.log(error);
    }
}
start();