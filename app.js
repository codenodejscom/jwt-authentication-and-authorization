var express     = require("express"),
    mongoose    = require("mongoose"),
    bodyParser  = require("body-parser");
    
var app = express();    
var db = require('./config/db');
var AuthController = require('./controllers/authController');
app.use('/api/auth', AuthController);

module.exports = app;