const express = require("express")
require('dotenv').config()
const dbConnect = require('./config/dbconnect')

const app = express()
const port = process.env.PORT || 8888
app.use(express.json())
app.use(express.urlencoded({extended: true}))
dbConnect()

app.use('/', (req, res) => { res.send('SERVER ONN') })

app.listen(port, () => { 
    console.log('Server running on the port: ' + port);
    
 })