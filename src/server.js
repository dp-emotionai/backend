import dotenv from "dotenv"
dotenv.config()

import http from "http"
import app from "./app.js"
import { initSocket } from "./socket/server.js"

const server = http.createServer(app)

initSocket(server)

const PORT = process.env.PORT || 5000
const HOST = process.env.HOST || "0.0.0.0"

server.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`)
})