const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const { SerialPort, ReadlineParser } = require("serialport");
const cors = require("cors");
const dotenv = require("dotenv");

// Load environment variables from .env file
dotenv.config();

const app = express();
const server = http.createServer(app);

const io = socketIo(server, {
	cors: {
		origin: `http://${process.env.LOCAL_IP}:3000`,
		methods: ["GET", "POST"],
		credentials: true,
	},
});

const corsOptions = {
	origin: [
		`http://${process.env.LOCAL_IP}:3000`,
		"http://localhost:3000", // Add localhost as an allowed origin
	],
	credentials: true,
};

// Enable CORS for all origins
app.use(cors(corsOptions));

const vendorId = process.env.VENDOR_ID;
const productId = process.env.PRODUCT_ID;

let connectedPorts = new Set();

function connectSerialPort(portPath) {
	const port = new SerialPort({ path: portPath, baudRate: 115200 }, (err) => {
		if (err) {
			console.error(`Error opening serial port ${portPath}:`, err.message);
			return;
		}
		connectedPorts.add(portPath);
		console.log("USB Connected:", portPath);

		const parser = port.pipe(new ReadlineParser({ delimiter: "\r\n" }));

		parser.on("data", (data) => {
			if (isValidJson(data)) {
				try {
					const json = JSON.parse(data);
					console.log("JSON data received:", json); // Log JSON data for debugging

					// Simulate the start of data generation
					io.emit("pixel-art", { loading: true });

					// Emit the actual JSON data
					setTimeout(() => {
						io.emit("pixel-art", { loading: false });
						io.emit("pixel-art", json); // Emit the JSON data to all connected clients
					}, 500); // Simulate some delay, adjust as necessary
				} catch (err) {
					console.error(
						"Error parsing JSON:",
						err.message,
						"Data received:",
						data
					);
				}
			} else {
				console.log("Non-JSON data received:", data);
			}
		});

		port.on("error", (err) => {
			console.error("Serial port error:", err.message);
			connectedPorts.delete(portPath);
			// Try to reconnect
			setTimeout(findAndConnectSerialPort, 5000);
		});

		port.on("close", () => {
			console.log("Serial port closed:", portPath);
			connectedPorts.delete(portPath);
		});
	});
}

function findAndConnectSerialPort() {
	SerialPort.list()
		.then((ports) => {
			ports.forEach((port) => {
				if (
					port.vendorId === vendorId &&
					port.productId === productId &&
					!connectedPorts.has(port.path)
				) {
					connectSerialPort(port.path);
				}
			});
		})
		.catch((err) => {
			console.error("Error listing serial ports:", err.message);
		});
}

// Find and connect to the serial port at startup
findAndConnectSerialPort();

// Periodically check for new devices every 10 seconds
setInterval(findAndConnectSerialPort, 10000);

io.on("connection", (socket) => {
	console.log("Client connected");
	socket.on("disconnect", () => {
		console.log("Client disconnected");
	});
});

server.listen(4000, () => {
	console.log("Listening on port 4000");
});

// Helper function to check if a string is valid JSON
function isValidJson(str) {
	try {
		JSON.parse(str);
		return true;
	} catch (e) {
		return false;
	}
}
