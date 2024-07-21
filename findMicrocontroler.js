const { SerialPort } = require("serialport");

SerialPort.list()
	.then((ports) => {
		ports.forEach((port) => {
			console.log(
				`Path: ${port.path}, Vendor ID: ${port.vendorId}, Product ID: ${port.productId}`
			);
		});
	})
	.catch((err) => {
		console.error("Error listing serial ports:", err.message);
	});
