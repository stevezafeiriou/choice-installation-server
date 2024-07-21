# Choice Installation Application Documentation

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
- [Components](#components)
  - [Server](#server)
  - [findMicrocontroller](#findmicrocontroller)
  - [PHP Endpoints](#php-endpoints)
- [Configuration](#configuration)
- [Notes](#notes)

## Introduction

The Choice Installation Application is designed to interact with an ESP32-S3 microcontroller to generate and display interactive generative art. The system includes a Node.js server for handling real-time data via WebSockets and a WordPress backend for storing and retrieving image data.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/saphirelabs/choice-installation-server.git
   cd choice-installation-server
   ```
2. **Install Node.js dependencies**:
   ```bash
   npm install
   ```
3. **Create and configure `.env` file**:
   ```env
   LOCAL_IP=your_local_ip
   VENDOR_ID=your_vendor_id
   PRODUCT_ID=your_product_id
   ```
4. **Upload `functions.php` to your WordPress theme or child theme directory**.

5. **Adjust `Access-Control-Allow-Origin` and `get_firmware_data()` function to include file to the .bin file**.

## Usage

1. **Start the Node.js server**:
   ```bash
   node server.js
   ```
2. **Run the `findMicrocontroller.js` script to list available serial ports**:
   ```bash
   node findMicrocontroller.js
   ```

## Components

### Server

Handles serial communication with the ESP32-S3 microcontroller and broadcasts real-time pixel art data via WebSockets.

#### Code

```javascript
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
	origin: [`http://${process.env.LOCAL_IP}:3000`, "http://localhost:3000"],
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
					console.log("JSON data received:", json);

					// Simulate the start of data generation
					io.emit("pixel-art", { loading: true });

					// Emit the actual JSON data
					setTimeout(() => {
						io.emit("pixel-art", { loading: false });
						io.emit("pixel-art", json);
					}, 500); // Adjust delay as necessary
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

function isValidJson(str) {
	try {
		JSON.parse(str);
		return true;
	} catch (e) {
		return false;
	}
}
```

### findMicrocontroller

Lists available serial ports and their details.

#### Code

```javascript
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
```

### PHP Endpoints

Defines custom REST API endpoints for handling image data and subscriptions in WordPress.

#### Code

```php
<?php
/* CHOICE IMPLEMENTATION ENDPOINTS START HERE */

//GET AND POST ITEMS

// Register custom endpoint for handling POST request to create a new image
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/image-data/', array(
        'methods' => 'POST',
        'callback' => 'create_custom_image',
        'args' => array(
            'chip_id' => array(
                'required' => true,
            ),
        ),
    ));
});

// Callback function for handling POST request to create a new image
function create_custom_image($data) {
    global $wpdb;
    $imageData = $data->get_params();

    // Validate input data
    if (empty($imageData['id']) || empty($imageData['image']) || empty($imageData['chip_id'])) {
        return new WP_Error('invalid_data', 'ID, Image data, and Chip ID are required.', array('status' => 400));
    }

    // Sanitize data
    $id = sanitize_text_field($imageData['id']);
    $description = sanitize_text_field($imageData['description']);
    $image = sanitize_textarea_field($imageData['image']);
    $name = sanitize_text_field($imageData['name']);
    $artist = sanitize_text_field($imageData['artist']);
    $attributes = maybe_serialize($imageData['attributes']);
    $chip_id = sanitize_text_field($imageData['chip_id']);

    // Check if the chip_id exists in the registered devices table
    $table_name_devices = $wpdb->prefix . 'registered_devices';
    $device = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name_devices WHERE chip_id = %s", $chip_id), ARRAY_A);

    if (!$device) {
        return new WP_Error('invalid_chip_id', 'Chip ID does not exist.', array('status' => 403));
    }

    $chip_id_edition = $device['edition'];

    // Check if the image already exists based on ID or image data URL
    $table_name_images = $wpdb->prefix . 'custom_images';
    $existing_image = $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM $table_name_images WHERE id = %s OR image = %s", $id, $image),
        ARRAY_A
    );

    if ($existing_image) {
        return new WP_Error('image_exists', 'Image already exists.', array('status' => 400));
    }

    // Insert the new image record with created_by_chip_id and chip_id_edition
    $wpdb->insert(
        $table_name_images,
        array(
            'id' => $id,
            'description' => $description,
            'image' => $image,
            'name' => $name,
            'artist' => $artist,
            'attributes' => $attributes,
            'created_by_chip_id' => $chip_id, // Add this line
            'chip_id_edition' => $chip_id_edition, // Add this line
            'validated' => false,
            'created_at' => current_time('mysql'), // Use current timestamp
        )
    );

    // Delete unvalidated images older than 15 minutes
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM $table_name_images WHERE validated = 0 AND created_at < %s",
            date('Y-m-d H:i:s', strtotime('-15 minutes'))
        )
    );

    return 'Image added successfully. Unvalidated images older than 15 minutes have been deleted.';
}

// Register custom endpoint for handling GET all items request
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/image-data/', array(
        'methods' => 'GET',
        'callback' => 'get_all_custom_images',


 ));
});

// Callback function for handling GET all items request
function get_all_custom_images() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images';

    $results = $wpdb->get_results("SELECT * FROM $table_name", ARRAY_A);

    // Get the current time
    $current_time = current_time('mysql');
    $current_time_unix = strtotime($current_time);

    foreach ($results as &$result) {
        // Calculate the time difference
        $created_at_unix = strtotime($result['created_at']);
        $time_diff_seconds = $current_time_unix - $created_at_unix;
        $time_diff_human = human_time_diff($created_at_unix, $current_time_unix);

        // Add time information to the result
        $result['current_time'] = $current_time;
        $result['time_since_creation'] = $time_diff_human;

        // Unserialize the attributes field and extract the Acceleration trait
        $attributes = unserialize($result['attributes']);
        foreach ($attributes as $attribute) {
            if ($attribute['trait_type'] === 'Acceleration') {
                $result['acceleration'] = $attribute['value'];
                break;
            }
        }

        // Remove the attributes field
        unset($result['attributes']);
    }

    return $results;
}

// Register custom endpoint for handling GET by ID request
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/image-data/(?P<id>\S+)', array(
        'methods' => 'GET',
        'callback' => 'get_custom_image_by_id',
    ));
});

// Callback function for handling GET by ID request
function get_custom_image_by_id($data) {
    $id = $data['id'];

    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images';

    $result = $wpdb->get_row($wpdb->prepare("SELECT id, description, image, name, artist, validated, created_at, created_by_chip_id, chip_id_edition, attributes FROM $table_name WHERE id = %s", $id), ARRAY_A);

    if (!$result) {
        return new WP_Error('not_found', 'Image not found', array('status' => 404));
    }

    // Unserialize the attributes field and extract the Acceleration trait
    $attributes = unserialize($result['attributes']);
    foreach ($attributes as $attribute) {
        if ($attribute['trait_type'] === 'Acceleration') {
            $result['acceleration'] = $attribute['value'];
            break;
        }
    }

    // Remove the attributes field
    unset($result['attributes']);

    return $result;
}

// Register custom endpoint for handling DELETE by ID request
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/image-data/(?P<id>\S+)', array(
        'methods' => 'DELETE',
        'callback' => 'delete_custom_image_by_id',
    ));
});

// Callback function for handling DELETE by ID request
function delete_custom_image_by_id($data) {
    $id = $data['id'];

    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images';

    $wpdb->delete($table_name, array('id' => $id));

    return 'Image deleted successfully.';
}

// Register custom endpoint for handling POST request to validate an image
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/image-data/validate/', array(
        'methods' => 'POST',
        'callback' => 'validate_custom_image',
    ));
});

// Callback function for handling POST request to validate an image
function validate_custom_image($data) {
    $id = sanitize_text_field($data['id']);

    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images';

    // Check if the image is already validated
    $image = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE id = %s", $id), ARRAY_A);

    if (!$image) {
        return new WP_Error('image_not_found', 'Image not found', array('status' => 404));
    }

    if ($image['validated']) {
        return 'Image already validated.';
    }

    // Update validation status
    $result = $wpdb->update(
        $table_name,
        array('validated' => true),
        array('id' => $id),
        array('%d'),
        array('%s')
    );

    if ($result === false) {
        return new WP_Error('db_update_error', 'Failed to update validation status.', array('status' => 500));
    }

    return 'Image validated successfully.';
}

// Function to add CORS headers
function add_cors_http_header() {
    // List of allowed origins
    $allowed_origins = [
        'http://192.168.237.249:3000',
        'http://192.168.237.253:3000',
    ];

    // Get the origin of the request
    $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

    // Check if the origin is in the allowed origins list
    if (in_array($origin, $allowed_origins)) {
        header("Access-Control-Allow-Origin: $origin");
    } else {
        header("Access-Control-Allow-Origin: 'none'");
    }

    header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With");
}

add_action('rest_api_init', 'add_cors_http_header');
add_action('wp_head', 'add_cors_http_header');
add_action('wp_footer', 'add_cors_http_header');

// Handle preflight requests
function handle_preflight() {
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        // List of allowed origins
        $allowed_origins = [
            'http://192.168.237.249:3000',
            'http://192.168.237.253:3000',
        ];

        // Get the origin of the request
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

        // Check if the origin is in the allowed origins list
        if (in_array($origin, $allowed_origins)) {
            header("Access-Control-Allow-Origin: $origin");
        } else {
            header("Access-Control-Allow-Origin: 'none'");
        }

        header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE");
        header("Access-Control-Allow-Credentials: true");
        header("Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With");
        exit;
    }
}

add_action('init', 'handle_preflight');

// Retrieve the most recent unvalidated images
function get_recent_unvalidated_images() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images';

    $query = $wpdb->prepare(
        "SELECT id, description, image, name, artist, validated, created_at, created_by_chip_id, chip_id_edition, attributes FROM $table_name WHERE validated = 0 ORDER BY created_at DESC LIMIT %d",
        5
    );

    $results = $wpdb->get_results($query, ARRAY_A);

    $current_time = current_time('mysql');
    $current_time_unix = strtotime($current_time);

    if (empty($results)) {
        return new WP_Error('no_unvalidated_images', 'No unvalidated images found.', array('status' => 404));
    }

    foreach ($results as &$result) {
        $created_at_unix = strtotime($result['created_at']);
        $time_diff_seconds = $current_time_unix - $created_at_unix;
        $time_diff_human = human_time_diff($created_at_unix, $current_time_unix);

        $result['current_time'] = $current_time;
        $result['time_since_creation'] = $time_diff_human;

        $attributes = unserialize($result['attributes']);
        foreach ($attributes as $attribute) {
            if ($attribute['trait_type'] === 'Acceleration') {
                $result['acceleration'] = $attribute['value'];
                break;
            }
        }

        unset($result['attributes']);
    }

    return $results;
}

add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/recent-unvalidated-images', array(
        'methods' => 'GET',
        'callback' => 'get_recent_unvalidated_images',
        'permission_callback' => '__return_true',
    ));
    error_log(print_r(rest_get_server()->get_routes(), true));
});

// Register custom REST API route for firmware data
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/firmware', array(
        'methods' => 'GET',
        'callback' => 'get_firmware_data',
    ));
});

// Callback function to return firmware data
function get_firmware_data() {
    $firmware_data = array(
        'version' => '1.0.0',
        'file' => '/path/to/file',
    );

    return new WP_REST_Response($firmware_data, 200);
}

/* CHOICE SUBSCRIPTION DB STARTS HERE */

// Handle subscription request
function handle_subscription(WP_REST_Request $request) {
    $email = sanitize_email($request->get_param('email'));

    if (!is_email($email))

 {
        return new WP_Error('invalid_email', 'Invalid email address.', array('status' => 400));
    }

    $validated_ids = $request->get_param('ids');

    foreach ($validated_ids as $uuid) {
        if (!is_string($uuid) || !preg_match('/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i', $uuid)) {
            return new WP_Error('invalid_id_format', 'Invalid UUID format.', array('status' => 400));
        }
    }

    if (count($validated_ids) > 9) {
        return new WP_Error('too_many_ids', 'Only up to 9 validated IDs are allowed per email.', array('status' => 400));
    }

    global $wpdb;
    $subs_table = $wpdb->prefix . 'custom_choice_subs';
    $validated_table = $wpdb->prefix . 'validated_ids';

    foreach ($validated_ids as $uuid) {
        $existing_entry = $wpdb->get_var($wpdb->prepare("SELECT user_email FROM $validated_table WHERE validated_id = %s", $uuid));
        if ($existing_entry && $existing_entry !== $email) {
            return new WP_Error('id_already_taken', "The validated ID '$uuid' is already used by another email address.", array('status' => 400));
        }
    }

    $existing_entry = $wpdb->get_row($wpdb->prepare("SELECT * FROM $subs_table WHERE user_email = %s", $email), ARRAY_A);

    if ($existing_entry) {
        $current_validated_ids = maybe_unserialize($existing_entry['validated_ids']);
        $updated_ids = array_unique(array_merge($current_validated_ids, $validated_ids));

        if (count($updated_ids) > 9) {
            return new WP_Error('too_many_ids', 'Only up to 9 validated IDs are allowed per email.', array('status' => 400));
        }

        $wpdb->update(
            $subs_table,
            array('validated_ids' => maybe_serialize($updated_ids)),
            array('user_email' => $email),
            array('%s'),
            array('%s')
        );

        $wpdb->delete($validated_table, array('user_email' => $email), array('%s'));
        foreach ($updated_ids as $uuid) {
            $wpdb->insert(
                $validated_table,
                array('user_email' => $email, 'validated_id' => $uuid),
                array('%s', '%s')
            );
        }
    } else {
        $wpdb->insert(
            $subs_table,
            array(
                'user_email' => $email,
                'validated_ids' => maybe_serialize($validated_ids)
            ),
            array('%s', '%s')
        );

        foreach ($validated_ids as $uuid) {
            $wpdb->insert(
                $validated_table,
                array('user_email' => $email, 'validated_id' => $uuid),
                array('%s', '%s')
            );
        }

        $subject = 'New subscriber from "CHOICE V5.3 INSTALLATION"';
        $message = "New subscriber details:\n\n";
        $message .= "Email: $email\n";

        $headers = array(
            'From: CHOICE V5.3 INSTALLATION <noreply@stevezafeiriou.com>',
            'Content-Type: text/plain; charset=UTF-8',
        );

        $email_sent = wp_mail(get_option('admin_email'), $subject, $message, $headers);

        if (!$email_sent) {
            error_log('Failed to send email notification for new subscriber.');
        }
    }

    return 'User subscribed successfully.';
}

// Handle update request
function handle_update_subscription(WP_REST_Request $request) {
    $email = sanitize_email($request->get_param('email'));

    $validated_ids = $request->get_param('ids');

    foreach ($validated_ids as $uuid) {
        if (!is_string($uuid) || !preg_match('/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i', $uuid)) {
            return new WP_Error('invalid_id_format', 'Invalid UUID format.', array('status' => 400));
        }
    }

    if (count($validated_ids) > 9) {
        return new WP_Error('too_many_ids', 'Only up to 9 validated IDs are allowed per email.', array('status' => 400));
    }

    global $wpdb;
    $subs_table = $wpdb->prefix . 'custom_choice_subs';
    $validated_table = $wpdb->prefix . 'validated_ids';

    foreach ($validated_ids as $uuid) {
        $existing_entry = $wpdb->get_var($wpdb->prepare("SELECT user_email FROM $validated_table WHERE validated_id = %s", $uuid));
        if ($existing_entry && $existing_entry !== $email) {
            return new WP_Error('id_already_taken', "The validated ID '$uuid' is already used by another email address.", array('status' => 400));
        }
    }

    $wpdb->update(
        $subs_table,
        array('validated_ids' => maybe_serialize($validated_ids)),
        array('user_email' => $email),
        array('%s'),
        array('%s')
    );

    $wpdb->delete($validated_table, array('user_email' => $email), array('%s'));
    foreach ($validated_ids as $uuid) {
        $wpdb->insert(
            $validated_table,
            array('user_email' => $email, 'validated_id' => $uuid),
            array('%s', '%s')
        );
    }

    return 'User subscription updated successfully.';
}

add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/subscribe', array(
        array(
            'methods' => 'POST',
            'callback' => 'handle_subscription',
            'permission_callback' => '__return_true',
        ),
        array(
            'methods' => 'PUT',
            'callback' => 'handle_update_subscription',
            'permission_callback' => '__return_true',
        ),
    ));
});

/* CHOICE SUBSCRIPTION DB ENDS HERE */
```

## Configuration

1. **Create a `.env` file** in the root directory of your Node.js server with the following content:
   ```env
   LOCAL_IP=your_local_ip
   VENDOR_ID=your_vendor_id
   PRODUCT_ID=your_product_id
   ```
2. **Upload `functions.php` to your WordPress theme or child theme directory**.

## Notes

- Ensure that the `.env` file contains the correct local IP address, vendor ID, and product ID for your setup.
- The PHP code in `functions.php` is a backup related to the PHP endpoints of the installation.
- The server-side code uses WebSockets to emit real-time data to connected clients.
- CORS headers are set to allow communication between different origins. Adjust the allowed origins as needed for your setup.

By following this documentation, you should be able to set up, run, and manage the Choice Installation Application effectively. For any issues or further information, please contact the project maintainers.
