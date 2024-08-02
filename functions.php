<?php




/* CHOICE IMPLEMENTATION STARTS HERE */

/* CORS Handling Functions */

// Function to add CORS headers for specific endpoints
function add_cors_headers() {
    $allowed_origins = [
        'https://choice.stevezafeiriou.com',
        'https://www.choice.stevezafeiriou.com',
        'http://192.168.237.253:3000',
      //'http://192.168.237.249:3000',
    ];

    $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

    if (in_array($origin, $allowed_origins)) {
        header("Access-Control-Allow-Origin: $origin");
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT");
        header("Access-Control-Allow-Credentials: true");
        header("Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With");
    }
}

// Handle preflight requests for specific endpoints
function handle_preflight() {
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        add_cors_headers();
        exit;
    }
}

// Apply CORS headers only to specific REST API routes
function add_cors_headers_to_rest_endpoints($value, $server) {
    $cors_endpoints = [
        '/wp-json/choice/v1/image-data',
        '/wp-json/choice/v1/image-data/(?P<id>\S+)',
        '/wp-json/choice/v1/recent-unvalidated-images',
        '/wp-json/choice/v1/subscribe',
        '/wp-json/choice/v1/firmware',
        '/wp-json/choice/v1/firmware/changelog',
        '/wp-json/choice/v1/firmware/upload',
        '/wp-json/choice/v1/subscribe/list',
		'/wp-json/choice/v1/subscribe/donation/update',
        '/wp-json/choice/v1/devices',
        '/wp-json/choice/v1/devices/total',
		'/wp-json/choice/v1/collected',
    ];

    $request_uri = $_SERVER['REQUEST_URI'];

    foreach ($cors_endpoints as $endpoint) {
        if (preg_match('@^' . $endpoint . '$@', $request_uri)) {
            add_cors_headers();
            break;
        }
    }

    return $value;
}

// Hook the CORS header addition and preflight handling to REST API init
add_action('rest_api_init', function () {
    add_action('rest_api_init', 'handle_preflight', 1);
    add_filter('rest_pre_serve_request', 'add_cors_headers_to_rest_endpoints', 15, 2);
});

// Ensure JWT Authentication for WP REST API plugin is included
if (!function_exists('jwt_auth_validate_token')) {
    include_once(ABSPATH . 'wp-content/plugins/jwt-auth/jwt-auth.php');
}

// Register endpoints and callbacks

add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/image-data', array(
        'methods' => 'POST',
        'callback' => 'create_custom_image',
    ));

    register_rest_route('choice/v1', '/image-data', array(
        'methods' => 'GET',
        'callback' => 'get_all_custom_images',
    ));

    register_rest_route('choice/v1', '/image-data/(?P<id>\S+)', array(
        'methods' => 'GET',
        'callback' => 'get_custom_image_by_id',
    ));

    register_rest_route('choice/v1', '/image-data/(?P<id>\S+)', array(
        'methods' => 'DELETE',
        'callback' => 'delete_custom_image_by_id',
        'permission_callback' => 'verify_jwt_token',
    ));

    register_rest_route('choice/v1', '/image-data/validate', array(
        'methods' => 'POST',
        'callback' => 'validate_custom_image',
    ));

    register_rest_route('choice/v1', '/recent-unvalidated-images', array(
        'methods' => 'GET',
        'callback' => 'get_recent_unvalidated_images',
    ));

    register_rest_route('choice/v1', '/subscribe', array(
        'methods' => 'POST',
        'callback' => 'handle_subscription',
    ));
    
    register_rest_route('choice/v1', '/subscribe/list', array(
        'methods' => 'GET',
        'callback' => 'get_subscriber_list',
        'permission_callback' => 'verify_jwt_token',
    ));

    register_rest_route('choice/v1', '/subscribe', array(
        'methods' => 'PUT',
        'callback' => 'handle_update_subscription',
    ));
	
	register_rest_route('choice/v1', '/subscribe/donation/update', array(
        'methods' => 'POST',
        'callback' => 'update_donation_status',
        'permission_callback' => 'verify_jwt_token', 
    ));

    register_rest_route('choice/v1', '/firmware', array(
        'methods' => 'GET',
        'callback' => 'get_firmware_data',
    ));

    register_rest_route('choice/v1', '/firmware/changelog', array(
        'methods' => 'GET',
        'callback' => 'get_firmware_changelog',
    ));

    register_rest_route('choice/v1', '/firmware/upload', array(
        'methods' => 'POST',
        'callback' => 'handle_firmware_upload',
        'permission_callback' => 'verify_jwt_token',
    ));

    register_rest_route('choice/v1', '/devices/total', array(
        'methods' => 'GET',
        'callback' => 'get_total_devices',
    ));

    register_rest_route('choice/v1', '/devices', array(
        'methods' => 'GET',
        'callback' => 'get_registered_devices',
        'permission_callback' => 'verify_jwt_token',
    ));

    register_rest_route('choice/v1', '/devices', array(
        'methods' => 'POST',
        'callback' => 'register_new_device',
        'permission_callback' => 'verify_jwt_token',
    ));
	
	register_rest_route('choice/v1', '/collected', array(
        'methods' => 'GET',
        'callback' => 'get_collected_images_by_email',
    ));
	
});

// Callback functions for endpoints (include your existing implementations here)
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
    $grid = maybe_serialize($imageData['grid']);

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
            'grid' => $grid,
            'created_by_chip_id' => $chip_id,
            'chip_id_edition' => $chip_id_edition,
            'validated' => false,
            'created_at' => current_time('mysql'), // Use current timestamp
        )
    );

    // Log the created_at time for debugging
    $created_at = current_time('mysql');
    error_log("Created at time: $created_at");

    // Delete unvalidated images older than 15 minutes
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM $table_name_images WHERE validated = 0 AND created_at < %s",
            date('Y-m-d H:i:s', strtotime('-15 minutes'))
        )
    );

    // Check the number of rows affected by the delete query
    $rows_affected = $wpdb->rows_affected;
    error_log("Rows deleted: $rows_affected");

    if ($rows_affected > 0) {
        return 'Image added successfully. Unvalidated images older than 15 minutes have been deleted.';
    } else {
        return 'Image added successfully. No unvalidated images older than 15 minutes found.';
    }
}

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
        $attributes = maybe_unserialize($result['attributes']);
        if (is_array($attributes)) {
            foreach ($attributes as $attribute) {
                if ($attribute['trait_type'] === 'Acceleration') {
                    $result['acceleration'] = $attribute['value'];
                    break;
                }
            }
        }

        // Unserialize the grid field
        $grid = maybe_unserialize($result['grid']);
        if (is_array($grid)) {
            $result['grid'] = $grid;
        }

        // Remove the attributes field
        unset($result['attributes']);
    }

    return $results;
}

// Callback function for handling GET by ID request
function get_custom_image_by_id($data) {
    $id = $data['id'];

    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images';

    $result = $wpdb->get_row($wpdb->prepare("SELECT id, description, image, name, artist, validated, created_at, created_by_chip_id, chip_id_edition, attributes, grid FROM $table_name WHERE id = %s", $id), ARRAY_A);

    if (!$result) {
        return new WP_Error('not_found', 'Image not found', array('status' => 404));
    }

    // Unserialize the attributes field and extract the Acceleration trait
    $attributes = maybe_unserialize($result['attributes']);
    if (is_array($attributes)) {
        foreach ($attributes as $attribute) {
            if ($attribute['trait_type'] === 'Acceleration') {
                $result['acceleration'] = $attribute['value'];
                break;
            }
        }
    }

    // Unserialize the grid field
    $grid = maybe_unserialize($result['grid']);
    if (is_array($grid)) {
        $result['grid'] = $grid;
    }

    // Remove the attributes field
    unset($result['attributes']);

    return $result;
}

// Callback function for handling DELETE by ID request
function delete_custom_image_by_id($data) {
    $id = $data['id'];

    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images';

    $wpdb->delete($table_name, array('id' => $id));

    return 'Image deleted successfully.';
}

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

// Function to retrieve recent unvalidated images
function get_recent_unvalidated_images() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images'; // Use the exact table name

    // Retrieve the 5 most recent unvalidated images
    $query = $wpdb->prepare(
        "SELECT id, description, image, name, artist, validated, created_at, created_by_chip_id, chip_id_edition, attributes, grid FROM $table_name WHERE validated = 0 ORDER BY created_at DESC LIMIT %d",
        5
    );

    // Execute the query
    $results = $wpdb->get_results($query, ARRAY_A);

    // Get the current time
    $current_time = current_time('mysql');
    $current_time_unix = strtotime($current_time);

    // If no unvalidated images are found, return a not found error
    if (empty($results)) {
        return new WP_Error('no_unvalidated_images', 'No unvalidated images found.', array('status' => 404));
    }

    // Add current time to each result and calculate the time difference
    foreach ($results as &$result) {
        $created_at_unix = strtotime($result['created_at']);
        $time_diff_seconds = $current_time_unix - $created_at_unix;
        $time_diff_human = human_time_diff($created_at_unix, $current_time_unix);

        // Add time information to the result
        $result['current_time'] = $current_time;
        $result['time_since_creation'] = $time_diff_human;

        // Unserialize the attributes field and extract the Acceleration trait
        $attributes = maybe_unserialize($result['attributes']);
        if (is_array($attributes)) {
            foreach ($attributes as $attribute) {
                if ($attribute['trait_type'] === 'Acceleration') {
                    $result['acceleration'] = $attribute['value'];
                    break;
                }
            }
        }

        // Unserialize the grid field
        $grid = maybe_unserialize($result['grid']);
        if (is_array($grid)) {
            $result['grid'] = $grid;
        }

        // Remove the attributes field
        unset($result['attributes']);
    }

    return $results;
}

// Handle subscription request
// Handle subscription request
function handle_subscription(WP_REST_Request $request) {
    // Retrieve email from request body and sanitize
    $email = sanitize_email($request->get_param('email'));
    $donate = filter_var($request->get_param('donate'), FILTER_VALIDATE_BOOLEAN);

    // Validate email address
    if (!is_email($email)) {
        return new WP_Error('invalid_email', 'Invalid email address.', array('status' => 400));
    }

    // Retrieve validated IDs from request body and sanitize
    $validated_ids = $request->get_param('ids');

    // Validate IDs format (assuming they are valid UUIDs)
    foreach ($validated_ids as $uuid) {
        if (!is_string($uuid) || !preg_match('/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i', $uuid)) {
            return new WP_Error('invalid_id_format', 'Invalid UUID format.', array('status' => 400));
        }
    }

    // Limit to 9 validated IDs per email
    if (count($validated_ids) > 9) {
        return new WP_Error('too_many_ids', 'Only up to 9 validated IDs are allowed per email.', array('status' => 400));
    }

    global $wpdb;
    $subs_table = $wpdb->prefix . 'custom_choice_subs'; // Make sure this matches your table name
    $validated_table = $wpdb->prefix . 'validated_ids'; // Make sure this matches your table name

    // Check for unique validated IDs across all emails
    foreach ($validated_ids as $uuid) {
        $existing_entry = $wpdb->get_var($wpdb->prepare("SELECT user_email FROM $validated_table WHERE validated_id = %s", $uuid));
        if ($existing_entry && $existing_entry !== $email) {
            return new WP_Error('id_already_taken', "The validated ID '$uuid' is already used by another email address.", array('status' => 400));
        }
    }

    // Check if email already exists in the subscriptions table
    $existing_entry = $wpdb->get_row($wpdb->prepare("SELECT * FROM $subs_table WHERE user_email = %s", $email), ARRAY_A);

    if ($existing_entry) {
        // Email already exists, update validated IDs and donate status
        $current_validated_ids = maybe_unserialize($existing_entry['validated_ids']);
        $updated_ids = array_unique(array_merge($current_validated_ids, $validated_ids));

        // Limit to 9 validated IDs
        if (count($updated_ids) > 9) {
            return new WP_Error('too_many_ids', 'Only up to 9 validated IDs are allowed per email.', array('status' => 400));
        }

        // Update the record in the subscriptions table
        $wpdb->update(
            $subs_table,
            array(
                'validated_ids' => maybe_serialize($updated_ids),
                'donate' => $donate
            ),
            array('user_email' => $email),
            array('%s', '%d'),
            array('%s')
        );

        // Update validated IDs table
        $wpdb->delete($validated_table, array('user_email' => $email), array('%s'));
        foreach ($updated_ids as $uuid) {
            $wpdb->insert(
                $validated_table,
                array('user_email' => $email, 'validated_id' => $uuid),
                array('%s', '%s')
            );
        }
    } else {
        // Email does not exist, create new record
        $wpdb->insert(
            $subs_table,
            array(
                'user_email' => $email,
                'validated_ids' => maybe_serialize($validated_ids),
                'donate' => $donate
            ),
            array('%s', '%s', '%d')
        );

        // Insert into validated IDs table
        foreach ($validated_ids as $uuid) {
            $wpdb->insert(
                $validated_table,
                array('user_email' => $email, 'validated_id' => $uuid),
                array('%s', '%s')
            );
        }

        // Send email notification for new subscriber
        $subject = 'New subscriber from "CHOICE V5.3 INSTALLATION"';
        $message = "New subscriber details:\n\n";
        $message .= "Email: $email\n";

        $headers = array(
            'From: CHOICE V5.3 INSTALLATION <noreply@stevezafeiriou.com>',
            'Content-Type: text/plain; charset=UTF-8',
        );

        // Send email
        $email_sent = wp_mail(get_option('admin_email'), $subject, $message, $headers);

        if (!$email_sent) {
            // Handle email sending failure if needed
            error_log('Failed to send email notification for new subscriber.');
        }
    }

    return 'User subscribed successfully.';
}


// Handle update request
function handle_update_subscription(WP_REST_Request $request) {
    // Retrieve email from request body and sanitize
    $email = sanitize_email($request->get_param('email'));

    // Retrieve validated IDs from request body and sanitize
    $validated_ids = $request->get_param('ids');

    // Validate IDs format (assuming they are valid UUIDs)
    foreach ($validated_ids as $uuid) {
        if (!is_string($uuid) || !preg_match('/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i', $uuid)) {
            return new WP_Error('invalid_id_format', 'Invalid UUID format.', array('status' => 400));
        }
    }

    // Limit to 9 validated IDs per email
    if (count($validated_ids) > 9) {
        return new WP_Error('too_many_ids', 'Only up to 9 validated IDs are allowed per email.', array('status' => 400));
    }

    global $wpdb;
    $subs_table = $wpdb->prefix . 'custom_choice_subs'; // Make sure this matches your table name
    $validated_table = $wpdb->prefix . 'validated_ids'; // Make sure this matches your table name

    // Check for unique validated IDs across all emails
    foreach ($validated_ids as $uuid) {
        $existing_entry = $wpdb->get_var($wpdb->prepare("SELECT user_email FROM $validated_table WHERE validated_id = %s", $uuid));
        if ($existing_entry && $existing_entry !== $email) {
            return new WP_Error('id_already_taken', "The validated ID '$uuid' is already used by another email address.", array('status' => 400));
        }
    }

    // Update the record in the subscriptions table
    $wpdb->update(
        $subs_table,
        array('validated_ids' => maybe_serialize($validated_ids)),
        array('user_email' => $email),
        array('%s'),
        array('%s')
    );

    // Update validated IDs table
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

// Function to get the firmware data
function get_firmware_data() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'firmware_data';

    $result = $wpdb->get_row("SELECT version, file_url FROM $table_name ORDER BY added_date DESC LIMIT 1", ARRAY_A);

    if (!$result) {
        return new WP_Error('no_firmware_data', 'No firmware data found.', array('status' => 404));
    }

    $firmware_data = array(
        'version' => $result['version'],
        'file' => $result['file_url'],
    );

    return new WP_REST_Response($firmware_data, 200);
}

// Callback function to return firmware changelog data
function get_firmware_changelog() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'firmware_changelog';

    $results = $wpdb->get_results("SELECT version, change_log, added_date FROM $table_name", ARRAY_A);

    return new WP_REST_Response($results, 200);
}

// Function to get the total number of devices
function get_total_devices() {
    global $wpdb;

    // Replace 'your_table_name' with the actual name of your table
    $table_name = $wpdb->prefix . 'registered_devices';
    
    // Query to count the total number of devices
    $total_devices = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");

    // Return the result
    return new WP_REST_Response(array('total' => $total_devices), 200);
}

// Function to verify if the user has a valid JWT token
function verify_jwt_token($request) {
    // Get the JWT token from the Authorization header
    $auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';

    if (!$auth_header) {
        return new WP_Error('missing_auth_header', 'Authorization header is missing', array('status' => 403));
    }

    // Remove "Bearer " from the beginning of the token
    list($token) = sscanf($auth_header, 'Bearer %s');

    if (!$token) {
        return new WP_Error('invalid_auth_header', 'Invalid Authorization header', array('status' => 403));
    }

    // Validate the token using the plugin's validation endpoint
    $response = wp_remote_post(
        rest_url('/jwt-auth/v1/token/validate'),
        array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $token,
            ),
        )
    );

    if (is_wp_error($response)) {
        return new WP_Error('token_validation_failed', 'Token validation failed', array('status' => 403));
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (isset($data['code']) && $data['code'] !== 'jwt_auth_valid_token') {
        return new WP_Error('invalid_token', 'Invalid JWT token', array('status' => 403));
    }

    return true;
}

// Function to handle the firmware file upload and update endpoints
function handle_firmware_upload(WP_REST_Request $request) {
    // Validate and sanitize inputs
    $version = sanitize_text_field($request->get_param('version'));
    $change_log = sanitize_textarea_field($request->get_param('change_log'));

    // Check if a file is uploaded
    if (empty($_FILES['file']) || $_FILES['file']['error'] != UPLOAD_ERR_OK) {
        return new WP_Error('no_file', 'No file uploaded or there was an upload error.', array('status' => 400));
    }

    // Handle file upload
    $uploaded_file = $_FILES['file'];
    $upload_dir = wp_upload_dir();
    $firmware_dir = $upload_dir['basedir'] . '/firmware_update';
    $firmware_url = $upload_dir['baseurl'] . '/firmware_update';

    // Create the directory if it doesn't exist
    if (!file_exists($firmware_dir)) {
        mkdir($firmware_dir, 0755, true);
    }

    $file_path = $firmware_dir . '/' . basename($uploaded_file['name']);
    $file_url = $firmware_url . '/' . basename($uploaded_file['name']);

    // Move the uploaded file to the firmware_update directory
    if (!move_uploaded_file($uploaded_file['tmp_name'], $file_path)) {
        return new WP_Error('upload_failed', 'Failed to move uploaded file.', array('status' => 500));
    }

    // Create .htaccess file for security
    $htaccess_content = "Options -Indexes\n<FilesMatch '\.(bin|BIN)$'>\n  ForceType application/octet-stream\n  Header set Content-Disposition attachment\n</FilesMatch>";
    file_put_contents($firmware_dir . '/.htaccess', $htaccess_content);

    // Update the firmware data in the custom table
    global $wpdb;
    $table_name = $wpdb->prefix . 'firmware_data';

    $existing_firmware = $wpdb->get_row("SELECT * FROM $table_name ORDER BY added_date DESC LIMIT 1");

    if ($existing_firmware) {
        // Update the existing record
        $wpdb->update(
            $table_name,
            array(
                'version' => $version,
                'file_url' => $file_url,
                'added_date' => current_time('mysql'),
            ),
            array('id' => $existing_firmware->id),
            array(
                '%s',
                '%s',
                '%s',
            ),
            array('%d')
        );
    } else {
        // Insert a new record if none exists
        $wpdb->insert(
            $table_name,
            array(
                'version' => $version,
                'file_url' => $file_url,
                'added_date' => current_time('mysql'),
            ),
            array(
                '%s',
                '%s',
                '%s',
            )
        );
    }

    // Insert the changelog into the database
    $changelog_table_name = $wpdb->prefix . 'firmware_changelog';

    $wpdb->insert(
        $changelog_table_name,
        array(
            'version' => $version,
            'change_log' => $change_log,
            'added_date' => current_time('mysql'),
        ),
        array(
            '%s',
            '%s',
            '%s',
        )
    );

    // Return a success message
    return new WP_REST_Response('Firmware updated successfully.', 200);
}

// Function to handle the new endpoint for listing subscribers
// Function to handle the new endpoint for listing subscribers
function get_subscriber_list(WP_REST_Request $request) {
    global $wpdb;
    $subs_table = $wpdb->prefix . 'custom_choice_subs'; // Make sure this matches your table name
    $validated_table = $wpdb->prefix . 'validated_ids'; // Make sure this matches your table name

    // Retrieve all subscribers and their validated IDs
    $subscribers = $wpdb->get_results("SELECT user_email, validated_ids, donate FROM $subs_table", ARRAY_A);

    // Prepare the response data
    $response_data = [];

    foreach ($subscribers as $subscriber) {
        $email = $subscriber['user_email'];
        $validated_ids = maybe_unserialize($subscriber['validated_ids']);
        $donate = $subscriber['donate'];

        $response_data[] = [
            'email' => $email,
            'validated_ids' => $validated_ids,
            'donate' => $donate
        ];
    }

    return new WP_REST_Response($response_data, 200);
}


// Handle device registration request
function register_new_device(WP_REST_Request $request) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'registered_devices';

    $chip_id = sanitize_text_field($request->get_param('chip_id'));
    $edition = sanitize_text_field($request->get_param('edition'));

    $device_data = array(
        'chip_id' => $chip_id,
        'edition' => $edition,
    );

    // Add logging to see what data is being received
    error_log('Registering device with data: ' . print_r($device_data, true));

    // Insert the new device record
    $result = $wpdb->insert($table_name, $device_data);

    if ($result === false) {
        $wpdb->print_error();
        return new WP_Error('db_insert_error', 'Failed to register device.', array('status' => 500));
    }

    return 'Device registered successfully.';
}

// Retrieve all registered devices
function get_registered_devices(WP_REST_Request $request) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'registered_devices';

    $results = $wpdb->get_results("SELECT * FROM $table_name", ARRAY_A);

    if (empty($results)) {
        return new WP_Error('no_devices_found', 'No registered devices found.', array('status' => 404));
    }

    return $results;
}
// Retrieve Validated - Collected Images by a User
function get_collected_images_by_email(WP_REST_Request $request) {
    global $wpdb;
    $user_email = sanitize_email($request->get_param('email'));

    // Fetch collected images
    $validated_table = $wpdb->prefix . 'validated_ids';
    $images_table = $wpdb->prefix . 'custom_images';
    $subs_table = $wpdb->prefix . 'custom_choice_subs';

    $validated_ids = $wpdb->get_col($wpdb->prepare("SELECT validated_id FROM $validated_table WHERE user_email = %s", $user_email));
    
    if (empty($validated_ids)) {
        return new WP_Error('no_images', 'No images found for this user.', array('status' => 404));
    }

    $placeholders = implode(',', array_fill(0, count($validated_ids), '%s'));
    $collected_images = $wpdb->get_results($wpdb->prepare("SELECT * FROM $images_table WHERE id IN ($placeholders)", $validated_ids), ARRAY_A);

    // Unserialize attributes field
    foreach ($collected_images as &$image) {
        if (!empty($image['attributes'])) {
            $image['attributes'] = maybe_unserialize($image['attributes']);
        }
    }

    // Fetch total number of images in the custom_images table
    $total_images = $wpdb->get_var("SELECT COUNT(*) FROM $images_table");

    // Calculate user's score
    $user_score = (count($collected_images) / $total_images) * 100;

    // Fetch donation status
    $donate_status = $wpdb->get_var($wpdb->prepare("SELECT donate FROM $subs_table WHERE user_email = %s", $user_email));

    return new WP_REST_Response(array(
        'collected_images' => $collected_images,
        'total_images' => (int) $total_images,
        'user_score' => $user_score,
        'donate' => (bool) $donate_status
    ), 200);
}

// Handle donation status update
function update_donation_status(WP_REST_Request $request) {
    global $wpdb;
    $email = sanitize_email($request->get_param('email'));

    if (empty($email)) {
        return new WP_Error('invalid_email', 'Invalid email address', array('status' => 400));
    }

    $table_name = $wpdb->prefix . 'custom_choice_subs';
    $result = $wpdb->update(
        $table_name,
        array('donate' => 1),  // Always set donate to 1
        array('user_email' => $email),
        array('%d'),
        array('%s')
    );

    if ($result === false) {
        return new WP_Error('db_update_error', 'Failed to update donation status', array('status' => 500));
    }

    return new WP_REST_Response('Donation status updated successfully', 200);
}


// Allow .bin file uploads
function add_custom_upload_mimes($existing_mimes) {
    // Add .bin file type
    $existing_mimes['bin'] = 'application/octet-stream';
    return $existing_mimes;
}
add_filter('upload_mimes', 'add_custom_upload_mimes');

/* CHOICE IMPLEMENTATION ENDS HERE */
