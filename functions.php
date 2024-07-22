<?php

/* CHOICE IMPLEMENTATION STARTS HERE */

/* CORS Handling Functions */

// Function to add CORS headers for Image Data and Subscription Endpoints
function add_image_data_subscription_cors_headers() {
    // List of allowed origins
    $allowed_origins = [
        'http://192.168.237.249:3000',
        'http://192.168.237.253:3000',
        'https://choice.stevezafeiriou.com',
    ];

    // Get the origin of the request
    $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

    // Check if the origin is in the allowed origins list
    if (in_array($origin, $allowed_origins)) {
        header("Access-Control-Allow-Origin: $origin");
    } else {
        header("Access-Control-Allow-Origin: 'none'");
    }

    header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With");
}

add_action('rest_api_init', 'add_image_data_subscription_cors_headers');
add_action('wp_head', 'add_image_data_subscription_cors_headers');
add_action('wp_footer', 'add_image_data_subscription_cors_headers');

// Handle preflight requests for Image Data and Subscription Endpoints
function handle_image_data_subscription_preflight() {
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        // List of allowed origins
        $allowed_origins = [
            'http://192.168.237.249:3000',
            'http://192.168.237.253:3000',
            'https://choice.stevezafeiriou.com',
        ];

        // Get the origin of the request
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

        // Check if the origin is in the allowed origins list
        if (in_array($origin, $allowed_origins)) {
            header("Access-Control-Allow-Origin: $origin");
        } else {
            header("Access-Control-Allow-Origin: 'none'");
        }

        header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT");
        header("Access-Control-Allow-Credentials: true");
        header("Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With");
        exit;
    }
}

add_action('init', 'handle_image_data_subscription_preflight');

// Function to add CORS headers for Firmware Endpoints
function add_firmware_cors_headers() {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, OPTIONS");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With");
}

// Handle preflight requests for Firmware Endpoints
function handle_firmware_preflight() {
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET, OPTIONS");
        header("Access-Control-Allow-Credentials: true");
        header("Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With");
        exit;
    }
}

add_action('init', 'handle_firmware_preflight');

/* Generated Images Data Endpoints (Table: custom_images) */

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
            'created_by_chip_id' => $chip_id,
            'chip_id_edition' => $chip_id_edition,
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

// Function to retrieve recent unvalidated images
function get_recent_unvalidated_images() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'custom_images'; // Use the exact table name

    // Retrieve the 5 most recent unvalidated images
    $query = $wpdb->prepare(
        "SELECT id, description, image, name, artist, validated, created_at, created_by_chip_id, chip_id_edition, attributes FROM $table_name WHERE validated = 0 ORDER BY created_at DESC LIMIT %d",
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

add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/recent-unvalidated-images', array(
        'methods' => 'GET',
        'callback' => 'get_recent_unvalidated_images',
        'permission_callback' => '__return_true', // Adjust as per your authentication/security requirements
    ));

    // Debug registered routes
    error_log(print_r(rest_get_server()->get_routes(), true));
});

/* Subscription Endpoints To Save Generations (Tables: custom_choice_subs, validated_ids) */

// Handle subscription request
function handle_subscription(WP_REST_Request $request) {
    // Retrieve email from request body and sanitize
    $email = sanitize_email($request->get_param('email'));

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
        // Email already exists, update validated IDs only
        $current_validated_ids = maybe_unserialize($existing_entry['validated_ids']);
        $updated_ids = array_unique(array_merge($current_validated_ids, $validated_ids));

        // Limit to 9 validated IDs
        if (count($updated_ids) > 9) {
            return new WP_Error('too_many_ids', 'Only up to 9 validated IDs are allowed per email.', array('status' => 400));
        }

        // Update the record in the subscriptions table
        $wpdb->update(
            $subs_table,
            array('validated_ids' => maybe_serialize($updated_ids)),
            array('user_email' => $email),
            array('%s'),
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
                'validated_ids' => maybe_serialize($validated_ids)
            ),
            array('%s', '%s')
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

// Register REST API endpoint for subscription and update
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/subscribe', array(
        array(
            'methods' => 'POST',
            'callback' => 'handle_subscription',
            'permission_callback' => '__return_true', // Adjust as per your authentication/security requirements
        ),
        array(
            'methods' => 'PUT',
            'callback' => 'handle_update_subscription',
            'permission_callback' => '__return_true', // Adjust as per your authentication/security requirements
        ),
    ));
});

/* Firmware Endpoints (Table: firmware_changelog) */

// Register custom REST API route
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/firmware', array(
        'methods' => 'GET',
        'callback' => 'get_firmware_data',
        'permission_callback' => function () {
            add_firmware_cors_headers();
            return true;
        },
    ));
});

// Callback function to return firmware data
function get_firmware_data() {
    $firmware_data = array(
        'version' => '1.0.0', // Replace with your current firmware version
        'file' => 'https://stevezafeiriou.com/choice-firmware/choice_v1.0.0.bin', // URL to the uploaded firmware binary
        'changelog_url' => 'https://stevezafeiriou.com/choice-firmware/CHANGELOG.md', // URL to the changelog file
    );

    return new WP_REST_Response($firmware_data, 200);
}

// Register custom REST API route for firmware changelog
add_action('rest_api_init', function () {
    register_rest_route('choice/v1', '/firmware/changelog', array(
        'methods' => 'GET',
        'callback' => 'get_firmware_changelog',
        'permission_callback' => function () {
            add_firmware_cors_headers();
            return true;
        },
    ));
});

// Callback function to return firmware changelog data
function get_firmware_changelog() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'firmware_changelog';

    $results = $wpdb->get_results("SELECT version, change_log, added_date FROM $table_name", ARRAY_A);

    return new WP_REST_Response($results, 200);
}

/* CHOICE IMPLEMENTATION ENDS HERE */

