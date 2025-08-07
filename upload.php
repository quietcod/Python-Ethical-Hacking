<?php
// Simple file upload script for Apache2 server
// Place this in your web server directory (e.g., /var/www/html/)

$upload_dir = '/var/www/html/files/uploads/'; // Directory to save uploaded files
$max_file_size = 10 * 1024 * 1024; // 10MB max file size

// Create upload directory if it doesn't exist
if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo "Upload error: " . $file['error'];
        exit;
    }
    
    // Check file size
    if ($file['size'] > $max_file_size) {
        http_response_code(400);
        echo "File too large";
        exit;
    }
    
    // Generate unique filename with timestamp
    $timestamp = date('Y-m-d_H-i-s');
    $client_ip = $_SERVER['REMOTE_ADDR'];
    $original_name = basename($file['name']);
    $filename = $timestamp . '_' . $client_ip . '_' . $original_name;
    
    $destination = $upload_dir . $filename;
    
    // Move uploaded file
    if (move_uploaded_file($file['tmp_name'], $destination)) {
        // Log the upload
        $log_entry = date('Y-m-d H:i:s') . " - Upload from " . $client_ip . " - File: " . $filename . "\n";
        file_put_contents($upload_dir . 'upload_log.txt', $log_entry, FILE_APPEND);
        
        http_response_code(200);
        echo "File uploaded successfully as: " . $filename;
    } else {
        http_response_code(500);
        echo "Failed to save file";
    }
} else {
    http_response_code(400);
    echo "No file uploaded";
}
?>
