<?php
// Start session
session_start();

// Include database connection and classes if needed for logging
require_once 'config/database.php';
require_once 'classes/SecurityManager.php';

// Check if user is logged in
if (isset($_SESSION['admin_id'])) {
    // Initialize security manager
    $security = new SecurityManager($pdo);
    
    // Log the logout activity
    $security->logActivity(
        $_SESSION['admin_id'],
        'logout',
        'admin_users',
        $_SESSION['admin_id'],
        'Admin logged out'
    );
    
    // Clear any remember me cookie
    if (isset($_COOKIE['remember_token'])) {
        setcookie('remember_token', '', time() - 3600, '/');
        setcookie('admin_email', '', time() - 3600, '/');
        
        // Also remove the token from database
        try {
            $stmt = $pdo->prepare("UPDATE admin_users SET remember_token = NULL WHERE admin_id = :admin_id");
            $stmt->bindParam(':admin_id', $_SESSION['admin_id']);
            $stmt->execute();
        } catch (PDOException $e) {
            // Just log the error, don't need to tell the user
            error_log('Error clearing remember token: ' . $e->getMessage());
        }
    }
}

// Unset all session variables
$_SESSION = array();

// Destroy the session
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}
session_destroy();

// Redirect to login page
header("Location: login.php");
exit;