<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session
session_start();

// Database connection
require_once '../config/database.php';

// Sanitize inputs
$email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
$password = $_POST['password'] ?? '';
$remember = isset($_POST['remember']);

// Validate inputs
if (empty($email) || empty($password)) {
    $_SESSION['error'] = "Email and password are required";
    header("Location: ../login.php");
    exit;
}

try {
    // Prepare statement to prevent SQL injection
    $stmt = $pdo->prepare("SELECT * FROM admin_users 
                          WHERE email = :email AND is_active = 1");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password'])) {
        // Successful login
        
        // Update last login time
        $updateStmt = $pdo->prepare("UPDATE admin_users SET last_login = NOW() 
                                    WHERE admin_id = :admin_id");
        $updateStmt->bindParam(':admin_id', $user['admin_id']);
        $updateStmt->execute();
        
        // Log activity
        $logStmt = $pdo->prepare("INSERT INTO admin_activity_logs 
                                (admin_id, action_type, entity_type, details, ip_address) 
                                VALUES (:admin_id, 'login', 'admin_users', 'Admin login successful', :ip)");
        $logStmt->bindParam(':admin_id', $user['admin_id']);
        $logStmt->bindParam(':ip', $_SERVER['REMOTE_ADDR']);
        $logStmt->execute();
        
        // Set session variables
        $_SESSION['admin_id'] = $user['admin_id'];
        $_SESSION['admin_name'] = $user['first_name'] . ' ' . $user['last_name'];
        $_SESSION['role_id'] = $user['role_id'];
        
        // Fetch role information
        $roleStmt = $pdo->prepare("SELECT * FROM roles WHERE role_id = :role_id");
        $roleStmt->bindParam(':role_id', $user['role_id']);
        $roleStmt->execute();
        $role = $roleStmt->fetch(PDO::FETCH_ASSOC);
        $_SESSION['role_name'] = $role['name'];
        
        // Fetch store access permissions
        $storeAccessStmt = $pdo->prepare("SELECT * FROM admin_store_access 
                                         WHERE admin_id = :admin_id");
        $storeAccessStmt->bindParam(':admin_id', $user['admin_id']);
        $storeAccessStmt->execute();
        
        $storeAccess = [];
        while ($access = $storeAccessStmt->fetch(PDO::FETCH_ASSOC)) {
            $storeAccess[] = $access;
        }
        $_SESSION['store_access'] = $storeAccess;
        
        // Set remember me cookie if requested
        if ($remember) {
            $token = bin2hex(random_bytes(32));
            $tokenHash = password_hash($token, PASSWORD_DEFAULT);
            
            // Store token in database
            $tokenStmt = $pdo->prepare("UPDATE admin_users 
                                       SET remember_token = :token 
                                       WHERE admin_id = :admin_id");
            $tokenStmt->bindParam(':token', $tokenHash);
            $tokenStmt->bindParam(':admin_id', $user['admin_id']);
            $tokenStmt->execute();
            
            // Set cookie (30 days)
            setcookie('remember_token', $token, time() + (86400 * 30), "/", "", true, true);
            setcookie('admin_email', $email, time() + (86400 * 30), "/", "", true, true);
        }
        
        // Redirect to dashboard
        header("Location: ../pages/dashboard.php");
        exit;
    } else {
        // Failed login
        $_SESSION['error'] = "Invalid email or password";
        
        // Log failed attempt
        $logStmt = $pdo->prepare("INSERT INTO admin_activity_logs 
                                (admin_id, action_type, entity_type, details, ip_address) 
                                VALUES (NULL, 'login_failed', 'admin_users', :details, :ip)");
        $details = "Failed login attempt for email: " . $email;
        $logStmt->bindParam(':details', $details);
        $logStmt->bindParam(':ip', $_SERVER['REMOTE_ADDR']);
        $logStmt->execute();
        
        header("Location: ../login.php");
        exit;
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "System error: Please try again later";
    // Log the actual error for administrators
    error_log('Database error: ' . $e->getMessage());
    header("Location: ../login.php");
    exit;
}