<?php
/**
 * SecurityManager Class
 * 
 * Handles authentication, authorization, and security-related functionality.
 */
class SecurityManager {
    private $pdo;
    
    /**
     * Constructor
     * 
     * @param PDO $pdo Database connection
     */
    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }
    
    /**
     * Authenticate user with email and password
     * 
     * @param string $email User email
     * @param string $password User password
     * @return array|bool User data array or false on authentication failure
     */
    public function authenticate($email, $password) {
        try {
            // Prepare statement to prevent SQL injection
            $stmt = $this->pdo->prepare("SELECT * FROM admin_users 
                                        WHERE email = :email AND is_active = 1");
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Verify password using secure password_verify function
            if ($user && password_verify($password, $user['password'])) {
                // Update last login time
                $updateStmt = $this->pdo->prepare("UPDATE admin_users SET last_login = NOW() 
                                                WHERE admin_id = :admin_id");
                $updateStmt->bindParam(':admin_id', $user['admin_id']);
                $updateStmt->execute();
                
                // Log activity
                $this->logActivity(
                    $user['admin_id'],
                    'login',
                    'admin_users',
                    $user['admin_id'],
                    'Admin login successful'
                );
                
                return $user;
            }
            
            // Log failed attempt
            $details = "Failed login attempt for email: " . $email;
            $this->logActivity(
                null,
                'login_failed',
                'admin_users',
                null,
                $details
            );
            
            return false;
        } catch (PDOException $e) {
            error_log('Authentication error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user has a specific permission
     * 
     * @param int $adminId Admin user ID
     * @param string $permissionName Permission name to check
     * @return bool True if user has permission, false otherwise
     */
    public function hasPermission($adminId, $permissionName) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) FROM role_permissions rp
                JOIN permissions p ON rp.permission_id = p.permission_id
                JOIN admin_users au ON au.role_id = rp.role_id
                WHERE au.admin_id = :admin_id AND p.name = :permission_name
            ");
            
            $stmt->bindParam(':admin_id', $adminId);
            $stmt->bindParam(':permission_name', $permissionName);
            $stmt->execute();
            
            return $stmt->fetchColumn() > 0;
        } catch (PDOException $e) {
            error_log('Permission check error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user has access to a specific store
     * 
     * @param int $adminId Admin user ID
     * @param int $storeId Store ID
     * @param bool $isMainStore Whether the store is a main store
     * @return bool True if user has access, false otherwise
     */
    public function hasStoreAccess($adminId, $storeId, $isMainStore = false) {
        try {
            // Get user role
            $roleStmt = $this->pdo->prepare("
                SELECT r.name as role_name 
                FROM admin_users au
                JOIN roles r ON au.role_id = r.role_id
                WHERE au.admin_id = :admin_id
            ");
            $roleStmt->bindParam(':admin_id', $adminId);
            $roleStmt->execute();
            $role = $roleStmt->fetch(PDO::FETCH_ASSOC);
            
            // SuperAdmin has access to everything
            if ($role && $role['role_name'] === 'SuperAdmin') {
                return true;
            }
            
            // Check store access
            if ($isMainStore) {
                $stmt = $this->pdo->prepare("
                    SELECT COUNT(*) FROM admin_store_access
                    WHERE admin_id = :admin_id AND main_store_id = :store_id
                ");
                $stmt->bindParam(':admin_id', $adminId);
                $stmt->bindParam(':store_id', $storeId);
            } else {
                $stmt = $this->pdo->prepare("
                    SELECT COUNT(*) FROM admin_store_access
                    WHERE admin_id = :admin_id AND 
                    (store_id = :store_id OR 
                     (store_id IS NULL AND main_store_id = (
                         SELECT main_store_id FROM stores WHERE store_id = :store_id
                     )))
                ");
                $stmt->bindParam(':admin_id', $adminId);
                $stmt->bindParam(':store_id', $storeId);
            }
            
            $stmt->execute();
            return $stmt->fetchColumn() > 0;
        } catch (PDOException $e) {
            error_log('Store access check error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Log admin activity
     * 
     * @param int|null $adminId Admin ID (null for anonymous)
     * @param string $actionType Action type
     * @param string $entityType Entity type
     * @param int|null $entityId Entity ID
     * @param string $details Additional details
     * @return bool Success or failure
     */
    public function logActivity($adminId, $actionType, $entityType, $entityId, $details) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO admin_activity_logs (
                    admin_id, action_type, entity_type, entity_id, details, ip_address, created_at
                ) VALUES (
                    :admin_id, :action_type, :entity_type, :entity_id, :details, :ip_address, NOW()
                )
            ");
            
            $stmt->bindValue(':admin_id', $adminId);
            $stmt->bindValue(':action_type', $actionType);
            $stmt->bindValue(':entity_type', $entityType);
            $stmt->bindValue(':entity_id', $entityId);
            $stmt->bindValue(':details', $details);
            $stmt->bindValue(':ip_address', $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
            
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log('Activity logging error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Generate CSRF token and store it in session
     * 
     * @param string $formName Form name for specific token
     * @return string CSRF token
     */
    public function generateCSRFToken($formName = 'default') {
        if (!isset($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_tokens'][$formName] = [
            'token' => $token,
            'time' => time()
        ];
        
        return $token;
    }
    
    /**
     * Validate CSRF token
     * 
     * @param string $token Token to validate
     * @param string $formName Form name for specific token
     * @param int $expireTime Token expiration time in seconds (default 1 hour)
     * @return bool True if valid, false otherwise
     */
    public function validateCSRFToken($token, $formName = 'default', $expireTime = 3600) {
        if (!isset($_SESSION['csrf_tokens'][$formName])) {
            return false;
        }
        
        $storedToken = $_SESSION['csrf_tokens'][$formName];
        
        // Check if token matches and is not expired
        if ($token === $storedToken['token'] && (time() - $storedToken['time']) < $expireTime) {
            // Remove used token for one-time use
            unset($_SESSION['csrf_tokens'][$formName]);
            return true;
        }
        
        return false;
    }
    
    /**
     * Generate a secure password
     * 
     * @param int $length Password length
     * @return string Generated password
     */
    public function generatePassword($length = 12) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+';
        $password = '';
        
        $max = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, $max)];
        }
        
        return $password;
    }
    
    /**
     * Send password reset email
     * 
     * @param string $email User email
     * @return bool Success or failure
     */
    public function sendPasswordResetEmail($email) {
        try {
            // Check if email exists
            $stmt = $this->pdo->prepare("SELECT admin_id FROM admin_users WHERE email = :email AND is_active = 1");
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                return false;
            }
            
            // Generate reset token
            $token = bin2hex(random_bytes(32));
            $tokenExpiry = date('Y-m-d H:i:s', strtotime('+24 hours'));
            
            // Store token in database
            $tokenStmt = $this->pdo->prepare("
                UPDATE admin_users 
                SET reset_token = :token, reset_token_expiry = :expiry 
                WHERE admin_id = :admin_id
            ");
            $tokenStmt->bindParam(':token', $token);
            $tokenStmt->bindParam(':expiry', $tokenExpiry);
            $tokenStmt->bindParam(':admin_id', $user['admin_id']);
            $tokenStmt->execute();
            
            // Send email with reset link
            // This is a placeholder - implement actual email sending based on your setup
            $resetLink = "https://yourwebsite.com/reset-password.php?token=$token";
            $subject = "Password Reset Request";
            $message = "Please click the following link to reset your password: $resetLink";
            
            // mail($email, $subject, $message); // Uncomment and configure for actual use
            
            return true;
        } catch (PDOException $e) {
            error_log('Password reset error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Reset password with token
     * 
     * @param string $token Reset token
     * @param string $newPassword New password
     * @return bool Success or failure
     */
    public function resetPassword($token, $newPassword) {
        try {
            // Find user with this token
            $stmt = $this->pdo->prepare("
                SELECT admin_id FROM admin_users 
                WHERE reset_token = :token 
                AND reset_token_expiry > NOW() 
                AND is_active = 1
            ");
            $stmt->bindParam(':token', $token);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                return false;
            }
            
            // Hash new password
            $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
            
            // Update password and clear token
            $updateStmt = $this->pdo->prepare("
                UPDATE admin_users 
                SET password = :password, 
                    reset_token = NULL, 
                    reset_token_expiry = NULL 
                WHERE admin_id = :admin_id
            ");
            $updateStmt->bindParam(':password', $hashedPassword);
            $updateStmt->bindParam(':admin_id', $user['admin_id']);
            
            $success = $updateStmt->execute();
            
            if ($success) {
                // Log activity
                $this->logActivity(
                    $user['admin_id'],
                    'password_reset',
                    'admin_users',
                    $user['admin_id'],
                    'Password reset successfully'
                );
            }
            
            return $success;
        } catch (PDOException $e) {
            error_log('Password reset error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Create password hash
     * 
     * @param string $password Plain text password
     * @return string Hashed password
     */
    public function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }
    
    /**
     * Verify password
     * 
     * @param string $password Plain text password
     * @param string $hash Hashed password
     * @return bool True if password matches hash
     */
    public function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Check if password meets security requirements
     * 
     * @param string $password Password to check
     * @return array Array with validation result and message
     */
    public function validatePassword($password) {
        $result = [
            'valid' => true,
            'message' => 'Password is valid'
        ];
        
        // Check length
        if (strlen($password) < 8) {
            $result['valid'] = false;
            $result['message'] = 'Password must be at least 8 characters long';
            return $result;
        }
        
        // Check for uppercase letter
        if (!preg_match('/[A-Z]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one uppercase letter';
            return $result;
        }
        
        // Check for lowercase letter
        if (!preg_match('/[a-z]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one lowercase letter';
            return $result;
        }
        
        // Check for number
        if (!preg_match('/[0-9]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one number';
            return $result;
        }
        
        // Check for special character
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one special character';
            return $result;
        }
        
        return $result;
    }
}