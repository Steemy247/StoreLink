<?php
/**
 * AdminUserManager Class
 * 
 * Handles all operations related to admin user management with security in mind
 */
class AdminUserManager {
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
     * Create a new admin user
     * 
     * @param array $userData User data (email, password, first_name, last_name, role_id, etc.)
     * @param int $createdBy Admin ID of the creator
     * @return int|bool The new user ID or false on failure
     */
    public function createUser(array $userData, int $createdBy) {
        try {
            // Start transaction
            $this->pdo->beginTransaction();
            
            // Hash password with secure algorithm
            $hashedPassword = password_hash($userData['password'], PASSWORD_BCRYPT, ['cost' => 12]);
            
            // Generate verification token (for email verification)
            $verificationToken = bin2hex(random_bytes(32));
            $tokenExpiry = date('Y-m-d H:i:s', strtotime('+24 hours'));
            
            // Create user
            $stmt = $this->pdo->prepare("
                INSERT INTO admin_users (
                    email, password, first_name, last_name, role_id, parent_admin_id,
                    is_active, email_verified, verification_token, token_expiry, created_at
                ) VALUES (
                    :email, :password, :first_name, :last_name, :role_id, :parent_admin_id,
                    :is_active, 0, :verification_token, :token_expiry, NOW()
                )
            ");
            
            $stmt->bindValue(':email', filter_var($userData['email'], FILTER_SANITIZE_EMAIL));
            $stmt->bindValue(':password', $hashedPassword);
            $stmt->bindValue(':first_name', htmlspecialchars($userData['first_name']));
            $stmt->bindValue(':last_name', htmlspecialchars($userData['last_name']));
            $stmt->bindValue(':role_id', (int)$userData['role_id']);
            $stmt->bindValue(':parent_admin_id', $createdBy);
            $stmt->bindValue(':is_active', isset($userData['is_active']) ? 1 : 0);
            $stmt->bindValue(':verification_token', $verificationToken);
            $stmt->bindValue(':token_expiry', $tokenExpiry);
            
            $stmt->execute();
            $userId = $this->pdo->lastInsertId();
            
            // If store access is provided, set it up
            if (!empty($userData['store_access'])) {
                foreach ($userData['store_access'] as $access) {
                    $storeStmt = $this->pdo->prepare("
                        INSERT INTO admin_store_access (
                            admin_id, main_store_id, store_id, created_at
                        ) VALUES (
                            :admin_id, :main_store_id, :store_id, NOW()
                        )
                    ");
                    
                    $storeStmt->bindValue(':admin_id', $userId);
                    $storeStmt->bindValue(':main_store_id', $access['main_store_id']);
                    $storeStmt->bindValue(':store_id', $access['store_id'] ?? null);
                    $storeStmt->execute();
                }
            }
            
            // Log the action
            $this->logActivity(
                $createdBy,
                'create',
                'admin_users',
                $userId,
                "Created new admin user: {$userData['email']}"
            );
            
            // Send verification email (implementation depends on your email setup)
            // $this->sendVerificationEmail($userData['email'], $verificationToken);
            
            // Commit transaction
            $this->pdo->commit();
            return $userId;
            
        } catch (Exception $e) {
            // Roll back transaction on error
            $this->pdo->rollBack();
            error_log('Error creating admin user: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Update an existing admin user
     * 
     * @param int $userId The user ID to update
     * @param array $userData The new user data
     * @param int $updatedBy Admin ID of the updater
     * @return bool Success or failure
     */
    public function updateUser(int $userId, array $userData, int $updatedBy) {
        try {
            // Start transaction
            $this->pdo->beginTransaction();
            
            // First, check if the updater has permission to modify this user
            if (!$this->canModifyUser($updatedBy, $userId)) {
                return false;
            }
            
            // Build update query based on provided fields
            $updateFields = [];
            $params = [':admin_id' => $userId];
            
            if (isset($userData['email'])) {
                $updateFields[] = "email = :email";
                $params[':email'] = filter_var($userData['email'], FILTER_SANITIZE_EMAIL);
            }
            
            if (isset($userData['first_name'])) {
                $updateFields[] = "first_name = :first_name";
                $params[':first_name'] = htmlspecialchars($userData['first_name']);
            }
            
            if (isset($userData['last_name'])) {
                $updateFields[] = "last_name = :last_name";
                $params[':last_name'] = htmlspecialchars($userData['last_name']);
            }
            
            if (isset($userData['role_id'])) {
                $updateFields[] = "role_id = :role_id";
                $params[':role_id'] = (int)$userData['role_id'];
            }
            
            if (isset($userData['is_active'])) {
                $updateFields[] = "is_active = :is_active";
                $params[':is_active'] = $userData['is_active'] ? 1 : 0;
            }
            
            // Only update password if provided
            if (!empty($userData['password'])) {
                $hashedPassword = password_hash($userData['password'], PASSWORD_BCRYPT, ['cost' => 12]);
                $updateFields[] = "password = :password";
                $params[':password'] = $hashedPassword;
            }
            
            // Update user if there are fields to update
            if (!empty($updateFields)) {
                $sql = "UPDATE admin_users SET " . implode(", ", $updateFields) . ", 
                       updated_at = NOW() WHERE admin_id = :admin_id";
                
                $stmt = $this->pdo->prepare($sql);
                $stmt->execute($params);
            }
            
            // Update store access if provided
            if (isset($userData['store_access'])) {
                // Remove existing access
                $deleteStmt = $this->pdo->prepare("
                    DELETE FROM admin_store_access WHERE admin_id = :admin_id
                ");
                $deleteStmt->bindValue(':admin_id', $userId);
                $deleteStmt->execute();
                
                // Add new access
                foreach ($userData['store_access'] as $access) {
                    $storeStmt = $this->pdo->prepare("
                        INSERT INTO admin_store_access (
                            admin_id, main_store_id, store_id, created_at
                        ) VALUES (
                            :admin_id, :main_store_id, :store_id, NOW()
                        )
                    ");
                    
                    $storeStmt->bindValue(':admin_id', $userId);
                    $storeStmt->bindValue(':main_store_id', $access['main_store_id']);
                    $storeStmt->bindValue(':store_id', $access['store_id'] ?? null);
                    $storeStmt->execute();
                }
            }
            
            // Log the action
            $this->logActivity(
                $updatedBy,
                'update',
                'admin_users',
                $userId,
                "Updated admin user ID: {$userId}"
            );
            
            // Commit transaction
            $this->pdo->commit();
            return true;
            
        } catch (Exception $e) {
            // Roll back transaction on error
            $this->pdo->rollBack();
            error_log('Error updating admin user: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Delete an admin user
     * 
     * @param int $userId The user ID to delete
     * @param int $deletedBy Admin ID of the deleter
     * @return bool Success or failure
     */
    public function deleteUser(int $userId, int $deletedBy) {
        try {
            // Start transaction
            $this->pdo->beginTransaction();
            
            // First, check if the deleter has permission to delete this user
            if (!$this->canModifyUser($deletedBy, $userId)) {
                return false;
            }
            
            // Get user email for logging
            $stmt = $this->pdo->prepare("SELECT email FROM admin_users WHERE admin_id = :admin_id");
            $stmt->bindValue(':admin_id', $userId);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Delete the user
            $stmt = $this->pdo->prepare("DELETE FROM admin_users WHERE admin_id = :admin_id");
            $stmt->bindValue(':admin_id', $userId);
            $stmt->execute();
            
            // Log the action
            $this->logActivity(
                $deletedBy,
                'delete',
                'admin_users',
                $userId,
                "Deleted admin user: {$user['email']}"
            );
            
            // Commit transaction
            $this->pdo->commit();
            return true;
            
        } catch (Exception $e) {
            // Roll back transaction on error
            $this->pdo->rollBack();
            error_log('Error deleting admin user: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get user by ID
     * 
     * @param int $userId The user ID
     * @return array|bool User data or false if not found
     */
    public function getUserById(int $userId) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT au.*, r.name as role_name 
                FROM admin_users au
                JOIN roles r ON au.role_id = r.role_id
                WHERE au.admin_id = :admin_id
            ");
            $stmt->bindValue(':admin_id', $userId);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                // Get store access
                $accessStmt = $this->pdo->prepare("
                    SELECT * FROM admin_store_access 
                    WHERE admin_id = :admin_id
                ");
                $accessStmt->bindValue(':admin_id', $userId);
                $accessStmt->execute();
                
                $user['store_access'] = $accessStmt->fetchAll(PDO::FETCH_ASSOC);
                return $user;
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log('Error getting admin user: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get users by parent
     * 
     * @param int $parentId The parent admin ID
     * @return array Array of users
     */
    public function getUsersByParent(int $parentId) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT au.*, r.name as role_name 
                FROM admin_users au
                JOIN roles r ON au.role_id = r.role_id
                WHERE au.parent_admin_id = :parent_id
                ORDER BY au.last_name, au.first_name
            ");
            $stmt->bindValue(':parent_id', $parentId);
            $stmt->execute();
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch (Exception $e) {
            error_log('Error getting users by parent: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Check if an admin can modify another user
     * 
     * @param int $adminId The admin checking permissions
     * @param int $targetUserId The user to be modified
     * @return bool True if can modify, false otherwise
     */
    private function canModifyUser(int $adminId, int $targetUserId) {
        // Don't allow modification of own account through this method
        if ($adminId === $targetUserId) {
            return false;
        }
        
        // Get admin role
        $stmt = $this->pdo->prepare("
            SELECT au.role_id, r.name as role_name 
            FROM admin_users au
            JOIN roles r ON au.role_id = r.role_id
            WHERE au.admin_id = :admin_id
        ");
        $stmt->bindValue(':admin_id', $adminId);
        $stmt->execute();
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // SuperAdmin can modify anyone
        if ($admin['role_name'] === 'SuperAdmin') {
            return true;
        }
        
        // Get target user info
        $stmt = $this->pdo->prepare("
            SELECT parent_admin_id, role_id, (
                SELECT name FROM roles WHERE role_id = admin_users.role_id
            ) as role_name
            FROM admin_users 
            WHERE admin_id = :target_user_id
        ");
        $stmt->bindValue(':target_user_id', $targetUserId);
        $stmt->execute();
        $targetUser = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // If target is SuperAdmin, only SuperAdmin can modify
        if ($targetUser['role_name'] === 'SuperAdmin') {
            return false;
        }
        
        // Check if current admin is the creator of target user
        if ($targetUser['parent_admin_id'] === $adminId) {
            return true;
        }
        
        // StoreAdmin can modify users in their hierarchy
        if ($admin['role_name'] === 'StoreAdmin') {
            // Check if target user is in admin's hierarchy
            $hierarchyCheck = $this->isInHierarchy($adminId, $targetUserId);
            return $hierarchyCheck;
        }
        
        return false;
    }
    
    /**
     * Check if one user is in another's hierarchy
     * 
     * @param int $ancestorId Potential ancestor
     * @param int $descendantId Potential descendant
     * @return bool True if in hierarchy, false otherwise
     */
    private function isInHierarchy(int $ancestorId, int $descendantId) {
        // Check direct parent
        $stmt = $this->pdo->prepare("
            SELECT parent_admin_id FROM admin_users WHERE admin_id = :descendant_id
        ");
        $stmt->bindValue(':descendant_id', $descendantId);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$result || !$result['parent_admin_id']) {
            return false;
        }
        
        $parentId = $result['parent_admin_id'];
        
        // Direct parent match
        if ($parentId === $ancestorId) {
            return true;
        }
        
        // Recursively check up the hierarchy
        return $this->isInHierarchy($ancestorId, $parentId);
    }
    
    /**
     * Log admin activity
     * 
     * @param int $adminId The admin ID
     * @param string $actionType The action type (create, update, delete)
     * @param string $entityType The entity type (admin_users, stores, etc.)
     * @param int $entityId The entity ID
     * @param string $details Additional details
     * @return bool Success or failure
     */
    private function logActivity($adminId, $actionType, $entityType, $entityId, $details) {
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
            
        } catch (Exception $e) {
            error_log('Error logging activity: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verify user's email
     * 
     * @param string $token Verification token
     * @return bool Success or failure
     */
    public function verifyEmail($token) {
        try {
            // Find user with this token
            $stmt = $this->pdo->prepare("
                SELECT admin_id FROM admin_users 
                WHERE verification_token = :token 
                AND token_expiry > NOW() 
                AND email_verified = 0
            ");
            $stmt->bindValue(':token', $token);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                return false;
            }
            
            // Update user as verified
            $updateStmt = $this->pdo->prepare("
                UPDATE admin_users 
                SET email_verified = 1, 
                    verification_token = NULL, 
                    token_expiry = NULL 
                WHERE admin_id = :admin_id
            ");
            $updateStmt->bindValue(':admin_id', $user['admin_id']);
            
            return $updateStmt->execute();
            
        } catch (Exception $e) {
            error_log('Error verifying email: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if email exists
     * 
     * @param string $email Email to check
     * @param int $excludeId User ID to exclude from check
     * @return bool True if exists, false otherwise
     */
    public function emailExists($email, $excludeId = null) {
        try {
            $sql = "SELECT COUNT(*) FROM admin_users WHERE email = :email";
            $params = [':email' => $email];
            
            if ($excludeId) {
                $sql .= " AND admin_id != :exclude_id";
                $params[':exclude_id'] = $excludeId;
            }
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchColumn() > 0;
            
        } catch (Exception $e) {
            error_log('Error checking email: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get all available roles
     * 
     * @return array Array of roles
     */
    public function getAllRoles() {
        try {
            $stmt = $this->pdo->query("SELECT * FROM roles ORDER BY name");
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch (Exception $e) {
            error_log('Error getting roles: ' . $e->getMessage());
            return [];
        }
    }
}