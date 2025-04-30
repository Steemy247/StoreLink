<?php
// Start session and check if user is logged in
session_start();
if (!isset($_SESSION['admin_id'])) {
    header("Location: login.php");
    exit;
}

// Include database connection and classes
require_once '../config/database.php';
require_once '../classes/SecurityManager.php';

// Initialize security manager
$security = new SecurityManager($pdo);

// Get admin information
$admin_id = $_SESSION['admin_id'];
$role_name = $_SESSION['role_name'];
$admin_name = $_SESSION['admin_name'];

// Generate CSRF token for forms
$csrf_token = $security->generateCSRFToken('profile_update');
$csrf_token_password = $security->generateCSRFToken('password_change');

// Get admin user details
try {
    $stmt = $pdo->prepare("
        SELECT au.*, r.name as role_name 
        FROM admin_users au
        JOIN roles r ON au.role_id = r.role_id
        WHERE au.admin_id = :admin_id
    ");
    $stmt->bindParam(':admin_id', $admin_id);
    $stmt->execute();
    $user = $stmt->fetch();
    
    if (!$user) {
        $_SESSION['error'] = "User not found.";
        header("Location: dashboard.php");
        exit;
    }
    
    // Get admin who created this user
    if ($user['parent_admin_id']) {
        $creatorStmt = $pdo->prepare("
            SELECT first_name, last_name FROM admin_users 
            WHERE admin_id = :parent_id
        ");
        $creatorStmt->bindParam(':parent_id', $user['parent_admin_id']);
        $creatorStmt->execute();
        $creator = $creatorStmt->fetch();
    }
    
    // Get access permissions (stores)
    $accessStmt = $pdo->prepare("
        SELECT asa.*, ms.name as main_store_name, s.name as store_name
        FROM admin_store_access asa
        LEFT JOIN main_stores ms ON asa.main_store_id = ms.main_store_id
        LEFT JOIN stores s ON asa.store_id = s.store_id
        WHERE asa.admin_id = :admin_id
    ");
    $accessStmt->bindParam(':admin_id', $admin_id);
    $accessStmt->execute();
    $store_access = $accessStmt->fetchAll();
    
    // Get recent activity
    $activityStmt = $pdo->prepare("
        SELECT * FROM admin_activity_logs
        WHERE admin_id = :admin_id
        ORDER BY created_at DESC
        LIMIT 10
    ");
    $activityStmt->bindParam(':admin_id', $admin_id);
    $activityStmt->execute();
    $activities = $activityStmt->fetchAll();
    
} catch (PDOException $e) {
    $_SESSION['error'] = "Database error: " . $e->getMessage();
    header("Location: dashboard.php");
    exit;
}

// Process profile update form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !$security->validateCSRFToken($_POST['csrf_token'], 'profile_update')) {
        $_SESSION['error'] = "Invalid request. Please try again.";
        header("Location: profile.php");
        exit;
    }
    
    // Sanitize and validate input
    $first_name = htmlspecialchars(trim($_POST['first_name'] ?? ''));
    $last_name = htmlspecialchars(trim($_POST['last_name'] ?? ''));
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    
    // Validate required fields
    $errors = [];
    
    if (empty($first_name)) {
        $errors[] = "First name is required.";
    }
    
    if (empty($last_name)) {
        $errors[] = "Last name is required.";
    }
    
    if (empty($email)) {
        $errors[] = "Email is required.";
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Email address is invalid.";
    } else if ($email !== $user['email']) {
        // Check if email already exists (only if changed)
        try {
            $emailStmt = $pdo->prepare("
                SELECT COUNT(*) FROM admin_users 
                WHERE email = :email AND admin_id != :admin_id
            ");
            $emailStmt->bindParam(':email', $email);
            $emailStmt->bindParam(':admin_id', $admin_id);
            $emailStmt->execute();
            
            if ($emailStmt->fetchColumn() > 0) {
                $errors[] = "Email address is already in use.";
            }
        } catch (PDOException $e) {
            $errors[] = "Database error: " . $e->getMessage();
        }
    }
    
    // If no errors, update profile
    if (empty($errors)) {
        try {
            $stmt = $pdo->prepare("
                UPDATE admin_users 
                SET first_name = :first_name, last_name = :last_name, email = :email, updated_at = NOW()
                WHERE admin_id = :admin_id
            ");
            
            $stmt->bindParam(':first_name', $first_name);
            $stmt->bindParam(':last_name', $last_name);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':admin_id', $admin_id);
            
            if ($stmt->execute()) {
                // Log the activity
                $security->logActivity(
                    $admin_id,
                    'update',
                    'admin_users',
                    $admin_id,
                    "Updated profile information"
                );
                
                // Update session variables
                $_SESSION['admin_name'] = $first_name . ' ' . $last_name;
                
                $_SESSION['success'] = "Profile updated successfully.";
                header("Location: profile.php");
                exit;
            } else {
                $errors[] = "Failed to update profile. Please try again.";
            }
        } catch (PDOException $e) {
            $errors[] = "Database error: " . $e->getMessage();
        }
    }
}

// Process password change form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token_password']) || !$security->validateCSRFToken($_POST['csrf_token_password'], 'password_change')) {
        $_SESSION['error'] = "Invalid request. Please try again.";
        header("Location: profile.php");
        exit;
    }
    
    // Get form data
    $current_password = $_POST['current_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // Validate input
    $password_errors = [];
    
    if (empty($current_password)) {
        $password_errors[] = "Current password is required.";
    } else if (!$security->verifyPassword($current_password, $user['password'])) {
        $password_errors[] = "Current password is incorrect.";
    }
    
    if (empty($new_password)) {
        $password_errors[] = "New password is required.";
    } else {
        // Validate password strength
        $validation = $security->validatePassword($new_password);
        if (!$validation['valid']) {
            $password_errors[] = $validation['message'];
        }
    }
    
    if ($new_password !== $confirm_password) {
        $password_errors[] = "New passwords do not match.";
    }
    
    // If no errors, update password
    if (empty($password_errors)) {
        try {
            // Hash new password
            $hashed_password = $security->hashPassword($new_password);
            
            // Update password
            $stmt = $pdo->prepare("
                UPDATE admin_users 
                SET password = :password, updated_at = NOW()
                WHERE admin_id = :admin_id
            ");
            
            $stmt->bindParam(':password', $hashed_password);
            $stmt->bindParam(':admin_id', $admin_id);
            
            if ($stmt->execute()) {
                // Log the activity
                $security->logActivity(
                    $admin_id,
                    'update',
                    'admin_users',
                    $admin_id,
                    "Changed password"
                );
                
                $_SESSION['success'] = "Password changed successfully.";
                header("Location: profile.php");
                exit;
            } else {
                $password_errors[] = "Failed to update password. Please try again.";
            }
        } catch (PDOException $e) {
            $password_errors[] = "Database error: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Profile</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .sidebar {
            min-height: 100vh;
            background-color: #343a40;
            color: white;
        }
        .sidebar .nav-link {
            color: rgba(255, 255, 255, 0.75);
        }
        .sidebar .nav-link:hover {
            color: white;
        }
        .sidebar .nav-link.active {
            color: white;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .main-content {
            padding: 20px;
        }
        .profile-header {
            background-color: #f8f9fa;
            border-radius: 0.5rem;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .profile-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background-color: #e9ecef;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            color: #6c757d;
            margin-bottom: 1rem;
        }
        .activity-item {
            padding: 0.75rem 0;
            border-bottom: 1px solid #e9ecef;
        }
        .activity-item:last-child {
            border-bottom: none;
        }
        .badge-access {
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 d-md-block sidebar collapse p-0">
                <div class="d-flex flex-column p-3 text-white">
                    <a href="../pages/dashboard.php" class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-white text-decoration-none">
                        <span class="fs-4">StoreLink Admin</span>
                    </a>
                    <hr>
                    <ul class="nav nav-pills flex-column mb-auto">
                        <li class="nav-item">
                            <a href="../pages/dashboard.php" class="nav-link text-white">
                                <i class="fas fa-home me-2"></i>
                                Dashboard
                            </a>
                        </li>
                        
                        <?php if (in_array($role_name, ['SuperAdmin', 'StoreAdmin'])): ?>
                        <li>
                            <a href="stores.php" class="nav-link text-white">
                                <i class="fas fa-store me-2"></i>
                                Stores
                            </a>
                        </li>
                        <?php endif; ?>
                        
                        <?php if (in_array($role_name, ['SuperAdmin', 'StoreAdmin', 'StoreModerator'])): ?>
                        <li>
                            <a href="branches.php" class="nav-link text-white">
                                <i class="fas fa-code-branch me-2"></i>
                                Branches
                            </a>
                        </li>
                        <?php endif; ?>
                        
                        <li>
                            <a href="products.php" class="nav-link text-white">
                                <i class="fas fa-box me-2"></i>
                                Products
                            </a>
                        </li>
                        
                        <li>
                            <a href="orders.php" class="nav-link text-white">
                                <i class="fas fa-shopping-cart me-2"></i>
                                Orders
                            </a>
                        </li>
                        
                        <?php if (in_array($role_name, ['SuperAdmin', 'StoreAdmin'])): ?>
                        <li>
                            <a href="users.php" class="nav-link text-white">
                                <i class="fas fa-users me-2"></i>
                                Admin Users
                            </a>
                        </li>
                        <?php endif; ?>
                        
                        <?php if ($role_name === 'SuperAdmin'): ?>
                        <li>
                            <a href="settings.php" class="nav-link text-white">
                                <i class="fas fa-cog me-2"></i>
                                Settings
                            </a>
                        </li>
                        <?php endif; ?>
                    </ul>
                    <hr>
                    <div class="dropdown">
                        <a href="#" class="d-flex align-items-center text-white text-decoration-none dropdown-toggle" id="dropdownUser1" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-user-circle me-2 fs-5"></i>
                            <strong><?php echo htmlspecialchars($admin_name); ?></strong>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-dark text-small shadow" aria-labelledby="dropdownUser1">
                            <li><a class="dropdown-item active" href="profile.php">Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php">Sign out</a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Main content -->
            <div class="col-md-9 ms-sm-auto col-lg-10 px-md-4 main-content">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">My Profile</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="dashboard.php" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-1"></i> Back to Dashboard
                        </a>
                    </div>
                </div>
                
                <?php if (isset($_SESSION['success'])): ?>
                    <div class="alert alert-success alert-dismissible fade show">
                        <?php echo $_SESSION['success']; unset($_SESSION['success']); ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($_SESSION['error'])): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <?php echo $_SESSION['error']; unset($_SESSION['error']); ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($errors) && !empty($errors)): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <ul class="mb-0">
                            <?php foreach ($errors as $error): ?>
                                <li><?php echo $error; ?></li>
                            <?php endforeach; ?>
                        </ul>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($password_errors) && !empty($password_errors)): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <ul class="mb-0">
                            <?php foreach ($password_errors as $error): ?>
                                <li><?php echo $error; ?></li>
                            <?php endforeach; ?>
                        </ul>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>
                
                <!-- Profile Header -->
                <div class="profile-header">
                    <div class="row">
                        <div class="col-md-3 text-center">
                            <div class="profile-avatar mx-auto">
                                <i class="fas fa-user"></i>
                            </div>
                        </div>
                        <div class="col-md-9">
                            <h3><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?></h3>
                            <p class="text-muted mb-2">
                                <i class="fas fa-envelope me-2"></i> <?php echo htmlspecialchars($user['email']); ?>
                            </p>
                            <p class="mb-2">
                                <span class="badge bg-primary"><?php echo htmlspecialchars($user['role_name']); ?></span>
                                <span class="badge <?php echo $user['is_active'] ? 'bg-success' : 'bg-danger'; ?>">
                                    <?php echo $user['is_active'] ? 'Active' : 'Inactive'; ?>
                                </span>
                            </p>
                            <p class="mb-2">
                                <small class="text-muted">
                                    Account created: <?php echo date('F j, Y', strtotime($user['created_at'])); ?>
                                    <?php if (isset($creator)): ?>
                                        by <?php echo htmlspecialchars($creator['first_name'] . ' ' . $creator['last_name']); ?>
                                    <?php endif; ?>
                                </small>
                            </p>
                            <p class="mb-0">
                                <small class="text-muted">
                                    Last login: 
                                    <?php echo $user['last_login'] ? date('F j, Y g:i A', strtotime($user['last_login'])) : 'Never'; ?>
                                </small>
                            </p>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <!-- Personal Information -->
                        <div class="card shadow-sm mb-4">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Personal Information</h5>
                            </div>
                            <div class="card-body">
                                <form method="post" action="profile.php">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    
                                    <div class="mb-3">
                                        <label for="first_name" class="form-label">First Name</label>
                                        <input type="text" class="form-control" id="first_name" name="first_name" value="<?php echo htmlspecialchars($user['first_name']); ?>" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="last_name" class="form-label">Last Name</label>
                                        <input type="text" class="form-control" id="last_name" name="last_name" value="<?php echo htmlspecialchars($user['last_name']); ?>" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="email" class="form-label">Email Address</label>
                                        <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
                                    </div>
                                    
                                    <div class="d-grid">
                                        <button type="submit" name="update_profile" class="btn btn-primary">Update Profile</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        
                        <!-- Store Access -->
                        <div class="card shadow-sm mb-4">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Store Access</h5>
                            </div>
                            <div class="card-body">
                                <?php if (empty($store_access)): ?>
                                    <p class="text-muted">You don't have access to any stores.</p>
                                <?php else: ?>
                                    <div class="mb-4">
                                        <h6 class="mb-3">You have access to the following stores:</h6>
                                        
                                        <?php foreach ($store_access as $access): ?>
                                            <span class="badge bg-info badge-access">
                                                <?php echo htmlspecialchars($access['main_store_name']); ?>
                                                <?php if ($access['store_id']): ?>
                                                    - <?php echo htmlspecialchars($access['store_name']); ?>
                                                <?php else: ?>
                                                    (All Branches)
                                                <?php endif; ?>
                                            </span>
                                        <?php endforeach; ?>
                                    </div>
                                    
                                    <div class="alert alert-info mb-0">
                                        <i class="fas fa-info-circle me-2"></i>
                                        Store access is managed by administrators. Contact your manager if you need access to additional stores.
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <!-- Change Password -->
                        <div class="card shadow-sm mb-4">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Change Password</h5>
                            </div>
                            <div class="card-body">
                                <form method="post" action="profile.php" id="password-form">
                                    <input type="hidden" name="csrf_token_password" value="<?php echo $csrf_token_password; ?>">
                                    
                                    <div class="mb-3">
                                        <label for="current_password" class="form-label">Current Password</label>
                                        <input type="password" class="form-control" id="current_password" name="current_password" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="new_password" class="form-label">New Password</label>
                                        <input type="password" class="form-control" id="new_password" name="new_password" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="confirm_password" class="form-label">Confirm New Password</label>
                                        <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                                    </div>
                                    
                                    <div class="alert alert-info mb-3">
                                        <strong>Password Requirements:</strong>
                                        <ul class="mb-0 small">
                                            <li>At least 8 characters long</li>
                                            <li>At least one uppercase letter</li>
                                            <li>At least one lowercase letter</li>
                                            <li>At least one number</li>
                                            <li>At least one special character</li>
                                        </ul>
                                    </div>
                                    
                                    <div class="d-grid">
                                        <button type="submit" name="change_password" class="btn btn-primary">Change Password</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        
                        <!-- Recent Activity -->
                        <div class="card shadow-sm mb-4">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Recent Activity</h5>
                            </div>
                            <div class="card-body">
                                <?php if (empty($activities)): ?>
                                    <p class="text-muted">No recent activity found.</p>
                                <?php else: ?>
                                    <?php foreach ($activities as $activity): ?>
                                        <div class="activity-item">
                                            <div class="d-flex justify-content-between">
                                                <div>
                                                    <strong><?php echo ucfirst($activity['action_type']); ?></strong>
                                                    <span class="text-muted"><?php echo $activity['entity_type']; ?></span>
                                                </div>
                                                <div class="text-muted">
                                                    <?php echo date('M j, g:i A', strtotime($activity['created_at'])); ?>
                                                </div>
                                            </div>
                                            <div class="small text-muted mt-1">
                                                <?php echo htmlspecialchars($activity['details']); ?>
                                            </div>
                                            <div class="small text-muted">
                                                IP: <?php echo htmlspecialchars($activity['ip_address']); ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password validation
        document.getElementById('password-form').addEventListener('submit', function(event) {
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            // Check if passwords match
            if (newPassword !== confirmPassword) {
                alert('Passwords do not match!');
                event.preventDefault();
                return;
            }
            
            // Check password strength
            const hasUpperCase = /[A-Z]/.test(newPassword);
            const hasLowerCase = /[a-z]/.test(newPassword);
            const hasNumbers = /\d/.test(newPassword);
            const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword);
            const isLongEnough = newPassword.length >= 8;
            
            if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar || !isLongEnough) {
                alert('Password does not meet the requirements. Please ensure it has at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.');
                event.preventDefault();
            }
        });
    </script>
</body>
</html>