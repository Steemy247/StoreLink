<?php
// Start session and check if user is logged in
session_start();
if (!isset($_SESSION['admin_id'])) {
    header("Location: ../login.php");
    exit;
}

// Include database connection and classes
require_once '../config/database.php';
require_once '../classes/AdminUserManager.php';

// Get admin information
$admin_id = $_SESSION['admin_id'];
$role_name = $_SESSION['role_name'];
$admin_name = $_SESSION['admin_name'];

// Check if user has permission to add users (SuperAdmin or StoreAdmin only)
if (!in_array($role_name, ['SuperAdmin', 'StoreAdmin'])) {
    header("Location: dashboard.php");
    exit;
}

// Initialize user manager
$userManager = new AdminUserManager($pdo);

// Get available roles (filtered by current user's role)
$availableRoles = [];
$allRoles = $userManager->getAllRoles();
foreach ($allRoles as $role) {
    // SuperAdmin can assign any role except SuperAdmin
    if ($role_name === 'SuperAdmin') {
        if ($role['name'] !== 'SuperAdmin') {
            $availableRoles[] = $role;
        }
    } 
    // StoreAdmin can only assign StoreModerator and StoreUser
    else if ($role_name === 'StoreAdmin') {
        if (in_array($role['name'], ['StoreModerator', 'StoreUser'])) {
            $availableRoles[] = $role;
        }
    }
}

// Get stores the admin has access to
$stores = [];
try {
    // Different queries based on role
    if ($role_name === 'SuperAdmin') {
        // SuperAdmin can see all main stores
        $storeStmt = $pdo->prepare("SELECT * FROM main_stores WHERE is_active = 1 ORDER BY name");
        $storeStmt->execute();
    } else {
        // StoreAdmin sees only assigned main stores
        $storeStmt = $pdo->prepare("
            SELECT ms.* 
            FROM main_stores ms
            JOIN admin_store_access asa ON ms.main_store_id = asa.main_store_id
            WHERE asa.admin_id = :admin_id AND ms.is_active = 1
            GROUP BY ms.main_store_id
            ORDER BY ms.name
        ");
        $storeStmt->bindParam(':admin_id', $admin_id);
        $storeStmt->execute();
    }
    
    while ($store = $storeStmt->fetch(PDO::FETCH_ASSOC)) {
        // Get branches for this store
        $branchStmt = $pdo->prepare("
            SELECT * FROM stores 
            WHERE main_store_id = :main_store_id AND is_active = 1
            ORDER BY name
        ");
        $branchStmt->bindParam(':main_store_id', $store['main_store_id']);
        $branchStmt->execute();
        
        $branches = [];
        while ($branch = $branchStmt->fetch(PDO::FETCH_ASSOC)) {
            $branches[] = $branch;
        }
        
        $store['branches'] = $branches;
        $stores[] = $store;
    }
} catch (PDOException $e) {
    $error = "Database error: " . $e->getMessage();
}

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $firstName = htmlspecialchars($_POST['first_name'] ?? '');
    $lastName = htmlspecialchars($_POST['last_name'] ?? '');
    $password = $_POST['password'] ?? '';
    $roleId = (int)($_POST['role_id'] ?? 0);
    $isActive = isset($_POST['is_active']) ? 1 : 0;
    
    // Process store access
    $storeAccess = [];
    if (isset($_POST['store_access']) && is_array($_POST['store_access'])) {
        foreach ($_POST['store_access'] as $access) {
            // Format: main_store_id:store_id or main_store_id:all
            $parts = explode(':', $access);
            $mainStoreId = (int)$parts[0];
            
            if ($parts[1] === 'all') {
                // Access to all branches of this main store
                $storeAccess[] = [
                    'main_store_id' => $mainStoreId,
                    'store_id' => null
                ];
            } else {
                // Access to specific branch
                $storeAccess[] = [
                    'main_store_id' => $mainStoreId,
                    'store_id' => (int)$parts[1]
                ];
            }
        }
    }
    
    // Validate input
    $errors = [];
    
    if (empty($email)) {
        $errors[] = "Email is required";
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Email is invalid";
    } else if ($userManager->emailExists($email)) {
        $errors[] = "Email is already in use";
    }
    
    if (empty($firstName)) {
        $errors[] = "First name is required";
    }
    
    if (empty($lastName)) {
        $errors[] = "Last name is required";
    }
    
    if (empty($password)) {
        $errors[] = "Password is required";
    } else if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    
    if ($roleId === 0) {
        $errors[] = "Role is required";
    }
    
    if (empty($storeAccess)) {
        $errors[] = "At least one store access is required";
    }
    
    // Check if selected role is allowed for current admin
    $roleAllowed = false;
    foreach ($availableRoles as $role) {
        if ($role['role_id'] === $roleId) {
            $roleAllowed = true;
            break;
        }
    }
    
    if (!$roleAllowed) {
        $errors[] = "Selected role is not allowed";
    }
    
    // If no errors, create user
    if (empty($errors)) {
        $userData = [
            'email' => $email,
            'password' => $password,
            'first_name' => $firstName,
            'last_name' => $lastName,
            'role_id' => $roleId,
            'is_active' => $isActive,
            'store_access' => $storeAccess
        ];
        
        $result = $userManager->createUser($userData, $admin_id);
        
        if ($result) {
            $_SESSION['success'] = "User created successfully";
            header("Location: users.php");
            exit;
        } else {
            $errors[] = "Failed to create user. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Add User</title>
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
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 d-md-block sidebar collapse p-0">
                <div class="d-flex flex-column p-3 text-white">
                    <a href="dashboard.php" class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-white text-decoration-none">
                        <span class="fs-4">StoreLink Admin</span>
                    </a>
                    <hr>
                    <ul class="nav nav-pills flex-column mb-auto">
                        <li class="nav-item">
                            <a href="dashboard.php" class="nav-link text-white">
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
                            <a href="users.php" class="nav-link active">
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
                            <li><a class="dropdown-item" href="profile.php">Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php">Sign out</a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Main content -->
            <div class="col-md-9 ms-sm-auto col-lg-10 px-md-4 main-content">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Add Admin User</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <a href="users.php" class="btn btn-sm btn-outline-secondary">
                                <i class="fas fa-arrow-left me-1"></i> Back to Users
                            </a>
                        </div>
                    </div>
                </div>
                
                <?php if (!empty($errors)): ?>
                    <div class="alert alert-danger">
                        <ul class="mb-0">
                            <?php foreach ($errors as $error): ?>
                                <li><?php echo $error; ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                
                <div class="row">
                    <div class="col-12">
                        <div class="card shadow mb-4">
                            <div class="card-header py-3">
                                <h6 class="m-0 font-weight-bold text-primary">User Information</h6>
                            </div>
                            <div class="card-body">
                                <form method="post" action="add-user.php">
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label for="first_name" class="form-label">First Name</label>
                                            <input type="text" class="form-control" id="first_name" name="first_name" value="<?php echo $_POST['first_name'] ?? ''; ?>" required>
                                        </div>
                                        <div class="col-md-6">
                                            <label for="last_name" class="form-label">Last Name</label>
                                            <input type="text" class="form-control" id="last_name" name="last_name" value="<?php echo $_POST['last_name'] ?? ''; ?>" required>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="email" class="form-label">Email</label>
                                        <input type="email" class="form-control" id="email" name="email" value="<?php echo $_POST['email'] ?? ''; ?>" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="password" class="form-label">Password</label>
                                        <input type="password" class="form-control" id="password" name="password" required>
                                        <div class="form-text">Password must be at least 8 characters long.</div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label for="role_id" class="form-label">Role</label>
                                            <select class="form-select" id="role_id" name="role_id" required>
                                                <option value="">Select Role</option>
                                                <?php foreach ($availableRoles as $role): ?>
                                                    <option value="<?php echo $role['role_id']; ?>" <?php echo (isset($_POST['role_id']) && $_POST['role_id'] == $role['role_id']) ? 'selected' : ''; ?>>
                                                        <?php echo htmlspecialchars($role['name']); ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="form-check mt-4">
                                                <input class="form-check-input" type="checkbox" id="is_active" name="is_active" <?php echo (!isset($_POST['is_active']) || $_POST['is_active']) ? 'checked' : ''; ?>>
                                                <label class="form-check-label" for="is_active">
                                                    Active User
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Store Access</label>
                                        <div class="alert alert-info">
                                            <i class="fas fa-info-circle me-2"></i>
                                            Select which stores and branches this user can access. You can grant access to an entire main store or specific branches.
                                        </div>
                                        
                                        <?php if (empty($stores)): ?>
                                            <div class="alert alert-warning">
                                                No stores available. Please create a store first.
                                            </div>
                                        <?php else: ?>
                                            <div class="row">
                                                <?php foreach ($stores as $store): ?>
                                                <div class="col-md-6 mb-3">
                                                    <div class="card">
                                                        <div class="card-header">
                                                            <div class="form-check">
                                                                <input class="form-check-input store-checkbox" type="checkbox" 
                                                                       id="store_<?php echo $store['main_store_id']; ?>" 
                                                                       name="store_access[]" 
                                                                       value="<?php echo $store['main_store_id']; ?>:all"
                                                                       data-store-id="<?php echo $store['main_store_id']; ?>">
                                                                <label class="form-check-label" for="store_<?php echo $store['main_store_id']; ?>">
                                                                    <strong><?php echo htmlspecialchars($store['name']); ?></strong> (All Branches)
                                                                </label>
                                                            </div>
                                                        </div>
                                                        <?php if (!empty($store['branches'])): ?>
                                                        <div class="card-body">
                                                            <div class="ms-4">
                                                                <?php foreach ($store['branches'] as $branch): ?>
                                                                <div class="form-check">
                                                                    <input class="form-check-input branch-checkbox" 
                                                                           type="checkbox" 
                                                                           id="branch_<?php echo $branch['store_id']; ?>" 
                                                                           name="store_access[]" 
                                                                           value="<?php echo $store['main_store_id']; ?>:<?php echo $branch['store_id']; ?>"
                                                                           data-store-id="<?php echo $store['main_store_id']; ?>">
                                                                    <label class="form-check-label" for="branch_<?php echo $branch['store_id']; ?>">
                                                                        <?php echo htmlspecialchars($branch['name']); ?>
                                                                    </label>
                                                                </div>
                                                                <?php endforeach; ?>
                                                            </div>
                                                        </div>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                                <?php endforeach; ?>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <a href="users.php" class="btn btn-secondary me-md-2">Cancel</a>
                                        <button type="submit" class="btn btn-primary">Create User</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS and dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // JavaScript for handling store/branch selection
        document.addEventListener('DOMContentLoaded', function() {
            // When a store checkbox is clicked
            const storeCheckboxes = document.querySelectorAll('.store-checkbox');
            storeCheckboxes.forEach(checkbox => {
                checkbox.addEventListener('change', function() {
                    const storeId = this.dataset.storeId;
                    const branchCheckboxes = document.querySelectorAll(`.branch-checkbox[data-store-id="${storeId}"]`);
                    
                    // If store is checked, check all branches and disable them
                    if (this.checked) {
                        branchCheckboxes.forEach(branchCheckbox => {
                            branchCheckbox.checked = false;
                            branchCheckbox.disabled = true;
                        });
                    } 
                    // If store is unchecked, enable all branches
                    else {
                        branchCheckboxes.forEach(branchCheckbox => {
                            branchCheckbox.disabled = false;
                        });
                    }
                });
            });
            
            // When a branch checkbox is clicked
            const branchCheckboxes = document.querySelectorAll('.branch-checkbox');
            branchCheckboxes.forEach(checkbox => {
                checkbox.addEventListener('change', function() {
                    const storeId = this.dataset.storeId;
                    const storeCheckbox = document.querySelector(`.store-checkbox[data-store-id="${storeId}"]`);
                    
                    // If any branch is checked, uncheck the store
                    if (this.checked) {
                        storeCheckbox.checked = false;
                    }
                });
            });
        });
    </script>
</body>
</html>