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

// Check if user has permission to add stores
if (!in_array($role_name, ['SuperAdmin', 'StoreAdmin'])) {
    $_SESSION['error'] = "You don't have permission to access this page.";
    header("Location: dashboard.php");
    exit;
}

// Generate CSRF token
$csrf_token = $security->generateCSRFToken('add_store');

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !$security->validateCSRFToken($_POST['csrf_token'], 'add_store')) {
        $_SESSION['error'] = "Invalid request. Please try again.";
        header("Location: add-store.php");
        exit;
    }
    
    // Sanitize and validate input
    $name = htmlspecialchars(trim($_POST['name'] ?? ''));
    $description = htmlspecialchars(trim($_POST['description'] ?? ''));
    $logo_url = htmlspecialchars(trim($_POST['logo_url'] ?? ''));
    $address = htmlspecialchars(trim($_POST['address'] ?? ''));
    $city = htmlspecialchars(trim($_POST['city'] ?? ''));
    $state = htmlspecialchars(trim($_POST['state'] ?? ''));
    $country = htmlspecialchars(trim($_POST['country'] ?? ''));
    $postal_code = htmlspecialchars(trim($_POST['postal_code'] ?? ''));
    $phone = htmlspecialchars(trim($_POST['phone'] ?? ''));
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    $website = htmlspecialchars(trim($_POST['website'] ?? ''));
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    
    // Validate required fields
    $errors = [];
    
    if (empty($name)) {
        $errors[] = "Store name is required.";
    }
    
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Email address is invalid.";
    }
    
    // If no errors, insert store into database
    if (empty($errors)) {
        try {
            // Start transaction
            $pdo->beginTransaction();
            
            // Insert store
            $stmt = $pdo->prepare("
                INSERT INTO main_stores (
                    name, description, logo_url, headquarters_address, headquarters_city, 
                    headquarters_state, headquarters_country, headquarters_postal_code, 
                    main_phone, main_email, website, is_active, created_at
                ) VALUES (
                    :name, :description, :logo_url, :address, :city, 
                    :state, :country, :postal_code, 
                    :phone, :email, :website, :is_active, NOW()
                )
            ");
            
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':description', $description);
            $stmt->bindParam(':logo_url', $logo_url);
            $stmt->bindParam(':address', $address);
            $stmt->bindParam(':city', $city);
            $stmt->bindParam(':state', $state);
            $stmt->bindParam(':country', $country);
            $stmt->bindParam(':postal_code', $postal_code);
            $stmt->bindParam(':phone', $phone);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':website', $website);
            $stmt->bindParam(':is_active', $is_active);
            
            $stmt->execute();
            $store_id = $pdo->lastInsertId();
            
            // If current user is StoreAdmin, automatically give them access to this store
            if ($role_name === 'StoreAdmin') {
                $accessStmt = $pdo->prepare("
                    INSERT INTO admin_store_access (
                        admin_id, main_store_id, created_at
                    ) VALUES (
                        :admin_id, :main_store_id, NOW()
                    )
                ");
                
                $accessStmt->bindParam(':admin_id', $admin_id);
                $accessStmt->bindParam(':main_store_id', $store_id);
                $accessStmt->execute();
            }
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'create',
                'main_stores',
                $store_id,
                "Created new main store: $name"
            );
            
            // Commit transaction
            $pdo->commit();
            
            $_SESSION['success'] = "Store created successfully.";
            header("Location: stores.php");
            exit;
        } catch (PDOException $e) {
            // Rollback transaction on error
            $pdo->rollBack();
            $errors[] = "Database error: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Add Store</title>
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
                            <a href="stores.php" class="nav-link active">
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
                    <h1 class="h2">Add Main Store</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="stores.php" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-1"></i> Back to Stores
                        </a>
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
                
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <form method="post" action="add-store.php">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            
                            <div class="row mb-3">
                                <div class="col-md-8">
                                    <label for="name" class="form-label">Store Name</label>
                                    <input type="text" class="form-control" id="name" name="name" value="<?php echo $_POST['name'] ?? ''; ?>" required>
                                </div>
                                <div class="col-md-4">
                                    <label for="is_active" class="form-label">Status</label>
                                    <div class="form-check form-switch mt-2">
                                        <input class="form-check-input" type="checkbox" id="is_active" name="is_active" <?php echo (!isset($_POST['is_active']) || $_POST['is_active']) ? 'checked' : ''; ?>>
                                        <label class="form-check-label" for="is_active">Active</label>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="description" class="form-label">Description</label>
                                <textarea class="form-control" id="description" name="description" rows="3"><?php echo $_POST['description'] ?? ''; ?></textarea>
                            </div>
                            
                            <div class="mb-3">
                                <label for="logo_url" class="form-label">Logo URL</label>
                                <input type="url" class="form-control" id="logo_url" name="logo_url" value="<?php echo $_POST['logo_url'] ?? ''; ?>">
                                <div class="form-text">Enter a URL for the store logo image.</div>
                            </div>
                            
                            <hr class="my-4">
                            <h5>Headquarters Information</h5>
                            
                            <div class="mb-3">
                                <label for="address" class="form-label">Address</label>
                                <input type="text" class="form-control" id="address" name="address" value="<?php echo $_POST['address'] ?? ''; ?>">
                            </div>
                            
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label for="city" class="form-label">City</label>
                                    <input type="text" class="form-control" id="city" name="city" value="<?php echo $_POST['city'] ?? ''; ?>">
                                </div>
                                <div class="col-md-6">
                                    <label for="state" class="form-label">State/Province</label>
                                    <input type="text" class="form-control" id="state" name="state" value="<?php echo $_POST['state'] ?? ''; ?>">
                                </div>
                            </div>
                            
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label for="country" class="form-label">Country</label>
                                    <input type="text" class="form-control" id="country" name="country" value="<?php echo $_POST['country'] ?? ''; ?>">
                                </div>
                                <div class="col-md-6">
                                    <label for="postal_code" class="form-label">Postal Code</label>
                                    <input type="text" class="form-control" id="postal_code" name="postal_code" value="<?php echo $_POST['postal_code'] ?? ''; ?>">
                                </div>
                            </div>
                            
                            <hr class="my-4">
                            <h5>Contact Information</h5>
                            
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label for="phone" class="form-label">Phone Number</label>
                                    <input type="tel" class="form-control" id="phone" name="phone" value="<?php echo $_POST['phone'] ?? ''; ?>">
                                </div>
                                <div class="col-md-6">
                                    <label for="email" class="form-label">Email Address</label>
                                    <input type="email" class="form-control" id="email" name="email" value="<?php echo $_POST['email'] ?? ''; ?>">
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <label for="website" class="form-label">Website</label>
                                <input type="url" class="form-control" id="website" name="website" value="<?php echo $_POST['website'] ?? ''; ?>">
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                <a href="stores.php" class="btn btn-outline-secondary me-md-2">Cancel</a>
                                <button type="submit" class="btn btn-primary">Create Store</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>