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

// Check if user has permission to view main stores
if (!in_array($role_name, ['SuperAdmin', 'StoreAdmin'])) {
    $_SESSION['error'] = "You don't have permission to access this page.";
    header("Location: dashboard.php");
    exit;
}

// Process store deletion if requested
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    $store_id = (int)$_GET['delete'];
    
    // Check if user has permission to delete this store
    if (($role_name === 'SuperAdmin') || 
        ($role_name === 'StoreAdmin' && $security->hasStoreAccess($admin_id, $store_id, true))) {
        
        try {
            // Start transaction
            $pdo->beginTransaction();
            
            // Check if store exists
            $checkStmt = $pdo->prepare("SELECT * FROM main_stores WHERE main_store_id = :id");
            $checkStmt->bindParam(':id', $store_id);
            $checkStmt->execute();
            
            if ($store = $checkStmt->fetch()) {
                // Delete store (this will cascade to related records due to constraints)
                $deleteStmt = $pdo->prepare("DELETE FROM main_stores WHERE main_store_id = :id");
                $deleteStmt->bindParam(':id', $store_id);
                $deleteStmt->execute();
                
                // Log the activity
                $security->logActivity(
                    $admin_id,
                    'delete',
                    'main_stores',
                    $store_id,
                    "Deleted main store: {$store['name']}"
                );
                
                $_SESSION['success'] = "Store deleted successfully.";
            } else {
                $_SESSION['error'] = "Store not found.";
            }
            
            // Commit transaction
            $pdo->commit();
        } catch (PDOException $e) {
            // Rollback transaction on error
            $pdo->rollBack();
            $_SESSION['error'] = "Could not delete store. It may have associated records.";
            error_log('Store deletion error: ' . $e->getMessage());
        }
    } else {
        $_SESSION['error'] = "You don't have permission to delete this store.";
    }
    
    header("Location: stores.php");
    exit;
}

// Get stores based on user role and permissions
try {
    if ($role_name === 'SuperAdmin') {
        // SuperAdmin can see all stores
        $stmt = $pdo->prepare("
            SELECT * FROM main_stores
            ORDER BY name
        ");
        $stmt->execute();
    } else {
        // StoreAdmin sees only assigned stores
        $stmt = $pdo->prepare("
            SELECT ms.* 
            FROM main_stores ms
            JOIN admin_store_access asa ON ms.main_store_id = asa.main_store_id
            WHERE asa.admin_id = :admin_id
            GROUP BY ms.main_store_id
            ORDER BY ms.name
        ");
        $stmt->bindParam(':admin_id', $admin_id);
        $stmt->execute();
    }
    
    $stores = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Database error: " . $e->getMessage();
    $stores = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Main Stores</title>
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
        .store-card {
            transition: transform 0.3s;
        }
        .store-card:hover {
            transform: translateY(-5px);
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
                    <h1 class="h2">Main Stores</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="add-store.php" class="btn btn-primary">
                            <i class="fas fa-plus me-1"></i> Add New Store
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
                
                <?php if (isset($error)): ?>
                    <div class="alert alert-danger">
                        <?php echo $error; ?>
                    </div>
                <?php endif; ?>
                
                <?php if (empty($stores)): ?>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        No stores found. Click the "Add New Store" button to create your first store.
                    </div>
                <?php else: ?>
                    <div class="row">
                        <?php foreach ($stores as $store): ?>
                            <div class="col-md-6 col-lg-4 mb-4">
                                <div class="card shadow-sm h-100 store-card">
                                    <div class="card-header bg-transparent d-flex justify-content-between align-items-center">
                                        <h5 class="card-title mb-0">
                                            <?php echo htmlspecialchars($store['name']); ?>
                                        </h5>
                                        <span class="badge <?php echo $store['is_active'] ? 'bg-success' : 'bg-danger'; ?>">
                                            <?php echo $store['is_active'] ? 'Active' : 'Inactive'; ?>
                                        </span>
                                    </div>
                                    <div class="card-body">
                                        <?php if ($store['logo_url']): ?>
                                            <img src="<?php echo htmlspecialchars($store['logo_url']); ?>" class="img-fluid mb-3" alt="<?php echo htmlspecialchars($store['name']); ?> Logo">
                                        <?php else: ?>
                                            <div class="text-center mb-3 bg-light py-5">
                                                <i class="fas fa-store fa-4x text-secondary"></i>
                                            </div>
                                        <?php endif; ?>
                                        
                                        <p class="text-muted mb-2">
                                            <i class="fas fa-map-marker-alt me-2"></i>
                                            <?php 
                                            $location = array_filter([
                                                $store['headquarters_city'],
                                                $store['headquarters_state'],
                                                $store['headquarters_country']
                                            ]);
                                            echo !empty($location) ? htmlspecialchars(implode(', ', $location)) : 'No location specified';
                                            ?>
                                        </p>
                                        <p class="text-muted mb-2">
                                            <i class="fas fa-phone me-2"></i>
                                            <?php echo $store['main_phone'] ? htmlspecialchars($store['main_phone']) : 'No phone specified'; ?>
                                        </p>
                                        <p class="text-muted mb-3">
                                            <i class="fas fa-envelope me-2"></i>
                                            <?php echo $store['main_email'] ? htmlspecialchars($store['main_email']) : 'No email specified'; ?>
                                        </p>
                                        
                                        <?php 
                                        // Count branches for this store
                                        try {
                                            $branchStmt = $pdo->prepare("
                                                SELECT COUNT(*) FROM stores 
                                                WHERE main_store_id = :main_store_id
                                            ");
                                            $branchStmt->bindParam(':main_store_id', $store['main_store_id']);
                                            $branchStmt->execute();
                                            $branchCount = $branchStmt->fetchColumn();
                                        } catch (PDOException $e) {
                                            $branchCount = 0;
                                        }
                                        ?>
                                        
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <span class="text-muted">Branches</span>
                                            <span class="badge bg-primary rounded-pill"><?php echo $branchCount; ?></span>
                                        </div>
                                        
                                        <?php 
                                        // Count products for this store
                                        try {
                                            $productStmt = $pdo->prepare("
                                                SELECT COUNT(*) FROM products 
                                                WHERE main_store_id = :main_store_id
                                            ");
                                            $productStmt->bindParam(':main_store_id', $store['main_store_id']);
                                            $productStmt->execute();
                                            $productCount = $productStmt->fetchColumn();
                                        } catch (PDOException $e) {
                                            $productCount = 0;
                                        }
                                        ?>
                                        
                                        <div class="d-flex justify-content-between align-items-center">
                                            <span class="text-muted">Products</span>
                                            <span class="badge bg-info rounded-pill"><?php echo $productCount; ?></span>
                                        </div>
                                    </div>
                                    <div class="card-footer bg-transparent">
                                        <div class="d-flex justify-content-between">
                                            <a href="view-store.php?id=<?php echo $store['main_store_id']; ?>" class="btn btn-outline-primary btn-sm">
                                                <i class="fas fa-eye me-1"></i> View
                                            </a>
                                            <div>
                                                <a href="edit-store.php?id=<?php echo $store['main_store_id']; ?>" class="btn btn-outline-secondary btn-sm">
                                                    <i class="fas fa-edit me-1"></i> Edit
                                                </a>
                                                <a href="javascript:void(0);" onclick="confirmDelete(<?php echo $store['main_store_id']; ?>, '<?php echo htmlspecialchars(addslashes($store['name'])); ?>')" class="btn btn-outline-danger btn-sm">
                                                    <i class="fas fa-trash me-1"></i> Delete
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Confirmation Modal -->
    <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="deleteModalLabel">Confirm Deletion</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete the store "<span id="storeName"></span>"?</p>
                    <p class="text-danger"><strong>Warning:</strong> This will also delete all branches, products, inventory, and other associated data. This action cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <a href="#" id="confirmDeleteButton" class="btn btn-danger">Delete Store</a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Function to show delete confirmation modal
        function confirmDelete(storeId, storeName) {
            document.getElementById('storeName').textContent = storeName;
            document.getElementById('confirmDeleteButton').href = 'stores.php?delete=' + storeId;
            
            const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
            deleteModal.show();
        }
    </script>
</body>
</html>