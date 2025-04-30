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

// Check if user has permission to view branches
if (!in_array($role_name, ['SuperAdmin', 'StoreAdmin', 'StoreModerator'])) {
    $_SESSION['error'] = "You don't have permission to access this page.";
    header("Location: dashboard.php");
    exit;
}

// Process branch deletion if requested
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    $branch_id = (int)$_GET['delete'];
    
    try {
        // Get main store ID for permission check
        $checkStmt = $pdo->prepare("
            SELECT main_store_id FROM stores WHERE store_id = :id
        ");
        $checkStmt->bindParam(':id', $branch_id);
        $checkStmt->execute();
        $branch = $checkStmt->fetch();
        
        // If branch exists and user has permission to delete it
        if ($branch && (
            ($role_name === 'SuperAdmin') || 
            ($security->hasStoreAccess($admin_id, $branch['main_store_id'], true))
        )) {
            // Start transaction
            $pdo->beginTransaction();
            
            // Get branch name for logging
            $nameStmt = $pdo->prepare("SELECT name FROM stores WHERE store_id = :id");
            $nameStmt->bindParam(':id', $branch_id);
            $nameStmt->execute();
            $branchName = $nameStmt->fetchColumn();
            
            // Delete branch
            $deleteStmt = $pdo->prepare("DELETE FROM stores WHERE store_id = :id");
            $deleteStmt->bindParam(':id', $branch_id);
            $deleteStmt->execute();
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'delete',
                'stores',
                $branch_id,
                "Deleted branch: $branchName"
            );
            
            // Commit transaction
            $pdo->commit();
            
            $_SESSION['success'] = "Branch deleted successfully.";
        } else {
            $_SESSION['error'] = "Branch not found or you don't have permission to delete it.";
        }
    } catch (PDOException $e) {
        // Rollback transaction on error
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $_SESSION['error'] = "Could not delete branch. It may have associated inventory or orders.";
        error_log('Branch deletion error: ' . $e->getMessage());
    }
    
    header("Location: branches.php");
    exit;
}

// Get main stores the user has access to for filtering
$accessible_stores = [];
try {
    if ($role_name === 'SuperAdmin') {
        // SuperAdmin can see all stores
        $storeStmt = $pdo->prepare("
            SELECT main_store_id, name FROM main_stores
            WHERE is_active = 1
            ORDER BY name
        ");
        $storeStmt->execute();
    } else {
        // Other roles see only assigned stores
        $storeStmt = $pdo->prepare("
            SELECT ms.main_store_id, ms.name
            FROM main_stores ms
            JOIN admin_store_access asa ON ms.main_store_id = asa.main_store_id
            WHERE asa.admin_id = :admin_id AND ms.is_active = 1
            GROUP BY ms.main_store_id
            ORDER BY ms.name
        ");
        $storeStmt->bindParam(':admin_id', $admin_id);
        $storeStmt->execute();
    }
    
    $accessible_stores = $storeStmt->fetchAll();
} catch (PDOException $e) {
    error_log('Store access error: ' . $e->getMessage());
}

// Filter by main store if specified
$filter_store = null;
if (isset($_GET['store']) && is_numeric($_GET['store'])) {
    $filter_store = (int)$_GET['store'];
    
    // Verify user has access to this store
    $has_access = false;
    foreach ($accessible_stores as $store) {
        if ($store['main_store_id'] == $filter_store) {
            $has_access = true;
            break;
        }
    }
    
    if (!$has_access && $role_name !== 'SuperAdmin') {
        $filter_store = null;
    }
}

// Get branches based on user role and permissions
$branches = [];
try {
    $params = [];
    $whereClause = '';
    
    // Build where clause based on permissions
    if ($role_name !== 'SuperAdmin') {
        $whereClause = "WHERE s.main_store_id IN (
            SELECT asa.main_store_id 
            FROM admin_store_access asa 
            WHERE asa.admin_id = :admin_id
        )";
        $params[':admin_id'] = $admin_id;
    }
    
    // Add filter if specified
    if ($filter_store) {
        if ($whereClause) {
            $whereClause .= " AND s.main_store_id = :filter_store";
        } else {
            $whereClause = "WHERE s.main_store_id = :filter_store";
        }
        $params[':filter_store'] = $filter_store;
    }
    
    $sql = "
        SELECT s.*, ms.name as main_store_name 
        FROM stores s
        JOIN main_stores ms ON s.main_store_id = ms.main_store_id
        $whereClause
        ORDER BY ms.name, s.name
    ";
    
    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->execute();
    
    $branches = $stmt->fetchAll();
} catch (PDOException $e) {
    $_SESSION['error'] = "Database error: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Branches</title>
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
                            <a href="branches.php" class="nav-link active">
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
                    <h1 class="h2">Store Branches</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="add-branch.php" class="btn btn-primary">
                            <i class="fas fa-plus me-1"></i> Add New Branch
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
                
                <!-- Filter Controls -->
                <?php if (!empty($accessible_stores)): ?>
                <div class="card mb-4">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-6">
                                <form method="get" action="branches.php" class="d-flex">
                                    <select name="store" class="form-select me-2">
                                        <option value="">All Stores</option>
                                        <?php foreach ($accessible_stores as $store): ?>
                                            <option value="<?php echo $store['main_store_id']; ?>" <?php echo ($filter_store == $store['main_store_id']) ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($store['name']); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                    <button type="submit" class="btn btn-outline-primary">Filter</button>
                                </form>
                            </div>
                            <div class="col-md-6 text-md-end mt-3 mt-md-0">
                                <span class="text-muted">
                                    Showing <?php echo count($branches); ?> branches
                                    <?php if ($filter_store): ?>
                                        for selected store
                                    <?php endif; ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if (empty($branches)): ?>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        No branches found. 
                        <?php if ($filter_store): ?>
                            Try changing your filter or 
                        <?php endif; ?>
                        <a href="add-branch.php" class="alert-link">create a new branch</a>.
                    </div>
                <?php else: ?>
                    <div class="card shadow-sm">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Branch Name</th>
                                        <th>Main Store</th>
                                        <th>Location</th>
                                        <th>Contact</th>
                                        <th>Status</th>
                                        <th>Options</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($branches as $branch): ?>
                                        <tr>
                                            <td>
                                                <div class="d-flex align-items-center">
                                                    <?php if ($branch['logo_url']): ?>
                                                        <img src="<?php echo htmlspecialchars($branch['logo_url']); ?>" width="32" height="32" class="rounded me-2" alt="Logo">
                                                    <?php else: ?>
                                                        <i class="fas fa-store-alt me-2 text-secondary"></i>
                                                    <?php endif; ?>
                                                    <div>
                                                        <div class="fw-bold"><?php echo htmlspecialchars($branch['name']); ?></div>
                                                        <?php if ($branch['pickup_location']): ?>
                                                            <span class="badge bg-info">Pickup Location</span>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                            </td>
                                            <td><?php echo htmlspecialchars($branch['main_store_name']); ?></td>
                                            <td>
                                                <?php 
                                                $location = array_filter([
                                                    $branch['city'],
                                                    $branch['state'],
                                                    $branch['country']
                                                ]);
                                                echo !empty($location) ? htmlspecialchars(implode(', ', $location)) : 'No location specified';
                                                ?>
                                            </td>
                                            <td>
                                                <?php if ($branch['phone']): ?>
                                                    <div><i class="fas fa-phone me-1 text-muted"></i> <?php echo htmlspecialchars($branch['phone']); ?></div>
                                                <?php endif; ?>
                                                <?php if ($branch['email']): ?>
                                                    <div><i class="fas fa-envelope me-1 text-muted"></i> <?php echo htmlspecialchars($branch['email']); ?></div>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <span class="badge <?php echo $branch['is_active'] ? 'bg-success' : 'bg-danger'; ?>">
                                                    <?php echo $branch['is_active'] ? 'Active' : 'Inactive'; ?>
                                                </span>
                                            </td>
                                            <td>
                                                <div class="btn-group btn-group-sm">
                                                    <a href="view-branch.php?id=<?php echo $branch['store_id']; ?>" class="btn btn-outline-primary">
                                                        <i class="fas fa-eye"></i>
                                                    </a>
                                                    <a href="edit-branch.php?id=<?php echo $branch['store_id']; ?>" class="btn btn-outline-secondary">
                                                        <i class="fas fa-edit"></i>
                                                    </a>
                                                    <a href="inventory.php?branch=<?php echo $branch['store_id']; ?>" class="btn btn-outline-info">
                                                        <i class="fas fa-boxes"></i>
                                                    </a>
                                                    <button type="button" class="btn btn-outline-danger" onclick="confirmDelete(<?php echo $branch['store_id']; ?>, '<?php echo htmlspecialchars(addslashes($branch['name'])); ?>')">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
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
                    <p>Are you sure you want to delete the branch "<span id="branchName"></span>"?</p>
                    <p class="text-danger"><strong>Warning:</strong> This will also delete all inventory, stock movements, and other branch-specific data. This action cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <a href="#" id="confirmDeleteButton" class="btn btn-danger">Delete Branch</a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Function to show delete confirmation modal
        function confirmDelete(branchId, branchName) {
            document.getElementById('branchName').textContent = branchName;
            document.getElementById('confirmDeleteButton').href = 'branches.php?delete=' + branchId;
            
            const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
            deleteModal.show();
        }
    </script>
</body>
</html>