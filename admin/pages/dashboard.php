<?php
// Start session and check if user is logged in
session_start();
if (!isset($_SESSION['admin_id'])) {
    header("Location: ../login.php");
    exit;
}

// Include database connection
require_once '../config/database.php';

// Get admin information
$admin_id = $_SESSION['admin_id'];
$role_name = $_SESSION['role_name'];
$admin_name = $_SESSION['admin_name'];

// Fetch stores the admin has access to
$stores = [];
try {
    // Different queries based on role
    if ($role_name === 'SuperAdmin') {
        // SuperAdmin can see all stores
        $storeStmt = $pdo->prepare("SELECT * FROM main_stores ORDER BY name");
        $storeStmt->execute();
    } else {
        // Other roles see only assigned stores
        $storeStmt = $pdo->prepare("
            SELECT ms.* 
            FROM main_stores ms
            JOIN admin_store_access asa ON ms.main_store_id = asa.main_store_id
            WHERE asa.admin_id = :admin_id
            ORDER BY ms.name
        ");
        $storeStmt->bindParam(':admin_id', $admin_id);
        $storeStmt->execute();
    }
    
    while ($store = $storeStmt->fetch(PDO::FETCH_ASSOC)) {
        $stores[] = $store;
    }
} catch (PDOException $e) {
    $error = "Database error: " . $e->getMessage();
}

// Get recent activity logs
$activities = [];
try {
    $activityStmt = $pdo->prepare("
        SELECT aal.*, au.first_name, au.last_name
        FROM admin_activity_logs aal
        LEFT JOIN admin_users au ON aal.admin_id = au.admin_id
        ORDER BY aal.created_at DESC
        LIMIT 10
    ");
    $activityStmt->execute();
    
    while ($activity = $activityStmt->fetch(PDO::FETCH_ASSOC)) {
        $activities[] = $activity;
    }
} catch (PDOException $e) {
    $error = "Database error: " . $e->getMessage();
}

// Get admin users (visible only to SuperAdmin and StoreAdmin)
$adminUsers = [];
if (in_array($role_name, ['SuperAdmin', 'StoreAdmin'])) {
    try {
        if ($role_name === 'SuperAdmin') {
            // SuperAdmin sees all admin users
            $userStmt = $pdo->prepare("
                SELECT au.*, r.name as role_name
                FROM admin_users au
                JOIN roles r ON au.role_id = r.role_id
                ORDER BY au.last_name, au.first_name
            ");
            $userStmt->execute();
        } else {
            // StoreAdmin sees only users they created
            $userStmt = $pdo->prepare("
                SELECT au.*, r.name as role_name
                FROM admin_users au
                JOIN roles r ON au.role_id = r.role_id
                WHERE au.parent_admin_id = :admin_id
                ORDER BY au.last_name, au.first_name
            ");
            $userStmt->bindParam(':admin_id', $admin_id);
            $userStmt->execute();
        }
        
        while ($user = $userStmt->fetch(PDO::FETCH_ASSOC)) {
            $adminUsers[] = $user;
        }
    } catch (PDOException $e) {
        $error = "Database error: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Dashboard</title>
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
        .stats-card {
            border-left: 4px solid;
            border-radius: 4px;
        }
        .card-blue {
            border-left-color: #4e73df;
        }
        .card-green {
            border-left-color: #1cc88a;
        }
        .card-orange {
            border-left-color: #f6c23e;
        }
        .card-red {
            border-left-color: #e74a3b;
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
                            <a href="dashboard.php" class="nav-link active" aria-current="page">
                                <i class="fas fa-home me-2"></i>
                                Dashboard
                            </a>
                        </li>
                        
                        <!-- Dynamic menu based on role -->
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
                            <li><a class="dropdown-item" href="profile.php">Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="../logout.php">Sign out</a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Main content -->
            <div class="col-md-9 ms-sm-auto col-lg-10 px-md-4 main-content">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Dashboard</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary">Share</button>
                            <button type="button" class="btn btn-sm btn-outline-secondary">Export</button>
                        </div>
                    </div>
                </div>
                
                <!-- Statistics Cards -->
                <div class="row mb-4">
                    <!-- Stores count -->
                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-0 shadow h-100 py-2">
                            <div class="card-body stats-card card-blue">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                            Stores</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800"><?php echo count($stores); ?></div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-store fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Products count -->
                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-0 shadow h-100 py-2">
                            <div class="card-body stats-card card-green">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-success text-uppercase mb-1">
                                            Products</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800">
                                            <?php
                                            // Count products (dynamic based on access)
                                            try {
                                                if ($role_name === 'SuperAdmin') {
                                                    $stmt = $pdo->query("SELECT COUNT(*) FROM products");
                                                } else {
                                                    $stmt = $pdo->prepare("
                                                        SELECT COUNT(p.product_id) 
                                                        FROM products p
                                                        JOIN admin_store_access asa ON p.main_store_id = asa.main_store_id
                                                        WHERE asa.admin_id = :admin_id
                                                    ");
                                                    $stmt->bindParam(':admin_id', $admin_id);
                                                    $stmt->execute();
                                                }
                                                echo $stmt->fetchColumn();
                                            } catch (PDOException $e) {
                                                echo "?";
                                            }
                                            ?>
                                        </div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-box fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Orders count -->
                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-0 shadow h-100 py-2">
                            <div class="card-body stats-card card-orange">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                            Orders</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800">
                                            <?php
                                            // Count orders (dynamic based on access)
                                            try {
                                                if ($role_name === 'SuperAdmin') {
                                                    $stmt = $pdo->query("SELECT COUNT(*) FROM orders");
                                                } else {
                                                    $stmt = $pdo->prepare("
                                                        SELECT COUNT(o.order_id) 
                                                        FROM orders o
                                                        JOIN admin_store_access asa ON o.main_store_id = asa.main_store_id
                                                        WHERE asa.admin_id = :admin_id
                                                    ");
                                                    $stmt->bindParam(':admin_id', $admin_id);
                                                    $stmt->execute();
                                                }
                                                echo $stmt->fetchColumn();
                                            } catch (PDOException $e) {
                                                echo "?";
                                            }
                                            ?>
                                        </div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-shopping-cart fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Users count -->
                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-0 shadow h-100 py-2">
                            <div class="card-body stats-card card-red">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-danger text-uppercase mb-1">
                                            Customers</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800">
                                            <?php
                                            // Count customers
                                            try {
                                                $stmt = $pdo->query("SELECT COUNT(*) FROM users");
                                                echo $stmt->fetchColumn();
                                            } catch (PDOException $e) {
                                                echo "?";
                                            }
                                            ?>
                                        </div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-users fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Content Row -->
                <div class="row">
                    <!-- Stores List -->
                    <div class="col-xl-8 col-lg-7">
                        <div class="card shadow mb-4">
                            <div class="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                                <h6 class="m-0 font-weight-bold text-primary">Your Stores</h6>
                                <?php if (in_array($role_name, ['SuperAdmin', 'StoreAdmin'])): ?>
                                <a href="add-store.php" class="btn btn-sm btn-primary">
                                    <i class="fas fa-plus fa-sm"></i> Add Store
                                </a>
                                <?php endif; ?>
                            </div>
                            <div class="card-body">
                                <?php if (empty($stores)): ?>
                                    <p class="text-center">No stores found</p>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr>
                                                    <th>Store Name</th>
                                                    <th>Location</th>
                                                    <th>Status</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($stores as $store): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($store['name']); ?></td>
                                                    <td><?php echo htmlspecialchars($store['headquarters_city'] . ', ' . $store['headquarters_country']); ?></td>
                                                    <td>
                                                        <?php if ($store['is_active']): ?>
                                                            <span class="badge bg-success">Active</span>
                                                        <?php else: ?>
                                                            <span class="badge bg-danger">Inactive</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <a href="view-store.php?id=<?php echo $store['main_store_id']; ?>" class="btn btn-sm btn-info">
                                                            <i class="fas fa-eye"></i>
                                                        </a>
                                                        <?php if (in_array($role_name, ['SuperAdmin', 'StoreAdmin'])): ?>
                                                        <a href="edit-store.php?id=<?php echo $store['main_store_id']; ?>" class="btn btn-sm btn-warning">
                                                            <i class="fas fa-edit"></i>
                                                        </a>
                                                        <?php endif; ?>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Activity -->
                    <div class="col-xl-4 col-lg-5">
                        <div class="card shadow mb-4">
                            <div class="card-header py-3">
                                <h6 class="m-0 font-weight-bold text-primary">Recent Activity</h6>
                            </div>
                            <div class="card-body">
                                <?php if (empty($activities)): ?>
                                    <p class="text-center">No recent activity</p>
                                <?php else: ?>
                                    <div class="timeline-activity">
                                        <?php foreach ($activities as $activity): ?>
                                            <div class="d-flex mb-3">
                                                <div class="flex-shrink-0">
                                                    <i class="fas fa-user-circle text-gray-500 fa-lg me-3"></i>
                                                </div>
                                                <div>
                                                    <p class="mb-0">
                                                        <?php 
                                                        if ($activity['admin_id']) {
                                                            echo htmlspecialchars($activity['first_name'] . ' ' . $activity['last_name']);
                                                        } else {
                                                            echo "Unknown user";
                                                        }
                                                        ?>
                                                        <span class="text-muted small">
                                                            <?php echo htmlspecialchars($activity['action_type']); ?>
                                                        </span>
                                                    </p>
                                                    <p class="text-muted small mb-0"><?php echo htmlspecialchars($activity['details']); ?></p>
                                                    <p class="text-muted small">
                                                        <?php 
                                                        $timestamp = strtotime($activity['created_at']);
                                                        echo date('M j, Y g:i A', $timestamp); 
                                                        ?>
                                                    </p>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Admin Users (visible only to SuperAdmin and StoreAdmin) -->
                <?php if (in_array($role_name, ['SuperAdmin', 'StoreAdmin']) && !empty($adminUsers)): ?>
                <div class="row">
                    <div class="col-12">
                        <div class="card shadow mb-4">
                            <div class="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                                <h6 class="m-0 font-weight-bold text-primary">Admin Users</h6>
                                <a href="add-user.php" class="btn btn-sm btn-primary">
                                    <i class="fas fa-plus fa-sm"></i> Add User
                                </a>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-bordered">
                                        <thead>
                                            <tr>
                                                <th>Name</th>
                                                <th>Email</th>
                                                <th>Role</th>
                                                <th>Status</th>
                                                <th>Last Login</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($adminUsers as $user): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?></td>
                                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                                <td><?php echo htmlspecialchars($user['role_name']); ?></td>
                                                <td>
                                                    <?php if ($user['is_active']): ?>
                                                        <span class="badge bg-success">Active</span>
                                                    <?php else: ?>
                                                        <span class="badge bg-danger">Inactive</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <?php 
                                                    if ($user['last_login']) {
                                                        $timestamp = strtotime($user['last_login']);
                                                        echo date('M j, Y g:i A', $timestamp);
                                                    } else {
                                                        echo "Never";
                                                    }
                                                    ?>
                                                </td>
                                                <td>
                                                    <a href="edit-user.php?id=<?php echo $user['admin_id']; ?>" class="btn btn-sm btn-warning">
                                                        <i class="fas fa-edit"></i>
                                                    </a>
                                                    <?php if ($user['admin_id'] != $admin_id): ?>
                                                    <a href="javascript:void(0);" class="btn btn-sm btn-danger" 
                                                       onclick="confirmDelete(<?php echo $user['admin_id']; ?>)">
                                                        <i class="fas fa-trash"></i>
                                                    </a>
                                                    <?php endif; ?>
                                                </td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS and dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Function to confirm user deletion
        function confirmDelete(userId) {
            if (confirm('Are you sure you want to delete this user?')) {
                window.location.href = 'delete-user.php?id=' + userId;
            }
        }
    </script>
</body>
</html>