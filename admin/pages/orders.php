<?php
// Start session and check if user is logged in
session_start();
if (!isset($_SESSION['admin_id'])) {
    header("Location: ../login.php");
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

// Process order status update if requested
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_status'])) {
    $order_id = (int)$_POST['order_id'];
    $new_status = htmlspecialchars(trim($_POST['status']));
    $valid_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'];
    
    if (in_array($new_status, $valid_statuses)) {
        try {
            // Get order details for permission check
            $checkStmt = $pdo->prepare("
                SELECT main_store_id, status FROM orders WHERE order_id = :order_id
            ");
            $checkStmt->bindParam(':order_id', $order_id);
            $checkStmt->execute();
            $order = $checkStmt->fetch();
            
            // If order exists and user has permission
            if ($order && (
                ($role_name === 'SuperAdmin') || 
                ($security->hasStoreAccess($admin_id, $order['main_store_id'], true))
            )) {
                // Update order status
                $updateStmt = $pdo->prepare("
                    UPDATE orders SET status = :status, updated_at = NOW()
                    WHERE order_id = :order_id
                ");
                $updateStmt->bindParam(':status', $new_status);
                $updateStmt->bindParam(':order_id', $order_id);
                $updateStmt->execute();
                
                // Log the activity
                $security->logActivity(
                    $admin_id,
                    'update',
                    'orders',
                    $order_id,
                    "Updated order status from {$order['status']} to {$new_status}"
                );
                
                $_SESSION['success'] = "Order status updated successfully.";
            } else {
                $_SESSION['error'] = "Order not found or you don't have permission to update it.";
            }
        } catch (PDOException $e) {
            $_SESSION['error'] = "Database error: " . $e->getMessage();
            error_log('Order status update error: ' . $e->getMessage());
        }
    } else {
        $_SESSION['error'] = "Invalid status selected.";
    }
    
    // Redirect to maintain clean URLs
    $redirect_url = 'orders.php';
    if (isset($_POST['redirect_url'])) {
        $redirect_url = $_POST['redirect_url'];
    }
    header("Location: $redirect_url");
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

// Setup pagination
$page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 20; // Orders per page
$offset = ($page - 1) * $limit;

// Setup filters
$filters = [];
$params = [];

// Store filter
if (isset($_GET['store']) && is_numeric($_GET['store']) && $_GET['store'] > 0) {
    $filters[] = "o.main_store_id = :store_id";
    $params[':store_id'] = (int)$_GET['store'];
}

// Status filter
if (isset($_GET['status']) && !empty($_GET['status'])) {
    $filters[] = "o.status = :status";
    $params[':status'] = $_GET['status'];
}

// Date range filter
if (isset($_GET['date_from']) && !empty($_GET['date_from'])) {
    $date_from = date('Y-m-d', strtotime($_GET['date_from']));
    $filters[] = "DATE(o.created_at) >= :date_from";
    $params[':date_from'] = $date_from;
}

if (isset($_GET['date_to']) && !empty($_GET['date_to'])) {
    $date_to = date('Y-m-d', strtotime($_GET['date_to']));
    $filters[] = "DATE(o.created_at) <= :date_to";
    $params[':date_to'] = $date_to;
}

// Search filter
if (isset($_GET['search']) && !empty($_GET['search'])) {
    $search = trim($_GET['search']);
    $filters[] = "(o.order_id LIKE :search OR u.email LIKE :search OR u.first_name LIKE :search OR u.last_name LIKE :search)";
    $params[':search'] = "%$search%";
}

// Store access filter for non-superadmin users
if ($role_name !== 'SuperAdmin') {
    $filters[] = "o.main_store_id IN (
        SELECT asa.main_store_id 
        FROM admin_store_access asa 
        WHERE asa.admin_id = :admin_id
    )";
    $params[':admin_id'] = $admin_id;
}

// Shipping method filter
if (isset($_GET['shipping_method']) && !empty($_GET['shipping_method'])) {
    $filters[] = "o.shipping_method = :shipping_method";
    $params[':shipping_method'] = $_GET['shipping_method'];
}

// Build the WHERE clause
$where_clause = "";
if (!empty($filters)) {
    $where_clause = "WHERE " . implode(" AND ", $filters);
}

// Setup sorting
$sort_options = [
    'newest' => 'o.created_at DESC',
    'oldest' => 'o.created_at ASC',
    'total_desc' => 'o.total_amount DESC',
    'total_asc' => 'o.total_amount ASC'
];

$sort = isset($_GET['sort']) && array_key_exists($_GET['sort'], $sort_options) 
    ? $_GET['sort'] 
    : 'newest';

$order_by = $sort_options[$sort];

// Get total number of orders
try {
    $count_sql = "
        SELECT COUNT(*) FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        $where_clause
    ";
    
    $count_stmt = $pdo->prepare($count_sql);
    foreach ($params as $key => $value) {
        $count_stmt->bindValue($key, $value);
    }
    $count_stmt->execute();
    
    $total_orders = $count_stmt->fetchColumn();
    $total_pages = ceil($total_orders / $limit);
} catch (PDOException $e) {
    error_log('Order count error: ' . $e->getMessage());
    $total_orders = 0;
    $total_pages = 1;
}

// Get orders with pagination and filtering
$orders = [];
try {
    $sql = "
        SELECT o.*, ms.name as store_name, 
               u.first_name as customer_first_name, u.last_name as customer_last_name, u.email as customer_email,
               s.name as pickup_store_name
        FROM orders o
        LEFT JOIN main_stores ms ON o.main_store_id = ms.main_store_id
        LEFT JOIN users u ON o.user_id = u.user_id
        LEFT JOIN stores s ON o.pickup_store_id = s.store_id
        $where_clause
        ORDER BY $order_by
        LIMIT :limit OFFSET :offset
    ";
    
    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    
    $orders = $stmt->fetchAll();
    
    // Get order items for each order
    foreach ($orders as &$order) {
        $items_stmt = $pdo->prepare("
            SELECT oi.*, p.name as product_name, p.sku as product_sku,
            (SELECT pi.image_url FROM product_images pi WHERE pi.product_id = oi.product_id AND pi.is_primary = 1 LIMIT 1) as product_image
            FROM order_items oi
            LEFT JOIN products p ON oi.product_id = p.product_id
            WHERE oi.order_id = :order_id
        ");
        $items_stmt->bindValue(':order_id', $order['order_id']);
        $items_stmt->execute();
        
        $order['items'] = $items_stmt->fetchAll();
        
        // Get payment info
        $payment_stmt = $pdo->prepare("
            SELECT * FROM payments
            WHERE order_id = :order_id
            ORDER BY created_at DESC
            LIMIT 1
        ");
        $payment_stmt->bindValue(':order_id', $order['order_id']);
        $payment_stmt->execute();
        
        $order['payment'] = $payment_stmt->fetch();
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "Database error: " . $e->getMessage();
    error_log('Order fetch error: ' . $e->getMessage());
}

// Build pagination URLs
function build_query($page = null, $sort = null, $overrides = []) {
    $query = $_GET;
    
    if ($page !== null) {
        $query['page'] = $page;
    }
    
    if ($sort !== null) {
        $query['sort'] = $sort;
    }
    
    // Apply any overrides
    foreach ($overrides as $key => $value) {
        if ($value === null && isset($query[$key])) {
            unset($query[$key]);
        } else {
            $query[$key] = $value;
        }
    }
    
    return http_build_query($query);
}

// Get current URL for redirect after status update
$current_url = $_SERVER['REQUEST_URI'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Orders</title>
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
        .order-item-image {
            width: 40px;
            height: 40px;
            object-fit: contain;
            background-color: #f8f9fa;
        }
        .filter-form label {
            font-size: 0.875rem;
            font-weight: 500;
        }
        .clear-filters {
            text-decoration: none;
            font-size: 0.875rem;
        }
        .pagination {
            justify-content: center;
        }
        .status-badge {
            width: 100px;
        }
        .order-details {
            font-size: 0.875rem;
        }
        .status-pending {
            background-color: #f8f9fa;
            color: #212529;
        }
        .status-processing {
            background-color: #cff4fc;
            color: #055160;
        }
        .status-shipped {
            background-color: #fff3cd;
            color: #664d03;
        }
        .status-delivered {
            background-color: #d1e7dd;
            color: #0f5132;
        }
        .status-cancelled {
            background-color: #f8d7da;
            color: #842029;
        }
        .status-refunded {
            background-color: #e2e3e5;
            color: #41464b;
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
                            <a href="orders.php" class="nav-link active">
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
                            <li><a class="dropdown-item" href="../account/profile.php">Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="../logout.php">Sign out</a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Main content -->
            <div class="col-md-9 ms-sm-auto col-lg-10 px-md-4 main-content">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Orders</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="#" class="btn btn-outline-secondary me-2" onclick="window.print();">
                            <i class="fas fa-print me-1"></i> Print
                        </a>
                        <a href="export-orders.php" class="btn btn-outline-secondary">
                            <i class="fas fa-file-export me-1"></i> Export
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
                
                <!-- Filters -->
                <div class="card mb-4">
                    <div class="card-body">
                        <form method="get" action="orders.php" class="filter-form">
                            <div class="row">
                                <div class="col-md-3 mb-3">
                                    <label for="search" class="form-label">Search</label>
                                    <input type="text" class="form-control" id="search" name="search" value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>" placeholder="Order ID or customer info">
                                </div>
                                
                                <div class="col-md-3 mb-3">
                                    <label for="store" class="form-label">Store</label>
                                    <select class="form-select" id="store" name="store">
                                        <option value="">All Stores</option>
                                        <?php foreach ($accessible_stores as $store): ?>
                                            <option value="<?php echo $store['main_store_id']; ?>" <?php echo (isset($_GET['store']) && $_GET['store'] == $store['main_store_id']) ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($store['name']); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                
                                <div class="col-md-3 mb-3">
                                    <label for="status" class="form-label">Status</label>
                                    <select class="form-select" id="status" name="status">
                                        <option value="">All Status</option>
                                        <option value="pending" <?php echo (isset($_GET['status']) && $_GET['status'] === 'pending') ? 'selected' : ''; ?>>Pending</option>
                                        <option value="processing" <?php echo (isset($_GET['status']) && $_GET['status'] === 'processing') ? 'selected' : ''; ?>>Processing</option>
                                        <option value="shipped" <?php echo (isset($_GET['status']) && $_GET['status'] === 'shipped') ? 'selected' : ''; ?>>Shipped</option>
                                        <option value="delivered" <?php echo (isset($_GET['status']) && $_GET['status'] === 'delivered') ? 'selected' : ''; ?>>Delivered</option>
                                        <option value="cancelled" <?php echo (isset($_GET['status']) && $_GET['status'] === 'cancelled') ? 'selected' : ''; ?>>Cancelled</option>
                                        <option value="refunded" <?php echo (isset($_GET['status']) && $_GET['status'] === 'refunded') ? 'selected' : ''; ?>>Refunded</option>
                                    </select>
                                </div>
                                
                                <div class="col-md-3 mb-3">
                                    <label for="shipping_method" class="form-label">Shipping Method</label>
                                    <select class="form-select" id="shipping_method" name="shipping_method">
                                        <option value="">All Methods</option>
                                        <option value="Pickup" <?php echo (isset($_GET['shipping_method']) && $_GET['shipping_method'] === 'Pickup') ? 'selected' : ''; ?>>Store Pickup</option>
                                        <option value="Delivery" <?php echo (isset($_GET['shipping_method']) && $_GET['shipping_method'] === 'Delivery') ? 'selected' : ''; ?>>Home Delivery</option>
                                    </select>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-3 mb-3">
                                    <label for="date_from" class="form-label">Date From</label>
                                    <input type="date" class="form-control" id="date_from" name="date_from" value="<?php echo isset($_GET['date_from']) ? htmlspecialchars($_GET['date_from']) : ''; ?>">
                                </div>
                                
                                <div class="col-md-3 mb-3">
                                    <label for="date_to" class="form-label">Date To</label>
                                    <input type="date" class="form-control" id="date_to" name="date_to" value="<?php echo isset($_GET['date_to']) ? htmlspecialchars($_GET['date_to']) : ''; ?>">
                                </div>
                                
                                <div class="col-md-6 mb-3 d-flex align-items-end">
                                    <button type="submit" class="btn btn-primary me-2">Filter</button>
                                    <?php if (count(array_intersect_key($_GET, array_flip(['search', 'store', 'status', 'date_from', 'date_to', 'shipping_method']))) > 0): ?>
                                        <a href="orders.php" class="btn btn-outline-secondary">Clear Filters</a>
                                    <?php endif; ?>
                                </div>
                            </div>
                            
                            <!-- Sort options - hidden but preserved when filtering -->
                            <?php if (isset($_GET['sort'])): ?>
                                <input type="hidden" name="sort" value="<?php echo htmlspecialchars($_GET['sort']); ?>">
                            <?php endif; ?>
                            
                            <!-- Page number - hidden but preserved when filtering -->
                            <?php if (isset($_GET['page'])): ?>
                                <input type="hidden" name="page" value="1"> <!-- Reset to page 1 when filtering -->
                            <?php endif; ?>
                        </form>
                    </div>
                </div>
                
                <!-- Sort and Results Info -->
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <div>
                        <span class="text-muted">
                            Showing <?php echo min($total_orders, $offset + 1); ?> - 
                            <?php echo min($total_orders, $offset + $limit); ?> of 
                            <?php echo $total_orders; ?> orders
                        </span>
                    </div>
                    <div class="dropdown">
                        <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="sortDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            Sort: 
                            <?php 
                                $sort_labels = [
                                    'newest' => 'Newest First',
                                    'oldest' => 'Oldest First',
                                    'total_desc' => 'Amount (High-Low)',
                                    'total_asc' => 'Amount (Low-High)'
                                ];
                                echo $sort_labels[$sort];
                            ?>
                        </button>
                        <ul class="dropdown-menu" aria-labelledby="sortDropdown">
                            <?php foreach ($sort_labels as $sort_key => $sort_label): ?>
                                <li>
                                    <a class="dropdown-item <?php echo ($sort === $sort_key) ? 'active' : ''; ?>" 
                                       href="?<?php echo build_query(1, $sort_key); ?>">
                                        <?php echo $sort_label; ?>
                                    </a>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
                
                <?php if (empty($orders)): ?>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        No orders found matching your criteria.
                        <?php if (count(array_intersect_key($_GET, array_flip(['search', 'store', 'status', 'date_from', 'date_to', 'shipping_method']))) > 0): ?>
                            Try changing your filters.
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <!-- Orders Accordion -->
                    <div class="accordion mb-4" id="ordersAccordion">
                        <?php foreach ($orders as $index => $order): ?>
                            <div class="accordion-item mb-3 border">
                                <h2 class="accordion-header" id="heading<?php echo $order['order_id']; ?>">
                                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse<?php echo $order['order_id']; ?>" aria-expanded="false" aria-controls="collapse<?php echo $order['order_id']; ?>">
                                        <div class="d-flex justify-content-between align-items-center w-100">
                                            <div class="me-3">
                                                <strong>Order #<?php echo $order['order_id']; ?></strong>
                                            </div>
                                            <div class="me-3 text-nowrap">
                                                <?php echo date('M j, Y g:i A', strtotime($order['created_at'])); ?>
                                            </div>
                                            <div class="me-3">
                                                <?php 
                                                $customer_name = "";
                                                if (!empty($order['customer_first_name']) || !empty($order['customer_last_name'])) {
                                                    $customer_name = trim($order['customer_first_name'] . ' ' . $order['customer_last_name']);
                                                } else {
                                                    $customer_name = "Guest";
                                                }
                                                echo htmlspecialchars($customer_name);
                                                ?>
                                            </div>
                                            <div class="me-3">
                                                <span class="badge status-badge status-<?php echo $order['status']; ?>">
                                                    <?php echo ucfirst($order['status']); ?>
                                                </span>
                                            </div>
                                            <div class="text-nowrap">
                                                <strong>$<?php echo number_format($order['total_amount'], 2); ?></strong>
                                            </div>
                                        </div>
                                    </button>
                                </h2>
                                <div id="collapse<?php echo $order['order_id']; ?>" class="accordion-collapse collapse" aria-labelledby="heading<?php echo $order['order_id']; ?>" data-bs-parent="#ordersAccordion">
                                    <div class="accordion-body">
                                        <div class="row">
                                            <div class="col-md-7">
                                                <!-- Order Items -->
                                                <h5 class="mb-3">Order Items</h5>
                                                <table class="table table-bordered table-sm">
                                                    <thead class="table-light">
                                                        <tr>
                                                            <th>Product</th>
                                                            <th class="text-center">Quantity</th>
                                                            <th class="text-end">Price</th>
                                                            <th class="text-end">Total</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php foreach ($order['items'] as $item): ?>
                                                            <tr>
                                                                <td>
                                                                    <div class="d-flex align-items-center">
                                                                        <?php if ($item['product_image']): ?>
                                                                            <img src="<?php echo htmlspecialchars($item['product_image']); ?>" class="order-item-image me-2" alt="<?php echo htmlspecialchars($item['product_name']); ?>">
                                                                        <?php else: ?>
                                                                            <div class="order-item-image me-2 d-flex align-items-center justify-content-center">
                                                                                <i class="fas fa-image text-secondary"></i>
                                                                            </div>
                                                                        <?php endif; ?>
                                                                        <div>
                                                                            <div><?php echo htmlspecialchars($item['product_name']); ?></div>
                                                                            <small class="text-muted">SKU: <?php echo htmlspecialchars($item['product_sku']); ?></small>
                                                                        </div>
                                                                    </div>
                                                                </td>
                                                                <td class="text-center"><?php echo $item['quantity']; ?></td>
                                                                <td class="text-end">$<?php echo number_format($item['price'], 2); ?></td>
                                                                <td class="text-end">$<?php echo number_format($item['total'], 2); ?></td>
                                                            </tr>
                                                        <?php endforeach; ?>
                                                    </tbody>
                                                    <tfoot class="table-light">
                                                        <tr>
                                                            <td colspan="3" class="text-end"><strong>Order Total:</strong></td>
                                                            <td class="text-end"><strong>$<?php echo number_format($order['total_amount'], 2); ?></strong></td>
                                                        </tr>
                                                    </tfoot>
                                                </table>
                                            </div>
                                            <div class="col-md-5">
                                                <!-- Order Details -->
                                                <h5 class="mb-3">Order Details</h5>
                                                <div class="card mb-3">
                                                    <div class="card-body">
                                                        <div class="row order-details">
                                                            <div class="col-md-4 mb-2">
                                                                <strong>Order Date:</strong>
                                                            </div>
                                                            <div class="col-md-8 mb-2">
                                                                <?php echo date('F j, Y, g:i A', strtotime($order['created_at'])); ?>
                                                            </div>
                                                            
                                                            <div class="col-md-4 mb-2">
                                                                <strong>Store:</strong>
                                                            </div>
                                                            <div class="col-md-8 mb-2">
                                                                <?php echo htmlspecialchars($order['store_name']); ?>
                                                            </div>
                                                            
                                                            <div class="col-md-4 mb-2">
                                                                <strong>Status:</strong>
                                                            </div>
                                                            <div class="col-md-8 mb-2">
                                                                <form method="post" action="orders.php" class="d-flex" id="statusForm<?php echo $order['order_id']; ?>">
                                                                    <input type="hidden" name="order_id" value="<?php echo $order['order_id']; ?>">
                                                                    <input type="hidden" name="redirect_url" value="<?php echo htmlspecialchars($current_url); ?>">
                                                                    <select class="form-select form-select-sm me-2" name="status" id="statusSelect<?php echo $order['order_id']; ?>">
                                                                        <option value="pending" <?php echo ($order['status'] === 'pending') ? 'selected' : ''; ?>>Pending</option>
                                                                        <option value="processing" <?php echo ($order['status'] === 'processing') ? 'selected' : ''; ?>>Processing</option>
                                                                        <option value="shipped" <?php echo ($order['status'] === 'shipped') ? 'selected' : ''; ?>>Shipped</option>
                                                                        <option value="delivered" <?php echo ($order['status'] === 'delivered') ? 'selected' : ''; ?>>Delivered</option>
                                                                        <option value="cancelled" <?php echo ($order['status'] === 'cancelled') ? 'selected' : ''; ?>>Cancelled</option>
                                                                        <option value="refunded" <?php echo ($order['status'] === 'refunded') ? 'selected' : ''; ?>>Refunded</option>
                                                                    </select>
                                                                    <button type="submit" name="update_status" class="btn btn-sm btn-outline-primary">Update</button>
                                                                </form>
                                                            </div>
                                                            
                                                            <div class="col-md-4 mb-2">
                                                                <strong>Customer:</strong>
                                                            </div>
                                                            <div class="col-md-8 mb-2">
                                                                <?php if (!empty($order['customer_first_name']) || !empty($order['customer_last_name'])): ?>
                                                                    <?php echo htmlspecialchars(trim($order['customer_first_name'] . ' ' . $order['customer_last_name'])); ?><br>
                                                                    <a href="mailto:<?php echo htmlspecialchars($order['customer_email']); ?>"><?php echo htmlspecialchars($order['customer_email']); ?></a>
                                                                <?php else: ?>
                                                                    Guest Customer
                                                                <?php endif; ?>
                                                            </div>
                                                            
                                                            <div class="col-md-4 mb-2">
                                                                <strong>Shipping:</strong>
                                                            </div>
                                                            <div class="col-md-8 mb-2">
                                                                <?php echo htmlspecialchars($order['shipping_method']); ?>
                                                                
                                                                <?php if ($order['shipping_method'] === 'Pickup'): ?>
                                                                    <br>
                                                                    <strong>Pickup Store:</strong> <?php echo htmlspecialchars($order['pickup_store_name']); ?>
                                                                <?php endif; ?>
                                                                
                                                                <?php if ($order['shipping_method'] === 'Delivery' && !empty($order['shipping_address'])): ?>
                                                                    <br>
                                                                    <strong>Shipping Address:</strong><br>
                                                                    <?php echo nl2br(htmlspecialchars($order['shipping_address'])); ?>
                                                                <?php endif; ?>
                                                                
                                                                <?php if (!empty($order['tracking_reference'])): ?>
                                                                    <br>
                                                                    <strong>Tracking:</strong> <?php echo htmlspecialchars($order['tracking_reference']); ?>
                                                                <?php endif; ?>
                                                            </div>
                                                            
                                                            <div class="col-md-4 mb-2">
                                                                <strong>Payment:</strong>
                                                            </div>
                                                            <div class="col-md-8 mb-2">
                                                                <?php echo htmlspecialchars($order['payment_method']); ?>
                                                                
                                                                <?php if (!empty($order['payment'])): ?>
                                                                    <br>
                                                                    <strong>Status:</strong> <?php echo htmlspecialchars($order['payment']['status']); ?>
                                                                    
                                                                    <?php if (!empty($order['payment']['transaction_id'])): ?>
                                                                        <br>
                                                                        <strong>Transaction ID:</strong> <?php echo htmlspecialchars($order['payment']['transaction_id']); ?>
                                                                    <?php endif; ?>
                                                                <?php endif; ?>
                                                            </div>
                                                            
                                                            <?php if (!empty($order['notes'])): ?>
                                                                <div class="col-md-4 mb-2">
                                                                    <strong>Notes:</strong>
                                                                </div>
                                                                <div class="col-md-8 mb-2">
                                                                    <?php echo nl2br(htmlspecialchars($order['notes'])); ?>
                                                                </div>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                <!-- Action Buttons -->
                                                <div class="d-flex justify-content-end">
                                                    <a href="view-order.php?id=<?php echo $order['order_id']; ?>" class="btn btn-outline-primary me-2">
                                                        <i class="fas fa-eye me-1"></i> View Details
                                                    </a>
                                                    <a href="print-invoice.php?id=<?php echo $order['order_id']; ?>" class="btn btn-outline-secondary" target="_blank">
                                                        <i class="fas fa-print me-1"></i> Print Invoice
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                        <nav aria-label="Order pagination">
                            <ul class="pagination">
                                <?php if ($page > 1): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?<?php echo build_query(1); ?>" aria-label="First">
                                            <span aria-hidden="true">&laquo;&laquo;</span>
                                        </a>
                                    </li>
                                    <li class="page-item">
                                        <a class="page-link" href="?<?php echo build_query($page - 1); ?>" aria-label="Previous">
                                            <span aria-hidden="true">&laquo;</span>
                                        </a>
                                    </li>
                                <?php endif; ?>
                                
                                <?php
                                // Display a range of page numbers
                                $range = 2; // Number of pages to show on either side of current page
                                $start_page = max(1, $page - $range);
                                $end_page = min($total_pages, $page + $range);
                                
                                // Always show first page
                                if ($start_page > 1) {
                                    echo '<li class="page-item"><a class="page-link" href="?' . build_query(1) . '">1</a></li>';
                                    if ($start_page > 2) {
                                        echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                    }
                                }
                                
                                // Show page numbers
                                for ($i = $start_page; $i <= $end_page; $i++) {
                                    echo '<li class="page-item ' . ($i == $page ? 'active' : '') . '">';
                                    echo '<a class="page-link" href="?' . build_query($i) . '">' . $i . '</a>';
                                    echo '</li>';
                                }
                                
                                // Always show last page
                                if ($end_page < $total_pages) {
                                    if ($end_page < $total_pages - 1) {
                                        echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                    }
                                    echo '<li class="page-item"><a class="page-link" href="?' . build_query($total_pages) . '">' . $total_pages . '</a></li>';
                                }
                                ?>
                                
                                <?php if ($page < $total_pages): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?<?php echo build_query($page + 1); ?>" aria-label="Next">
                                            <span aria-hidden="true">&raquo;</span>
                                        </a>
                                    </li>
                                    <li class="page-item">
                                        <a class="page-link" href="?<?php echo build_query($total_pages); ?>" aria-label="Last">
                                            <span aria-hidden="true">&raquo;&raquo;</span>
                                        </a>
                                    </li>
                                <?php endif; ?>
                            </ul>
                        </nav>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>