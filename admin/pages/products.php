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

// Process product deletion if requested
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    $product_id = (int)$_GET['delete'];
    
    try {
        // Get main store ID for permission check
        $checkStmt = $pdo->prepare("
            SELECT main_store_id FROM products WHERE product_id = :id
        ");
        $checkStmt->bindParam(':id', $product_id);
        $checkStmt->execute();
        $product = $checkStmt->fetch();
        
        // If product exists and user has permission to delete it
        if ($product && (
            ($role_name === 'SuperAdmin') || 
            ($security->hasStoreAccess($admin_id, $product['main_store_id'], true))
        )) {
            // Start transaction
            $pdo->beginTransaction();
            
            // Get product name for logging
            $nameStmt = $pdo->prepare("SELECT name FROM products WHERE product_id = :id");
            $nameStmt->bindParam(':id', $product_id);
            $nameStmt->execute();
            $productName = $nameStmt->fetchColumn();
            
            // Delete product
            $deleteStmt = $pdo->prepare("DELETE FROM products WHERE product_id = :id");
            $deleteStmt->bindParam(':id', $product_id);
            $deleteStmt->execute();
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'delete',
                'products',
                $product_id,
                "Deleted product: $productName"
            );
            
            // Commit transaction
            $pdo->commit();
            
            $_SESSION['success'] = "Product deleted successfully.";
        } else {
            $_SESSION['error'] = "Product not found or you don't have permission to delete it.";
        }
    } catch (PDOException $e) {
        // Rollback transaction on error
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $_SESSION['error'] = "Could not delete product. It may have associated orders or inventory.";
        error_log('Product deletion error: ' . $e->getMessage());
    }
    
    // Redirect to maintain clean URLs
    header("Location: products.php");
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

// Get all categories for filtering
$categories = [];
try {
    $catStmt = $pdo->query("
        SELECT * FROM categories
        WHERE is_active = 1
        ORDER BY name
    ");
    $categories = $catStmt->fetchAll();
} catch (PDOException $e) {
    error_log('Category fetch error: ' . $e->getMessage());
}

// Setup pagination
$page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 20; // Products per page
$offset = ($page - 1) * $limit;

// Setup filters
$filters = [];
$params = [];

// Store filter
if (isset($_GET['store']) && is_numeric($_GET['store']) && $_GET['store'] > 0) {
    $filters[] = "p.main_store_id = :store_id";
    $params[':store_id'] = (int)$_GET['store'];
}

// Category filter
if (isset($_GET['category']) && is_numeric($_GET['category']) && $_GET['category'] > 0) {
    $filters[] = "p.product_id IN (
        SELECT pc.product_id FROM product_categories pc WHERE pc.category_id = :category_id
    )";
    $params[':category_id'] = (int)$_GET['category'];
}

// Status filter
if (isset($_GET['status']) && in_array($_GET['status'], ['active', 'inactive'])) {
    $filters[] = "p.is_active = :is_active";
    $params[':is_active'] = ($_GET['status'] === 'active') ? 1 : 0;
}

// Featured filter
if (isset($_GET['featured']) && $_GET['featured'] === '1') {
    $filters[] = "p.is_featured = 1";
}

// Search filter
if (isset($_GET['search']) && !empty($_GET['search'])) {
    $search = trim($_GET['search']);
    $filters[] = "(p.name LIKE :search OR p.sku LIKE :search OR p.description LIKE :search)";
    $params[':search'] = "%$search%";
}

// Store access filter for non-superadmin users
if ($role_name !== 'SuperAdmin') {
    $filters[] = "p.main_store_id IN (
        SELECT asa.main_store_id 
        FROM admin_store_access asa 
        WHERE asa.admin_id = :admin_id
    )";
    $params[':admin_id'] = $admin_id;
}

// Build the WHERE clause
$where_clause = "";
if (!empty($filters)) {
    $where_clause = "WHERE " . implode(" AND ", $filters);
}

// Setup sorting
$sort_options = [
    'name_asc' => 'p.name ASC',
    'name_desc' => 'p.name DESC',
    'price_asc' => 'p.price ASC',
    'price_desc' => 'p.price DESC',
    'newest' => 'p.created_at DESC',
    'oldest' => 'p.created_at ASC'
];

$sort = isset($_GET['sort']) && array_key_exists($_GET['sort'], $sort_options) 
    ? $_GET['sort'] 
    : 'newest';

$order_by = $sort_options[$sort];

// Get total number of products
try {
    $count_sql = "
        SELECT COUNT(*) FROM products p
        $where_clause
    ";
    
    $count_stmt = $pdo->prepare($count_sql);
    foreach ($params as $key => $value) {
        $count_stmt->bindValue($key, $value);
    }
    $count_stmt->execute();
    
    $total_products = $count_stmt->fetchColumn();
    $total_pages = ceil($total_products / $limit);
} catch (PDOException $e) {
    error_log('Product count error: ' . $e->getMessage());
    $total_products = 0;
    $total_pages = 1;
}

// Get products with pagination and filtering
$products = [];
try {
    $sql = "
        SELECT p.*, ms.name as store_name,
        (SELECT pi.image_url FROM product_images pi WHERE pi.product_id = p.product_id AND pi.is_primary = 1 LIMIT 1) as primary_image
        FROM products p
        LEFT JOIN main_stores ms ON p.main_store_id = ms.main_store_id
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
    
    $products = $stmt->fetchAll();
    
    // Get categories for each product
    foreach ($products as &$product) {
        $cat_stmt = $pdo->prepare("
            SELECT c.category_id, c.name
            FROM categories c
            JOIN product_categories pc ON c.category_id = pc.category_id
            WHERE pc.product_id = :product_id
        ");
        $cat_stmt->bindValue(':product_id', $product['product_id']);
        $cat_stmt->execute();
        
        $product['categories'] = $cat_stmt->fetchAll();
    }
} catch (PDOException $e) {
    $_SESSION['error'] = "Database error: " . $e->getMessage();
    error_log('Product fetch error: ' . $e->getMessage());
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
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - Products</title>
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
        .product-image {
            width: 60px;
            height: 60px;
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
                            <a href="products.php" class="nav-link active">
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
                    <h1 class="h2">Products</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="add-product.php" class="btn btn-primary">
                            <i class="fas fa-plus me-1"></i> Add New Product
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
                        <form method="get" action="products.php" class="filter-form">
                            <div class="row align-items-end">
                                <div class="col-md-3 mb-3">
                                    <label for="search" class="form-label">Search</label>
                                    <input type="text" class="form-control" id="search" name="search" value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>" placeholder="Name, SKU, or description">
                                </div>
                                
                                <div class="col-md-2 mb-3">
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
                                
                                <div class="col-md-2 mb-3">
                                    <label for="category" class="form-label">Category</label>
                                    <select class="form-select" id="category" name="category">
                                        <option value="">All Categories</option>
                                        <?php foreach ($categories as $category): ?>
                                            <option value="<?php echo $category['category_id']; ?>" <?php echo (isset($_GET['category']) && $_GET['category'] == $category['category_id']) ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($category['name']); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                
                                <div class="col-md-2 mb-3">
                                    <label for="status" class="form-label">Status</label>
                                    <select class="form-select" id="status" name="status">
                                        <option value="">All Status</option>
                                        <option value="active" <?php echo (isset($_GET['status']) && $_GET['status'] === 'active') ? 'selected' : ''; ?>>Active</option>
                                        <option value="inactive" <?php echo (isset($_GET['status']) && $_GET['status'] === 'inactive') ? 'selected' : ''; ?>>Inactive</option>
                                    </select>
                                </div>
                                
                                <div class="col-md-1 mb-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="featured" name="featured" value="1" <?php echo (isset($_GET['featured']) && $_GET['featured'] === '1') ? 'checked' : ''; ?>>
                                        <label class="form-check-label" for="featured">
                                            Featured
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="col-md-2 mb-3 d-flex">
                                    <button type="submit" class="btn btn-primary me-2">Filter</button>
                                    <?php if (count(array_intersect_key($_GET, array_flip(['search', 'store', 'category', 'status', 'featured']))) > 0): ?>
                                        <a href="products.php" class="btn btn-outline-secondary">Clear</a>
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
                            Showing <?php echo min($total_products, $offset + 1); ?> - 
                            <?php echo min($total_products, $offset + $limit); ?> of 
                            <?php echo $total_products; ?> products
                        </span>
                    </div>
                    <div class="dropdown">
                        <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="sortDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            Sort: 
                            <?php 
                                $sort_labels = [
                                    'name_asc' => 'Name (A-Z)',
                                    'name_desc' => 'Name (Z-A)',
                                    'price_asc' => 'Price (Low-High)',
                                    'price_desc' => 'Price (High-Low)',
                                    'newest' => 'Newest First',
                                    'oldest' => 'Oldest First'
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
                
                <?php if (empty($products)): ?>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        No products found matching your criteria. 
                        <?php if (count(array_intersect_key($_GET, array_flip(['search', 'store', 'category', 'status', 'featured']))) > 0): ?>
                            Try changing your filters or 
                        <?php endif; ?>
                        <a href="add-product.php" class="alert-link">create a new product</a>.
                    </div>
                <?php else: ?>
                    <!-- Products Table -->
                    <div class="card shadow-sm mb-4">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th scope="col">Product</th>
                                        <th scope="col">SKU</th>
                                        <th scope="col">Store</th>
                                        <th scope="col">Price</th>
                                        <th scope="col">Status</th>
                                        <th scope="col">Categories</th>
                                        <th scope="col" class="text-end">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($products as $product): ?>
                                        <tr>
                                            <td>
                                                <div class="d-flex align-items-center">
                                                    <?php if ($product['primary_image']): ?>
                                                        <img src="../../<?php echo htmlspecialchars($product['primary_image']); ?>" class="product-image me-3" alt="<?php echo htmlspecialchars($product['name']); ?>">
                                                    <?php else: ?>
                                                        <div class="product-image me-3 d-flex align-items-center justify-content-center">
                                                            <i class="fas fa-image text-secondary"></i>
                                                        </div>
                                                    <?php endif; ?>
                                                    <div>
                                                        <div class="fw-bold"><?php echo htmlspecialchars($product['name']); ?></div>
                                                        <?php if ($product['is_featured']): ?>
                                                            <span class="badge bg-warning">Featured</span>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                            </td>
                                            <td><?php echo htmlspecialchars($product['sku']); ?></td>
                                            <td><?php echo htmlspecialchars($product['store_name']); ?></td>
                                            <td>
                                                <?php if ($product['sale_price']): ?>
                                                    <span class="text-danger">$<?php echo number_format($product['sale_price'], 2); ?></span>
                                                    <small class="text-muted text-decoration-line-through">$<?php echo number_format($product['price'], 2); ?></small>
                                                <?php else: ?>
                                                    $<?php echo number_format($product['price'], 2); ?>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <span class="badge <?php echo $product['is_active'] ? 'bg-success' : 'bg-danger'; ?>">
                                                    <?php echo $product['is_active'] ? 'Active' : 'Inactive'; ?>
                                                </span>
                                            </td>
                                            <td>
                                                <?php if (!empty($product['categories'])): ?>
                                                    <?php foreach ($product['categories'] as $index => $cat): ?>
                                                        <span class="badge bg-secondary">
                                                            <?php echo htmlspecialchars($cat['name']); ?>
                                                        </span>
                                                        <?php if ($index < count($product['categories']) - 1): ?>
                                                            <span class="text-muted"> </span>
                                                        <?php endif; ?>
                                                    <?php endforeach; ?>
                                                <?php else: ?>
                                                    <span class="text-muted small">No categories</span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="text-end">
                                                <div class="btn-group btn-group-sm">
                                                    <a href="view-product.php?id=<?php echo $product['product_id']; ?>" class="btn btn-outline-primary">
                                                        <i class="fas fa-eye"></i>
                                                    </a>
                                                    <a href="edit-product.php?id=<?php echo $product['product_id']; ?>" class="btn btn-outline-secondary">
                                                        <i class="fas fa-edit"></i>
                                                    </a>
                                                    <button type="button" class="btn btn-outline-danger" onclick="confirmDelete(<?php echo $product['product_id']; ?>, '<?php echo htmlspecialchars(addslashes($product['name'])); ?>')">
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
                    
                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                        <nav aria-label="Product pagination">
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
    
    <!-- Delete Confirmation Modal -->
    <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="deleteModalLabel">Confirm Deletion</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete the product "<span id="productName"></span>"?</p>
                    <p class="text-danger"><strong>Warning:</strong> This will permanently delete this product, including all images, attributes, and inventory data. This action cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <a href="#" id="confirmDeleteButton" class="btn btn-danger">Delete Product</a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Function to show delete confirmation modal
        function confirmDelete(productId, productName) {
            document.getElementById('productName').textContent = productName;
            document.getElementById('confirmDeleteButton').href = 'products.php?delete=' + productId;
            
            const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
            deleteModal.show();
        }
    </script>
</body>
</html>