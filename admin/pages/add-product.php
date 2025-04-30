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

// Generate CSRF token
$csrf_token = $security->generateCSRFToken('add_product');

// Get stores the admin has access to
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

// Get all categories
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

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !$security->validateCSRFToken($_POST['csrf_token'], 'add_product')) {
        $_SESSION['error'] = "Invalid request. Please try again.";
        header("Location: add-product.php");
        exit;
    }
    
    // Sanitize and validate input
    $name = htmlspecialchars(trim($_POST['name'] ?? ''));
    $description = htmlspecialchars(trim($_POST['description'] ?? ''));
    $main_store_id = (int)($_POST['main_store_id'] ?? 0);
    $price = (float)($_POST['price'] ?? 0);
    $sale_price = !empty($_POST['sale_price']) ? (float)$_POST['sale_price'] : null;
    $sku = htmlspecialchars(trim($_POST['sku'] ?? ''));
    $weight = !empty($_POST['weight']) ? (float)$_POST['weight'] : null;
    $length = !empty($_POST['length']) ? (float)$_POST['length'] : null;
    $width = !empty($_POST['width']) ? (float)$_POST['width'] : null;
    $height = !empty($_POST['height']) ? (float)$_POST['height'] : null;
    $is_featured = isset($_POST['is_featured']) ? 1 : 0;
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    $category_ids = $_POST['categories'] ?? [];
    $attributes = $_POST['attributes'] ?? [];
    
    // Image URLs (comma separated)
    $image_urls = !empty($_POST['image_urls']) ? explode(',', $_POST['image_urls']) : [];
    $primary_image = (int)($_POST['primary_image'] ?? 0);
    
    // Validate required fields
    $errors = [];
    
    if (empty($name)) {
        $errors[] = "Product name is required.";
    }
    
    if ($main_store_id <= 0) {
        $errors[] = "Please select a store.";
    } else {
        // Check if admin has access to this store
        $hasAccess = false;
        foreach ($accessible_stores as $store) {
            if ($store['main_store_id'] == $main_store_id) {
                $hasAccess = true;
                break;
            }
        }
        
        if (!$hasAccess && $role_name !== 'SuperAdmin') {
            $errors[] = "You don't have permission to add products to this store.";
        }
    }
    
    if ($price <= 0) {
        $errors[] = "Price must be greater than zero.";
    }
    
    if (!empty($sale_price) && $sale_price >= $price) {
        $errors[] = "Sale price must be less than regular price.";
    }
    
    if (empty($sku)) {
        $errors[] = "SKU is required.";
    } else {
        // Check if SKU exists in this store
        try {
            $skuStmt = $pdo->prepare("
                SELECT COUNT(*) FROM products
                WHERE sku = :sku AND main_store_id = :main_store_id
            ");
            $skuStmt->bindParam(':sku', $sku);
            $skuStmt->bindParam(':main_store_id', $main_store_id);
            $skuStmt->execute();
            
            if ($skuStmt->fetchColumn() > 0) {
                $errors[] = "This SKU already exists for the selected store.";
            }
        } catch (PDOException $e) {
            error_log('SKU check error: ' . $e->getMessage());
        }
    }
    
    // If no errors, insert product into database
    if (empty($errors)) {
        try {
            // Start transaction
            $pdo->beginTransaction();
            
            // Insert product
            $stmt = $pdo->prepare("
                INSERT INTO products (
                    main_store_id, name, description, price, sale_price, sku,
                    weight, length, width, height, is_featured, is_active, created_at
                ) VALUES (
                    :main_store_id, :name, :description, :price, :sale_price, :sku,
                    :weight, :length, :width, :height, :is_featured, :is_active, NOW()
                )
            ");
            
            $stmt->bindParam(':main_store_id', $main_store_id);
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':description', $description);
            $stmt->bindParam(':price', $price);
            $stmt->bindParam(':sale_price', $sale_price);
            $stmt->bindParam(':sku', $sku);
            $stmt->bindParam(':weight', $weight);
            $stmt->bindParam(':length', $length);
            $stmt->bindParam(':width', $width);
            $stmt->bindParam(':height', $height);
            $stmt->bindParam(':is_featured', $is_featured);
            $stmt->bindParam(':is_active', $is_active);
            
            $stmt->execute();
            $product_id = $pdo->lastInsertId();
            
            // Add categories
            if (!empty($category_ids)) {
                foreach ($category_ids as $category_id) {
                    $catStmt = $pdo->prepare("
                        INSERT INTO product_categories (
                            product_id, category_id, created_at
                        ) VALUES (
                            :product_id, :category_id, NOW()
                        )
                    ");
                    
                    $catStmt->bindParam(':product_id', $product_id);
                    $catStmt->bindParam(':category_id', $category_id);
                    $catStmt->execute();
                }
            }
            
            // Add attributes
            if (!empty($attributes['name']) && !empty($attributes['value'])) {
                $attrCount = count($attributes['name']);
                
                for ($i = 0; $i < $attrCount; $i++) {
                    if (!empty($attributes['name'][$i]) && !empty($attributes['value'][$i])) {
                        $attrName = htmlspecialchars(trim($attributes['name'][$i]));
                        $attrValue = htmlspecialchars(trim($attributes['value'][$i]));
                        
                        $attrStmt = $pdo->prepare("
                            INSERT INTO product_attributes (
                                product_id, name, value, created_at
                            ) VALUES (
                                :product_id, :name, :value, NOW()
                            )
                        ");
                        
                        $attrStmt->bindParam(':product_id', $product_id);
                        $attrStmt->bindParam(':name', $attrName);
                        $attrStmt->bindParam(':value', $attrValue);
                        $attrStmt->execute();
                    }
                }
            }
            
            // Add images
            if (!empty($image_urls)) {
                foreach ($image_urls as $index => $url) {
                    $url = trim($url);
                    if (!empty($url)) {
                        $imgStmt = $pdo->prepare("
                            INSERT INTO product_images (
                                product_id, image_url, alt_text, is_primary, display_order, created_at
                            ) VALUES (
                                :product_id, :image_url, :alt_text, :is_primary, :display_order, NOW()
                            )
                        ");
                        
                        $isPrimary = ($index == $primary_image) ? 1 : 0;
                        $altText = $name . " - Image " . ($index + 1);
                        
                        $imgStmt->bindParam(':product_id', $product_id);
                        $imgStmt->bindParam(':image_url', $url);
                        $imgStmt->bindParam(':alt_text', $altText);
                        $imgStmt->bindParam(':is_primary', $isPrimary);
                        $imgStmt->bindParam(':display_order', $index);
                        $imgStmt->execute();
                    }
                }
            }
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'create',
                'products',
                $product_id,
                "Created new product: $name"
            );
            
            // Commit transaction
            $pdo->commit();
            
            $_SESSION['success'] = "Product created successfully.";
            header("Location: products.php");
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
    <title>StoreLink Admin - Add Product</title>
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
        .attribute-row {
            margin-bottom: 10px;
        }
        .image-preview {
            max-width: 100px;
            max-height: 100px;
            margin-right: 10px;
            object-fit: contain;
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
                    <h1 class="h2">Add New Product</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="products.php" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-1"></i> Back to Products
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
                
                <?php if (empty($accessible_stores)): ?>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        You don't have access to any active stores. Please contact an administrator to grant you access.
                    </div>
                <?php else: ?>
                    <form method="post" action="add-product.php" id="productForm">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        
                        <div class="card shadow-sm mb-4">
                            <div class="card-header bg-primary text-white">
                                <h5 class="card-title mb-0">Basic Information</h5>
                            </div>
                            <div class="card-body">
                                <div class="row mb-3">
                                    <div class="col-md-8">
                                        <label for="name" class="form-label">Product Name</label>
                                        <input type="text" class="form-control" id="name" name="name" value="<?php echo $_POST['name'] ?? ''; ?>" required>
                                    </div>
                                    <div class="col-md-4">
                                        <label for="main_store_id" class="form-label">Store</label>
                                        <select class="form-select" id="main_store_id" name="main_store_id" required>
                                            <option value="">Select Store</option>
                                            <?php foreach ($accessible_stores as $store): ?>
                                                <option value="<?php echo $store['main_store_id']; ?>" <?php echo (isset($_POST['main_store_id']) && $_POST['main_store_id'] == $store['main_store_id']) ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($store['name']); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="description" class="form-label">Description</label>
                                    <textarea class="form-control" id="description" name="description" rows="4"><?php echo $_POST['description'] ?? ''; ?></textarea>
                                </div>
                                
                                <div class="row mb-3">
                                    <div class="col-md-3">
                                        <label for="price" class="form-label">Price</label>
                                        <div class="input-group">
                                            <span class="input-group-text">$</span>
                                            <input type="number" class="form-control" id="price" name="price" min="0.01" step="0.01" value="<?php echo $_POST['price'] ?? ''; ?>" required>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="sale_price" class="form-label">Sale Price (optional)</label>
                                        <div class="input-group">
                                            <span class="input-group-text">$</span>
                                            <input type="number" class="form-control" id="sale_price" name="sale_price" min="0.01" step="0.01" value="<?php echo $_POST['sale_price'] ?? ''; ?>">
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="sku" class="form-label">SKU</label>
                                        <input type="text" class="form-control" id="sku" name="sku" value="<?php echo $_POST['sku'] ?? ''; ?>" required>
                                    </div>
                                    <div class="col-md-3 d-flex align-items-end">
                                        <div class="form-check me-3">
                                            <input class="form-check-input" type="checkbox" id="is_featured" name="is_featured" <?php echo (isset($_POST['is_featured'])) ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="is_featured">Featured</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="is_active" name="is_active" <?php echo (!isset($_POST) || isset($_POST['is_active'])) ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="is_active">Active</label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card shadow-sm mb-4">
                                    <div class="card-header bg-secondary text-white">
                                        <h5 class="card-title mb-0">Categories</h5>
                                    </div>
                                    <div class="card-body">
                                        <?php if (empty($categories)): ?>
                                            <p class="text-muted">No categories available. <a href="add-category.php">Create categories</a> first.</p>
                                        <?php else: ?>
                                            <div class="row">
                                                <?php foreach ($categories as $category): ?>
                                                    <div class="col-md-6">
                                                        <div class="form-check mb-2">
                                                            <input class="form-check-input" type="checkbox" name="categories[]" value="<?php echo $category['category_id']; ?>" id="category_<?php echo $category['category_id']; ?>" <?php echo (isset($_POST['categories']) && in_array($category['category_id'], $_POST['categories'])) ? 'checked' : ''; ?>>
                                                            <label class="form-check-label" for="category_<?php echo $category['category_id']; ?>">
                                                                <?php echo htmlspecialchars($category['name']); ?>
                                                            </label>
                                                        </div>
                                                    </div>
                                                <?php endforeach; ?>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="card shadow-sm mb-4">
                                    <div class="card-header bg-secondary text-white">
                                        <h5 class="card-title mb-0">Dimensions & Weight</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="row mb-3">
                                            <div class="col-md-6">
                                                <label for="weight" class="form-label">Weight (kg)</label>
                                                <input type="number" class="form-control" id="weight" name="weight" min="0" step="0.01" value="<?php echo $_POST['weight'] ?? ''; ?>">
                                            </div>
                                        </div>
                                        <div class="row">
                                            <div class="col-md-4">
                                                <label for="length" class="form-label">Length (cm)</label>
                                                <input type="number" class="form-control" id="length" name="length" min="0" step="0.1" value="<?php echo $_POST['length'] ?? ''; ?>">
                                            </div>
                                            <div class="col-md-4">
                                                <label for="width" class="form-label">Width (cm)</label>
                                                <input type="number" class="form-control" id="width" name="width" min="0" step="0.1" value="<?php echo $_POST['width'] ?? ''; ?>">
                                            </div>
                                            <div class="col-md-4">
                                                <label for="height" class="form-label">Height (cm)</label>
                                                <input type="number" class="form-control" id="height" name="height" min="0" step="0.1" value="<?php echo $_POST['height'] ?? ''; ?>">
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card shadow-sm mb-4">
                            <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0">Product Attributes</h5>
                                <button type="button" class="btn btn-light btn-sm" id="addAttributeBtn">
                                    <i class="fas fa-plus me-1"></i> Add Attribute
                                </button>
                            </div>
                            <div class="card-body">
                                <div id="attributesContainer">
                                    <?php if (isset($_POST['attributes']) && !empty($_POST['attributes']['name'])): ?>
                                        <?php foreach ($_POST['attributes']['name'] as $key => $name): ?>
                                            <?php if (!empty($name) && !empty($_POST['attributes']['value'][$key])): ?>
                                                <div class="row attribute-row">
                                                    <div class="col-md-5">
                                                        <input type="text" class="form-control" name="attributes[name][]" placeholder="Attribute Name (e.g. Color)" value="<?php echo htmlspecialchars($name); ?>">
                                                    </div>
                                                    <div class="col-md-5">
                                                        <input type="text" class="form-control" name="attributes[value][]" placeholder="Attribute Value (e.g. Blue)" value="<?php echo htmlspecialchars($_POST['attributes']['value'][$key]); ?>">
                                                    </div>
                                                    <div class="col-md-2">
                                                        <button type="button" class="btn btn-outline-danger removeAttributeBtn">
                                                            <i class="fas fa-trash"></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            <?php endif; ?>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <div class="row attribute-row">
                                            <div class="col-md-5">
                                                <input type="text" class="form-control" name="attributes[name][]" placeholder="Attribute Name (e.g. Color)">
                                            </div>
                                            <div class="col-md-5">
                                                <input type="text" class="form-control" name="attributes[value][]" placeholder="Attribute Value (e.g. Blue)">
                                            </div>
                                            <div class="col-md-2">
                                                <button type="button" class="btn btn-outline-danger removeAttributeBtn">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </div>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                <div id="attributeTemplate" class="d-none">
                                    <div class="row attribute-row">
                                        <div class="col-md-5">
                                            <input type="text" class="form-control" name="attributes[name][]" placeholder="Attribute Name (e.g. Color)">
                                        </div>
                                        <div class="col-md-5">
                                            <input type="text" class="form-control" name="attributes[value][]" placeholder="Attribute Value (e.g. Blue)">
                                        </div>
                                        <div class="col-md-2">
                                            <button type="button" class="btn btn-outline-danger removeAttributeBtn">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card shadow-sm mb-4">
                            <div class="card-header bg-secondary text-white">
                                <h5 class="card-title mb-0">Product Images</h5>
                            </div>
                            <div class="card-body">
                                <p class="text-muted mb-3">Enter URLs for product images. The first image will be used as the primary image.</p>
                                
                                <div class="mb-3">
                                    <label class="form-label">Image URLs (comma separated)</label>
                                    <textarea class="form-control" id="image_urls" name="image_urls" rows="3" placeholder="https://example.com/image1.jpg, https://example.com/image2.jpg"><?php echo $_POST['image_urls'] ?? ''; ?></textarea>
                                </div>
                                
                                <div class="mb-3">
                                    <label class="form-label">Primary Image (select the index of the primary image, starting from 0)</label>
                                    <input type="number" class="form-control" id="primary_image" name="primary_image" min="0" value="<?php echo $_POST['primary_image'] ?? '0'; ?>">
                                </div>
                                
                                <div id="imagePreviewContainer" class="d-flex flex-wrap mt-3">
                                    <!-- Image previews will be displayed here -->
                                </div>
                            </div>
                        </div>
                        
                        <div class="d-grid gap-2 d-md-flex justify-content-md-end mb-4">
                            <a href="products.php" class="btn btn-outline-secondary me-md-2">Cancel</a>
                            <button type="submit" class="btn btn-primary">Create Product</button>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Handle attributes
            const attributesContainer = document.getElementById('attributesContainer');
            const attributeTemplate = document.getElementById('attributeTemplate');
            const addAttributeBtn = document.getElementById('addAttributeBtn');
            
            // Add attribute row
            addAttributeBtn.addEventListener('click', function() {
                const newAttribute = attributeTemplate.querySelector('.attribute-row').cloneNode(true);
                attributesContainer.appendChild(newAttribute);
                
                // Add event listener to the new remove button
                newAttribute.querySelector('.removeAttributeBtn').addEventListener('click', function() {
                    newAttribute.remove();
                });
            });
            
            // Set up existing remove buttons
            document.querySelectorAll('.removeAttributeBtn').forEach(button => {
                button.addEventListener('click', function() {
                    button.closest('.attribute-row').remove();
                });
            });
            
            // Image preview
            const imageUrlsInput = document.getElementById('image_urls');
            const imagePreviewContainer = document.getElementById('imagePreviewContainer');
            const primaryImageInput = document.getElementById('primary_image');
            
            function updateImagePreviews() {
                // Clear existing previews
                imagePreviewContainer.innerHTML = '';
                
                // Get image URLs
                const imageUrls = imageUrlsInput.value.split(',').map(url => url.trim()).filter(url => url);
                
                // Update primary image max value
                primaryImageInput.max = Math.max(0, imageUrls.length - 1);
                
                // Create previews
                imageUrls.forEach((url, index) => {
                    const previewContainer = document.createElement('div');
                    previewContainer.className = 'mb-2 me-2 d-flex flex-column align-items-center';
                    
                    const img = document.createElement('img');
                    img.src = url;
                    img.className = 'image-preview';
                    img.alt = 'Preview';
                    img.onerror = function() {
                        img.src = 'assets/img/no-image.png';
                        img.alt = 'Image not found';
                    };
                    
                    const indexSpan = document.createElement('span');
                    indexSpan.textContent = `Image ${index}`;
                    indexSpan.className = 'text-muted small mt-1';
                    
                    const primaryIndicator = document.createElement('span');
                    if (parseInt(primaryImageInput.value) === index) {
                        primaryIndicator.textContent = 'Primary';
                        primaryIndicator.className = 'badge bg-primary mt-1';
                        previewContainer.appendChild(primaryIndicator);
                    }
                    
                    previewContainer.appendChild(img);
                    previewContainer.appendChild(indexSpan);
                    
                    imagePreviewContainer.appendChild(previewContainer);
                });
            }
            
            // Update previews when inputs change
            imageUrlsInput.addEventListener('input', updateImagePreviews);
            primaryImageInput.addEventListener('input', updateImagePreviews);
            
            // Initial preview update
            updateImagePreviews();
        });
    </script>
</body>
</html>