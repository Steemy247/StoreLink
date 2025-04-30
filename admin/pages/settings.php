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

// Only SuperAdmin can access settings
if ($role_name !== 'SuperAdmin') {
    $_SESSION['error'] = "You don't have permission to access the settings page.";
    header("Location: dashboard.php");
    exit;
}

// Generate CSRF tokens for each settings form
$general_token = $security->generateCSRFToken('general_settings');
$payment_token = $security->generateCSRFToken('payment_settings');
$email_token = $security->generateCSRFToken('email_settings');
$security_token = $security->generateCSRFToken('security_settings');

// Create settings table if it doesn't exist
try {
    $checkTableStmt = $pdo->prepare("
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE table_schema = DATABASE() 
        AND table_name = 'system_settings'
    ");
    $checkTableStmt->execute();
    
    if ($checkTableStmt->fetchColumn() == 0) {
        // Create the settings table
        $createTableStmt = $pdo->prepare("
            CREATE TABLE system_settings (
                setting_id INT AUTO_INCREMENT PRIMARY KEY,
                setting_key VARCHAR(100) NOT NULL UNIQUE,
                setting_value TEXT,
                setting_group VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        ");
        $createTableStmt->execute();
        
        // Add default settings
        $defaultSettings = [
            // General settings
            ['site_name', 'StoreLink', 'general'],
            ['company_name', 'StoreLink Inc.', 'general'],
            ['contact_email', 'contact@storelink.example.com', 'general'],
            ['contact_phone', '+1 (555) 123-4567', 'general'],
            ['default_currency', 'USD', 'general'],
            ['timezone', 'America/New_York', 'general'],
            ['tax_rate', '7.5', 'general'],
            
            // Payment settings
            ['allow_credit_cards', '1', 'payment'],
            ['allow_paypal', '1', 'payment'],
            ['allow_bank_transfer', '0', 'payment'],
            ['paypal_email', 'payments@storelink.example.com', 'payment'],
            ['stripe_publishable_key', '', 'payment'],
            ['stripe_secret_key', '', 'payment'],
            ['payment_instructions', 'Please complete your payment within 48 hours.', 'payment'],
            
            // Email settings
            ['smtp_host', 'smtp.example.com', 'email'],
            ['smtp_port', '587', 'email'],
            ['smtp_username', 'notifications@storelink.example.com', 'email'],
            ['smtp_password', '', 'email'],
            ['smtp_encryption', 'tls', 'email'],
            ['email_from_name', 'StoreLink Notifications', 'email'],
            ['email_from_address', 'notifications@storelink.example.com', 'email'],
            ['order_notification_emails', 'orders@storelink.example.com', 'email'],
            
            // Security settings
            ['allow_password_reset', '1', 'security'],
            ['password_reset_expiry', '24', 'security'],
            ['minimum_password_length', '8', 'security'],
            ['require_strong_passwords', '1', 'security'],
            ['session_timeout', '120', 'security'],
            ['failed_login_attempts', '5', 'security'],
            ['lockout_time', '15', 'security'],
            ['two_factor_auth', '0', 'security'],
        ];
        
        $insertStmt = $pdo->prepare("
            INSERT INTO system_settings (setting_key, setting_value, setting_group)
            VALUES (?, ?, ?)
        ");
        
        foreach ($defaultSettings as $setting) {
            $insertStmt->execute($setting);
        }
    }
} catch (PDOException $e) {
    error_log('Error setting up settings table: ' . $e->getMessage());
}

// Function to get settings by group
function getSettingsByGroup($pdo, $group) {
    try {
        $stmt = $pdo->prepare("
            SELECT setting_key, setting_value
            FROM system_settings
            WHERE setting_group = :group
        ");
        $stmt->bindParam(':group', $group);
        $stmt->execute();
        
        $settings = [];
        while ($row = $stmt->fetch()) {
            $settings[$row['setting_key']] = $row['setting_value'];
        }
        
        return $settings;
    } catch (PDOException $e) {
        error_log('Error fetching settings: ' . $e->getMessage());
        return [];
    }
}

// Get current settings by group
$general_settings = getSettingsByGroup($pdo, 'general');
$payment_settings = getSettingsByGroup($pdo, 'payment');
$email_settings = getSettingsByGroup($pdo, 'email');
$security_settings = getSettingsByGroup($pdo, 'security');

// Function to get available timezones
function getTimezones() {
    $regions = [
        'Africa' => DateTimeZone::AFRICA,
        'America' => DateTimeZone::AMERICA,
        'Antarctica' => DateTimeZone::ANTARCTICA,
        'Arctic' => DateTimeZone::ARCTIC,
        'Asia' => DateTimeZone::ASIA,
        'Atlantic' => DateTimeZone::ATLANTIC,
        'Australia' => DateTimeZone::AUSTRALIA,
        'Europe' => DateTimeZone::EUROPE,
        'Indian' => DateTimeZone::INDIAN,
        'Pacific' => DateTimeZone::PACIFIC
    ];
    
    $timezones = [];
    foreach ($regions as $name => $mask) {
        $zones = DateTimeZone::listIdentifiers($mask);
        foreach ($zones as $timezone) {
            $time = new DateTime(NULL, new DateTimeZone($timezone));
            $offset = $time->format('P');
            $timezones[$name][$timezone] = '(UTC' . $offset . ') ' . $timezone;
        }
    }
    
    return $timezones;
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process General Settings
    if (isset($_POST['update_general_settings'])) {
        // Validate CSRF token
        if (!isset($_POST['csrf_token']) || !$security->validateCSRFToken($_POST['csrf_token'], 'general_settings')) {
            $_SESSION['error'] = "Invalid request. Please try again.";
            header("Location: settings.php");
            exit;
        }
        
        // Update settings
        try {
            $pdo->beginTransaction();
            
            $updateStmt = $pdo->prepare("
                UPDATE system_settings 
                SET setting_value = :value 
                WHERE setting_key = :key
            ");
            
            // Process each general setting
            $settings = [
                'site_name' => htmlspecialchars(trim($_POST['site_name'] ?? '')),
                'company_name' => htmlspecialchars(trim($_POST['company_name'] ?? '')),
                'contact_email' => filter_var(trim($_POST['contact_email'] ?? ''), FILTER_SANITIZE_EMAIL),
                'contact_phone' => htmlspecialchars(trim($_POST['contact_phone'] ?? '')),
                'default_currency' => htmlspecialchars(trim($_POST['default_currency'] ?? 'USD')),
                'timezone' => htmlspecialchars(trim($_POST['timezone'] ?? 'UTC')),
                'tax_rate' => floatval($_POST['tax_rate'] ?? 0)
            ];
            
            foreach ($settings as $key => $value) {
                $updateStmt->bindParam(':key', $key);
                $updateStmt->bindParam(':value', $value);
                $updateStmt->execute();
            }
            
            $pdo->commit();
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'update',
                'settings',
                null,
                "Updated general settings"
            );
            
            $_SESSION['success'] = "General settings updated successfully.";
            header("Location: settings.php");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('Error updating general settings: ' . $e->getMessage());
            $_SESSION['error'] = "Database error when updating settings.";
        }
    }
    
    // Process Payment Settings
    if (isset($_POST['update_payment_settings'])) {
        // Validate CSRF token
        if (!isset($_POST['csrf_token']) || !$security->validateCSRFToken($_POST['csrf_token'], 'payment_settings')) {
            $_SESSION['error'] = "Invalid request. Please try again.";
            header("Location: settings.php");
            exit;
        }
        
        // Update settings
        try {
            $pdo->beginTransaction();
            
            $updateStmt = $pdo->prepare("
                UPDATE system_settings 
                SET setting_value = :value 
                WHERE setting_key = :key
            ");
            
            // Process each payment setting
            $settings = [
                'allow_credit_cards' => isset($_POST['allow_credit_cards']) ? '1' : '0',
                'allow_paypal' => isset($_POST['allow_paypal']) ? '1' : '0',
                'allow_bank_transfer' => isset($_POST['allow_bank_transfer']) ? '1' : '0',
                'paypal_email' => filter_var(trim($_POST['paypal_email'] ?? ''), FILTER_SANITIZE_EMAIL),
                'stripe_publishable_key' => htmlspecialchars(trim($_POST['stripe_publishable_key'] ?? '')),
                'stripe_secret_key' => htmlspecialchars(trim($_POST['stripe_secret_key'] ?? '')),
                'payment_instructions' => htmlspecialchars(trim($_POST['payment_instructions'] ?? ''))
            ];
            
            foreach ($settings as $key => $value) {
                $updateStmt->bindParam(':key', $key);
                $updateStmt->bindParam(':value', $value);
                $updateStmt->execute();
            }
            
            $pdo->commit();
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'update',
                'settings',
                null,
                "Updated payment settings"
            );
            
            $_SESSION['success'] = "Payment settings updated successfully.";
            header("Location: settings.php");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('Error updating payment settings: ' . $e->getMessage());
            $_SESSION['error'] = "Database error when updating settings.";
        }
    }
    
    // Process Email Settings
    if (isset($_POST['update_email_settings'])) {
        // Validate CSRF token
        if (!isset($_POST['csrf_token']) || !$security->validateCSRFToken($_POST['csrf_token'], 'email_settings')) {
            $_SESSION['error'] = "Invalid request. Please try again.";
            header("Location: settings.php");
            exit;
        }
        
        // Update settings
        try {
            $pdo->beginTransaction();
            
            $updateStmt = $pdo->prepare("
                UPDATE system_settings 
                SET setting_value = :value 
                WHERE setting_key = :key
            ");
            
            // Process each email setting
            $settings = [
                'smtp_host' => htmlspecialchars(trim($_POST['smtp_host'] ?? '')),
                'smtp_port' => intval($_POST['smtp_port'] ?? 587),
                'smtp_username' => htmlspecialchars(trim($_POST['smtp_username'] ?? '')),
                'smtp_password' => htmlspecialchars(trim($_POST['smtp_password'] ?? '')),
                'smtp_encryption' => htmlspecialchars(trim($_POST['smtp_encryption'] ?? 'tls')),
                'email_from_name' => htmlspecialchars(trim($_POST['email_from_name'] ?? '')),
                'email_from_address' => filter_var(trim($_POST['email_from_address'] ?? ''), FILTER_SANITIZE_EMAIL),
                'order_notification_emails' => htmlspecialchars(trim($_POST['order_notification_emails'] ?? ''))
            ];
            
            foreach ($settings as $key => $value) {
                $updateStmt->bindParam(':key', $key);
                $updateStmt->bindParam(':value', $value);
                $updateStmt->execute();
            }
            
            $pdo->commit();
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'update',
                'settings',
                null,
                "Updated email settings"
            );
            
            $_SESSION['success'] = "Email settings updated successfully.";
            header("Location: settings.php");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('Error updating email settings: ' . $e->getMessage());
            $_SESSION['error'] = "Database error when updating settings.";
        }
    }
    
    // Process Security Settings
    if (isset($_POST['update_security_settings'])) {
        // Validate CSRF token
        if (!isset($_POST['csrf_token']) || !$security->validateCSRFToken($_POST['csrf_token'], 'security_settings')) {
            $_SESSION['error'] = "Invalid request. Please try again.";
            header("Location: settings.php");
            exit;
        }
        
        // Update settings
        try {
            $pdo->beginTransaction();
            
            $updateStmt = $pdo->prepare("
                UPDATE system_settings 
                SET setting_value = :value 
                WHERE setting_key = :key
            ");
            
            // Process each security setting
            $settings = [
                'allow_password_reset' => isset($_POST['allow_password_reset']) ? '1' : '0',
                'password_reset_expiry' => intval($_POST['password_reset_expiry'] ?? 24),
                'minimum_password_length' => intval($_POST['minimum_password_length'] ?? 8),
                'require_strong_passwords' => isset($_POST['require_strong_passwords']) ? '1' : '0',
                'session_timeout' => intval($_POST['session_timeout'] ?? 120),
                'failed_login_attempts' => intval($_POST['failed_login_attempts'] ?? 5),
                'lockout_time' => intval($_POST['lockout_time'] ?? 15),
                'two_factor_auth' => isset($_POST['two_factor_auth']) ? '1' : '0'
            ];
            
            foreach ($settings as $key => $value) {
                $updateStmt->bindParam(':key', $key);
                $updateStmt->bindParam(':value', $value);
                $updateStmt->execute();
            }
            
            $pdo->commit();
            
            // Log the activity
            $security->logActivity(
                $admin_id,
                'update',
                'settings',
                null,
                "Updated security settings"
            );
            
            $_SESSION['success'] = "Security settings updated successfully.";
            header("Location: settings.php");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('Error updating security settings: ' . $e->getMessage());
            $_SESSION['error'] = "Database error when updating settings.";
        }
    }
}

// Get available timezones for dropdown
$timezones = getTimezones();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StoreLink Admin - System Settings</title>
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
        .settings-section {
            margin-bottom: 2rem;
        }
        .tab-content {
            padding-top: 1.5rem;
        }
        .form-label {
            font-weight: 500;
        }
        .form-text {
            font-size: 0.825rem;
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
                            <a href="inventory.php" class="nav-link text-white">
                                <i class="fas fa-boxes me-2"></i>
                                Inventory
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
                            <a href="settings.php" class="nav-link active">
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
                    <h1 class="h2">System Settings</h1>
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
                
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <ul class="nav nav-tabs" id="settingsTabs" role="tablist">
                            <li class="nav-item" role="presentation">
                                <button class="nav-link active" id="general-tab" data-bs-toggle="tab" data-bs-target="#general" type="button" role="tab" aria-controls="general" aria-selected="true">
                                    <i class="fas fa-sliders-h me-2"></i>General
                                </button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="payment-tab" data-bs-toggle="tab" data-bs-target="#payment" type="button" role="tab" aria-controls="payment" aria-selected="false">
                                    <i class="fas fa-credit-card me-2"></i>Payment
                                </button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="email-tab" data-bs-toggle="tab" data-bs-target="#email" type="button" role="tab" aria-controls="email" aria-selected="false">
                                    <i class="fas fa-envelope me-2"></i>Email
                                </button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab" aria-controls="security" aria-selected="false">
                                    <i class="fas fa-shield-alt me-2"></i>Security
                                </button>
                            </li>
                        </ul>
                        
                        <div class="tab-content" id="settingsTabsContent">
                            <!-- General Settings -->
                            <div class="tab-pane fade show active" id="general" role="tabpanel" aria-labelledby="general-tab">
                                <form method="post" action="settings.php">
                                    <input type="hidden" name="csrf_token" value="<?php echo $general_token; ?>">
                                    
                                    <div class="mb-3">
                                        <label for="site_name" class="form-label">Site Name</label>
                                        <input type="text" class="form-control" id="site_name" name="site_name" value="<?php echo htmlspecialchars($general_settings['site_name'] ?? ''); ?>" required>
                                        <div class="form-text">The name displayed in browser titles and emails.</div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="company_name" class="form-label">Company Name</label>
                                        <input type="text" class="form-control" id="company_name" name="company_name" value="<?php echo htmlspecialchars($general_settings['company_name'] ?? ''); ?>" required>
                                        <div class="form-text">The official name of your business.</div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label for="contact_email" class="form-label">Contact Email</label>
                                            <input type="email" class="form-control" id="contact_email" name="contact_email" value="<?php echo htmlspecialchars($general_settings['contact_email'] ?? ''); ?>" required>
                                            <div class="form-text">Public contact email address.</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label for="contact_phone" class="form-label">Contact Phone</label>
                                            <input type="text" class="form-control" id="contact_phone" name="contact_phone" value="<?php echo htmlspecialchars($general_settings['contact_phone'] ?? ''); ?>">
                                            <div class="form-text">Public contact phone number.</div>
                                        </div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4">
                                            <label for="default_currency" class="form-label">Default Currency</label>
                                            <select class="form-select" id="default_currency" name="default_currency">
                                                <option value="USD" <?php echo ($general_settings['default_currency'] ?? '') === 'USD' ? 'selected' : ''; ?>>US Dollar (USD)</option>
                                                <option value="EUR" <?php echo ($general_settings['default_currency'] ?? '') === 'EUR' ? 'selected' : ''; ?>>Euro (EUR)</option>
                                                <option value="GBP" <?php echo ($general_settings['default_currency'] ?? '') === 'GBP' ? 'selected' : ''; ?>>British Pound (GBP)</option>
                                                <option value="CAD" <?php echo ($general_settings['default_currency'] ?? '') === 'CAD' ? 'selected' : ''; ?>>Canadian Dollar (CAD)</option>
                                                <option value="AUD" <?php echo ($general_settings['default_currency'] ?? '') === 'AUD' ? 'selected' : ''; ?>>Australian Dollar (AUD)</option>
                                                <option value="JPY" <?php echo ($general_settings['default_currency'] ?? '') === 'JPY' ? 'selected' : ''; ?>>Japanese Yen (JPY)</option>
                                            </select>
                                            <div class="form-text">Default currency used for pricing.</div>
                                        </div>
                                        <div class="col-md-4">
                                            <label for="timezone" class="form-label">Timezone</label>
                                            <select class="form-select" id="timezone" name="timezone">
                                                <?php foreach ($timezones as $region => $list): ?>
                                                    <optgroup label="<?php echo $region; ?>">
                                                        <?php foreach ($list as $timezone => $name): ?>
                                                            <option value="<?php echo $timezone; ?>" <?php echo ($general_settings['timezone'] ?? '') === $timezone ? 'selected' : ''; ?>>
                                                                <?php echo $name; ?>
                                                            </option>
                                                        <?php endforeach; ?>
                                                    </optgroup>
                                                <?php endforeach; ?>
                                            </select>
                                            <div class="form-text">System default timezone.</div>
                                        </div>
                                        <div class="col-md-4">
                                            <label for="tax_rate" class="form-label">Default Tax Rate (%)</label>
                                            <input type="number" class="form-control" id="tax_rate" name="tax_rate" min="0" max="100" step="0.01" value="<?php echo htmlspecialchars($general_settings['tax_rate'] ?? '0'); ?>">
                                            <div class="form-text">Default tax rate for orders.</div>
                                        </div>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <button type="submit" name="update_general_settings" class="btn btn-primary">
                                            <i class="fas fa-save me-1"></i> Save General Settings
                                        </button>
                                    </div>
                                </form>
                            </div>
                            
                            <!-- Payment Settings -->
                            <div class="tab-pane fade" id="payment" role="tabpanel" aria-labelledby="payment-tab">
                                <form method="post" action="settings.php">
                                    <input type="hidden" name="csrf_token" value="<?php echo $payment_token; ?>">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Payment Methods</label>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="allow_credit_cards" name="allow_credit_cards" <?php echo ($payment_settings['allow_credit_cards'] ?? '0') === '1' ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="allow_credit_cards">
                                                Credit Card / Debit Card
                                            </label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="allow_paypal" name="allow_paypal" <?php echo ($payment_settings['allow_paypal'] ?? '0') === '1' ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="allow_paypal">
                                                PayPal
                                            </label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="allow_bank_transfer" name="allow_bank_transfer" <?php echo ($payment_settings['allow_bank_transfer'] ?? '0') === '1' ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="allow_bank_transfer">
                                                Bank Transfer
                                            </label>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="paypal_email" class="form-label">PayPal Email</label>
                                        <input type="email" class="form-control" id="paypal_email" name="paypal_email" value="<?php echo htmlspecialchars($payment_settings['paypal_email'] ?? ''); ?>">
                                        <div class="form-text">Email address associated with your PayPal account.</div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="stripe_publishable_key" class="form-label">Stripe Publishable Key</label>
                                        <input type="text" class="form-control" id="stripe_publishable_key" name="stripe_publishable_key" value="<?php echo htmlspecialchars($payment_settings['stripe_publishable_key'] ?? ''); ?>">
                                        <div class="form-text">Your Stripe publishable key for credit card processing.</div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="stripe_secret_key" class="form-label">Stripe Secret Key</label>
                                        <input type="password" class="form-control" id="stripe_secret_key" name="stripe_secret_key" value="<?php echo htmlspecialchars($payment_settings['stripe_secret_key'] ?? ''); ?>">
                                        <div class="form-text">Your Stripe secret key for credit card processing.</div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="payment_instructions" class="form-label">Payment Instructions</label>
                                        <textarea class="form-control" id="payment_instructions" name="payment_instructions" rows="3"><?php echo htmlspecialchars($payment_settings['payment_instructions'] ?? ''); ?></textarea>
                                        <div class="form-text">Instructions shown to customers when completing payment.</div>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <button type="submit" name="update_payment_settings" class="btn btn-primary">
                                            <i class="fas fa-save me-1"></i> Save Payment Settings
                                        </button>
                                    </div>
                                </form>
                            </div>
                            
                            <!-- Email Settings -->
                            <div class="tab-pane fade" id="email" role="tabpanel" aria-labelledby="email-tab">
                                <form method="post" action="settings.php">
                                    <input type="hidden" name="csrf_token" value="<?php echo $email_token; ?>">
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label for="smtp_host" class="form-label">SMTP Host</label>
                                            <input type="text" class="form-control" id="smtp_host" name="smtp_host" value="<?php echo htmlspecialchars($email_settings['smtp_host'] ?? ''); ?>">
                                        </div>
                                        <div class="col-md-6">
                                            <label for="smtp_port" class="form-label">SMTP Port</label>
                                            <input type="number" class="form-control" id="smtp_port" name="smtp_port" value="<?php echo htmlspecialchars($email_settings['smtp_port'] ?? '587'); ?>">
                                        </div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label for="smtp_username" class="form-label">SMTP Username</label>
                                            <input type="text" class="form-control" id="smtp_username" name="smtp_username" value="<?php echo htmlspecialchars($email_settings['smtp_username'] ?? ''); ?>">
                                        </div>
                                        <div class="col-md-6">
                                            <label for="smtp_password" class="form-label">SMTP Password</label>
                                            <input type="password" class="form-control" id="smtp_password" name="smtp_password" value="<?php echo htmlspecialchars($email_settings['smtp_password'] ?? ''); ?>">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="smtp_encryption" class="form-label">SMTP Encryption</label>
                                        <select class="form-select" id="smtp_encryption" name="smtp_encryption">
                                            <option value="none" <?php echo ($email_settings['smtp_encryption'] ?? '') === 'none' ? 'selected' : ''; ?>>None</option>
                                            <option value="tls" <?php echo ($email_settings['smtp_encryption'] ?? '') === 'tls' ? 'selected' : ''; ?>>TLS</option>
                                            <option value="ssl" <?php echo ($email_settings['smtp_encryption'] ?? '') === 'ssl' ? 'selected' : ''; ?>>SSL</option>
                                        </select>
                                        <div class="form-text">Encryption method for SMTP server.</div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label for="email_from_name" class="form-label">From Name</label>
                                            <input type="text" class="form-control" id="email_from_name" name="email_from_name" value="<?php echo htmlspecialchars($email_settings['email_from_name'] ?? ''); ?>">
                                            <div class="form-text">Name that appears in the "From" field of emails.</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label for="email_from_address" class="form-label">From Email Address</label>
                                            <input type="email" class="form-control" id="email_from_address" name="email_from_address" value="<?php echo htmlspecialchars($email_settings['email_from_address'] ?? ''); ?>">
                                            <div class="form-text">Email address that appears in the "From" field.</div>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="order_notification_emails" class="form-label">Order Notification Recipients</label>
                                        <input type="text" class="form-control" id="order_notification_emails" name="order_notification_emails" value="<?php echo htmlspecialchars($email_settings['order_notification_emails'] ?? ''); ?>">
                                        <div class="form-text">Email addresses that receive order notifications. Separate multiple emails with commas.</div>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <button type="submit" name="update_email_settings" class="btn btn-primary">
                                            <i class="fas fa-save me-1"></i> Save Email Settings
                                        </button>
                                    </div>
                                </form>
                            </div>
                            
                            <!-- Security Settings -->
                            <div class="tab-pane fade" id="security" role="tabpanel" aria-labelledby="security-tab">
                                <form method="post" action="settings.php">
                                    <input type="hidden" name="csrf_token" value="<?php echo $security_token; ?>">
                                    
                                    <div class="mb-3">
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" id="allow_password_reset" name="allow_password_reset" <?php echo ($security_settings['allow_password_reset'] ?? '1') === '1' ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="allow_password_reset">
                                                Allow Password Reset
                                            </label>
                                        </div>
                                        <div class="form-text">Enable or disable the password reset functionality.</div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-6">
                                            <label for="password_reset_expiry" class="form-label">Password Reset Token Expiry (hours)</label>
                                            <input type="number" class="form-control" id="password_reset_expiry" name="password_reset_expiry" min="1" max="72" value="<?php echo htmlspecialchars($security_settings['password_reset_expiry'] ?? '24'); ?>">
                                            <div class="form-text">How long a password reset link remains valid.</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label for="minimum_password_length" class="form-label">Minimum Password Length</label>
                                            <input type="number" class="form-control" id="minimum_password_length" name="minimum_password_length" min="6" max="32" value="<?php echo htmlspecialchars($security_settings['minimum_password_length'] ?? '8'); ?>">
                                            <div class="form-text">Minimum number of characters required for passwords.</div>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" id="require_strong_passwords" name="require_strong_passwords" <?php echo ($security_settings['require_strong_passwords'] ?? '1') === '1' ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="require_strong_passwords">
                                                Require Strong Passwords
                                            </label>
                                        </div>
                                        <div class="form-text">Enforce password complexity requirements (uppercase, lowercase, numbers, and special characters).</div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4">
                                            <label for="session_timeout" class="form-label">Session Timeout (minutes)</label>
                                            <input type="number" class="form-control" id="session_timeout" name="session_timeout" min="10" max="1440" value="<?php echo htmlspecialchars($security_settings['session_timeout'] ?? '120'); ?>">
                                            <div class="form-text">How long users can remain inactive before being logged out.</div>
                                        </div>
                                        <div class="col-md-4">
                                            <label for="failed_login_attempts" class="form-label">Failed Login Attempts</label>
                                            <input type="number" class="form-control" id="failed_login_attempts" name="failed_login_attempts" min="3" max="10" value="<?php echo htmlspecialchars($security_settings['failed_login_attempts'] ?? '5'); ?>">
                                            <div class="form-text">Number of failed login attempts before account lockout.</div>
                                        </div>
                                        <div class="col-md-4">
                                            <label for="lockout_time" class="form-label">Lockout Time (minutes)</label>
                                            <input type="number" class="form-control" id="lockout_time" name="lockout_time" min="5" max="1440" value="<?php echo htmlspecialchars($security_settings['lockout_time'] ?? '15'); ?>">
                                            <div class="form-text">Duration of account lockout after too many failed login attempts.</div>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" id="two_factor_auth" name="two_factor_auth" <?php echo ($security_settings['two_factor_auth'] ?? '0') === '1' ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="two_factor_auth">
                                                Enable Two-Factor Authentication
                                            </label>
                                        </div>
                                        <div class="form-text">Require two-factor authentication for admin users.</div>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <button type="submit" name="update_security_settings" class="btn btn-primary">
                                            <i class="fas fa-save me-1"></i> Save Security Settings
                                        </button>
                                    </div>
                                </form>
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
        // Show the tab specified in the URL hash, if any
        document.addEventListener('DOMContentLoaded', function() {
            const hash = window.location.hash;
            if (hash) {
                const tab = document.querySelector(`[data-bs-target="${hash}"]`);
                if (tab) {
                    const tabInstance = new bootstrap.Tab(tab);
                    tabInstance.show();
                }
            }
            
            // Update URL hash when tab changes
            const tabs = document.querySelectorAll('button[data-bs-toggle="tab"]');
            tabs.forEach(tab => {
                tab.addEventListener('shown.bs.tab', function(event) {
                    const targetId = event.target.getAttribute('data-bs-target');
                    window.history.replaceState(null, null, targetId);
                });
            });
        });
    </script>
</body>
</html>