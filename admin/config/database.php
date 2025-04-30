<?php
/**
 * Database Configuration
 * 
 * This file handles database connection and provides basic functionality
 * for secure database operations.
 */

// Define database connection parameters
$db_host = 'localhost';
$db_name = 'storelin_db_v2';
$db_user = 'storelin_adminuser_v2'; // Change to your database username
$db_pass = 'M~5j65Mf1r*C'; // Change to your database password

// Set error mode to exception
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

try {
    // Create a new PDO instance
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, $options);
    
    // Uncomment the line below for debugging
    // echo "Database connection successful!";
} catch (PDOException $e) {
    // Handle connection error
    $error_message = 'Database Connection Error: ' . $e->getMessage();
    
    // Log error
    error_log($error_message);
    
    // Display user-friendly message
    die('Sorry, a database error occurred. Please try again later.');
}

/**
 * Sanitize user input
 * 
 * @param string $input User input to sanitize
 * @return string Sanitized input
 */
function sanitize($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Get a single record from database
 * 
 * @param string $table Table name
 * @param string $column Column to match
 * @param mixed $value Value to match
 * @return array|bool Record array or false if not found
 */
function getRecord($table, $column, $value) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM $table WHERE $column = :value LIMIT 1");
        $stmt->bindValue(':value', $value);
        $stmt->execute();
        
        return $stmt->fetch();
    } catch (PDOException $e) {
        error_log('Get record error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Get multiple records from database
 * 
 * @param string $table Table name
 * @param string $where Where clause (optional)
 * @param array $params Parameters for prepared statement (optional)
 * @param string $orderBy Order by clause (optional)
 * @param int $limit Result limit (optional)
 * @return array Records array
 */
function getRecords($table, $where = '', $params = [], $orderBy = '', $limit = 0) {
    global $pdo;
    
    try {
        $sql = "SELECT * FROM $table";
        
        if ($where) {
            $sql .= " WHERE $where";
        }
        
        if ($orderBy) {
            $sql .= " ORDER BY $orderBy";
        }
        
        if ($limit > 0) {
            $sql .= " LIMIT $limit";
        }
        
        $stmt = $pdo->prepare($sql);
        
        foreach ($params as $key => $value) {
            $stmt->bindValue(":$key", $value);
        }
        
        $stmt->execute();
        
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log('Get records error: ' . $e->getMessage());
        return [];
    }
}

/**
 * Insert record into database
 * 
 * @param string $table Table name
 * @param array $data Associative array of column => value
 * @return int|bool Last insert ID or false on failure
 */
function insertRecord($table, $data) {
    global $pdo;
    
    try {
        // Build column and placeholder lists
        $columns = implode(', ', array_keys($data));
        $placeholders = ':' . implode(', :', array_keys($data));
        
        $sql = "INSERT INTO $table ($columns) VALUES ($placeholders)";
        $stmt = $pdo->prepare($sql);
        
        // Bind values
        foreach ($data as $key => $value) {
            $stmt->bindValue(":$key", $value);
        }
        
        $stmt->execute();
        return $pdo->lastInsertId();
    } catch (PDOException $e) {
        error_log('Insert record error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Update record in database
 * 
 * @param string $table Table name
 * @param array $data Associative array of column => new value
 * @param string $where Where clause
 * @param array $whereParams Parameters for where clause
 * @return bool Success or failure
 */
function updateRecord($table, $data, $where, $whereParams = []) {
    global $pdo;
    
    try {
        // Build update fragments
        $updateFragments = [];
        foreach (array_keys($data) as $column) {
            $updateFragments[] = "$column = :$column";
        }
        
        $updateString = implode(', ', $updateFragments);
        
        $sql = "UPDATE $table SET $updateString WHERE $where";
        $stmt = $pdo->prepare($sql);
        
        // Bind data values
        foreach ($data as $key => $value) {
            $stmt->bindValue(":$key", $value);
        }
        
        // Bind where parameters
        foreach ($whereParams as $key => $value) {
            $stmt->bindValue(":$key", $value);
        }
        
        return $stmt->execute();
    } catch (PDOException $e) {
        error_log('Update record error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Delete record from database
 * 
 * @param string $table Table name
 * @param string $where Where clause
 * @param array $params Parameters for where clause
 * @return bool Success or failure
 */
function deleteRecord($table, $where, $params = []) {
    global $pdo;
    
    try {
        $sql = "DELETE FROM $table WHERE $where";
        $stmt = $pdo->prepare($sql);
        
        foreach ($params as $key => $value) {
            $stmt->bindValue(":$key", $value);
        }
        
        return $stmt->execute();
    } catch (PDOException $e) {
        error_log('Delete record error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Count records in table
 * 
 * @param string $table Table name
 * @param string $where Where clause (optional)
 * @param array $params Parameters for where clause (optional)
 * @return int Record count
 */
function countRecords($table, $where = '', $params = []) {
    global $pdo;
    
    try {
        $sql = "SELECT COUNT(*) FROM $table";
        
        if ($where) {
            $sql .= " WHERE $where";
        }
        
        $stmt = $pdo->prepare($sql);
        
        foreach ($params as $key => $value) {
            $stmt->bindValue(":$key", $value);
        }
        
        $stmt->execute();
        
        return (int)$stmt->fetchColumn();
    } catch (PDOException $e) {
        error_log('Count records error: ' . $e->getMessage());
        return 0;
    }
}