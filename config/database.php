<?php
/**
 * ApexPlanet Task 04 - Database Configuration & Auto-Migration
 * Establishes secure MySQLi connection and ensures schema columns
 * for roles (RBAC) and user ownership exist.
 */

// Include security utilities (session, headers, CSRF, RBAC)
require_once __DIR__ . "/security.php";

$host = "localhost";
$username = "root";
$password = "";
$database = "blog";

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$conn->set_charset("utf8mb4");

/**
 * Automatically ensures Task 04 schema enhancements are present:
 *  - role column in users table
 *  - user_id column in posts table
 *  - default demo users (admin, editor, student)
 */
function ensure_task4_schema_upgrades(mysqli $conn): void {
    // 1. Ensure 'role' column exists in 'users' table
    $colCheck = $conn->query("SHOW COLUMNS FROM `users` LIKE 'role'");
    if ($colCheck && $colCheck->num_rows === 0) {
        $conn->query("ALTER TABLE `users` ADD COLUMN `role` ENUM('admin', 'editor', 'user') NOT NULL DEFAULT 'user' AFTER `password`");
    }

    // 2. Ensure 'created_at' column exists in 'users' table
    $createdCheck = $conn->query("SHOW COLUMNS FROM `users` LIKE 'created_at'");
    if ($createdCheck && $createdCheck->num_rows === 0) {
        $conn->query("ALTER TABLE `users` ADD COLUMN `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP AFTER `role`");
    }

    // 3. Ensure 'user_id' column exists in 'posts' table
    $postColCheck = $conn->query("SHOW COLUMNS FROM `posts` LIKE 'user_id'");
    if ($postColCheck && $postColCheck->num_rows === 0) {
        $conn->query("ALTER TABLE `posts` ADD COLUMN `user_id` INT NULL AFTER `id`");
    }

    // 4. Seed default demo accounts if not present
    $checkAdmin = $conn->prepare("SELECT id FROM users WHERE username = ?");
    if ($checkAdmin) {
        $adminUser = 'admin';
        $checkAdmin->bind_param("s", $adminUser);
        $checkAdmin->execute();
        $adminRes = $checkAdmin->get_result();
        
        if ($adminRes->num_rows === 0) {
            // Seed Admin, Editor, and Student accounts
            $seedUsers = [
                ['admin', 'Admin@12345', 'admin'],
                ['editor', 'Editor@12345', 'editor'],
                ['student', 'Student@12345', 'user']
            ];

            $insertStmt = $conn->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
            if ($insertStmt) {
                foreach ($seedUsers as $u) {
                    $uName = $u[0];
                    $uHash = password_hash($u[1], PASSWORD_DEFAULT);
                    $uRole = $u[2];
                    $insertStmt->bind_param("sss", $uName, $uHash, $uRole);
                    $insertStmt->execute();
                }
                $insertStmt->close();
            }
        }
        $checkAdmin->close();
    }
}

// Run schema verification gracefully
try {
    ensure_task4_schema_upgrades($conn);
} catch (Throwable $e) {
    // Graceful fallback if tables are being freshly installed
}
