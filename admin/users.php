<?php
/**
 * ApexPlanet Task 04 - Admin User Roles Management Panel
 * Accessible only by users with the 'admin' role.
 * Demonstrates Role-Based Access Control (RBAC) with prepared statements & CSRF.
 */

require_once "../config/database.php";

// Enforce admin-only access
require_admin();

$message = "";
$messageType = "error";

// Handle Role Change Request
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["action"]) && $_POST["action"] === "update_role") {
    // 1. Verify CSRF Token
    require_csrf_valid();

    $targetUserId = isset($_POST["user_id"]) ? (int)$_POST["user_id"] : 0;
    $newRole = trim($_POST["new_role"] ?? "");

    $allowedRoles = ['admin', 'editor', 'user'];

    if (!in_array($newRole, $allowedRoles, true)) {
        $message = "Invalid role specified.";
    } elseif ($targetUserId === current_user_id() && $newRole !== 'admin') {
        $message = "Safety restriction: You cannot demote your own administrator account.";
    } else {
        // 2. Update role using Prepared Statement
        $updateStmt = $conn->prepare("UPDATE users SET role = ? WHERE id = ?");
        if ($updateStmt) {
            $updateStmt->bind_param("si", $newRole, $targetUserId);
            if ($updateStmt->execute()) {
                $message = "User ID #{$targetUserId} role updated successfully to '{$newRole}'.";
                $messageType = "success";
            } else {
                $message = "Failed to update role in database.";
            }
            $updateStmt->close();
        } else {
            $message = "Query preparation failed.";
        }
    }
}

// Fetch all users with their post count using a prepared query
$usersStmt = $conn->prepare("
    SELECT u.id, u.username, u.role, u.created_at, COUNT(p.id) AS post_count
    FROM users u
    LEFT JOIN posts p ON u.id = p.user_id
    GROUP BY u.id, u.username, u.role, u.created_at
    ORDER BY u.id ASC
");

$users = [];
if ($usersStmt) {
    $usersStmt->execute();
    $result = $usersStmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }
    $usersStmt->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Role Management - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>

<div class="container" style="max-width: 960px;">

    <div class="header-bar">
        <div>
            <h1>User & Role Management</h1>
            <p class="header-user">
                Logged in as <strong><?php echo htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8'); ?></strong> 
                <?php echo render_role_badge(current_user_role()); ?>
            </p>
        </div>
        <div class="nav-actions">
            <a href="../posts/index.php" class="btn btn-primary">← All Posts</a>
            <a href="../auth/logout.php" class="btn btn-secondary">Logout</a>
        </div>
    </div>

    <div class="alert alert-info">
        🛡️ <strong>Role-Based Access Control (RBAC) Console:</strong> 
        Administrators can promote or demote registered users between <em>Student (User)</em>, <em>Editor</em>, and <em>Admin</em>.
    </div>

    <?php if (!empty($message)): ?>
        <div class="alert alert-<?php echo $messageType; ?>">
            <?php echo $messageType === 'success' ? '✅' : '⚠️'; ?> 
            <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <h2>Registered System Accounts (<?php echo count($users); ?>)</h2>

    <div style="overflow-x: auto; margin-top: 16px;">
        <table class="users-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Current Role</th>
                    <th>Posts Authored</th>
                    <th>Registered On</th>
                    <th>Change Role (RBAC)</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $u): ?>
                    <tr>
                        <td><strong>#<?php echo (int)$u["id"]; ?></strong></td>
                        <td>
                            <strong><?php echo htmlspecialchars($u["username"], ENT_QUOTES, 'UTF-8'); ?></strong>
                            <?php if ((int)$u["id"] === current_user_id()): ?>
                                <small style="color: var(--primary); font-weight: 700;">(You)</small>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php echo render_role_badge($u["role"]); ?>
                        </td>
                        <td>
                            <span class="meta-pill" style="font-size: 12px; padding: 3px 8px;">
                                📝 <?php echo (int)$u["post_count"]; ?>
                            </span>
                        </td>
                        <td>
                            <small class="meta">
                                <?php echo !empty($u["created_at"]) ? date("M d, Y", strtotime($u["created_at"])) : "N/A"; ?>
                            </small>
                        </td>
                        <td>
                            <form method="POST" action="users.php" style="flex-direction: row; gap: 8px; align-items: center; margin: 0;">
                                <?php echo csrf_field(); ?>
                                <input type="hidden" name="action" value="update_role">
                                <input type="hidden" name="user_id" value="<?php echo (int)$u["id"]; ?>">

                                <select name="new_role" class="form-select form-select-sm" style="padding: 6px 10px; font-size: 13px;">
                                    <option value="user" <?php echo $u["role"] === 'user' ? 'selected' : ''; ?>>👤 Student</option>
                                    <option value="editor" <?php echo $u["role"] === 'editor' ? 'selected' : ''; ?>>✏️ Editor</option>
                                    <option value="admin" <?php echo $u["role"] === 'admin' ? 'selected' : ''; ?>>🛡️ Admin</option>
                                </select>

                                <button type="submit" class="btn btn-secondary btn-sm" <?php echo ((int)$u["id"] === current_user_id()) ? 'title="Self-demotion disabled"' : ''; ?>>
                                    Save
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div style="margin-top: 30px; padding: 20px; background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius-md);">
        <h3 style="font-size: 16px; margin-bottom: 8px;">Role Permissions Reference Matrix:</h3>
        <ul style="font-size: 14px; color: #475569; padding-left: 20px; line-height: 1.8;">
            <li><strong>Admin:</strong> Full permissions. Can create, edit any post, delete any post, and manage user roles.</li>
            <li><strong>Editor:</strong> Editorial permissions. Can create posts, edit ANY post to maintain quality, and delete their own posts.</li>
            <li><strong>Student (User):</strong> Standard author. Can create posts, and can edit or delete ONLY their own posts.</li>
        </ul>
    </div>

</div>

</body>
</html>
