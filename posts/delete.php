<?php
/**
 * ApexPlanet Task 04 - Secure Post Deletion with RBAC & Anti-CSRF Protection
 * Prevents unauthorized deletion and Cross-Site Request Forgery (CSRF).
 */

require_once "../config/database.php";

// 1. Enforce Authentication
require_login();

if (!isset($_GET["id"]) || !is_numeric($_GET["id"])) {
    header("Location: index.php");
    exit();
}

$id = (int) $_GET["id"];

// 2. Fetch Post using Prepared Statement
$stmt = $conn->prepare(
    "SELECT p.id, p.title, p.user_id, u.username AS author_name 
     FROM posts p 
     LEFT JOIN users u ON p.user_id = u.id 
     WHERE p.id = ?"
);

if (!$stmt) {
    die("Database error.");
}

$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

if (!$result || $result->num_rows !== 1) {
    $stmt->close();
    header("Location: index.php");
    exit();
}

$post = $result->fetch_assoc();
$stmt->close();

// 3. Enforce Role-Based Access Control (RBAC)
if (!can_delete_post($post)) {
    http_response_code(403);
    render_access_denied("You do not have permission to delete this post. Standard users can only delete their own posts, while only Administrators can delete any post.");
    exit();
}

// 4. If POST request, verify CSRF and execute deletion
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    require_csrf_valid();

    $deleteStmt = $conn->prepare("DELETE FROM posts WHERE id = ?");
    if ($deleteStmt) {
        $deleteStmt->bind_param("i", $id);
        $deleteStmt->execute();
        $deleteStmt->close();
    }

    header("Location: index.php?deleted=1");
    exit();
}

// 5. If accessed via GET, render secure CSRF-protected confirmation modal/page
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confirm Delete Post - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>

<div class="container" style="max-width: 540px; margin-top: 40px;">

    <div style="text-align: center; margin-bottom: 20px;">
        <div style="font-size: 48px; margin-bottom: 8px;">🗑️</div>
        <h1 style="margin-bottom: 8px;">Confirm Post Deletion</h1>
        <p style="color: var(--text-muted); font-size: 14px;">
            This action is permanent and cannot be undone.
        </p>
    </div>

    <div class="alert alert-error" style="flex-direction: column; align-items: flex-start;">
        <div><strong>⚠️ Are you sure you want to delete this post?</strong></div>
        <div style="margin-top: 6px; font-size: 13px;">
            Title: <em>"<?php echo htmlspecialchars($post["title"], ENT_QUOTES, 'UTF-8'); ?>"</em>
        </div>
        <?php if (!empty($post["author_name"])): ?>
            <div style="margin-top: 4px; font-size: 12px; color: var(--text-muted);">
                Author: <strong><?php echo htmlspecialchars($post["author_name"], ENT_QUOTES, 'UTF-8'); ?></strong>
            </div>
        <?php endif; ?>
    </div>

    <form method="POST" action="delete.php?id=<?php echo $id; ?>" style="margin-top: 24px;">
        <!-- CSRF Token Field to Prevent CSRF Attacks -->
        <?php echo csrf_field(); ?>

        <div style="display: flex; gap: 12px; justify-content: center;">
            <button type="submit" class="btn btn-danger" style="padding: 12px 24px;">
                Yes, Delete Permanently
            </button>
            <a href="view.php?id=<?php echo $id; ?>" class="btn btn-secondary" style="padding: 12px 24px;">
                Cancel
            </a>
        </div>
    </form>

</div>

</body>
</html>
