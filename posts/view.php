<?php
/**
 * ApexPlanet Task 04 - Single Post View with Authorship, Role Badges & RBAC Controls
 */

require_once "../config/database.php";

// Enforce authentication
require_login();

if (!isset($_GET["id"]) || !is_numeric($_GET["id"])) {
    header("Location: index.php");
    exit();
}

$id = (int) $_GET["id"];

// Fetch post using Prepared Statement
$stmt = $conn->prepare(
    "SELECT p.id, p.title, p.content, p.created_at, p.user_id, 
            u.username AS author_name, u.role AS author_role
     FROM posts p 
     LEFT JOIN users u ON p.user_id = u.id 
     WHERE p.id = ?"
);

$post = null;
if ($stmt) {
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows === 1) {
        $post = $result->fetch_assoc();
    }
    $stmt->close();
}

if (!function_exists('formatPostContent')) {
    function formatPostContent($text) {
        $escaped = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
        
        // BBCode style [b], [i], [u]
        $escaped = preg_replace('/\[b\](.*?)\[\/b\]/is', '<strong>$1</strong>', $escaped);
        $escaped = preg_replace('/\[i\](.*?)\[\/i\]/is', '<em>$1</em>', $escaped);
        $escaped = preg_replace('/\[u\](.*?)\[\/u\]/is', '<u>$1</u>', $escaped);
        
        // Markdown style **bold**, *italic*, __underline__
        $escaped = preg_replace('/\*\*(.*?)\*\*/s', '<strong>$1</strong>', $escaped);
        $escaped = preg_replace('/(?<!\*)\*(?!\*)(.*?)(?<!\*)\*(?!\*)/s', '<em>$1</em>', $escaped);
        $escaped = preg_replace('/__(.*?)__/s', '<u>$1</u>', $escaped);
        
        return nl2br($escaped);
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $post ? htmlspecialchars($post["title"], ENT_QUOTES, 'UTF-8') : "Post Not Found"; ?> - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="../style.css">
</head>

<body>

<div class="container">

    <div class="header-bar">
        <div>
            <h1>Student Management System</h1>
            <p class="header-user">
                Logged in as <strong><?php echo htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8'); ?></strong>
                <?php echo render_role_badge(current_user_role()); ?>
            </p>
        </div>
        <div class="nav-actions">
            <?php if (is_admin()): ?>
                <a href="../admin/users.php" class="btn btn-secondary">👥 Manage Users</a>
            <?php endif; ?>
            <a href="index.php" class="btn btn-secondary">← Back to Posts</a>
            <a href="create.php" class="btn btn-primary">+ Create Post</a>
            <a href="../auth/logout.php" class="btn btn-secondary">Logout</a>
        </div>
    </div>

    <?php if ($post): ?>

        <div class="single-post-container">
            <div class="single-post-header">
                <div style="margin-bottom: 12px;">
                    <a href="index.php" style="font-size: 13px; font-weight: 600;">← All Posts</a>
                    <span style="color: var(--text-muted); margin: 0 8px;">/</span>
                    <span style="color: var(--text-muted); font-size: 13px;">Post #<?php echo (int)$post["id"]; ?></span>
                </div>

                <h2 class="single-post-title">
                    <?php echo htmlspecialchars($post["title"], ENT_QUOTES, 'UTF-8'); ?>
                </h2>

                <div class="single-post-meta">
                    <span class="meta-pill">
                        👤 Author: <strong><?php echo htmlspecialchars($post["author_name"] ?? "Anonymous", ENT_QUOTES, 'UTF-8'); ?></strong>
                        <?php echo render_role_badge($post["author_role"] ?? "user"); ?>
                    </span>
                    <span class="meta-pill">
                        🕒 Published: <?php echo date("M d, Y - h:i A", strtotime($post["created_at"])); ?>
                    </span>
                    <span class="meta-pill">
                        📌 Post ID: #<?php echo (int)$post["id"]; ?>
                    </span>
                </div>
            </div>

            <div class="single-post-body">
                <?php echo formatPostContent($post["content"]); ?>
            </div>

            <div class="single-post-footer">
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                    <a href="index.php" class="btn btn-secondary">← Back to All Posts</a>
                    <button type="button" class="btn btn-secondary" onclick="copyPostLink()">📋 Share / Copy Link</button>
                </div>

                <div class="article-actions">
                    <!-- RBAC: Only display Edit if user has edit permission -->
                    <?php if (can_edit_post($post)): ?>
                        <a href="edit.php?id=<?php echo (int)$post["id"]; ?>" class="btn btn-secondary btn-sm">
                            ✏️ Edit Post
                        </a>
                    <?php endif; ?>

                    <!-- RBAC: Only display Delete if user has delete permission -->
                    <?php if (can_delete_post($post)): ?>
                        <a href="delete.php?id=<?php echo (int)$post["id"]; ?>" class="btn btn-danger btn-sm">
                            🗑️ Delete Post
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>

    <?php else: ?>

        <div class="empty-state">
            <div class="alert alert-error" style="display: inline-flex; margin-bottom: 20px;">
                ⚠️ Post not found or it may have been deleted.
            </div>
            <p>
                <a href="index.php" class="btn btn-primary">← Return to All Posts</a>
            </p>
        </div>

    <?php endif; ?>

</div>

<div id="copyToast" class="copy-toast">Link copied to clipboard!</div>

<script>
function copyPostLink() {
    navigator.clipboard.writeText(window.location.href).then(function() {
        const toast = document.getElementById('copyToast');
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2200);
    }).catch(function() {
        alert('Post URL: ' + window.location.href);
    });
}
</script>

</body>
</html>
