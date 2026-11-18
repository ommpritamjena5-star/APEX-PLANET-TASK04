<?php
/**
 * ApexPlanet Task 04 - Edit Post with RBAC Authorization,
 * Prepared Statements, Anti-CSRF, and Form Validation.
 */

require_once "../config/database.php";

// Enforce authentication
require_login();

if (!isset($_GET["id"]) || !is_numeric($_GET["id"])) {
    header("Location: index.php");
    exit();
}

$id = (int) $_GET["id"];
$message = "";
$errors = [];

// 1. Fetch existing post using Prepared Statement
$stmt = $conn->prepare(
    "SELECT p.id, p.title, p.content, p.user_id, u.username AS author_name 
     FROM posts p 
     LEFT JOIN users u ON p.user_id = u.id 
     WHERE p.id = ?"
);

if (!$stmt) {
    die("Database query error.");
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

// 2. Enforce Role-Based Access Control (RBAC)
if (!can_edit_post($post)) {
    http_response_code(403);
    render_access_denied("You do not have permission to edit this post. Only the post author, an Editor, or an Administrator can modify this content.");
    exit();
}

// 3. Handle Update Request
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Enforce Anti-CSRF Token
    require_csrf_valid();

    $title = trim($_POST["title"] ?? "");
    $content = trim($_POST["content"] ?? "");

    // Server-side validation
    $titleErr = validate_post_title($title);
    if ($titleErr) {
        $errors['title'] = $titleErr;
    }

    $contentErr = validate_post_content($content);
    if ($contentErr) {
        $errors['content'] = $contentErr;
    }

    if (empty($errors)) {
        // Update using Prepared Statement
        $updateStmt = $conn->prepare(
            "UPDATE posts SET title = ?, content = ? WHERE id = ?"
        );

        if ($updateStmt) {
            $updateStmt->bind_param("ssi", $title, $content, $id);

            if ($updateStmt->execute()) {
                $updateStmt->close();
                header("Location: view.php?id=" . $id);
                exit();
            } else {
                $message = "Failed to update post in database.";
            }

            $updateStmt->close();
        } else {
            $message = "Query preparation failed.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Post - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="../style.css">
</head>

<body>

<div class="container">

    <div class="header-bar">
        <div>
            <h1>Edit Post</h1>
            <p class="header-user">
                Editing as <strong><?php echo htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8'); ?></strong>
                <?php echo render_role_badge(current_user_role()); ?>
                <?php if ($post['author_name']): ?>
                    &bull; Original Author: <strong><?php echo htmlspecialchars($post['author_name'], ENT_QUOTES, 'UTF-8'); ?></strong>
                <?php endif; ?>
            </p>
        </div>
        <div class="nav-actions">
            <a href="view.php?id=<?php echo $id; ?>" class="btn btn-secondary">← View Post</a>
            <a href="index.php" class="btn btn-secondary">All Posts</a>
        </div>
    </div>

    <?php if (!empty($message)): ?>
        <div class="alert alert-error">
            ⚠️ <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-error">
            <ul style="margin: 0; padding-left: 18px; text-align: left;">
                <?php foreach ($errors as $err): ?>
                    <li><?php echo htmlspecialchars($err, ENT_QUOTES, 'UTF-8'); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="POST" action="edit.php?id=<?php echo $id; ?>" id="editPostForm" novalidate>
        <!-- CSRF Protection Field -->
        <?php echo csrf_field(); ?>

        <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <label for="title">Post Title</label>
                <span class="char-counter" id="titleCounter">0 / 200</span>
            </div>
            <input
                type="text"
                id="title"
                name="title"
                maxlength="200"
                value="<?php echo htmlspecialchars($_POST['title'] ?? $post["title"], ENT_QUOTES, 'UTF-8'); ?>"
                required
            >
            <span class="field-feedback" id="titleFeedback"></span>
        </div>

        <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <label for="content-input">Post Content</label>
                <span class="char-counter" id="contentCounter">0 / 50,000</span>
            </div>
            <div class="formatting-toolbar">
                <button type="button" class="toolbar-btn bold" onclick="formatText('b')" title="Bold (Ctrl+B)">B</button>
                <button type="button" class="toolbar-btn italic" onclick="formatText('i')" title="Italic (Ctrl+I)">I</button>
                <button type="button" class="toolbar-btn underline" onclick="formatText('u')" title="Underline (Ctrl+U)">U</button>
                <span class="toolbar-hint">Tip: Select text and click <strong>B</strong>, <em>I</em>, or <u>U</u></span>
            </div>
            <textarea
                id="content-input"
                name="content"
                rows="8"
                required
            ><?php echo htmlspecialchars($_POST['content'] ?? $post["content"], ENT_QUOTES, 'UTF-8'); ?></textarea>
            <span class="field-feedback" id="contentFeedback"></span>
        </div>

        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button type="submit" class="btn btn-primary">Save Changes</button>
            <a href="view.php?id=<?php echo $id; ?>" class="btn btn-secondary">Cancel</a>
        </div>

    </form>

</div>

<script>
function formatText(tag) {
    const textarea = document.getElementById('content-input');
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.substring(start, end) || 'formatted text';
    const replacement = '[' + tag + ']' + selected + '[/' + tag + ']';
    
    textarea.setRangeText(replacement, start, end, 'end');
    textarea.focus();
    updateContentCount();
}

// Keyboard shortcuts for Ctrl+B, Ctrl+I, Ctrl+U
document.getElementById('content-input').addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey)) {
        if (e.key === 'b' || e.key === 'B') {
            e.preventDefault();
            formatText('b');
        } else if (e.key === 'i' || e.key === 'I') {
            e.preventDefault();
            formatText('i');
        } else if (e.key === 'u' || e.key === 'U') {
            e.preventDefault();
            formatText('u');
        }
    }
});

// Live Character Counters & Validation
const titleInput = document.getElementById('title');
const contentInput = document.getElementById('content-input');
const titleCounter = document.getElementById('titleCounter');
const contentCounter = document.getElementById('contentCounter');
const titleFeedback = document.getElementById('titleFeedback');
const contentFeedback = document.getElementById('contentFeedback');

function updateTitleCount() {
    const len = titleInput.value.trim().length;
    titleCounter.textContent = `${len} / 200`;
    if (len >= 3 && len <= 200) {
        titleInput.classList.remove('is-invalid');
        titleInput.classList.add('is-valid');
        titleFeedback.textContent = '';
    } else if (len > 0) {
        titleInput.classList.remove('is-valid');
        titleInput.classList.add('is-invalid');
        titleFeedback.textContent = 'Title must be between 3 and 200 characters.';
        titleFeedback.className = 'field-feedback invalid-feedback';
    } else {
        titleInput.classList.remove('is-valid', 'is-invalid');
        titleFeedback.textContent = '';
    }
}

function updateContentCount() {
    const len = contentInput.value.trim().length;
    contentCounter.textContent = `${len} / 50,000`;
    if (len >= 10 && len <= 50000) {
        contentInput.classList.remove('is-invalid');
        contentInput.classList.add('is-valid');
        contentFeedback.textContent = '';
    } else if (len > 0) {
        contentInput.classList.remove('is-valid');
        contentInput.classList.add('is-invalid');
        contentFeedback.textContent = 'Content must be at least 10 characters.';
        contentFeedback.className = 'field-feedback invalid-feedback';
    } else {
        contentInput.classList.remove('is-valid', 'is-invalid');
        contentFeedback.textContent = '';
    }
}

titleInput.addEventListener('input', updateTitleCount);
contentInput.addEventListener('input', updateContentCount);

// Initialize on load
updateTitleCount();
updateContentCount();

// Form submit interception
document.getElementById('editPostForm').addEventListener('submit', function(e) {
    let valid = true;
    const tLen = titleInput.value.trim().length;
    const cLen = contentInput.value.trim().length;

    if (tLen < 3 || tLen > 200) {
        titleInput.classList.add('is-invalid');
        titleFeedback.textContent = 'Title must be between 3 and 200 characters.';
        titleFeedback.className = 'field-feedback invalid-feedback';
        valid = false;
    }

    if (cLen < 10) {
        contentInput.classList.add('is-invalid');
        contentFeedback.textContent = 'Content must be at least 10 characters.';
        contentFeedback.className = 'field-feedback invalid-feedback';
        valid = false;
    }

    if (!valid) {
        e.preventDefault();
    }
});
</script>

</body>
</html>
