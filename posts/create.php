<?php
/**
 * ApexPlanet Task 04 - Create Post with Prepared Statements,
 * Robust Server-side Validation & Interactive Character Counters.
 */

require_once "../config/database.php";

// Enforce authentication
require_login();

$message = "";
$errors = [];

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // 1. Enforce Anti-CSRF Protection
    require_csrf_valid();

    $title = trim($_POST["title"] ?? "");
    $content = trim($_POST["content"] ?? "");
    $userId = current_user_id();

    // 2. Server-side Validation
    $titleErr = validate_post_title($title);
    if ($titleErr) {
        $errors['title'] = $titleErr;
    }

    $contentErr = validate_post_content($content);
    if ($contentErr) {
        $errors['content'] = $contentErr;
    }

    // 3. Insert using Prepared Statement
    if (empty($errors)) {
        $stmt = $conn->prepare(
            "INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)"
        );

        if ($stmt) {
            $stmt->bind_param("ssi", $title, $content, $userId);

            if ($stmt->execute()) {
                $newId = (int)$stmt->insert_id;
                $stmt->close();
                header("Location: view.php?id=" . $newId);
                exit();
            } else {
                $message = "Failed to create post due to a database error. Please try again.";
            }

            $stmt->close();
        } else {
            $message = "Failed to prepare database insertion query.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Post - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="../style.css">
</head>

<body>

<div class="container">

    <div class="header-bar">
        <div>
            <h1>Create New Post</h1>
            <p class="header-user">
                Posting as <strong><?php echo htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8'); ?></strong>
                <?php echo render_role_badge(current_user_role()); ?>
            </p>
        </div>
        <div class="nav-actions">
            <a href="index.php" class="btn btn-secondary">← Back to Posts</a>
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

    <form method="POST" action="create.php" id="createPostForm" novalidate>
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
                placeholder="Enter post title (3 to 200 characters)..."
                value="<?php echo isset($_POST['title']) ? htmlspecialchars($_POST['title'], ENT_QUOTES, 'UTF-8') : ''; ?>"
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
                placeholder="Write your post content here (min 10 characters)... You can use formatting toolbar above."
                required
            ><?php echo isset($_POST['content']) ? htmlspecialchars($_POST['content'], ENT_QUOTES, 'UTF-8') : ''; ?></textarea>
            <span class="field-feedback" id="contentFeedback"></span>
        </div>

        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button type="submit" class="btn btn-primary">Publish Post</button>
            <a href="index.php" class="btn btn-secondary">Cancel</a>
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
        titleFeedback.textContent = 'Title must be at least 3 characters.';
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

// Initial count on load
updateTitleCount();
updateContentCount();

// Form submit interception
document.getElementById('createPostForm').addEventListener('submit', function(e) {
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
