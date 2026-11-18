<?php
/**
 * ApexPlanet Task 04 - Security, Auth, RBAC & Validation Helper
 * Provides CSRF protection, RBAC permission checks, secure session handling,
 * security HTTP headers, and server-side form validation routines.
 */

// 1. Send Defensive Security HTTP Headers
if (!headers_sent()) {
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: SAMEORIGIN");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
}

// 2. Initialize Secure Session
if (session_status() === PHP_SESSION_NONE) {
    // Configure secure session cookie parameters before starting
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params([
        'lifetime' => $cookieParams['lifetime'],
        'path'     => $cookieParams['path'] ?: '/',
        'domain'   => $cookieParams['domain'],
        'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    session_start();
}

// 3. CSRF Protection Utilities
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Returns the current CSRF token string.
 */
function get_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Generates an HTML hidden input containing the CSRF token.
 */
function csrf_field(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(get_csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

/**
 * Validates the submitted CSRF token against the session token.
 */
function validate_csrf_token(?string $token): bool {
    if (empty($token) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Enforces CSRF token check on POST requests. Halts with 403 if invalid.
 */
function require_csrf_valid(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (!validate_csrf_token($token)) {
            http_response_code(403);
            render_access_denied("Invalid or missing CSRF security token. Please refresh the page and try again.");
            exit();
        }
    }
}

// 4. Authentication & RBAC Helper Functions

/**
 * Check if a user is currently authenticated.
 */
function is_logged_in(): bool {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * Enforce authentication. Redirects to login if not logged in.
 */
function require_login(): void {
    if (!is_logged_in()) {
        header("Location: ../auth/login.php");
        exit();
    }
}

/**
 * Returns current logged-in user's ID or null.
 */
function current_user_id(): ?int {
    return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
}

/**
 * Returns current logged-in user's username or empty string.
 */
function current_user_name(): string {
    return $_SESSION['username'] ?? '';
}

/**
 * Returns current logged-in user's role ('admin', 'editor', 'user', or guest).
 */
function current_user_role(): string {
    return $_SESSION['role'] ?? 'guest';
}

/**
 * Checks if current user has the 'admin' role.
 */
function is_admin(): bool {
    return current_user_role() === 'admin';
}

/**
 * Checks if current user has the 'editor' role.
 */
function is_editor(): bool {
    return current_user_role() === 'editor';
}

/**
 * Enforces admin-only access.
 */
function require_admin(): void {
    require_login();
    if (!is_admin()) {
        http_response_code(403);
        render_access_denied("Access Denied: Only administrators have permission to access this area.");
        exit();
    }
}

/**
 * Checks if the current user can edit a specific post.
 * Rules:
 *  - Admin: Can edit ANY post.
 *  - Editor: Can edit ANY post (editorial privilege).
 *  - User/Author: Can edit ONLY their OWN posts.
 */
function can_edit_post($post): bool {
    if (!is_logged_in()) {
        return false;
    }
    if (is_admin() || is_editor()) {
        return true;
    }
    $postAuthorId = is_array($post) ? ($post['user_id'] ?? null) : null;
    return $postAuthorId !== null && (int)$postAuthorId === current_user_id();
}

/**
 * Checks if the current user can delete a specific post.
 * Rules:
 *  - Admin: Can delete ANY post.
 *  - Editor / User: Can delete ONLY their OWN posts.
 */
function can_delete_post($post): bool {
    if (!is_logged_in()) {
        return false;
    }
    if (is_admin()) {
        return true;
    }
    $postAuthorId = is_array($post) ? ($post['user_id'] ?? null) : null;
    return $postAuthorId !== null && (int)$postAuthorId === current_user_id();
}

/**
 * Renders an accessible HTML role badge.
 */
function render_role_badge(?string $role): string {
    $role = strtolower($role ?? 'user');
    switch ($role) {
        case 'admin':
            return '<span class="role-badge role-admin">🛡️ Admin</span>';
        case 'editor':
            return '<span class="role-badge role-editor">✏️ Editor</span>';
        case 'user':
        default:
            return '<span class="role-badge role-user">👤 Student</span>';
    }
}

/**
 * Renders an access denied 403 page.
 */
function render_access_denied(string $message): void {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Denied - 403 Forbidden</title>
        <link rel="stylesheet" href="../style.css">
    </head>
    <body>
    <div class="container" style="max-width: 560px; text-align: center; margin-top: 40px;">
        <div style="font-size: 54px; margin-bottom: 12px;">🚫</div>
        <h1 style="color: var(--danger); margin-bottom: 12px;">403 - Access Denied</h1>
        <p style="color: var(--text-main); font-size: 15px; margin-bottom: 24px;">
            <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
        </p>
        <div style="display: flex; gap: 10px; justify-content: center;">
            <a href="../posts/index.php" class="btn btn-primary">← Return to Posts</a>
            <a href="../index.php" class="btn btn-secondary">Home</a>
        </div>
    </div>
    </body>
    </html>
    <?php
}

// 5. Server-Side Form Validation Functions

/**
 * Validates a username.
 * Rules:
 *  - Required
 *  - 3 to 30 characters
 *  - Letters, numbers, underscores, and dashes only
 */
function validate_username(string $username): ?string {
    $trimmed = trim($username);
    if (empty($trimmed)) {
        return "Username is required.";
    }
    if (strlen($trimmed) < 3 || strlen($trimmed) > 30) {
        return "Username must be between 3 and 30 characters long.";
    }
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $trimmed)) {
        return "Username may only contain letters, numbers, underscores, and hyphens.";
    }
    return null;
}

/**
 * Validates a password.
 * Rules:
 *  - Required
 *  - Minimum 8 characters
 *  - At least 1 uppercase letter
 *  - At least 1 lowercase letter
 *  - At least 1 number
 */
function validate_password(string $password): ?string {
    if (empty($password)) {
        return "Password is required.";
    }
    if (strlen($password) < 8) {
        return "Password must be at least 8 characters long.";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        return "Password must include at least one uppercase letter (A-Z).";
    }
    if (!preg_match('/[a-z]/', $password)) {
        return "Password must include at least one lowercase letter (a-z).";
    }
    if (!preg_match('/\d/', $password)) {
        return "Password must include at least one number (0-9).";
    }
    return null;
}

/**
 * Validates post title.
 * Rules:
 *  - Required
 *  - 3 to 200 characters
 */
function validate_post_title(string $title): ?string {
    $trimmed = trim($title);
    if (empty($trimmed)) {
        return "Post title is required.";
    }
    if (mb_strlen($trimmed) < 3) {
        return "Post title must be at least 3 characters long.";
    }
    if (mb_strlen($trimmed) > 200) {
        return "Post title cannot exceed 200 characters.";
    }
    return null;
}

/**
 * Validates post content.
 * Rules:
 *  - Required
 *  - 10 to 50,000 characters
 */
function validate_post_content(string $content): ?string {
    $trimmed = trim($content);
    if (empty($trimmed)) {
        return "Post content is required.";
    }
    if (mb_strlen($trimmed) < 10) {
        return "Post content must be at least 10 characters long.";
    }
    if (mb_strlen($trimmed) > 50000) {
        return "Post content exceeds the maximum allowed length of 50,000 characters.";
    }
    return null;
}
