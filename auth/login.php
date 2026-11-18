<?php
/**
 * ApexPlanet Task 04 - Secure Login with Prepared Statements & CSRF Protection
 */

require_once "../config/database.php";

// If already logged in, redirect to posts
if (is_logged_in()) {
    header("Location: ../posts/index.php");
    exit();
}

$message = "";
$messageType = "error";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // 1. Verify CSRF Token
    require_csrf_valid();

    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    // 2. Server-side Validation
    if (empty($username) || empty($password)) {
        $message = "Please enter both username and password.";
    } else {
        // 3. Prepared Statement to Prevent SQL Injection
        $stmt = $conn->prepare(
            "SELECT id, username, password, role FROM users WHERE username = ?"
        );

        if ($stmt) {
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows === 1) {
                $user = $result->fetch_assoc();

                // 4. Verify password with bcrypt
                if (password_verify($password, $user["password"])) {
                    // Prevent Session Fixation attacks
                    session_regenerate_id(true);

                    // Set authenticated session state
                    $_SESSION["user_id"] = (int)$user["id"];
                    $_SESSION["username"] = $user["username"];
                    $_SESSION["role"] = $user["role"] ?? "user";

                    // Generate a fresh CSRF token for the authenticated session
                    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));

                    header("Location: ../posts/index.php");
                    exit();
                } else {
                    $message = "Invalid username or password.";
                }
            } else {
                $message = "Invalid username or password.";
            }

            $stmt->close();
        } else {
            $message = "A database query error occurred. Please try again.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Login - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>

<div class="container" style="max-width: 520px;">

    <h1>Account Login</h1>
    <p style="color: var(--text-muted); font-size: 14px; margin-top: -10px; margin-bottom: 20px;">
        Sign in to manage your posts and records with role-based access.
    </p>

    <?php if (!empty($message)): ?>
        <div class="alert alert-<?php echo $messageType; ?>">
            ⚠️ <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="login.php" id="loginForm" novalidate>
        <!-- CSRF Protection Field -->
        <?php echo csrf_field(); ?>

        <div class="form-group">
            <label for="username">Username</label>
            <input 
                type="text" 
                id="username" 
                name="username" 
                placeholder="Enter your username"
                value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') : ''; ?>"
                required
                autocomplete="username"
            >
            <span class="field-feedback" id="usernameFeedback"></span>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input 
                type="password" 
                id="password" 
                name="password" 
                placeholder="Enter your password"
                required
                autocomplete="current-password"
            >
            <span class="field-feedback" id="passwordFeedback"></span>
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 6px;">Sign In</button>
    </form>

    <hr>

    <!-- Quick Demo Accounts for Testing Roles -->
    <div class="demo-accounts-box">
        <div class="demo-accounts-title">🔑 Quick Test Accounts (Pre-configured):</div>
        <div class="demo-accounts-grid">
            <div class="demo-account-pill" onclick="fillCredentials('admin', 'Admin@12345')">
                <span class="role-badge role-admin">Admin</span>
                <code>admin / Admin@12345</code>
            </div>
            <div class="demo-account-pill" onclick="fillCredentials('editor', 'Editor@12345')">
                <span class="role-badge role-editor">Editor</span>
                <code>editor / Editor@12345</code>
            </div>
            <div class="demo-account-pill" onclick="fillCredentials('student', 'Student@12345')">
                <span class="role-badge role-user">Student</span>
                <code>student / Student@12345</code>
            </div>
        </div>
        <small style="color: var(--text-muted); font-size: 11px; display: block; margin-top: 6px;">
            Click any account above to autofill credentials for testing.
        </small>
    </div>

    <p style="text-align: center; font-size: 14px; margin-top: 18px; margin-bottom: 0;">
        Don't have an account?
        <a href="register.php"><u>Register here</u></a>
    </p>

</div>

<script>
function fillCredentials(user, pass) {
    document.getElementById('username').value = user;
    document.getElementById('password').value = pass;
}

// Client-side instant validation
const loginForm = document.getElementById('loginForm');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');

loginForm.addEventListener('submit', function(e) {
    let isValid = true;

    if (!usernameInput.value.trim()) {
        showError(usernameInput, 'Please enter your username.');
        isValid = false;
    } else {
        clearError(usernameInput);
    }

    if (!passwordInput.value) {
        showError(passwordInput, 'Please enter your password.');
        isValid = false;
    } else {
        clearError(passwordInput);
    }

    if (!isValid) {
        e.preventDefault();
    }
});

function showError(input, msg) {
    input.classList.add('is-invalid');
    const feedback = input.parentElement.querySelector('.field-feedback');
    if (feedback) {
        feedback.textContent = msg;
        feedback.className = 'field-feedback invalid-feedback';
    }
}

function clearError(input) {
    input.classList.remove('is-invalid');
    const feedback = input.parentElement.querySelector('.field-feedback');
    if (feedback) {
        feedback.textContent = '';
        feedback.className = 'field-feedback';
    }
}

usernameInput.addEventListener('input', () => clearError(usernameInput));
passwordInput.addEventListener('input', () => clearError(passwordInput));
</script>

</body>
</html>
