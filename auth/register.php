<?php
/**
 * ApexPlanet Task 04 - Secure Registration with Prepared Statements,
 * Robust Server-Side Validation, and Interactive Client-Side Experience.
 */

require_once "../config/database.php";

// If already logged in, redirect to posts
if (is_logged_in()) {
    header("Location: ../posts/index.php");
    exit();
}

$message = "";
$isSuccess = false;
$errors = [];

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // 1. Enforce CSRF Security
    require_csrf_valid();

    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";
    $role = trim($_POST["role"] ?? "user");

    // Allowed self-registration roles (defaults to 'user')
    $allowedRoles = ['user', 'editor', 'admin'];
    if (!in_array($role, $allowedRoles, true)) {
        $role = 'user';
    }

    // 2. Server-side Validation
    $usernameErr = validate_username($username);
    if ($usernameErr) {
        $errors['username'] = $usernameErr;
    }

    $passwordErr = validate_password($password);
    if ($passwordErr) {
        $errors['password'] = $passwordErr;
    }

    if ($password !== $confirmPassword) {
        $errors['confirm_password'] = "Passwords do not match.";
    }

    // 3. If validation passed, check username uniqueness using Prepared Statement
    if (empty($errors)) {
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        if ($checkStmt) {
            $checkStmt->bind_param("s", $username);
            $checkStmt->execute();
            $checkResult = $checkStmt->get_result();

            if ($checkResult && $checkResult->num_rows > 0) {
                $errors['username'] = "Username is already taken. Please choose another one.";
            }
            $checkStmt->close();
        } else {
            $message = "Database verification error occurred.";
        }
    }

    // 4. Insert New User using Prepared Statement
    if (empty($errors) && empty($message)) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $insertStmt = $conn->prepare(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
        );

        if ($insertStmt) {
            $insertStmt->bind_param("sss", $username, $hashedPassword, $role);

            if ($insertStmt->execute()) {
                $message = "Account created successfully with role '" . htmlspecialchars($role) . "'! You can now sign in.";
                $isSuccess = true;
            } else {
                $message = "Registration failed due to a server error. Please try again.";
            }

            $insertStmt->close();
        } else {
            $message = "Failed to prepare user insertion statement.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>

<div class="container" style="max-width: 520px;">

    <h1>Create Account</h1>
    <p style="color: var(--text-muted); font-size: 14px; margin-top: -10px; margin-bottom: 20px;">
        Register a new account with server-side validation and role assignment.
    </p>

    <?php if (!empty($message)): ?>
        <div class="alert <?php echo $isSuccess ? 'alert-success' : 'alert-error'; ?>">
            <?php echo $isSuccess ? '✅' : '⚠️'; ?> <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
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

    <?php if (!$isSuccess): ?>
    <form method="POST" action="register.php" id="registerForm" novalidate>
        <!-- CSRF Protection Field -->
        <?php echo csrf_field(); ?>

        <div class="form-group">
            <label for="username">Username</label>
            <input 
                type="text" 
                id="username" 
                name="username" 
                placeholder="Choose a username (3-30 letters/numbers)"
                value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') : ''; ?>"
                required
                autocomplete="username"
            >
            <span class="field-feedback" id="usernameFeedback"></span>
        </div>

        <div class="form-group">
            <label for="role">Account Role</label>
            <select id="role" name="role" class="form-select">
                <option value="user" <?php echo (isset($_POST['role']) && $_POST['role'] === 'user') ? 'selected' : ''; ?>>👤 Student (Standard User)</option>
                <option value="editor" <?php echo (isset($_POST['role']) && $_POST['role'] === 'editor') ? 'selected' : ''; ?>>✏️ Editor (Can edit all posts)</option>
                <option value="admin" <?php echo (isset($_POST['role']) && $_POST['role'] === 'admin') ? 'selected' : ''; ?>>🛡️ Admin (Full privileges & user management)</option>
            </select>
            <small style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">
                Select a role to test role-based permissions (RBAC).
            </small>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input 
                type="password" 
                id="password" 
                name="password" 
                placeholder="At least 8 chars with upper, lower, & number"
                required
                autocomplete="new-password"
            >
            <span class="field-feedback" id="passwordFeedback"></span>

            <!-- Interactive Password Strength Meter -->
            <div class="password-strength-container">
                <div class="strength-meter-bar">
                    <div id="strengthBar" class="strength-bar"></div>
                </div>
                <div class="strength-meta">
                    <span id="strengthLabel" class="strength-text">Password strength: None</span>
                </div>
            </div>

            <!-- Password Requirements Checklist -->
            <div class="requirements-checklist">
                <div id="reqLength" class="req-item">❌ At least 8 characters</div>
                <div id="reqUpper" class="req-item">❌ One uppercase letter (A-Z)</div>
                <div id="reqLower" class="req-item">❌ One lowercase letter (a-z)</div>
                <div id="reqNumber" class="req-item">❌ One number (0-9)</div>
            </div>
        </div>

        <div class="form-group">
            <label for="confirm_password">Confirm Password</label>
            <input 
                type="password" 
                id="confirm_password" 
                name="confirm_password" 
                placeholder="Re-type your password"
                required
                autocomplete="new-password"
            >
            <span class="field-feedback" id="confirmFeedback"></span>
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 8px;">Create Account</button>
    </form>
    <?php else: ?>
        <div style="text-align: center; margin-top: 20px;">
            <a href="login.php" class="btn btn-primary">Proceed to Sign In →</a>
        </div>
    <?php endif; ?>

    <hr>

    <p style="text-align: center; font-size: 14px; margin-bottom: 0;">
        Already have an account?
        <a href="login.php"><u>Login here</u></a>
    </p>

</div>

<script>
// Client-side real-time interactive validation
const registerForm = document.getElementById('registerForm');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const confirmInput = document.getElementById('confirm_password');

const reqLength = document.getElementById('reqLength');
const reqUpper = document.getElementById('reqUpper');
const reqLower = document.getElementById('reqLower');
const reqNumber = document.getElementById('reqNumber');
const strengthBar = document.getElementById('strengthBar');
const strengthLabel = document.getElementById('strengthLabel');

function updateChecklist(input, valid, elem, text) {
    if (valid) {
        elem.innerHTML = '✅ ' + text;
        elem.classList.add('valid');
        elem.classList.remove('invalid');
    } else {
        elem.innerHTML = '❌ ' + text;
        elem.classList.remove('valid');
        elem.classList.add('invalid');
    }
}

passwordInput?.addEventListener('input', function() {
    const val = this.value;
    const hasLen = val.length >= 8;
    const hasUp = /[A-Z]/.test(val);
    const hasLow = /[a-z]/.test(val);
    const hasNum = /\d/.test(val);

    updateChecklist(this, hasLen, reqLength, 'At least 8 characters');
    updateChecklist(this, hasUp, reqUpper, 'One uppercase letter (A-Z)');
    updateChecklist(this, hasLow, reqLower, 'One lowercase letter (a-z)');
    updateChecklist(this, hasNum, reqNumber, 'One number (0-9)');

    let score = 0;
    if (hasLen) score++;
    if (hasUp) score++;
    if (hasLow) score++;
    if (hasNum) score++;
    if (val.length >= 12 && score === 4) score++;

    strengthBar.className = 'strength-bar';
    if (val.length === 0) {
        strengthBar.style.width = '0%';
        strengthLabel.textContent = 'Password strength: None';
        strengthLabel.style.color = 'var(--text-muted)';
    } else if (score <= 2) {
        strengthBar.style.width = '25%';
        strengthBar.classList.add('weak');
        strengthLabel.textContent = 'Password strength: Weak';
        strengthLabel.style.color = '#ef4444';
    } else if (score === 3) {
        strengthBar.style.width = '60%';
        strengthBar.classList.add('medium');
        strengthLabel.textContent = 'Password strength: Fair / Medium';
        strengthLabel.style.color = '#f59e0b';
    } else {
        strengthBar.style.width = '100%';
        strengthBar.classList.add('strong');
        strengthLabel.textContent = 'Password strength: Strong 🔒';
        strengthLabel.style.color = '#10b981';
    }

    validatePasswordMatch();
});

function validatePasswordMatch() {
    if (!confirmInput) return true;
    const pass = passwordInput.value;
    const confirm = confirmInput.value;
    const feedback = document.getElementById('confirmFeedback');

    if (!confirm) {
        confirmInput.classList.remove('is-invalid', 'is-valid');
        feedback.textContent = '';
        return false;
    }

    if (pass === confirm) {
        confirmInput.classList.remove('is-invalid');
        confirmInput.classList.add('is-valid');
        feedback.textContent = '✓ Passwords match';
        feedback.className = 'field-feedback valid-feedback';
        return true;
    } else {
        confirmInput.classList.remove('is-valid');
        confirmInput.classList.add('is-invalid');
        feedback.textContent = '✗ Passwords do not match';
        feedback.className = 'field-feedback invalid-feedback';
        return false;
    }
}

confirmInput?.addEventListener('input', validatePasswordMatch);

usernameInput?.addEventListener('input', function() {
    const val = this.value.trim();
    const feedback = document.getElementById('usernameFeedback');

    if (val.length === 0) {
        this.classList.remove('is-valid', 'is-invalid');
        feedback.textContent = '';
        return;
    }

    const regex = /^[a-zA-Z0-9_-]{3,30}$/;
    if (regex.test(val)) {
        this.classList.remove('is-invalid');
        this.classList.add('is-valid');
        feedback.textContent = '✓ Valid username format';
        feedback.className = 'field-feedback valid-feedback';
    } else {
        this.classList.remove('is-valid');
        this.classList.add('is-invalid');
        feedback.textContent = 'Must be 3-30 letters, numbers, hyphens, or underscores.';
        feedback.className = 'field-feedback invalid-feedback';
    }
});

registerForm?.addEventListener('submit', function(e) {
    let isValid = true;

    // Check username
    const usernameVal = usernameInput.value.trim();
    if (!/^[a-zA-Z0-9_-]{3,30}$/.test(usernameVal)) {
        usernameInput.classList.add('is-invalid');
        isValid = false;
    }

    // Check password
    const passVal = passwordInput.value;
    const hasLen = passVal.length >= 8;
    const hasUp = /[A-Z]/.test(passVal);
    const hasLow = /[a-z]/.test(passVal);
    const hasNum = /\d/.test(passVal);
    if (!hasLen || !hasUp || !hasLow || !hasNum) {
        passwordInput.classList.add('is-invalid');
        isValid = false;
    }

    // Check confirm password
    if (passVal !== confirmInput.value) {
        confirmInput.classList.add('is-invalid');
        isValid = false;
    }

    if (!isValid) {
        e.preventDefault();
        alert('Please correct the validation errors in the form before submitting.');
    }
});
</script>

</body>
</html>
