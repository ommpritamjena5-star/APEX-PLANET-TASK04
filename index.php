<?php
/**
 * ApexPlanet Task 04 - Home / Landing Page
 * Showcases Application Security Enhancements, Role-Based Access Control,
 * and Prepared Statements Architecture.
 */

require_once "config/database.php";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Management System - ApexPlanet Task 04</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>

<div class="container">

    <h1>Student Management System</h1>

    <div style="display: inline-flex; align-items: center; gap: 8px; margin-top: -6px; margin-bottom: 20px;">
        <span class="role-badge role-admin" style="font-size: 13px;">🛡️ Task 04: Security Enhancements</span>
        <span class="meta-pill" style="font-size: 13px;">PHP 8 & MySQL</span>
    </div>

    <p style="font-size: 16px; margin-top: 10px; margin-bottom: 25px; color: #475569; line-height: 1.7;">
        An enterprise-grade, secure web application hardened against common vulnerabilities. Featuring <strong>100% Prepared Statements</strong> to prevent SQL Injection, <strong>Role-Based Access Control (RBAC)</strong> across Admin, Editor, and Student roles, <strong>Anti-CSRF Tokens</strong>, and comprehensive <strong>Server & Client-side Form Validation</strong>.
    </p>

    <!-- Security Badges Showcase -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 28px;">
        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 16px;">
            <div style="font-size: 20px; margin-bottom: 6px;">💉 <strong>Prepared Statements</strong></div>
            <p style="font-size: 13px; color: var(--text-muted); margin: 0;">
                All queries parameterized via MySQLi to neutralize SQL Injection.
            </p>
        </div>

        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 16px;">
            <div style="font-size: 20px; margin-bottom: 6px;">🛡️ <strong>RBAC Roles</strong></div>
            <p style="font-size: 13px; color: var(--text-muted); margin: 0;">
                Granular permissions for <em>Admin</em>, <em>Editor</em>, and <em>Student</em> accounts.
            </p>
        </div>

        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 16px;">
            <div style="font-size: 20px; margin-bottom: 6px;">🔒 <strong>CSRF & Fixation</strong></div>
            <p style="font-size: 13px; color: var(--text-muted); margin: 0;">
                Cryptographic synchronizer tokens and session rotation on login.
            </p>
        </div>

        <div style="background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 16px;">
            <div style="font-size: 20px; margin-bottom: 6px;">✅ <strong>Form Validation</strong></div>
            <p style="font-size: 13px; color: var(--text-muted); margin: 0;">
                Dual-layer: regex server sanitization + live interactive JS feedback.
            </p>
        </div>
    </div>

    <?php if (is_logged_in()): ?>

        <div class="alert alert-info">
            👋 Welcome back, <strong><?php echo htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8'); ?></strong>! 
            You are logged in as <?php echo render_role_badge(current_user_role()); ?>
        </div>

        <div style="display: flex; gap: 12px; margin-top: 20px; flex-wrap: wrap;">
            <a href="posts/index.php" class="btn btn-primary">Manage & Search Posts →</a>
            <a href="posts/create.php" class="btn btn-secondary">+ Create Post</a>
            <?php if (is_admin()): ?>
                <a href="admin/users.php" class="btn btn-secondary">👥 Admin User Roles</a>
            <?php endif; ?>
            <a href="auth/logout.php" class="btn btn-secondary">Logout</a>
        </div>

    <?php else: ?>

        <div style="display: flex; gap: 12px; margin-top: 20px; flex-wrap: wrap;">
            <a href="auth/login.php" class="btn btn-primary">Sign In to Account →</a>
            <a href="auth/register.php" class="btn btn-secondary">Create Account</a>
        </div>

        <!-- Quick Demo Credentials Box -->
        <div class="demo-accounts-box" style="margin-top: 28px;">
            <div class="demo-accounts-title">🔑 Pre-configured Accounts for Testing RBAC:</div>
            <div class="demo-accounts-grid">
                <div class="demo-account-pill">
                    <span class="role-badge role-admin">Admin</span>
                    <code>admin / Admin@12345</code>
                </div>
                <div class="demo-account-pill">
                    <span class="role-badge role-editor">Editor</span>
                    <code>editor / Editor@12345</code>
                </div>
                <div class="demo-account-pill">
                    <span class="role-badge role-user">Student</span>
                    <code>student / Student@12345</code>
                </div>
            </div>
        </div>

    <?php endif; ?>

</div>

</body>
</html>
