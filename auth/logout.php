<?php
/**
 * ApexPlanet Task 04 - Secure Logout
 * Destroys session, clears session cookies, and redirects.
 */

require_once "../config/security.php";

$_SESSION = [];

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

session_destroy();

header("Location: login.php");
exit();
