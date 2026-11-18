# ApexPlanet Task 04 - Security Enhancements & Role-Based Access Control (RBAC)

## Project Overview

**ApexPlanet Task 04** is an enterprise-hardened PHP & MySQL Student Management and Blogging application engineered to defend against common web security vulnerabilities. This release implements **100% Prepared Statements** to eliminate SQL Injection, a **Dual-Layer Form Validation Engine** (robust server-side checks and interactive client-side feedback), a **Role-Based Access Control (RBAC)** architecture with distinct user tiers, **Anti-CSRF Synchronizer Tokens**, **Session Fixation countermeasures**, and defensive **Security HTTP Headers**.

---

## Key Technologies Used

- **PHP 8.x** (Object-Oriented MySQLi with Prepared Statements)
- **MySQL / MariaDB** (InnoDB, Foreign Key Constraints, Cascading Rules)
- **HTML5 & CSS3** (Custom Design System, Modern Typography, Micro-interactions)
- **JavaScript (ES6+)** (Real-time live validation, password strength calculation, character counters)
- **XAMPP / Apache** (Web server environment)
- **Git & GitHub** (Version control)

---

## Security Enhancements & Vulnerability Mitigations

### 1. Prepared Statements (SQL Injection Mitigation)
- **Objective:** Prevent SQL Injection attacks across all database interactions.
- **Implementation:**
  - 100% of database queries (authentication, user checks, post listing, search filtering, post creation, post editing, post deletion, and role management) strictly utilize MySQLi prepared statements (`$conn->prepare()`).
  - Parameter binding is strictly enforced via `$stmt->bind_param()` with explicit type specifiers (`s` for string, `i` for integer).
  - No user inputs are ever concatenated or interpolated directly into SQL query strings.
  - Safe parameterized search queries use wildcards within parameter binding:
    ```php
    $searchTerm = "%" . $search . "%";
    $stmt = $conn->prepare("SELECT ... FROM posts WHERE title LIKE ? OR content LIKE ?");
    $stmt->bind_param("ss", $searchTerm, $searchTerm);
    $stmt->execute();
    ```

---

### 2. Form Validation Architecture

#### A. Server-Side Validation (Data Integrity & Hardened Security)
Server-side validation ensures malicious payloads cannot bypass frontend controls:
- **User Registration Form (`auth/register.php`):**
  - **Username:** Required, length between 3 and 30 characters, alphanumeric with hyphens and underscores only (`/^[a-zA-Z0-9_-]{3,30}$/`). Duplicate usernames are checked using prepared queries.
  - **Password:** Minimum 8 characters; enforced complexity requiring at least one uppercase letter (`A-Z`), one lowercase letter (`a-z`), and at least one numeric digit (`0-9`).
  - **Password Confirmation:** Verified to ensure exact match with the chosen password.
  - **Role Whitelisting:** Submitted role is validated against allowed values (`admin`, `editor`, `user`).
- **User Login Form (`auth/login.php`):**
  - Validates that non-empty username and password are provided.
  - Protects against user enumeration by returning unified generic error messages (`"Invalid username or password."`).
- **Post Management Forms (`posts/create.php` & `posts/edit.php`):**
  - **Post Title:** Required, length between 3 and 200 characters (`validate_post_title()`).
  - **Post Content:** Required, length between 10 and 50,000 characters (`validate_post_content()`).
- **Admin Role Management Form (`admin/users.php`):**
  - Whitelists permissible target roles.
  - Includes a critical safety constraint: prevents administrators from demoting their own account to prevent lockout.

#### B. Client-Side Validation (Interactive User Experience)
Interactive client-side feedback guides users in real-time before form submission:
- **Real-Time Password Strength Meter:** Visual progress bar that dynamically updates (None &rarr; Weak &rarr; Medium &rarr; Strong) with color coding (`#ef4444`, `#f59e0b`, `#10b981`).
- **Live Requirement Checklist:** Real-time checklist items with animated tick/cross indicators:
  - `[x]` At least 8 characters
  - `[x]` One uppercase letter (A-Z)
  - `[x]` One lowercase letter (a-z)
  - `[x]` One number (0-9)
- **Live Password Match Verification:** Instant visual indication confirming whether confirm-password matches the primary password.
- **Dynamic Character Counters:** Live character counters for Post Title (`X / 200`) and Post Content (`X / 50,000`).
- **Visual State Styling:** Automatic border highlighting (`is-valid` green, `is-invalid` red) and inline feedback labels.
- **Form Submission Interception:** JavaScript halts form dispatch and focuses invalid inputs if rules fail.

---

### 3. Role-Based Access Control (RBAC)

The application implements a 3-tier Role-Based Access Control structure linked via database schema:

| Role | Badge | Permissions & Capabilities |
|---|---|---|
| **Admin** | 🛡️ `Admin` | Full administrative access: create posts, edit **any** post, delete **any** post, view all records, access the **User Management Console** (`admin/users.php`), and promote/demote user roles. |
| **Editor** | ✏️ `Editor` | Editorial access: create posts, edit **any** post (editorial oversight), delete **only their own** posts, view all records. No access to user management. |
| **Student (User)** | 👤 `Student` | Standard access: create posts, edit **only their own** posts, delete **only their own** posts, view all records. No access to other users' records or user management. |

#### RBAC Technical Implementation:
- **Authorship Tracking:** The `posts` table includes a `user_id` foreign key referencing `users(id)`.
- **Dynamic Action Buttons:** Edit and Delete buttons on post cards and detail views are rendered conditionally using helper functions `can_edit_post($post)` and `can_delete_post($post)`.
- **Strict Server-Side Enforcement:** Even if an unauthorized user attempts direct URL navigation to `edit.php?id=X` or `delete.php?id=X`, server-side verification halts execution and returns an **HTTP 403 Forbidden** page with a descriptive Access Denied notice.
- **Admin Management Console (`admin/users.php`):** A dedicated interface for administrators to view account statistics and modify user roles dynamically.

---

### 4. Cross-Site Request Forgery (CSRF) Defense
- **Synchronizer Token Pattern:** A cryptographically secure random token (`bin2hex(random_bytes(32))`) is generated and maintained in `$_SESSION['csrf_token']`.
- **Form Integration:** Every form includes a hidden token field generated via `csrf_field()`.
- **Timing-Safe Comparison:** Incoming POST tokens are validated against session state using PHP's constant-time comparison `hash_equals()`.
- **POST-Only State Modification:** The destructive post deletion workflow has been hardened from an insecure GET request to a secure POST transaction with CSRF protection and a confirmation modal.

---

### 5. Session Security & Fixation Prevention
- **Session Fixation Defense:** `session_regenerate_id(true)` is executed immediately upon successful user login to invalidate the pre-authentication session ID.
- **Hardened Cookie Parameters:** Session cookies are configured with:
  - `httponly: true` (prevents JavaScript access to cookies via XSS).
  - `samesite: Lax` (mitigates cross-site tracking and CSRF risks).

---

### 6. Cross-Site Scripting (XSS) Mitigation & Security Headers
- **Context-Aware Escaping:** All user-supplied data rendered in HTML is sanitized using `htmlspecialchars($data, ENT_QUOTES, 'UTF-8')`.
- **Security HTTP Headers:** Automatically dispatched by `config/security.php`:
  ```http
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  X-XSS-Protection: 1; mode=block
  Referrer-Policy: strict-origin-when-cross-origin
  ```

---

## Pre-configured Test Accounts

For testing and evaluating the Role-Based Access Control (RBAC) tiers:

| Role | Username | Password | Access Highlights |
|---|---|---|---|
| **Admin** | `admin` | `Admin@12345` | Can edit/delete any post, access `admin/users.php`, manage roles |
| **Editor** | `editor` | `Editor@12345` | Can edit all posts, delete own posts |
| **Student** | `student` | `Student@12345` | Can only edit and delete their own posts |

*(Note: The login screen also features quick-fill buttons to autofill these credentials for immediate testing).*

---

## Database Architecture & Setup

### Setup Instructions
1. Start **Apache** and **MySQL** in the XAMPP Control Panel.
2. Open **phpMyAdmin** (`http://localhost/phpmyadmin/`).
3. Import the [`database.sql`](database.sql) file.
4. *(Automatic Migration)* If connecting to an existing Task 2/3 database, `config/database.php` automatically performs non-destructive schema upgrades to add the `role` and `user_id` columns and seed default accounts.

### Schema Details

#### `users` Table
| Column | Type | Attributes | Description |
|---|---|---|---|
| `id` | INT | PRIMARY KEY, AUTO_INCREMENT | Unique user identifier |
| `username` | VARCHAR(100) | UNIQUE, NOT NULL | Account username |
| `password` | VARCHAR(255) | NOT NULL | Bcrypt hashed password |
| `role` | ENUM('admin','editor','user') | NOT NULL, DEFAULT 'user' | RBAC role |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Registration date |

#### `posts` Table
| Column | Type | Attributes | Description |
|---|---|---|---|
| `id` | INT | PRIMARY KEY, AUTO_INCREMENT | Unique post identifier |
| `user_id` | INT | NULL, FOREIGN KEY &rarr; `users(id)` | Author link |
| `title` | VARCHAR(255) | NOT NULL | Post title |
| `content` | TEXT | NOT NULL | Rich post content |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Published timestamp |

---

## Project Structure

```text
ApexPlanet-Task04/
├── config/
│   ├── database.php      # Secure MySQLi connection & auto-schema migration
│   └── security.php      # CSRF tokens, RBAC helpers, security headers & validation routines
├── auth/
│   ├── register.php      # Registration with server validation & live password strength meter
│   ├── login.php         # Secure login with prepared statements & session regeneration
│   └── logout.php        # Secure session destruction & cookie clearing
├── admin/
│   └── users.php         # Admin-only user role management console (RBAC)
├── posts/
│   ├── index.php         # Prepared statement search, post listing & role badges
│   ├── view.php          # Single post view with author metadata & permission-based actions
│   ├── create.php        # Post creation with live character counters & validation
│   ├── edit.php          # Post edit with RBAC checks & prepared statement updates
│   └── delete.php        # Post deletion with CSRF protection & confirmation page
├── database.sql          # Complete schema with RBAC tables and seeded test accounts
├── index.php             # Modern landing page showcasing Task 04 security enhancements
├── README.md             # Comprehensive technical and security documentation
└── style.css             # Unified modern styles, role badges & validation indicators
```

---

## Verification & Testing Guide

1. **SQL Injection Prevention:**
   - Attempt entering SQL injection strings (e.g. `' OR '1'='1`, `'; DROP TABLE posts; --`) in the search box, login, registration, and post forms. All inputs are safely parameterized and treated as literal text.
2. **Form Validation Checks:**
   - **Password Strength:** In `auth/register.php`, type different passwords. Verify the strength meter responds dynamically and checklist items turn green when criteria are met.
   - **Character Counters:** In `posts/create.php`, observe character counters updating in real-time. Try submitting an empty or 2-character title to test validation interception.
3. **Role-Based Access Control (RBAC) Verification:**
   - Log in as `student` and try accessing `admin/users.php` &rarr; blocked with **403 Access Denied**.
   - As `student`, note that edit/delete buttons only appear on your own posts. Attempting to directly open `edit.php?id=1` (authored by admin) will trigger the 403 Access Denied screen.
   - Log in as `editor` &rarr; observe you can edit any post, but cannot access user management.
   - Log in as `admin` &rarr; observe full permissions across all posts and full access to `admin/users.php` to promote/demote user roles.
4. **CSRF Protection Verification:**
   - Verify all forms include `<input type="hidden" name="csrf_token" ...>`. Modifying or omitting the token will result in a 403 Forbidden rejection.
