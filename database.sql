-- ============================================================================
-- ApexPlanet Task 04 - Enhanced Security & RBAC Database Schema
-- Features:
--  - Prepared Statements architecture support
--  - Role-Based Access Control (roles: 'admin', 'editor', 'user')
--  - Post authorship linkage (foreign key user_id)
--  - Pre-seeded test accounts for instant role evaluation
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `blog` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `blog`;

-- 1. Users Table (with role column)
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(100) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `role` ENUM('admin', 'editor', 'user') NOT NULL DEFAULT 'user',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Posts Table (with user_id authorship link)
CREATE TABLE IF NOT EXISTS `posts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NULL,
    `title` VARCHAR(255) NOT NULL,
    `content` TEXT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_posts_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Pre-seeded Demo Accounts for Testing Roles
-- Admin Account:   admin   / Admin@12345   (Role: admin)
-- Editor Account:  editor  / Editor@12345  (Role: editor)
-- Student Account: student / Student@12345 (Role: user)

INSERT INTO `users` (`id`, `username`, `password`, `role`) VALUES
(1, 'admin', '$2y$10$xBPYUUQtzN4kk43AEYOobe9AkRwSM1j8TTUfWgpvbG3p.zkAHjKMa', 'admin'),
(2, 'editor', '$2y$10$OL0rArW1buof0Yp2yba8o.zRUpZVe0ax8WDu9bx6HlHSLVE/QJ3jK', 'editor'),
(3, 'student', '$2y$10$5MDMSXNJb/eTpW./YrykMOFaTjU1GZblrX5OoQNNIMokrgKG/gI9.', 'user')
ON DUPLICATE KEY UPDATE `role` = VALUES(`role`);

-- 4. Sample Demonstration Posts with Authorship
INSERT INTO `posts` (`id`, `user_id`, `title`, `content`, `created_at`) VALUES
(1, 1, 'Security Architecture & Best Practices Guide', 'Welcome to the updated [b]Student Management System (Task 04)[/b]! This version implements enterprise-grade security enhancements:\n\n1. [b]Prepared Statements[/b]: All queries use MySQLi parameter binding to prevent [u]SQL Injection[/u].\n2. [b]CSRF Defense[/b]: Synchronizer token pattern applied to all forms.\n3. [b]Role-Based Access Control (RBAC)[/b]: Distinct permissions for Admin, Editor, and Student users.\n4. [b]Form Validation[/b]: Rigorous server-side sanitation and real-time client-side interactive validation.', NOW()),
(2, 2, 'Editorial Policy & Community Posting Guidelines', 'As an [b]Editor[/b], you have privileges to review and edit posts across the platform to ensure academic quality.\n\nPlease remember:\n* Keep updates respectful and clear.\n* Use [i]italic[/i] for citations and [u]underline[/u] for key terms.\n* Administrators oversee global user management and role assignment.', NOW()),
(3, 3, 'My First Academic Study Notes & Project Plan', 'Hello everyone! This is a student post demonstrating [b]standard user privileges[/b]. As a standard student account:\n- I can create new posts\n- I can edit and delete [u]my own[/u] posts\n- I cannot alter or delete posts authored by other users.', NOW())
ON DUPLICATE KEY UPDATE `title` = VALUES(`title`);
