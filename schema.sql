

-- Select the database
USE mess_app;

-- USERS TABLE
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL UNIQUE,
    phone VARCHAR(15),
    course VARCHAR(100),
    password VARCHAR(255) NOT NULL,
    user_type ENUM('student','admin') DEFAULT 'student',
    approved TINYINT(1) DEFAULT 0,
    qr_path VARCHAR(255),
    mess_count INT DEFAULT 0
);

-- TEMPORARY REGISTRATION (awaiting approval)
CREATE TABLE new_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL UNIQUE,
    phone VARCHAR(15),
    course VARCHAR(100),
    password VARCHAR(255) NOT NULL,
    user_type ENUM('student','admin') DEFAULT 'student',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- MESS CUT REQUESTS
CREATE TABLE mess_cut (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    course VARCHAR(100),
    date_applied TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- LATE MESS REQUESTS
CREATE TABLE late_mess (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    date_requested DATE NOT NULL,
    reason TEXT,
    approved TINYINT(1) DEFAULT 0,
    status ENUM('pending','approved','reset') DEFAULT 'pending',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- MEAL ATTENDANCE
CREATE TABLE meal_attendance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    meal_type ENUM('breakfast','lunch','dinner') NOT NULL,
    attendance_date DATE NOT NULL,
    UNIQUE KEY unique_attendance (user_id, meal_type, attendance_date),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- USER MEAL COUNTS
CREATE TABLE user_meal_counts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    meal_type ENUM('breakfast','lunch','dinner') NOT NULL,
    scan_date DATE NOT NULL,
    scan_count INT DEFAULT 0,
    UNIQUE KEY unique_user_meal (user_id, meal_type, scan_date),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);