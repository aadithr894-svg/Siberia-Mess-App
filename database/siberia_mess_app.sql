-- 1️⃣ Create Database
CREATE DATABASE IF NOT EXISTS siberia_mess_app;
USE siberia_mess_app;

-- 2️⃣ Create Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    course VARCHAR(50),
    phone VARCHAR(20),
    is_admin BOOLEAN DEFAULT FALSE
);

-- 3️⃣ Create Mess Cut Table
CREATE TABLE IF NOT EXISTS mess_cut (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4️⃣ Create Mess Attendance Table
CREATE TABLE IF NOT EXISTS mess_attendance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    meal_type ENUM('breakfast','lunch','dinner') NOT NULL,
    date DATE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5️⃣ Create Menu Table
CREATE TABLE IF NOT EXISTS menu (
    id INT AUTO_INCREMENT PRIMARY KEY,
    meal_type ENUM('breakfast','lunch','dinner') NOT NULL,
    items TEXT NOT NULL,
    date DATE NOT NULL
);

-- 6️⃣ Insert Initial Admin User
-- Replace 'adminpassword' with a hashed password using werkzeug in Python if possible
INSERT INTO users (name, email, password, course, phone, is_admin)
VALUES ('Admin', 'admin@siberia.com', '$pbkdf2-sha256$29000$e2s..REPLACE_WITH_HASH..', 'NA', '0000000000', TRUE);

