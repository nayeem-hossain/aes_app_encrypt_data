CREATE DATABASE IF NOT EXISTS aes_flask_db;

USE aes_flask_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(200) NOT NULL,
    encryption_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    encrypted_data TEXT NULL,
    file_path VARCHAR(255),
    file_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);