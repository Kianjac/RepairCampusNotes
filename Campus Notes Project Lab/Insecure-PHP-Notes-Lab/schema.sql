CREATE DATABASE IF NOT EXISTS notes_lab CHARACTER SET utf8mb4;
USE notes_lab;

CREATE TABLE users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,   -- bcrypt via password_hash(); never MD5
  role VARCHAR(20) NOT NULL DEFAULT 'student'
);

CREATE TABLE notes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  title VARCHAR(120) NOT NULL,
  body TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Synthetic accounts for local use only. Passwords are stored as bcrypt hashes
-- (the test passwords are listed in README.md). To reset everything, drop the
-- notes_lab database and import this file again.
INSERT INTO users (id, email, password_hash, role) VALUES
  (1, 'alex@example.test', '$2y$10$vvh.8fAsd9CdxDxE.7spK.D.wBdA44efDf1X17VqoIFMER4Zo7a3y', 'student'),
  (2, 'sam@example.test', '$2y$10$350VLvuKpjQENBHcnwCMMeN8JHlKDWDF3cN9AAV5VRlhSgZj5Acga', 'student');

INSERT INTO notes (user_id, title, body) VALUES
  (1, 'Alex: course reminder', 'Review the security reading before class.'),
  (1, 'Alex: project idea', 'Build a small student directory.'),
  (2, 'Sam: study plan', 'Compare authentication and authorization.'),
  (2, 'Sam: meeting', 'Prepare questions for the next group discussion.');
