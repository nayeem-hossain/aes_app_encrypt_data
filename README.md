# AES Encryption Flask Application

A secure web application for encrypting and decrypting text data using AES-256 encryption.  
Users can register, log in, and safely store their encrypted text data in a MySQL database.



# Features

- User registration and login (Flask-Login)
- AES-256 encryption and decryption for text data
- Secure password storage with hashing (Werkzeug)
- Database storage of encrypted data (Flask-SQLAlchemy, MySQL)
- Responsive Bootstrap 5 UI



# Setup Instructions

# 1. Install XAMPP and Start MySQL

- Download and install [XAMPP](https://www.apachefriends.org/)
- Start **Apache** and **MySQL** services

# 2. Create the Database

- Open phpMyAdmin: [http://localhost/phpmyadmin](http://localhost/phpmyadmin)
- Create a new database (e.g., `aes_app`)
- Run the SQL script from `init_db.sql` to create the necessary tables

# 3. Set Up Python Environment

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

# 4. Configure Database Connection

- Edit `config.py` or your app's configuration to set your MySQL URI, for example:
  ```
  SQLALCHEMY_DATABASE_URI = "mysql://username:password@localhost/aes_app"
  ```

# 5. Initialize the Database

```bash
# Run the Flask app once to create tables, or use Flask-Migrate if set up
python app.py
```



# Usage

1. Register a new user account.
2. Log in with your credentials.
3. Add text data to be encrypted and stored securely.
4. View and decrypt your stored data from the dashboard.



# Project Structure

```
aes_app_v2/
│
├── app.py
├── database.py
├── encryption.py
├── routes.py
├── requirements.txt
├── init_db.sql
├── /templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── view_data.html
│   └── add_data.html
└── /static
    └── css/
        └── style.css
```



# Dependencies

- Flask
- Flask-Login
- Flask-SQLAlchemy
- cryptography
- pycryptodome
- mysqlclient (or PyMySQL)
- Bootstrap 5

Install all dependencies with:
```bash
pip install -r requirements.txt
```



# Security Notes

- AES keys are unique per user and stored encrypted.
- Passwords are hashed using Werkzeug.
- All sensitive operations require authentication.



# License

This project is for educational purposes.