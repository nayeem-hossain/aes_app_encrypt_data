from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from encryption import encrypt_key, decrypt_key

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    _encryption_key = db.Column('encryption_key', db.Text, nullable=False)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    @property
    def encryption_key(self):
        return decrypt_key(self._encryption_key)
    
    @encryption_key.setter
    def encryption_key(self, value):
        self._encryption_key = encrypt_key(value)
    
    def __repr__(self):
        return f'<User {self.username}>'

class EncryptedData(db.Model):
    __tablename__ = 'data'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_data = db.Column(db.Text, nullable=True)  # For text data
    file_path = db.Column(db.String(255), nullable=True)  # For file paths
    file_name = db.Column(db.String(255), nullable=True)  # Original filename
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    user = db.relationship('User', backref='data')
    
    def __repr__(self):
        return f'<EncryptedData {self.id}>'