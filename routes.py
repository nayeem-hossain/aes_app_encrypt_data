from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import db, User, EncryptedData
from encryption import AESCipher
import os
from datetime import datetime

main_blueprint = Blueprint('main', __name__)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx'}

@main_blueprint.route('/')
def index():
    return redirect(url_for('main.login'))

@main_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('main.login'))
        
        login_user(user, remember=remember)
        session['aes_key'] = user.encryption_key
        return redirect(url_for('main.dashboard'))
    
    return render_template('login.html')

@main_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('main.register'))
        
        cipher = AESCipher()
        new_user = User(
            username=username,
            encryption_key=cipher.get_key()
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('register.html')

@main_blueprint.route('/dashboard')
@login_required
def dashboard():
    data_entries = EncryptedData.query.filter_by(user_id=current_user.id).order_by(EncryptedData.created_at.desc()).all()
    return render_template('dashboard.html', data_entries=data_entries)

@main_blueprint.route('/add_data', methods=['GET', 'POST'])
@login_required
def add_data():
    if request.method == 'POST':
        text_data = request.form.get('text_data', '').strip()
        cipher = AESCipher(AESCipher.key_from_string(current_user.encryption_key))

        if text_data:
            # Encrypt and save text data
            encrypted_data = cipher.encrypt(text_data)
            new_entry = EncryptedData(
                user_id=current_user.id,
                encrypted_data=encrypted_data,
                file_path=None,
                file_name=None
            )
            db.session.add(new_entry)
            db.session.commit()
            flash('Text encrypted and saved successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Please enter some text to encrypt.', 'warning')

    return render_template('add_data.html')

@main_blueprint.route('/view/<int:data_id>', methods=['GET', 'POST'])
@login_required
def view_data(data_id):
    data_entry = EncryptedData.query.filter_by(id=data_id, user_id=current_user.id).first()
    
    if not data_entry:
        flash('Data not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    decrypted_data = None
    if request.method == 'POST' and data_entry.encrypted_data:
        cipher = AESCipher(AESCipher.key_from_string(current_user.encryption_key))
        try:
            decrypted_data = cipher.decrypt(data_entry.encrypted_data)
        except Exception as e:
            flash('Decryption failed. The data may be corrupted.', 'danger')
    
    return render_template('view_data.html', 
                         data_entry=data_entry, 
                         decrypted_data=decrypted_data)

@main_blueprint.route('/download/<int:data_id>')
@login_required
def download_file(data_id):
    data_entry = EncryptedData.query.filter_by(id=data_id, user_id=current_user.id).first()
    
    if not data_entry or not data_entry.file_path:
        flash('File not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    cipher = AESCipher(AESCipher.key_from_string(current_user.encryption_key))
    temp_filename = f"decrypted_{data_entry.file_name}"
    temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
    encrypted_path = os.path.join(current_app.config['UPLOAD_FOLDER'], data_entry.file_path)
    
    cipher.decrypt_file(encrypted_path, temp_path)
    
    response = send_from_directory(
        current_app.config['UPLOAD_FOLDER'],
        temp_filename,
        as_attachment=True,
        download_name=data_entry.file_name
    )
    
    @response.call_on_close
    def remove_file():
        try:
            os.remove(temp_path)
        except:
            pass
    
    return response

@main_blueprint.route('/delete/<int:data_id>', methods=['POST'])
@login_required
def delete(data_id):
    data_entry = EncryptedData.query.filter_by(id=data_id, user_id=current_user.id).first()
    
    if not data_entry:
        flash('Data not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if data_entry.file_path:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], data_entry.file_path)
        try:
            os.remove(file_path)
        except:
            pass
    
    db.session.delete(data_entry)
    db.session.commit()
    
    flash('Data deleted successfully', 'success')
    return redirect(url_for('main.dashboard'))

@main_blueprint.route('/logout')
@login_required
def logout():
    session.pop('aes_key', None)
    logout_user()
    return redirect(url_for('main.login'))