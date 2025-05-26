from flask import Flask
from flask_login import LoginManager
from database import db, User
from routes import main_blueprint
from cryptography.fernet import Fernet
import os

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'super-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/aes_flask_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = 'encrypted_uploads'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
    
    # Initialize master key
    if not os.path.exists('master.key'):
        with open('master.key', 'wb') as f:
            f.write(Fernet.generate_key())
    with open('master.key', 'rb') as f:
        app.config['MASTER_KEY'] = f.read()
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize extensions
    db.init_app(app)
    
    # Login manager setup
    login_manager = LoginManager()
    login_manager.login_view = 'main.login'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    app.register_blueprint(main_blueprint)
    
    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)