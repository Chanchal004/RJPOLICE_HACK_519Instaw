from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    files = db.relationship('File', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']

        user = User.query.filter_by(user_id=user_id).first()

        if user and check_password_hash(user.password, password):
            login_user(user)  # Use Flask-Login's login_user function
            flash('Login successful', 'success')
            return redirect(url_for('home'))

        else:
            flash('Login failed. Check your user ID and password.', 'danger')

    return render_template('login.html')

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        chosen_user_id = request.form['chosen_user_id']

        if not chosen_user_id:
            user_id = f"{first_name}-{User.query.count() + 1}"
            flash(f'Auto-generated User ID: {user_id}', 'info')
        else:
            user_id = chosen_user_id

        hashed_password = generate_password_hash(password)

        new_user = User(first_name=first_name, last_name=last_name, user_id=user_id, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('create_account.html')

@app.route('/check_user_id', methods=['POST'])
def check_user_id():
    user_id = request.form['user_id']
    is_unique = not User.query.filter_by(user_id=user_id).first()
    return jsonify({'is_unique': is_unique})

@app.route('/generate_user_id', methods=['GET'])
def generate_user_id():
    generated_user_id = f"auto-{User.query.count() + 1}"
    return jsonify({'generated_user_id': generated_user_id})

@app.route('/home', methods=['GET', 'POST'])
@login_required  # This decorator ensures that the user is logged in to access the Home page
def home():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            new_file = File(filename=filename, user_id=current_user.id)  # Replace '1' with the current user's ID
            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded successfully', 'success')

    # Fetch files for the current user
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('home.html', user_files=user_files, current_user=current_user)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
@login_required  # Ensure the user is logged in to access this route
def logout():
    logout_user()
    flash('You have been signed out', 'success')
    return redirect(url_for('login'))


def create_upload_folder():
    folder_path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'])
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

if __name__ == '__main__':
    with app.app_context():
        create_upload_folder()
        db.create_all()
    app.run(debug=True)
