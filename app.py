from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import logging
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secretkey123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.DEBUG)

# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_owner(self):
        return self.role == 'owner'

    def is_admin(self):
        return self.role in ('admin', 'owner')
    
    def is_user(self):
        return self.role in ('user', 'admin', 'owner')
    
    def can_create_post(self):
        return self.role in ('admin', 'owner')
    
    def can_upload_video(self):
        return self.role == 'owner'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(500))
    video_url = db.Column(db.String(500))
    post_type = db.Column(db.String(20), default='text')
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='posts')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Доступ запрещён', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# Маршруты
@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.asc()).all()
    return render_template('post_detail.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    if current_user.role == 'reader':
        flash('У вас нет прав на комментарии', 'danger')
        return redirect(url_for('post_detail', post_id=post_id))
    content = request.form.get('content')
    if content:
        comment = Comment(content=content, author_id=current_user.id, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
        flash('Комментарий добавлен', 'success')
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if not current_user.can_create_post():
        flash('Недостаточно прав', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        post_type = request.form.get('post_type')
        video_url = request.form.get('video_url')
        if post_type == 'video' and not current_user.can_upload_video():
            flash('Только владелец может публиковать видео', 'danger')
            return redirect(url_for('index'))
        post = Post(
            title=request.form['title'],
            content=request.form.get('content', ''),
            image_url=request.form.get('image_url'),
            video_url=video_url,
            post_type=post_type,
            author_id=current_user.id
        )
        db.session.add(post)
        db.session.commit()
        flash('Пост опубликован', 'success')
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            flash(f'С возвращением, {user.username}', 'success')
            return redirect(url_for('index'))
        flash('Неверный логин или пароль', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if User.query.filter_by(username=username).first():
            flash('Логин занят', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=request.form['email'])
        user.set_password(request.form['password'])
        if User.query.count() == 0:
            user.role = 'owner'
            flash('Вы стали владельцем сайта', 'success')
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin():
        return 'Доступ запрещён', 403
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/set_role/<int:user_id>', methods=['POST'])
@login_required
def set_role(user_id):
    if not current_user.is_admin():
        return 'Доступ запрещён', 403
    target = User.query.get_or_404(user_id)
    if target.is_owner() or target.id == current_user.id:
        return 'Нельзя изменить эту роль', 403
    target.role = request.form.get('role')
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error(f"Ошибка: {str(e)}")
    return f"Ошибка: {str(e)}", 500

# Создание таблиц при запуске (для gunicorn)
with app.app_context():
    db.create_all()

# Принудительное создание таблиц при первом запросе
@app.before_request
def ensure_tables():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True)