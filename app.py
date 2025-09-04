from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime, func, Text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, scoped_session
from werkzeug.security import generate_password_hash, check_password_hash
import os, datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'sqlite:///voting.db')

# --- Database setup ---
engine = create_engine(app.config['DATABASE_URL'], echo=False, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()

class Settings(Base):
    __tablename__ = 'settings'
    id = Column(Integer, primary_key=True)
    is_open = Column(Boolean, default=True)

class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    has_voted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    votes = relationship('Vote', back_populates='user')

    def get_id(self):
        return str(self.id)

class Candidate(Base):
    __tablename__ = 'candidates'
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False, unique=True)
    manifesto = Column(Text, default='')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    votes = relationship('Vote', back_populates='candidate', cascade='all, delete-orphan')

class Vote(Base):
    __tablename__ = 'votes'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, unique=True)  # enforce one vote per user
    candidate_id = Column(Integer, ForeignKey('candidates.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship('User', back_populates='votes')
    candidate = relationship('Candidate', back_populates='votes')

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(120), nullable=False)
    details = Column(Text, default='')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship('User')

Base.metadata.create_all(bind=engine)

# Ensure a single Settings row exists
db = SessionLocal()
if not db.query(Settings).first():
    s = Settings(is_open=True)
    db.add(s)
    db.commit()

# Default admin
if not db.query(User).filter_by(email='admin@site.com').first():
    admin = User(
        username='admin',
        email='admin@site.com',
        password_hash=generate_password_hash('Admin123!'),
        is_admin=True
    )
    db.add(admin)
    db.add(AuditLog(user=admin, action='bootstrap', details='Default admin created'))
    db.commit()
db.close()

# --- Auth setup ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    session = SessionLocal()
    return session.get(User, int(user_id))

# --- Forms ---
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current password', validators=[DataRequired()])
    new_password = PasswordField('New password', validators=[DataRequired(), Length(min=6)])
    confirm_new = PasswordField('Confirm new password', validators=[DataRequired(), EqualTo('new_password')])

class CandidateForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=120)])
    manifesto = TextAreaField('Manifesto')

# --- Helpers ---
def get_settings(session):
    return session.query(Settings).first()

def log_action(session, user, action, details=''):
    session.add(AuditLog(user=user, action=action, details=details))

@app.context_processor
def inject_now():
    return {'now': datetime.datetime.utcnow}

# --- Routes ---
@app.route('/')
def index():
    session = SessionLocal()
    users = session.query(User).count()
    votes = session.query(Vote).count()
    settings = get_settings(session)
    stats = {'users': users, 'votes': votes}
    session.close()
    return render_template('index.html', stats=stats, settings=settings)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        session = SessionLocal()
        if session.query(User).filter((User.email==form.email.data)|(User.username==form.username.data)).first():
            flash('Email or username already exists', 'error')
            session.close()
            return redirect(url_for('register'))
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            password_hash=generate_password_hash(form.password.data)
        )
        session.add(user)
        log_action(session, user, 'register', f'user={user.email}')
        session.commit()
        session.close()
        flash('Account created. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = SessionLocal()
        user = session.query(User).filter_by(email=form.email.data.strip().lower()).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            log_action(session, user, 'login', '')
            session.commit()
            session.close()
            flash('Welcome back!', 'success')
            return redirect(url_for('index'))
        session.close()
        flash('Invalid credentials', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session = SessionLocal()
    log_action(session, current_user, 'logout', '')
    session.commit()
    session.close()
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    form = ChangePasswordForm()
    return render_template('dashboard.html', form=form)

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        session = SessionLocal()
        user = session.get(User, current_user.id)
        if not check_password_hash(user.password_hash, form.current_password.data):
            session.close()
            flash('Current password is incorrect', 'error')
            return redirect(url_for('dashboard'))
        user.password_hash = generate_password_hash(form.new_password.data)
        log_action(session, user, 'change_password')
        session.commit()
        session.close()
        flash('Password updated', 'success')
        return redirect(url_for('dashboard'))
    flash('Please correct the errors in the form', 'error')
    return redirect(url_for('dashboard'))

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    session = SessionLocal()
    settings = get_settings(session)
    candidates = session.query(Candidate).order_by(Candidate.created_at.asc()).all()
    if request.method == 'POST':
        if not settings.is_open:
            session.close()
            flash('Election is closed.', 'error')
            return redirect(url_for('vote'))
        selected = request.form.get('candidate_id', type=int)
        candidate = session.get(Candidate, selected) if selected else None
        if not candidate:
            session.close()
            flash('Invalid candidate', 'error')
            return redirect(url_for('vote'))
        existing = session.query(Vote).filter_by(user_id=current_user.id).first()
        if existing:
            # allow re-vote (update) while election is open
            existing.candidate_id = candidate.id
            action = 'revote'
        else:
            v = Vote(user_id=current_user.id, candidate_id=candidate.id)
            session.add(v)
            user = session.get(User, current_user.id)
            user.has_voted = True
            action = 'vote'
        log_action(session, current_user, action, f'candidate={candidate.name}')
        session.commit()
        session.close()
        flash('Your vote has been recorded.', 'success')
        return redirect(url_for('results'))
    session.close()
    class DummyForm(FlaskForm): pass
    form = DummyForm()
    return render_template('vote.html', candidates=candidates, settings=settings, form=form)

@app.route('/results')
def results():
    session = SessionLocal()
    users = session.query(User).count()
    votes = session.query(Vote).count()
    stats = {'users': users, 'votes': votes}
    session.close()
    return render_template('results.html', stats=stats)

@app.route('/api/results')
def api_results():
    session = SessionLocal()
    q = session.query(Candidate.name, func.count(Vote.id)).outerjoin(Vote).group_by(Candidate.id).all()
    labels = [name for name, _ in q]
    counts = [cnt for _, cnt in q]
    total_votes = sum(counts)
    session.close()
    return jsonify({'labels': labels, 'counts': counts, 'total_votes': total_votes})

# --- Admin ---
def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin only.', 'error')
            return redirect(url_for('index'))
        return fn(*args, **kwargs)
    return wrapper

@app.route('/admin')
@login_required
@admin_required
def admin():
    session = SessionLocal()
    candidates = session.query(Candidate).order_by(Candidate.created_at.asc()).all()
    settings = get_settings(session)
    session.close()
    form = FlaskForm()
    cand_form = CandidateForm()
    return render_template('admin.html', candidates=candidates, settings=settings, form=form, cand_form=cand_form)

@app.route('/admin/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_election():
    form = FlaskForm()
    if form.validate_on_submit():
        session = SessionLocal()
        settings = get_settings(session)
        settings.is_open = not settings.is_open
        log_action(session, current_user, 'toggle_election', f'is_open={settings.is_open}')
        session.commit()
        session.close()
        flash('Election state updated.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/candidate', methods=['POST'])
@login_required
@admin_required
def add_candidate():
    cand_form = CandidateForm()
    if cand_form.validate_on_submit():
        session = SessionLocal()
        c = Candidate(name=cand_form.name.data.strip(), manifesto=cand_form.manifesto.data.strip())
        session.add(c)
        log_action(session, current_user, 'add_candidate', f'name={c.name}')
        session.commit()
        session.close()
        flash('Candidate added.', 'success')
    else:
        flash('Please fill candidate details correctly.', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/candidate/<int:cid>/delete', methods=['POST'])
@login_required
@admin_required
def delete_candidate(cid):
    form = FlaskForm()
    if form.validate_on_submit():
        session = SessionLocal()
        c = session.get(Candidate, cid)
        if c:
            log_action(session, current_user, 'delete_candidate', f'name={c.name}')
            session.delete(c)
            session.commit()
            flash('Candidate deleted.', 'info')
        session.close()
    return redirect(url_for('admin'))

@app.route('/audit')
@login_required
@admin_required
def audit():
    session = SessionLocal()
    logs = session.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(500).all()
    session.close()
    return render_template('audit.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
