rom flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventify.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    major = db.Column(db.String(100))
    year = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    image_url = db.Column(db.String(300))
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    capacity = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    host = db.relationship('User', backref='events')

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='registrations')
    event = db.relationship('Event', backref='registrations')

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    events = Event.query.order_by(Event.start_time.asc()).all()
    return render_template('index.html', events=events)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['is_admin'] = user.is_admin
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        major = request.form.get('major')
        year = request.form.get('year')
        is_admin = True if request.form.get('is_admin') else False
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        
        # Create new user
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            major=major,
            year=year,
            is_admin=is_admin
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/events')
def all_events():
    events = Event.query.order_by(Event.start_time.asc()).all()
    return render_template('events.html', events=events)

@app.route('/events/<int:event_id>')
def event_details(event_id):
    event = Event.query.get_or_404(event_id)
    is_registered = False
    
    if 'user_id' in session:
        is_registered = Registration.query.filter_by(
            user_id=session['user_id'],
            event_id=event_id
        ).first() is not None
    
    return render_template('event_details.html', event=event, is_registered=is_registered)

@app.route('/events/create', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session:
        flash('Please login to create events', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        start_time = datetime.strptime(request.form.get('start_time'), '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(request.form.get('end_time'), '%Y-%m-%dT%H:%M')
        location = request.form.get('location')
        image_url = request.form.get('image_url')
        capacity = request.form.get('capacity')
        
        new_event = Event(
            title=title,
            description=description,
            category=category,
            start_time=start_time,
            end_time=end_time,
            location=location,
            image_url=image_url,
            host_id=session['user_id'],
            capacity=int(capacity) if capacity else None
        )
        
        db.session.add(new_event)
        db.session.commit()
        
        flash('Event created successfully!', 'success')
        return redirect(url_for('event_details', event_id=new_event.id))
    
    return render_template('create_event.html')

@app.route('/events/<int:event_id>/register', methods=['POST'])
def register_event(event_id):
    if 'user_id' not in session:
        flash('Please login to register for events', 'error')
        return redirect(url_for('login'))
    
    event = Event.query.get_or_404(event_id)
    
    # Check if already registered
    existing_registration = Registration.query.filter_by(
        user_id=session['user_id'],
        event_id=event_id
    ).first()
    
    if existing_registration:
        flash('You are already registered for this event', 'info')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Check capacity
    if event.capacity and len(event.registrations) >= event.capacity:
        flash('This event has reached its capacity', 'error')
        return redirect(url_for('event_details', event_id=event_id))
    
    # Register user
    new_registration = Registration(
        user_id=session['user_id'],
        event_id=event_id
    )
    
    db.session.add(new_registration)
    db.session.commit()
    
    flash('Successfully registered for the event!', 'success')
    return redirect(url_for('event_details', event_id=event_id))

@app.route('/events/<int:event_id>/cancel', methods=['POST'])
def cancel_registration(event_id):
    if 'user_id' not in session:
        flash('Please login to manage registrations', 'error')
        return redirect(url_for('login'))
    
    registration = Registration.query.filter_by(
        user_id=session['user_id'],
        event_id=event_id
    ).first()
    
    if registration:
        db.session.delete(registration)
        db.session.commit()
        flash('Registration cancelled successfully', 'success')
    else:
        flash('You are not registered for this event', 'error')
    
    return redirect(url_for('event_details', event_id=event_id))

@app.route('/my-events')
def my_events():
    if 'user_id' not in session:
        flash('Please login to view your events', 'error')
        return redirect(url_for('login'))
    
    registrations = Registration.query.filter_by(user_id=session['user_id']).all()
    return render_template('my_events.html', registrations=registrations)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Admin access required', 'error')
        return redirect(url_for('home'))
    
    total_events = Event.query.count()
    total_users = User.query.count()
    upcoming_events = Event.query.filter(Event.start_time > datetime.utcnow()).count()
    active_registrations = Registration.query.count()
    
    events = Event.query.all()
    users = User.query.all()
    
    return render_template('admin_dashboard.html',
                         total_events=total_events,
                         total_users=total_users,
                         upcoming_events=upcoming_events,
                         active_registrations=active_registrations,
                         events=events,
                         users=users)
from flask_debugtoolbar import DebugToolbarExtension

# Configure the toolbar
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False  # Set to True if you want to debug redirects
toolbar = DebugToolbarExtension(app)

if __name__ == '__main__':
    app.run(debug=True)
