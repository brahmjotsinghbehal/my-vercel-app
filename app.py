from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'fintrack.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    date_of_birth = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

def calculate_totals(user_id):
    income = sum(t.amount for t in Transaction.query.filter_by(user_id=user_id, type='income').all())
    expenses = sum(t.amount for t in Transaction.query.filter_by(user_id=user_id, type='expense').all())
    debt = sum(t.amount for t in Transaction.query.filter_by(user_id=user_id, type='debt').all())
    investment = sum(t.amount for t in Transaction.query.filter_by(user_id=user_id, type='investment').all())
    return income, expenses, debt, investment

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        dob = datetime.strptime(request.form['dob'], '%Y-%m-%d')
        
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            date_of_birth=dob
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        user = User.query.filter(
            (User.email == identifier) | (User.username == identifier)
        ).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    income, expenses, debt, investment = calculate_totals(user_id)
    
    return render_template('home.html', 
                         income=income, 
                         expenses=expenses, 
                         debt=debt, 
                         investment=investment)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    income, expenses, debt, investment = calculate_totals(user_id)
    
    return render_template('dashboard.html', 
                         income=income, 
                         expenses=expenses, 
                         debt=debt, 
                         investment=investment)

@app.route('/transaction/<transaction_type>', methods=['GET', 'POST'])
def transaction(transaction_type):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        description = request.form['description']
        
        transaction = Transaction(
            user_id=session['user_id'],
            type=transaction_type,
            amount=amount,
            description=description
        )
        db.session.add(transaction)
        db.session.commit()
        
        return redirect(url_for('transaction', transaction_type=transaction_type))
    
    transactions = Transaction.query.filter_by(
        user_id=session['user_id'],
        type=transaction_type
    ).order_by(Transaction.date.desc()).all()
    
    return render_template(f'{transaction_type}.html', transactions=transactions)

@app.route('/delete_transaction/<int:id>', methods=['POST'])
def delete_transaction(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    transaction = Transaction.query.get_or_404(id)
    if transaction.user_id == session['user_id']:
        transaction_type = transaction.type
        db.session.delete(transaction)
        db.session.commit()
        return redirect(url_for('transaction', transaction_type=transaction_type))
    
    return redirect(url_for('dashboard'))

@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('account.html', user=user)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        dob = datetime.strptime(request.form['dob'], '%Y-%m-%d').date()
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = User.query.filter_by(username=username, date_of_birth=dob).first()

        if not user:
            flash('Invalid username or date of birth')
            return redirect(url_for('reset_password'))

        if new_password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('reset_password'))

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password reset successfully')
        return redirect(url_for('login'))

    return render_template('reset.html')

@app.route('/update_details', methods=['GET', 'POST'])
def update_details():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']

        if not check_password_hash(user.password_hash, current_password):
            flash('Current password is incorrect')
            return redirect(url_for('update_details'))

        user.username = request.form['username']
        user.email = request.form['email']
        user.date_of_birth = datetime.strptime(request.form['dob'], '%Y-%m-%d').date()

        new_password = request.form.get('new_password')
        if new_password:
            user.password_hash = generate_password_hash(new_password)

        db.session.commit()
        flash('Details updated successfully')
        return redirect(url_for('account'))

    return render_template('update.html', user=user)

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = User.query.get(session['user_id'])
        username = request.form['username']
        password = request.form['password']

        if username != user.username:
            flash('Invalid username')
            return redirect(url_for('delete_account'))

        if not check_password_hash(user.password_hash, password):
            flash('Invalid password')
            return redirect(url_for('delete_account'))

        # Delete all user's transactions
        Transaction.query.filter_by(user_id=user.id).delete()
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        session.clear()
        flash('Account deleted successfully')
        return redirect(url_for('index'))

    return render_template('delete.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
