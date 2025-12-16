from flask import Blueprint,render_template,redirect,request,flash,url_for
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,login_required
from .models import User
from .import db
auth = Blueprint('auth',__name__)

next_page = '/'


@auth.route('/login_home',methods=['POST','GET'])
def login_home():
    if request.method == 'POST':
        global next_page
        email = request.form.get('email')   
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('/login_home'))
        login_user(user, remember=remember)
        
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        else:
            return redirect('/')
    return render_template('main-login.html')
    

@auth.route('/signUp',methods=['GET','POST'])
def signUp():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            flash('Email address already exists.')
            return redirect('/signUp')
        
        new_user = User(email=email,username = username,password=generate_password_hash(password, method="pbkdf2:sha256"))
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login_home')
    return render_template('signup.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login_home')