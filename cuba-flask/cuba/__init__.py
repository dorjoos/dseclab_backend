from flask import Flask,redirect,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,current_user
from flask_admin import Admin,AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_assets import Environment
from sassutils.wsgi import SassMiddleware
from flask_migrate import Migrate


app = Flask(__name__)


assets = Environment(app)

app.config['SECRET_KEY'] = '340ab03a37eaa432fc52d8a2ae8cf26c'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cuba.db'


db = SQLAlchemy(app)

with app.app_context():
    db.create_all()


migrate = Migrate(app, db)

app.wsgi_app = SassMiddleware(app.wsgi_app, {
    'cuba': ('static/assets/scss', 'static/assets/css', '/static/assets/css')
})


class UserModelView(ModelView):
    def is_accessible(self):
        isAdmin = False
        if current_user.is_authenticated:
            isAdmin = current_user.isAdmin
        return isAdmin
    
    def inaccessible_callback(self, name,**kwargs):
        return redirect('/login_home')

class cubaAdminIndexView(AdminIndexView):
    def is_accessible(self):
        isAdmin = True
        if current_user.is_authenticated:
            isAdmin = current_user.isAdmin
        return isAdmin
    
    def inaccessible_callback(self, name,**kwargs):
        return redirect('/login_home')

admin = Admin(app,index_view=cubaAdminIndexView())




login_manager = LoginManager()
login_manager.login_view = 'auth.login_home'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from .routes import main as main_blueprint
app.register_blueprint(main_blueprint)

from .auth import auth as auth_blueprint
app.register_blueprint(auth_blueprint)

from .models import User,Todo
admin.add_view(ModelView(Todo,db.session))
admin.add_view(ModelView(User,db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))