import os,re,secrets
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from utils import password_check
from markupsafe import escape
from flask_wtf.csrf import CSRFProtect
from flask.sessions import SecureCookieSessionInterface

# Cargando las variables de entorno desde .env
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_ENABLED'] = True
app.session_interface = SecureCookieSessionInterface()

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    Password = db.Column(db.String(128), nullable=False)

class LoginForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[DataRequired(), Length(max=30)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')
    
    
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            user = User.query.filter_by(Username=username).first()

            if user and bcrypt.check_password_hash(user.Password, password):
                # Contraseña válida
                session['user_id'] = user.id
                flash('Inicio de sesión exitoso', 'success')

            else:
                # Contraseña inválida
                flash('Inicio de sesión fallido. Verifica tus credenciales', 'error')

        else:
            flash('Mala conexión', 'error')

    return render_template('login.html', form=form)

# Ruta para agregar un nuevo usuario con contraseña segura
@app.route('/nuevo_usuario', methods=['GET', 'POST'])
def nuevo_usuario():
    form = LoginForm()
    if request.method == 'POST':
        # Obtener datos del formulario
        username = form.username.data
        password = form.password.data

        # Verificar la fortaleza de la contraseña
        if not password_check(password):
            flash('La contraseña no cumple con los requisitos de seguridad', 'error')

        else:
            # Generar el hash de la contraseña
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Crear un nuevo usuario con el hash de la contraseña
            nuevo_usuario = User(Username=username, Password=hashed_password)

            # Agregar el usuario a la base de datos y hacer commit
            db.session.add(nuevo_usuario)
            db.session.commit()
            
            flash('Nuevo usuario añadido con éxito', 'success')


    return render_template('register.html', form=form)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    app.run(port=3000, debug=True)
