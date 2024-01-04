import os,re,secrets
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from utils import password_check
from markupsafe import escape
from flask.sessions import SecureCookieSessionInterface

# Cargando las variables de entorno desde .env
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.session_interface = SecureCookieSessionInterface()

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    Password = db.Column(db.String(128), nullable=False)
    
    
@app.route('/', methods=['GET', 'POST'])
def login():
    message = ''
    escaped_message= ''
    if request.method == 'POST':
        
        if 'username' in request.form and 'password' in request.form:
            # Solicitud de inicio de sesión
            username = request.form.get('username')[:30]
            password = request.form.get('password')


            user = User.query.filter_by(Username=username).first()

            if user and bcrypt.check_password_hash(user.Password, password):
                # Contraseña válida
                session['user_id'] = user.id
                message = 'Inicio de sesión exitoso'
                escaped_message = escape(message)

            else:
                # Contraseña inválida
                message = 'Inicio de sesión fallido. Verifica tus credenciales'
                escaped_message = escape(message)

        else:
            message = 'Mala conexion'
            escaped_message = escape(message)

    return render_template('index.html', message=escaped_message)

# Ruta para agregar un nuevo usuario con contraseña segura
@app.route('/nuevo_usuario', methods=['GET', 'POST'])
def nuevo_usuario():
    message = ''
    escaped_message= ''
    if request.method == 'POST':
        # Obtener datos del formulario
        username = request.form.get('username')[:30]
        password = request.form.get('password')


        # Verificar la fortaleza de la contraseña
        if not password_check(password):
            message = 'La contraseña no cumple con los requisitos de seguridad'
            escaped_message = escape(message)

        else:
            # Generar el hash de la contraseña
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Crear un nuevo usuario con el hash de la contraseña
            nuevo_usuario = User(Username=username, Password=hashed_password)

            # Agregar el usuario a la base de datos y hacer commit
            db.session.add(nuevo_usuario)
            db.session.commit()
            
            message = 'Nuevo usuario añadido con éxito'
            escaped_message = escape(message)


    return render_template('index.html', message=escaped_message)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    app.run(port=3000, debug=True)