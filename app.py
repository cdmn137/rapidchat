from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, send, emit, join_room
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__, template_folder = 'templates')
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'clave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

socketio = SocketIO(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar contraseña', validators=[DataRequired(),
                                                     EqualTo('password', message='Las contraseñas no coinciden')])
    submit = SubmitField('Registrarse')

class LoginForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')
    remember = BooleanField('Recuérdame')

class UpdateProfileForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Actualizar')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'error')
    return render_template('login.html', form=form)
   
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Tu cuenta ha sido creada! Ahora puedes iniciar sesión', 'success')
        return redirect(url_for('login'))
    return render_template('registro.html', form=form)

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        db.session.commit()
        flash('Tu perfil ha sido actualizado!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.username.data = current_user.username
    return render_template('perfil.html', form=form)

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    """Función para manejar el mensaje enviado por el usuario"""
    message = request.form['message']
    emit('message', {'username': current_user.username, 'message': message}, room='chat')
    return '', 204

@socketio.on('joined')
def joined():
    """Cuando un usuario se une a la sala de chat, envía un mensaje al resto de los usuarios"""
    username = current_user.username
    join_room('chat')
    emit('status', {'message': username + ' se ha unido a la sala de chat.'}, room='chat')

@socketio.on('message')
def message(data):
    """Cuando un usuario envía un mensaje, los demás usuarios de la sala de chat lo reciben"""
    username = current_user.username
    message = data['message']
    emit('message', {'username': username, 'message': message}, room='chat')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app)
    
