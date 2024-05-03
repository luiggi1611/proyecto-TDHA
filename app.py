import os
#from dotenv import load_dotenv
#import pymongo
import datetime
#from bson.objectid import ObjectId
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
#import bcrypt
from functools import wraps
import sqlite3
from flask import Flask
from flask import render_template, jsonify
import json
import os
app = Flask(__name__)
app.secret_key = os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)
import logging
from logging.handlers import RotatingFileHandler

from exchangelib import Message, Mailbox, FileAttachment
import smtplib
import datetime
import datetime as dt
import re, os
from exchangelib import DELEGATE, IMPERSONATION, Account, Credentials, FaultTolerance, Configuration, Message, \
    FileAttachment, CalendarItem, Folder, EWSTimeZone, EWSDateTime
from exchangelib.recurrence import Recurrence, WeeklyPattern
import mariadb
# from config import cfg  # load your credentials

import base64
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from requests import HTTPError

SCOPES = [
        "https://www.googleapis.com/auth/gmail.send"
    ]
flow = InstalledAppFlow.from_client_secrets_file('client_secret.json', SCOPES)
creds = flow.run_local_server(port=0)


def send_email(subject, body, recipients, attachments=None):
    """
    Send an email.

    Parameters
    ----------
    account : Account object
    subject : str
    body : str
    recipients : list of str
        Each str is and email adress
    attachments : list of tuples or None
        (filename, binary contents)

    Examples
    --------
    ### msend_email(account, 'Subject line', 'Hello!', ['info@example.com'])
    """
    username = 'iapariciob@bn.com.pe'
    password = 'Tema123.'


    host = 'owa.bn.com.pe'

    credentials = Credentials(
        username=username,
        password=password)

    config = Configuration(retry_policy=FaultTolerance(max_wait=3600),
                           server=host, credentials=credentials)

    account = Account(
        primary_smtp_address=username,
        config=config,
        autodiscover=True,
        access_type=DELEGATE)

    to_recipients = []
    for recipient in recipients:
        to_recipients.append(Mailbox(email_address=recipient))
    # Create message
    m = Message(account=account,
                folder=account.sent,
                subject=subject,
                body=body,
                to_recipients=to_recipients)

    # attach files
    for attachment_name, attachment_content in attachments or []:
        file = FileAttachment(name=attachment_name, content=attachment_content)
        m.attach(file)
    m.send_and_save()


# Read attachment

# with open(r"D:\ENVIOS_INFORMACION\CALL_AGENCIAS\Datos_usuarios"+str(date.today()).replace('-','_')+".xlsx", 'rb') as f:
#   content = f.read()
# attachments.append(('Datos_usuarios.xlsx', content))


########################################################################################################################
#                                                      MANEJO DE LOGS
#
########################################################################################################################
#handler = RotatingFileHandler(os.path.join(app.root_path, 'logs', 'oboeqa_web.log'), maxBytes=102400, backupCount=10)
#logging_format = logging.Formatter(
#    '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')

#handler.setFormatter(logging_format)
#app.logger.addHandler(handler)


@app.errorhandler(404)
def page_not_found(error):
    app.logger.error(error)

    return 'This page does not exist', 404


@app.errorhandler(500)
def special_exception_handler(error):
    app.logger.error(error)
    return '500 error', 500


def page_not_found(error):
    return 'This page does not exist', 404


app.error_handler_spec[None][404] = page_not_found
## necessary for python-dotenv ##
#APP_ROOT = os.path.join(os.path.dirname(__file__), '..')  # refers to application_top
#dotenv_path = os.path.join(APP_ROOT, '.env')
#load_dotenv(dotenv_path)

########################################################################################################################
#                  CARGA DE ROLES Y USUARIOS
#
########################################################################################################################

import mariadb
conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')


#conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute('SELECT roles_name FROM roles')
roles = cur.fetchone()
cur.execute('SELECT * FROM users')
users = cur.fetchall()
conn.close()
login = LoginManager()
login.init_app(app)
login.login_view = 'login'


########################################################################################################################
#                  CONTROL DE LOGIN
#
########################################################################################################################
@login.user_loader
def load_user(username):
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    curs = conn.cursor()
    curs.execute("SELECT * from users where email = (?)", [username.lower()])
    lu = curs.fetchone()
    conn.close()
    if lu is None:
        return None
    else:
        return User(username=lu[4].lower(), role=lu[6], id=lu[0], name=lu[1])


def insertUser(first_name, last_name,dni, email, password, role,fecha_nacimiento):
    date = datetime.datetime.now()
    con = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (first_name,last_name,dni,email,password,role,date_added,date_modified,fecha_nacimiento) VALUES (?,?,?,?,?,?,?,?,?)",
        (first_name, last_name, dni, email.lower(), password, role, date, date,fecha_nacimiento))
    con.commit()
    con.close()


class User:
    def __init__(self, id, username, role, name):
        self._id = id
        self.username = username
        self.role = role
        self.name = name

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.username


### custom wrap to determine role access  ###
def roles_required(*role_names):
    def decorator(original_route):
        @wraps(original_route)
        def decorated_route(*args, **kwargs):
            if not current_user.is_authenticated:
                print('The user is not authenticated.')
                return redirect(url_for('login'))

            print(current_user.role)
            print(role_names)
            if not current_user.role in role_names:
                print('The user does not have this role.')
                return redirect(url_for('login'))
            else:
                print('The user is in this role.')
                return original_route(*args, **kwargs)

        return decorated_route

    return decorator


########################################################################################################################
#                   CARGA DE PAGINAS REGISTRO
#
########################################################################################################################


@app.route('/test2')
def page2():

    return render_template(
        '/vertical-modern-menu-template/dashboard-crypto.html',

    )
# PAGINA PRINCIPAL
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('Paginas/Pagina_registro/login-advanced.html')



@app.route('/dash', methods=['GET', 'POST'])
def dash():
    return render_template('Paginas/Pagina_inicio/Reporte - dash.html')

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():

    return render_template('Paginas/Pagina_inicio/Pagina Inicio.html')

# pruebas
@app.route('/prueba', methods=['GET', 'POST'])
def prueba():
    return render_template('Paginas/Pagina_portales/Portal_Base.html')


########################################################################################################################

# PAGINA DE REGISTRO
@app.route('/register')
def register():
    return render_template('Paginas/Pagina_registro/register-advanced.html')

########################################################################################################################

# PAGINA DE LOGEO
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
        curs = conn.cursor()
        curs.execute("SELECT * FROM users where email = (?)", [request.form['username'].lower()])
        user = curs.fetchone()
        conn.close()
        if user == None:
            flash("Ingrese correctamente su  usuario o contraseña!", category='danger')
            return render_template('Paginas/Pagina_registro/login-advanced.html')
        print(user[4])
        if user and user[5] == request.form['password']:
            user_obj = User(username=user[4].lower(), role=user[6], id=user[0], name=user[1])
            login_user(user_obj)
            next_page = request.args.get('next')

            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('home')
                return redirect(next_page)
            flash("Ingreso Exitosamente!", category='success')
            return redirect(request.args.get("next") or url_for("home"))

        flash("Ingrese correctamente su  usuario o contraseña!", category='danger')
    return render_template('Paginas/Pagina_registro/login-advanced.html')


########################################################################################################################

# PAGINA DE DESLOGEO
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('Se ha retirado exitosamente! Buen dia.', 'success')
    return redirect(url_for('login'))


########################################################################################################################
# PAGINA DE USUARIO
@app.route('/my-account/<user_id>', methods=['GET', 'POST'])
@login_required
# @roles_required('user', 'contributor', 'admin','visitor')
def my_account(user_id):
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    curs = conn.cursor()
    curs.execute("SELECT * FROM users where user_id = (?)", [user_id])
    edit_account = curs.fetchone()
    conn.close()
    # edit_account = users.find_one({'_id': ObjectId(user_id)})
    if edit_account:
        return render_template('Paginas/Pagina_registro/edit-advanced.html', user=edit_account)
    flash('User not found.', 'warning')
    return redirect(url_for('home'))


########################################################################################################################

# PAGINA DE ACTUALIZACION DE USUARIO
@app.route('/update-myaccount/<user_id>', methods=['GET', 'POST'])
@login_required
def update_myaccount(user_id):
    if request.method == 'POST':
        conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
        cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        if form['password'] != form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('my_account', user_id=user_id))

        cur.execute(
            "UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, role = ? , date_added = ? , date_modified = ? where  user_id = (?)",
            (first_name, last_name, email.lower(), password, role, date_added, date_modified, user_id))
        conn.commit()
        cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id))
        update_account =cur.fetchone()
        conn.close()
        flash(update_account[3] + ' Su cuenta ha sido actualizada', 'success')
        return redirect(url_for('home'))
    return redirect(url_for('home'))


########################################################################################################################

# PAGINA DE ACTUALIZACION DE USUARIO
@app.route('/add-user', methods=['GET', 'POST'])
def visitor_add_user():
    if request.method == 'POST':
        form = request.form
        password = request.form['password']
        conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
        curs = conn.cursor()
        curs.execute("SELECT * FROM users where email = (?)", [request.form['email'].lower()])
        email = curs.fetchone()
        conn.close()
        if email:
            flash('El correo ya existe!', 'warning')
            return redirect(url_for('visitor_users'))
        if request.form['password'] != request.form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('visitor_users'))
        if "@bn.com.pe" not in request.form['email'].lower():
            flash('Ingrese un correo del banco', 'warning')
            return redirect(url_for('visitor_users'))
        insertUser(form['first_name'], form['last_name'],form['dni'], form['email'].lower(), password, form['role'])

        flash(form['email'].lower() + ' El usuario ha sido agregado', 'success')
        return redirect(url_for('login'))
        # return redirect(url_for('visitor_users'))
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()

    return render_template('Paginas/Pagina_registro/register-advanced.html', all_roles=roles, all_users=users)


########################################################################################################################

# PAGINA DE ACTUALIZACION DE USUARIO

@app.route('/users', methods=['GET', 'POST'])
def visitor_users():
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/register-advanced.html', all_roles=roles, all_users=users)


@app.route('/recuperar_correo', methods=['GET', 'POST'])
def recuperar_usuario():
    conn = sqlite3.connect('database.db')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/recuperar-advanced.html', all_roles=roles, all_users=users)


########################################################################################################################

# PAGINA DE EDICION USUARIO

@app.route('/edit-user-visitor/<user_id>', methods=['GET', 'POST'])
def visitor_edit_user(user_id):
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    cur = conn.cursor()
    cur.execute("select *  FROM  users WHERE user_id = (?)", (user_id))
    edit_user = cur.fetchone()
    conn.close()
    # edit_user = users.find_one({'_id': ObjectId(user_id)})
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()
    if edit_user:
        return render_template('Paginas/Pagina_registro/edit-advanced.html', user=edit_user, all_roles=roles.find())
    flash('Usuario no encontrado!', 'warning')
    return redirect(url_for('visitor_users'))


########### enviar correos ####################################################################
@app.route('/correo', methods=['GET', 'POST'])
def correo():
    nombre = request.form['Nombre']
    correo = request.form['Email']
    texto = request.form['texto']
    attachments = []
    # Send email
    send_email('Correo del Portal de Analitica: ' + nombre, 'Correo de :' + correo + ' \n\n' + texto,
               ['7822001@bn.com.pe','iapariciob@bn.com.pe']
               ,  # lcanov@bn.com.pe','mconchau@bn.com.pe'
               attachments=attachments)
    flash('Mensaje Enviado', 'warning')
    return redirect(url_for('home'))

import pickle
########### enviar correos ####################################################################
@app.route('/correo_recuperar', methods=['GET', 'POST'])
def correo_recuperar():
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    curs = conn.cursor()
    curs.execute("SELECT * FROM users where email = (?)", [request.form['username'].lower()])
    email = curs.fetchone()
    conn.close()
    if email:
        flash('Correo enviado. revise su correo del Banco', 'warning')
        attachments = []
        # Send email

        send_email('Correo de recuperacion de  contraseña ',
                   'Su contraseña es :' + email[4] + ' \n\n tenga un buen dia.',
                   ['7822001@bn.com.pe', email[3]]
                   ,  # lcanov@bn.com.pe','mconchau@bn.com.pe'
                   attachments=attachments)
        return redirect(url_for('recuperar_usuario'))
    if "@bn.com.pe" not in request.form['email'].lower():
        flash('Ingrese un correo del banco', 'warning')
        return redirect(url_for('recuperar_usuario'))

    flash('Correo no existe, cree un nuevo usuario', 'warning')
    return redirect(url_for('recuperar_usuario'))


@login_required
def update_myaccount(user_id):
    if request.method == 'POST':
        conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
        cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        if form['password'] != form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('my_account', user_id=user_id))

        cur.execute(
            "UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, role = ? , date_added = ? , date_modified = ? where  user_id = (?)",
            (first_name, last_name, email.lower(), password, role, date_added, date_modified, user_id))
        conn.commit()
        cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id))\

        update_account =cur.fetchone()

        conn.close()
        flash(update_account[3] + ' Su cuenta ha sido actualizada', 'success')
        return redirect(url_for('home'))
    return redirect(url_for('home'))


########################################################################################################################

# FUNCIONES DE ADMINISTRACION

##########  Admin functionality -- Administracion de usuarios ##########################################################

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@roles_required('admin','Psicólogo')
def admin_users():
    # return render_template('users.html', all_roles=roles.find(), all_users=users.find())
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    if current_user.role=="admin":
        cur.execute('SELECT * FROM users')
    else:
        cur.execute('SELECT * FROM users where role in ("Paciente","paciente") ' )

    users  = cur.fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/editadmin-advanced.html', all_roles=roles, all_users=users)
import pandas as pd
import numpy as np
import mariadb
@login_required
@roles_required('admin','Psicólogo')
@app.route('/reporte', methods=("POST", "GET"))
def reporte():
    conn = mariadb.connect(
        host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
        port=3306,
        user='admin',
        password='prueba123456',
        database='base')

    cur = conn.cursor()
    cur.execute('SELECT * FROM register')
    datos = cur.fetchall()
    df = pd.DataFrame(datos)
    # users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()
    dfuser = pd.DataFrame(users)[[0,1,2,3,4,9]]
    dfuser.columns = [0,"nombre","apellido","DNI","correo","fecha_nacimiento"]
    df = df.merge(dfuser,on=[0],how='inner')

    df_1 = df.copy()[["nombre", "apellido", "DNI", "correo", 2, 48,"fecha_nacimiento"]]
    df_1.columns = ["nombre", "apellido", "DNI", "correo", "edad", "score","fecha_nacimiento"]
    for x in df_1.iterrows():
        print(x)

    return render_template('Paginas/Pagina_inicio/Reporte.html',   tables=df_1)
from flask import jsonify
@app.route('/page_test')
def page_test():
    conn = mariadb.connect(
        host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
        port=3306,
        user='admin',
        password='prueba123456',
        database='base')

    cur = conn.cursor()
    cur.execute('SELECT * FROM register')
    datos = cur.fetchall()
    df = pd.DataFrame(datos)
    # users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()
    dfuser = pd.DataFrame(users)[[0, 1, 2, 3, 4]]
    dfuser.columns = [0, "nombre", "apellido", "DNI", "correo"]
    df = df.merge(dfuser, on=[0], how='inner')
    df_1 = df.copy()[["nombre","apellido","DNI","correo",2,48]]
    df_1.columns =  ["nombre","apellido","DNI","correo","edad","score"]
    meas = df_1.to_json(orient="records")
    return jsonify({'data': meas})

import pandas as pd
import pickle
import numpy as np
@app.route('/registro', methods=['GET', 'POST'])
@login_required
@roles_required('Paciente')
def registro_paciente():
    if request.method == 'POST':
        user_id = current_user._id

        form = request.form
        print(form)
        p1 = form['p1']
        p2 = form['p2']
        p3 = form['p3']
        p4 = form['p4']

        p6 = form['p6']
        p7 = form['p7']
        p8 = form['p8']
        p9 = form['p9']
        p10 = form['p10']
        p11 = form['p11']
        p12 = form['p12']
        p13 = form['p13']
        p14 = form['p14']
        p15 = form['p15']
        p16 = form['p16']
        p17 = form['p17']
        p18 = form['p18']
        p19 = form['p19']
        p20 = form['p20']
        p21 = form['p21']
        p22 = form['p22']
        p23 = form['p23']
        p24 = form['p24']
        p25 = form['p25']
        p26 = form['p26']
        p27 = form['p27']
        p28 = form['p28']
        p29 = form['p29']
        p30 = form['p30']
        p31 = form['p31']
        p32 = form['p32']
        p33 = form['p33']
        p34 = form['p34']
        p35 = form['p35']
        p36 = form['p36']
        p37 = form['p37']
        p38 = form['p38']
        p39 = form['p39']
        p40 = form['p40']
        p41 = form['p41']
        p42 = form['p42']
        p43 = form['p43']
        p44 = form['p44']
        p45 = form['p45']
        p46 = form['p46']
        p47 = form['p47']
        df = pd.DataFrame([[ p1  ,p2  ,p3  ,p4    ,p6  ,p7  ,p8  ,p9  ,p10  ,p11  ,p12  ,p13  ,p14  ,p15  ,p16  ,p17  ,p18  ,p19  ,p20  ,p21  ,p22  ,p23  ,p24  ,p25  ,p26  ,p27  ,p28  ,p29  ,p30  ,p31  ,p32  ,p33  ,p34  ,p35  ,p36  ,p37  ,p38  ,p39  ,p40  ,p41  ,p42  ,p43  ,p44  ,p45  ,p46  ,p47 ]],
                          columns = ['p1',
                                        'p2',
                                        'p3',
                                        'p4',

                                        'p6',
                                        'p7',
                                        'p8',
                                        'p9',
                                        'p10',
                                        'p11',
                                        'p12',
                                        'p13',
                                        'p14',
                                        'p15',
                                        'p16',
                                        'p17',
                                        'p18',
                                        'p19',
                                        'p20',
                                        'p21',
                                        'p22',
                                        'p23',
                                        'p24',
                                        'p25',
                                        'p26',
                                        'p27',
                                        'p28',
                                        'p29',
                                        'p30',
                                        'p31',
                                        'p32',
                                        'p33',
                                        'p34',
                                        'p35',
                                        'p36',
                                        'p37',
                                        'p38',
                                        'p39',
                                        'p40',
                                        'p41',
                                        'p42',
                                        'p43',
                                        'p44',
                                        'p45',
                                        'p46',
                                        'p47'])
        filename = 'finalized_model.sav'

        df['p1'] = np.where(df['p1'] == "Masculino", 1, 0)

        # In[76]:

        df['p2'] = df['p2'].str.split(" ", expand=True)[0]

        # In[77]:

        df['p3_ESTE'] = np.where(df['p3'] == "Lima Este", 1, 0)
        df['p3_SUR'] = np.where(df['p3'] == "Lima Sur", 1, 0)
        df['p3_NORTE'] = np.where(df['p3'] == "Lima Norte", 1, 0)

        # In[78]:

        df['p4_public'] = np.where(df['p4'] == "Público", 1, 0)
        df['p4_private'] = np.where(df['p4'] == "Privado", 1, 0)

        # In[79]:

        #df['p5_target'] = np.where(df['p5'] == "Ha sido diagnostica con Déficit de Atención", 1, 0)

        # In[80]:

        # df['p6'].value_counts()
        df['p6_val'] = np.where(df['p6'] == "Buena", 2,
                                np.where(df['p6'] == "Muy buena", 3,
                                         np.where(df['p6'] == "Ni buena, ni mala",1,
                                                  np.where(df['p6'] == "Mala", 0, 0
                                                           ))))

        # In[81]:

        df['p7'] = np.where(df['p7'] == "Sí", 2,
                            np.where(df['p7'] == "No", 0,
                                     np.where(df['p7'] == "Tal vez", 1, 0)))
        # df['p7'].value_counts()

        # In[82]:

        # df['p8'].value_counts()
        df['p8'] = np.where(df['p8'] == "Sí", 1,
                            np.where(df['p8'] == "No", 0, 0))

        # In[83]:

        ##df['p9'].value_counts()
        df['p9'] = np.where(df['p9'] == "De acuerdo", 4,
                            np.where(df['p9'] == "Totalmente de acuerdo", 3,
                                     np.where(df['p9'] == "Ni de acuerdo ni en desacuerdo", 2,
                                              np.where(df['p9'] == "En desacuerdo", 1,
                                                       np.where(df['p9'] == "Totalmente en desacuerdo", 0, 0)))))

        df['p10'] = np.where(df['p10'] == "De acuerdo", 4,
                             np.where(df['p10'] == "Totalmente de acuerdo", 3,
                                      np.where(df['p10'] == "Ni de acuerdo ni en desacuerdo", 2,
                                               np.where(df['p10'] == "En desacuerdo", 1,
                                                        np.where(df['p10'] == "Totalmente en desacuerdo", 0, 0)))))

        df['p11'] = np.where(df['p11'] == "De acuerdo", 4,
                             np.where(df['p11'] == "Totalmente de acuerdo", 3,
                                      np.where(df['p11'] == "Ni de acuerdo ni en desacuerdo", 2,
                                               np.where(df['p11'] == "En desacuerdo", 1,
                                                        np.where(df['p11'] == "Totalmente en desacuerdo", 0, 0)))))

        df['p12'] = np.where(df['p12'] == "De acuerdo", 4,
                             np.where(df['p12'] == "Totalmente de acuerdo", 3,
                                      np.where(df['p12'] == "Ni de acuerdo ni en desacuerdo", 2,
                                               np.where(df['p12'] == "En desacuerdo", 1,
                                                        np.where(df['p12'] == "Totalmente en desacuerdo", 0, 0)))))

        df['p13'] = np.where(df['p13'] == "De acuerdo", 4,
                             np.where(df['p13'] == "Totalmente de acuerdo", 3,
                                      np.where(df['p13'] == "Ni de acuerdo ni en desacuerdo", 2,
                                               np.where(df['p13'] == "En desacuerdo", 1,
                                                        np.where(df['p13'] == "Totalmente en desacuerdo", 0, 0)))))

        df['p14'] = np.where(df['p14'] == "De acuerdo", 4,
                             np.where(df['p14'] == "Totalmente de acuerdo", 3,
                                      np.where(df['p14'] == "Ni de acuerdo ni en desacuerdo", 2,
                                               np.where(df['p14'] == "En desacuerdo", 1,
                                                        np.where(df['p14'] == "Totalmente en desacuerdo", 0, 0)))))

        df['p15'] = np.where(df['p15'] == "De acuerdo", 3,
                             np.where(df['p15'] == "Totalmente de acuerdo", 4,
                                      np.where(df['p15'] == "Ni de acuerdo ni en desacuerdo", 2,
                                               np.where(df['p15'] == "En desacuerdo", 1,
                                                        np.where(df['p15'] == "Totalmente en desacuerdo", 0, 0)))))

        df['p16'] = np.where(df['p16'] == "De acuerdo", 4,
                             np.where(df['p16'] == "Totalmente de acuerdo", 3,
                                      np.where(df['p16'] == "Ni de acuerdo ni en desacuerdo", 2,
                                               np.where(df['p16'] == "En desacuerdo", 1,
                                                        np.where(df['p16'] == "Totalmente en desacuerdo", 0, 0)))))

        # In[92]:

        df['p17_M'] = np.where(df['p17'] == "Matemáticas", 1, 0)
        df['p17_N'] = np.where(df['p17'] == "Ninguna de las anteriores", 1, 0)
        df['p17_L'] = np.where(df['p17'] == "Letras", 1, 0)
        df['p17_H'] = np.where(df['p17'] == "Historia", 1, 0)
        df['p17_A'] = np.where(df['p17'] == "Historia", 1, 0)

        # In[65]:

        df['p18'].value_counts()

        # In[93]:

        df['p18'] = np.where(df['p18'] == "Menos de 30 minutos", 1,
                             np.where(df['p18'] == "Entre 1 y 2 horas", 2,
                                      np.where(df['p18'] == "Entre 2 y 4 horas", 3,
                                               np.where(df['p18'] == "Más de 4 horas", 4,
                                                        0))))

        # In[109]:


        X = df[['p14', 'p21', 'p3_ESTE', 'p26', 'p19', 'p27', 'p15', 'p13', 'p23',
       'p34', 'p32', 'p28', 'p20', 'p2', 'p7', 'p44', 'p31', 'p12',
       'p17_H', 'p17_M', 'p17_L', 'p4_private', 'p40', 'p6_val', 'p24',
       'p47', 'p11']].astype(int)
        print(X)
        loaded_model = pickle.load(open(filename, 'rb'))
        prediccion = loaded_model.predict_proba(X)
        date = datetime.datetime.now()
        con = mariadb.connect(
            host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
            port=3306,
            user='admin',
            password='prueba123456',
            database='base')
        cur = con.cursor()
        cur.execute(
            "INSERT INTO register (user_id,p1  ,p2  ,p3  ,p4    ,p6  ,p7  ,p8  ,p9  ,p10  ,p11  ,p12  ,p13  ,p14  ,p15  ,p16  ,p17  ,p18  ,p19  ,p20  ,p21  ,p22  ,p23  ,p24  ,p25  ,p26  ,p27  ,p28  ,p29  ,p30  ,p31  ,p32  ,p33  ,p34  ,p35  ,p36  ,p37  ,p38  ,p39  ,p40  ,p41  ,p42  ,p43  ,p44  ,p45  ,p46  ,p47  ,date_added,prediccion) VALUES (?,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?  ,?)",
            (user_id, p1  ,p2  ,p3  ,p4    ,p6  ,p7  ,p8  ,p9  ,p10  ,p11  ,p12  ,p13  ,p14  ,p15  ,p16  ,p17  ,p18  ,p19  ,p20  ,p21  ,p22  ,p23  ,p24  ,p25  ,p26  ,p27  ,p28  ,p29  ,p30  ,p31  ,p32  ,p33  ,p34  ,p35  ,p36  ,p37  ,p38  ,p39  ,p40  ,p41  ,p42  ,p43  ,p44  ,p45  ,p46  ,p47  , date,list(prediccion[0])[1]*100))
        con.commit()
        con.close()
        flash( 'Cuestionario enviado.', 'success')
        return redirect(url_for('home'))

    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()
    flash( 'Cuestionario enviado.', 'success')

    return render_template('Paginas/Pagina_inicio/Pagina Inicio.html', all_roles=roles, all_users=users)

##########  Admin functionality -- Agregar Usuarios ####################################################################

@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@roles_required('admin','Psicólogo')
def admin_add_user():
    if request.method == 'POST':
        form = request.form
        password = request.form['password']
        conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
        curs = conn.cursor()
        curs.execute("SELECT * FROM users where email = (?)", [request.form['email']])
        email = curs.fetchone()
        conn.close()
        if email:
            flash('Este correo ya existe!', 'warning')
            return 'This email has already been registered.'

        insertUser(form['first_name'], form['last_name'],form['dni'], form['email'], password, form['role'],form['fecha_nacimiento'])
        flash(form['email'] + ' user ha sido agregado.', 'success')
        usuario = form['email']
        service = build('gmail', 'v1', credentials=creds)
        message = MIMEText(f'El usuario es {usuario} y la contraseña es {password} ')
        message['to'] = form['email']
        message['subject'] = 'Envio de usuario'
        create_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

        try:
            message = (service.users().messages().send(userId="me", body=create_message).execute())
            print(F'sent message to {message} Message Id: {message["id"]}')
        except HTTPError as error:
            print(F'An error occurred: {error}')
            message = None

        return redirect(url_for('admin_users'))

    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()



    return render_template('Paginas/Pagina_registro/register-advanced-admi.html', all_roles=roles, all_users=users)


###########  Admin functionality -- borrar Usuarios ####################################################################

@app.route('/ficha', methods=['GET', 'POST'])
@login_required
@roles_required('Psicólogo')
def ficha():
    nombre = request.args.get('nombre')
    apellido = request.args.get('apellido')
    DNI = request.args.get('DNI')
    fecha_nacimiento  = request.args.get('fecha_nacimiento')
    score = request.args.get('score')
    if float(score)>50:
        sospecha="SI"
    else:
        sospecha = "NO"
    return render_template('Paginas/Pagina_inicio/resultado.html', nombre= nombre,apellido=apellido,DNI=DNI,fecha_nacimiento=fecha_nacimiento,score=score,sospecha=sospecha)

@app.route('/admin/delete-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin','Psicólogo')
def admin_delete_user(user_id):
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id,))
    delete_user = cur.fetchone()
    conn.close()
    if delete_user:
        conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
        cur = conn.cursor()
        cur.execute("DELETE FROM  users WHERE user_id = (?)", (user_id,))
        conn.commit()
        conn.close()
        flash(delete_user[4] + ' ha sido eliminado.', 'warning')
        return redirect(url_for('admin_users'))
    flash('User not found.', 'warning')
    return redirect(url_for('admin_users'))

###########  Admin functionality -- Editar Usuarios ####################################################################

@app.route('/admin/edit-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin','Psicólogo')
def admin_edit_user(user_id):
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    cur = conn.cursor()
    cur.execute("select *  FROM  users WHERE user_id = (?)", (user_id,))
    edit_user = cur.fetchone()
    conn.close()
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')

    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()
    if edit_user:
        return render_template('Paginas/Pagina_registro/edit-advanced-admin.html', user=edit_user, all_roles=roles)
    flash('Usuario no encontrado', 'warning')
    return redirect(url_for('admin_users'))


###########  Admin functionality -- Editar Usuarios ####################################################################

@app.route('/admin/update-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin','Psicólogo')
def admin_update_user(user_id):
    if request.method == 'POST':
        conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
        cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        #role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        fecha_nacimiento = form['fecha_nacimiento']
        cur.execute(
            "UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, date_added = ? , date_modified = ? , fecha_nacimiento = ? where  user_id = (?)",
            (first_name, last_name, email, password,  date_added, date_modified, fecha_nacimiento,user_id))
        conn.commit()

        cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id,))
        update_account = cur.fetchone()
        conn.close()
        flash(update_account[3] + ' ha sido modificado.', 'success')
        return redirect(url_for('admin_users'))
    conn = mariadb.connect(
         host='database-1.ctdogw6p3pwb.us-east-2.rds.amazonaws.com',
         port= 3306,
         user='admin',
         password='prueba123456',
         database = 'base')
    cur = conn.cursor()
    cur.execute('SELECT roles_name FROM roles')
    roles = cur.fetchall()
    #users = conn.execute('SELECT * FROM users').fetchall()
    cur.execute('SELECT * FROM users')
    users  = cur.fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/register-advanced-admi.html', all_roles=roles, all_users=users)


if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    app.run() #host='0.0.0.0', port=80)


# app.run(debug=True)host='0.0.0.0', port=5000,v
