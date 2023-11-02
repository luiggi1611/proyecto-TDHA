########################################################################################################################
#                                         CONSTRUCCION PORTAL ANALITICA
#  Autor : Luiggi Silva  / luiggi11.16@gmail.com /996261574
#
########################################################################################################################

import os
from dotenv import load_dotenv
import pymongo
import datetime
from bson.objectid import ObjectId
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
import bcrypt
from functools import wraps
import sqlite3
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
from exchangelib import DELEGATE, IMPERSONATION, Account, Credentials, FaultTolerance,Configuration, Message, FileAttachment,CalendarItem,Folder,EWSTimeZone,EWSDateTime
from exchangelib.recurrence import Recurrence, WeeklyPattern
    
#from config import cfg  # load your credentials
def send_email( subject, body, recipients, attachments=None):
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
    >>> send_email(account, 'Subject line', 'Hello!', ['info@example.com'])
    """
    username = '7822001@bn.com.pe'
    password = '123456Ab'

    host='owa.bn.com.pe'

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

#with open(r"D:\ENVIOS_INFORMACION\CALL_AGENCIAS\Datos_usuarios"+str(date.today()).replace('-','_')+".xlsx", 'rb') as f:
#   content = f.read()
#attachments.append(('Datos_usuarios.xlsx', content))


########################################################################################################################
#                                                      MANEJO DE LOGS
#
########################################################################################################################
handler = RotatingFileHandler(os.path.join(app.root_path, 'logs', 'oboeqa_web.log'), maxBytes=102400, backupCount=10)
logging_format = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')

handler.setFormatter(logging_format)
app.logger.addHandler(handler)

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
APP_ROOT = os.path.join(os.path.dirname(__file__), '..')   # refers to application_top
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path)

########################################################################################################################
#                  CARGA DE ROLES Y USUARIOS
#
########################################################################################################################

conn = sqlite3.connect('database.db')
roles = conn.execute('SELECT roles_name FROM roles').fetchall()
users = conn.execute('SELECT * FROM users').fetchall()
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
   conn = sqlite3.connect('database.db')
   curs = conn.cursor()
   curs.execute("SELECT * from users where email = (?)",[username.lower()])
   lu = curs.fetchone()
   conn.close()
   if lu is None:
      return None
   else:
       return User(username=lu[3].lower(), role=lu[5], id=lu[0] , name=lu[1])

def insertUser(first_name,last_name,email,password,role):
    date=datetime.datetime.now()
    con = sqlite3.connect("database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO users (first_name,last_name,email,password,role,date_added,date_modified) VALUES (?,?,?,?,?,?,?)", (first_name,last_name,email.lower(),password,role,date,date))
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

#PAGINA PRINCIPAL
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('Paginas/Pagina_inicio/Pagina Inicio.html')



#pruebas
@app.route('/prueba', methods=['GET', 'POST'])
def prueba():
    return render_template('Paginas/Pagina_portales/Portal_Base.html')


########################################################################################################################

#PAGINA DE REGISTRO
@app.route('/register')
def register():
   return render_template('Paginas/Pagina_registro/register-advanced.html')

########################################################################################################################

#PAGINA DE PRUEBAS
@app.route('/test_01')
def test_01():
   return render_template('CRISP-DM.html')


########################################################################################################################

#PAGINA DE LOGEO
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        conn = sqlite3.connect('database.db')
        curs = conn.cursor()
        curs.execute("SELECT * FROM users where email = (?)", [request.form['username'].lower()])
        user = curs.fetchone()
        conn.close()
        if user==None:
            flash("Ingrese correctamente su  usuario o contraseña!", category='error')
            return render_template('Paginas/Pagina_registro/login-advanced.html')
        print(user[3])
        if user and user[4] == request.form['password']:
            user_obj = User(username=user[3].lower(), role=user[5], id=user[0],name=user[1])
            login_user(user_obj)
            next_page = request.args.get('next')

            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
                return redirect(next_page)
            flash("Ingreso Exitosamente!", category='success')
            return redirect(request.args.get("next") or url_for("index"))

        flash("Ingrese correctamente su  usuario o contraseña!", category='error')
    return render_template('Paginas/Pagina_registro/login-advanced.html')

########################################################################################################################

#PAGINA DE DESLOGEO
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('Se ha retirado exitosamente! Buen dia.', 'success')
    return redirect(url_for('login'))
########################################################################################################################
#PAGINA DE USUARIO
@app.route('/my-account/<user_id>', methods=['GET', 'POST'])
@login_required
#@roles_required('user', 'contributor', 'admin','visitor')
def my_account(user_id):
    conn = sqlite3.connect('database.db')
    curs = conn.cursor()
    curs.execute("SELECT * FROM users where user_id = (?)", [user_id])
    edit_account = curs.fetchone()
    conn.close()
    #edit_account = users.find_one({'_id': ObjectId(user_id)})
    if edit_account:
        return render_template('Paginas/Pagina_registro/edit-advanced.html', user=edit_account)
    flash('User not found.', 'warning')
    return redirect(url_for('index'))

########################################################################################################################

#PAGINA DE ACTUALIZACION DE USUARIO
@app.route('/update-myaccount/<user_id>', methods=['GET', 'POST'])
@login_required
def update_myaccount(user_id):
    if request.method == 'POST':
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        if form['password']!=form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('my_account',user_id=user_id))

        cur.execute("UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, role = ? , date_added = ? , date_modified = ? where  user_id = (?)",
                    (first_name, last_name, email.lower() , password,role,date_added,date_modified, user_id))
        conn.commit()
        update_account = cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id)).fetchone()
        conn.close()
        flash(update_account[3] + ' Su cuenta ha sido actualizada', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('index'))

########################################################################################################################

#PAGINA DE ACTUALIZACION DE USUARIO
@app.route('/add-user', methods=['GET', 'POST'])
def visitor_add_user():
    if request.method == 'POST':
        form = request.form
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        curs = conn.cursor()
        curs.execute("SELECT * FROM users where email = (?)", [request.form['email'].lower()])
        email = curs.fetchone()
        conn.close()
        if email:
            flash('El correo ya existe!', 'warning')
            return redirect(url_for('visitor_users'))
        if request.form['password']!=request.form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('visitor_users'))
        if "@bn.com.pe" not in request.form['email'].lower():
            flash('Ingrese un correo del banco', 'warning')
            return redirect(url_for('visitor_users'))
        insertUser(form['first_name'], form['last_name'], form['email'].lower(), password, form['role'])

        flash(form['email'].lower() + ' El usuario ha sido agregado', 'success')
        return redirect(url_for('login'))
        #return redirect(url_for('visitor_users'))
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()

    return render_template('Paginas/Pagina_registro/register-advanced.html', all_roles=roles, all_users=users)


########################################################################################################################

#PAGINA DE ACTUALIZACION DE USUARIO

@app.route('/users', methods=['GET', 'POST'])
def visitor_users():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/register-advanced.html', all_roles= roles , all_users=users)


@app.route('/recuperar_correo', methods=['GET', 'POST'])
def recuperar_usuario():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/recuperar-advanced.html', all_roles= roles , all_users=users)
########################################################################################################################

#PAGINA DE EDICION USUARIO

@app.route('/edit-user-visitor/<user_id>', methods=['GET', 'POST'])
def visitor_edit_user(user_id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    edit_user =  cur.execute("select *  FROM  users WHERE user_id = (?)", (user_id)).fetchone()
    conn.close()
    #edit_user = users.find_one({'_id': ObjectId(user_id)})
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
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
    send_email( 'Correo del Portal de Analitica: '+nombre ,'Correo de :' +correo+ ' \n\n'+texto,
            [ '7822001@bn.com.pe','mconchau@bn.com.pe']
            ,#lcanov@bn.com.pe','mconchau@bn.com.pe'
           attachments=attachments)
    flash('Mensaje Enviado', 'warning')
    return redirect(url_for('index'))

########### enviar correos ####################################################################
@app.route('/correo_recuperar', methods=['GET', 'POST'])
def correo_recuperar():
    conn = sqlite3.connect('database.db')
    curs = conn.cursor()
    curs.execute("SELECT * FROM users where email = (?)", [request.form['username'].lower()])
    email = curs.fetchone()
    conn.close()
    if email:
        flash('Correo enviado. revise su correo del Banco', 'warning')
        attachments = []
        # Send email
       
        send_email( 'Correo de recuperacion de  contraseña ','Su contraseña es :' +email[4]+ ' \n\n tenga un buen dia.',
            [ '7822001@bn.com.pe',email[3]]
            ,#lcanov@bn.com.pe','mconchau@bn.com.pe'
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
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        if form['password']!=form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('my_account',user_id=user_id))

        cur.execute("UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, role = ? , date_added = ? , date_modified = ? where  user_id = (?)",
                    (first_name, last_name, email.lower() , password,role,date_added,date_modified, user_id))
        conn.commit()
        update_account = cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id)).fetchone()
        conn.close()
        flash(update_account[3] + ' Su cuenta ha sido actualizada', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('index'))




########################################################################################################################

#FUNCIONES DE ADMINISTRACION

##########  Admin functionality -- Administracion de usuarios ##########################################################

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_users():
    #return render_template('users.html', all_roles=roles.find(), all_users=users.find())
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/editadmin-advanced.html', all_roles=roles, all_users=users)

##########  Admin functionality -- Agregar Usuarios ####################################################################

@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_add_user():
    if request.method == 'POST':
        form = request.form
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        curs = conn.cursor()
        curs.execute("SELECT * FROM users where email = (?)", [request.form['email']])
        email = curs.fetchone()
        conn.close()
        if email:
            flash('Este correo ya existe!', 'warning')
            return 'This email has already been registered.'
        insertUser(form['first_name'], form['last_name'], form['email'], password, form['role'])
        flash(form['email'] + ' user ha sido agregado.', 'success')
        return redirect(url_for('admin_users'))
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/register-advanced-admi.html', all_roles=roles, all_users=users)

###########  Admin functionality -- borrar Usuarios ####################################################################

@app.route('/admin/delete-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_delete_user(user_id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    delete_user = cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id,)).fetchone()
    conn.close()
    if delete_user:
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute("DELETE FROM  users WHERE user_id = (?)", (user_id,))
        conn.commit()
        conn.close()
        flash(delete_user[3] + ' ha sido eliminado.', 'warning')
        return redirect(url_for('admin_users'))
    flash('User not found.', 'warning')
    return redirect(url_for('admin_users'))

###########  Admin functionality -- Editar Usuarios ####################################################################

@app.route('/admin/edit-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_edit_user(user_id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    edit_user =  cur.execute("select *  FROM  users WHERE user_id = (?)", (user_id,)).fetchone()
    conn.close()
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    conn.close()
    if edit_user:
        return render_template('Paginas/Pagina_registro/edit-advanced-admin.html', user=edit_user, all_roles=roles)
    flash('Usuario no encontrado', 'warning')
    return redirect(url_for('admin_users'))

###########  Admin functionality -- Editar Usuarios ####################################################################

@app.route('/admin/update-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_update_user(user_id):
    if request.method == 'POST':
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        cur.execute("UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, role = ? , date_added = ? , date_modified = ? where  user_id = (?)",
                    (first_name, last_name, email , password,role,date_added,date_modified, user_id))
        conn.commit()
        update_account = cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id,)).fetchone()
        conn.close()
        flash(update_account[3] + ' ha sido modificado.', 'success')
        return redirect(url_for('admin_users'))
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_registro/register-advanced-admi.html', all_roles=roles, all_users=users)

########################             Pagina Principal               ####################################################

@app.route('/dashboard')
@login_required
def dashboard():
   return render_template('Paginas/Pagina_portales/Portal_Base.html')

@app.route('/Proyectos Analitica')
@login_required
def Proyectos_Analitica():
   return render_template('Menu_pages/Proyectos Analitica2.html')


@app.route('/formulario_Analitica')
@login_required
def formulario_Analitica():
   return render_template('Menu_pages/Formulario Proyectos2.html')

#######################               REPORTE PARA TODOS            #####################################################


@app.route('/SBS_MORA', methods=['GET', 'POST'])
@login_required
def reporte_SBS_MORA():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/SBS_MORA.html', all_roles=roles, all_users=users)

@app.route('/SBS_FINANCIERO', methods=['GET', 'POST'])
@login_required
def reporte_SBS_FINANCIERO():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/SBS_FINANCIERO.html', all_roles=roles, all_users=users)

########################################################################################################################
#PAGINAS ---------- MODIFICAR A PARTIR DE AQUI -------------------------------
########################################################################################################################

############################# CUMPLIMIENTO #############################################################################
@app.route('/CUMPLIMIENTO', methods=['GET', 'POST'])
@login_required
@roles_required('CUMPLIMIENTO','admin')
def Pagina_Cumplimiento():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_portales/Portal_Cumplimiento.html', all_roles=roles, all_users=users)

@app.route('/CUMPLIMIENTO/REPORTE_8UIT', methods=['GET', 'POST'])
@login_required
@roles_required('CUMPLIMIENTO','admin')
def reporte_cumplimiento_8uit():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/Cumplimiento/Reporte_8UIT.html', all_roles=roles, all_users=users)

@app.route('/CUMPLIMIENTO/REPORTE_TC', methods=['GET', 'POST'])
@login_required
@roles_required('CUMPLIMIENTO','admin')
def reporte_cumplimiento_TC():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/Cumplimiento/Programacion_TC.html', all_roles=roles, all_users=users)

############################# BANCA DIGITAL ############################################################################

@app.route('/BANCA_DIGITAL', methods=['GET', 'POST'])
@login_required
@roles_required('BANCA DIGITAL','admin')
def Pagina_Bancadigital():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_portales/Portal_BancaDigital.html', all_roles=roles, all_users=users)

@app.route('/BANCA_DIGITAL/PAGALO', methods=['GET', 'POST'])
@login_required
@roles_required('BANCA DIGITAL','admin')
def reporte_bancadigital_pagalo():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/Banca Digital/PAGALO.html', all_roles=roles, all_users=users)


############################# AUDITORIA INTERNA ########################################################################

@app.route('/AUDITORIA_INTERNA', methods=['GET', 'POST'])
@login_required
@roles_required('AUDITORIA INTERNA','admin')
def Pagina_Auditoriainterna():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_portales/Portal_Auditoria.html', all_roles=roles, all_users=users)

@app.route('/AUDITORIA_INTERNA/REPORTE_OPERACIONES', methods=['GET', 'POST'])
@login_required
@roles_required('AUDITORIA INTERNA','admin')
def reporte_auditoriainterna_roperaciones():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/Auditoria interna/Reporte operaciones.html', all_roles=roles, all_users=users)


############################# INCLUSION FINANCIERA #####################################################################

@app.route('/INCLUSION_FINANCIERA', methods=['GET', 'POST'])
@login_required
@roles_required('INCLUSION FINANCIERA','admin')
def Pagina_Inclusionfinanciera():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_portales/Portal_Inclusion.html', all_roles=roles, all_users=users)

@app.route('/INCLUSION_FINANCIERA/IMPACTO BCP', methods=['GET', 'POST'])
@login_required
@roles_required('INCLUSION FINANCIERA','admin')
def reporte_inclusionfinanciera_impactobcp():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/Inclusion Financiera/Impacto BCP.html', all_roles=roles, all_users=users)

############################# AUDITORIA INTERNA ######################################################################

@app.route('/FRAUDES', methods=['GET', 'POST'])
@login_required
@roles_required('FRAUDES','RIESGOS','admin')
def Pagina_Fraudes():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_portales/Portal_Fraudes.html', all_roles=roles, all_users=users)

@app.route('/FRAUDES/REPORTE_FRAUDES', methods=['GET', 'POST'])
@login_required
@roles_required('FRAUDES','RIESGOS','admin')
def reporte_fraudes_operaciones():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/Fraudes/Reporte_Fraudes.html', all_roles=roles, all_users=users)

############################# RIESGOS  ##############################################################################

@app.route('/RIESGOS', methods=['GET', 'POST'])
@login_required
@roles_required('RIESGOS','FRAUDES','admin')
def Pagina_riesgos():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_portales/Portal_Riesgos.html', all_roles=roles, all_users=users)

@app.route('/RIESGOS/REPORTE_FRAUDES', methods=['GET', 'POST'])
@login_required
@roles_required('RIESGOS','FRAUDES','admin')
def reporte_riesgos_scoring():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('Paginas/Pagina_reportes/Riesgos/Reporte_Scoring.html', all_roles=roles, all_users=users)
if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    app.run()
 #app.run(debug=True)host='0.0.0.0', port=5000,v
