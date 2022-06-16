'''
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
#======================================================
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
#======================================================

app = Flask(__name__)
#======================================================
auth = HTTPBasicAuth()
#======================================================

app.config["DEBUG"] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/erik/test.db'  # db location

db = SQLAlchemy(app)

is_admin = True  # For TEST purposes only


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(128), unique=False, nullable=False)
    group = db.Column(db.String(128), unique=False, nullable=True)

    def __repr__(self):
        return '<user %r>' % self.username


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(128), unique=True, nullable=False)
    size = db.Column(db.Integer, unique=False, nullable=False)
    last_modified = db.Column(db.DateTime)
    type = db.Column(db.String(32), unique=False, nullable=True)

    def __repr__(self):
        return '<file %r>' % self.filename


class Authorization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    authorization = db.Column(db.String(32), unique=False, nullable=False)

    def __repr__(self):
        return '<The authorization between %r and %r is %r.>' % (
            self.user, self.file, self.authorization)
AUTH_TYPES = ['unauthorized', 'read', 'write']  #


@auth.verify_password
def verify_password(username, password):
    #=====================================================
    user = User.query.filter_by(username=username).first()
    if not user:
        return False

    stored_hash = user.password

    if check_password_hash(stored_hash, password):
        return username
    #======================================================


# Utility functions:
def add_user(username, email, password, group=None):
    user = User(
        username=username,
        email=email,
        #---------------------------------------------------------
        password=generate_password_hash(password),
        #---------------------------------------------------------
        group=group)
    db.session.add(user)
    db.session.commit()


def add_file(filename, size, last_modified, type):
    split_date = last_modified.split('/')
    file = File(
        filename=filename,
        size=size,
        # String date format: DD/MM/YYYY
        last_modified=datetime(int(split_date[2]), int(split_date[1]),
                               int(split_date[0])),
        type=type)
    db.session.add(file)
    db.session.commit()

def add_auth(user_id, file_id, auth_type):
    new_auth = Authorization(
        user= user_id,
        file= file_id,
        authorization=auth_type
    )
    db.session.add(new_auth)
    db.session.commit()

def get_file_auth(username, filename):
    user = User.query.filter_by(username=username).first()
    user_id = user.id #take user id
    file = File.query.filter_by(filename=filename).first()
    file_id = file.id #take file id
    auth = Authorization.query.filter_by(user=user_id, file=file_id).first()
    if not auth:
        return {'auth_type' : 'None'}
    auth_type = auth.authorization
    return {
        'username' : username,
        'auth_type': auth_type,
        'filename' : filename
    }


# REST API
# Error handler
@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404


# Homepage
@app.route('/', methods=['GET'])
@auth.login_required
def home():
    return "Homepage"

# Admin
@app.route('/admin/add_user/', methods=['POST'])
def admin_add_user():
    if is_admin == True:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        add_user(username, email, password)
        # return "<h1>%s %s %s</h1>" % (username, email, password)
        return 'User Added!'
    else:
        return "<h1>You can't acces this page!</h1>"


@app.route('/admin/set_admin/', methods=['POST'])
def admin_set_admin():
    if is_admin == True:
        return "<h1>Set user as admin</h1>"
    else:
        return "<h1>You can't acces this page!</h1>"


@app.route('/admin/add_file/', methods=['POST'])
def admin_add_file():
    if is_admin == True:
        filename = request.form.get('filename')
        size = request.form.get('size')
        last_modified = request.form.get('last_modified')
        type = request.form.get('type')
        add_file(filename,size,last_modified,type)
        return "The file was added to the storage"
    else:
        return "<h1>You DON'T have the athorization to add a file!</h1>"

@app.route('/admin/add_auth/', methods=['POST'])
def admin_add_auth():
    if is_admin == True:
        user_id = request.form.get('user_id')
        file_id = request.form.get('file_id')
        auth_type = request.form.get('auth_type')
        add_auth(user_id, file_id, auth_type)
        return "The authorization was registered"
    else:
        return "<h1>You DON'T have the athorization to add a file!</h1>"

# DB interactions
@app.route('/storage/all/', methods=['GET'])
@auth.login_required
def storage_all():
    x = File.query.all()
    filelist = ", ".join([i.filename for i in x])
    return "<h1>%s</h1>" % filelist


@app.route('/storage', methods=['GET'])
@auth.login_required
def show_file_id():
    query_parameters = request.args
    id = query_parameters.get('id')
    filename = query_parameters.get('filename')
    if id:
        x = File.query.filter_by(id=id).first()
        return """
               <h1>Filename: %s - Size: %s Bit - Last modified: %s - Type: %s</h1>
               """ % (x.filename, x.size, x.last_modified, x.type)
    if filename:
        x = File.query.filter_by(filename=filename).first()
        return """
               <h1>Filename: %s - Size: %s Bit - Last modified: %s - Type: %s</h1>
               """ % (x.filename, x.size, x.last_modified, x.type)
    if not (id or filename):
        return page_not_found(404)

    return "<h1>Content not found.</h1>"

# User Page
@app.route('/user/<username>/<filename>/auth/', methods=['GET'])
@auth.login_required
def user_authorization(username, filename):
    if auth.current_user() == username: #check that current user is the same as route <username>
        if not File.query.filter_by(filename=filename).first():
            return 'There is no such file'
        auth_temp = get_file_auth(username, filename)
        if not auth_temp['auth_type']:
            return 'You have no authorization to access this file'
        return "You have the right to %s the %s file." % (
            auth_temp['auth_type'], filename)
        get_file_auth(username, filename)
    return 'You are not the right user!'




# Start application:
if __name__ == '__main__':
    app.run()


'''





# @app.route('/ping/', methods=['POST'])
# def ping():
#     username = request.form.get('username')
#     email = request.form.get('email')

#     return email
# Tests:
# def admin_check(user_id):
#     pass

# test_admin = add_user('admin', 'mail', '123456', 'admin')
# test_user = add_user('mario', 'mail@falsa.it', '1234')

# # Authentication OLD
# @app.route('/authentication/login/', methods=['POST'])
# def authentication_login():
#     auth = request.headers.get("Authorization", None)
#     body = request.body
#     print(body)
#     return "<h1>Login</h1>"


# @app.route('/authentication/logout/', methods=['GET'])
# def authentication_logout():
#     return "<h1>Logout</h1>"


