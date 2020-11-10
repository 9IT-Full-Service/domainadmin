from flask import Flask, render_template, request, redirect, url_for
from flask_mongoengine import MongoEngine, Document
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import Email, Length, InputRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from bson.json_util import dumps
from flask_cors import CORS
import os
import time
import requests
import json
import logging
import socket
import ssl
import datetime
import sys


UPLOAD_FOLDER = '/app/static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
# MyAnonymousUser = "Nobody"
app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'db': 'domainadmin',
    # 'host': 'mongodb://',
    'host': 'mongodb://mongo/domainadmin?retryWrites=true&w=majority'
}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = MongoEngine(app)
app.config["SECRET_KEY"] = "OCML3BRawWEUeaxcuKHLpw"
cors = CORS(app, resources={r"/*": {"origins": "*"}})
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# login_manager.anonymous_user = MyAnonymousUser

class User(UserMixin, db.Document):
    meta = {'collection': 'users'}
    email = db.StringField(max_length=30)
    password = db.StringField()
    userlevel = db.StringField()
    # name = db.StringField()
    # meta = {'strict': False}

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

class RegForm(FlaskForm):
    email = StringField('email',  validators=[InputRequired(), Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])
    # name = StringField('name', validators=[InputRequired(),Length(min=3, max=30)])

@app.route('/')
@login_required
def index():
    # data = read_categories()
    # categories = {}
    # for d in data:
    #     categories[id] = d['name']
    profileExtras = getProfileExtras()
    for i in profileExtras:
        name=i['name']
    if current_user.is_authenticated:
        return render_template('index.html',
          pwhash=current_user.password,
          userlevel=current_user.userlevel,
          userid=current_user.id,
          data=read_domains(),
          # categories=categories,
          # cats=read_categories(),
          # categories=read_categories(),
          name=name,
          # userlist=read_userlist(),
          loggedIn = "1",
        )
    else:
        return render_template('index.html',
            loggedIn = "0",
            data=read_markedplace_active(),
            categories=categories,
        )

@app.route('/dashboard/profil', methods=['GET'])
@login_required
def dashboardProfil():
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = getProfileExtras()
    for i in profileExtras:
        name=i['name']
    # print ("Name: " + str(profileExtras) ) # + " test: " + profileExtras)
    # x = dict(profileExtras)
    # print ("X: ", x['name'])
    return render_template('profil.html',
      email=current_user.email,
      password=current_user.password,
      userlevel=current_user.userlevel,
      userid=current_user.id,
      profileExtras=profileExtras,
      name=name,
      categories=read_categories(),
      loggedIn = loggedIn
    )

@app.route('/dashboard/profil/save', methods=['POST'])
@login_required
def dashboardProfilSave():
    name = str(request.form['name'])
    email = request.form['email']
    userid = request.form['userid']
    print ("seller: " + userid)
    apiurl = "http://api:4006/api/v1/marketplace/profil/edit"
    data = {
        'id': userid,
        'name': name,
        'email': email
        }
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    r = requests.post(apiurl, json=dumps(data), headers=headers)
    return redirect(url_for('dashboard'))


@app.route('/newdomain', methods=['POST'])
def addItemSave():
    # print ("Title: " + request.form['title'])
    domain = str(request.form['domain'])
    description = request.form['description']
    registrar = request.form['registrar']
    dnsserver = request.form['dnsserver']
    seller=current_user.id
    apiurl = "http://api:4006/api/v1/domain/add"
    data = {
        'domain': domain,
        'description': description,
        'registrar': registrar,
        'dnsserver': dnsserver,
        }
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    r = requests.post(apiurl, json=dumps(data), headers=headers)
    return redirect(url_for('index'))

@app.route('/newdomain', methods=['GET'])
def addItem():
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = getProfileExtras()
    for i in profileExtras:
        name=i['name']
    return render_template('newdomain.html',
        seller=current_user.id,
        name=name,
        loggedIn=loggedIn
        )

@app.route('/view/<id>', methods=['GET'])
@login_required
def viewOffer(id):
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = getProfileExtras()
    for i in profileExtras:
        name=i['name']
    # categories = read_categories()
    data = read_domain_data(id)
    # print ("data: " + str(data))
    return render_template('domain.html',
      name=name,
      pwhash=current_user.password,
      userlevel=current_user.userlevel,
      userid=current_user.id,
      data=data,
      id=id,
      # categories=categories,
      userlist=read_userlist(),
      loggedIn=loggedIn
    )

@app.route('/sslcheck/all', methods=['GET'])
# @login_required
def sslcheckAll():
    domains = read_domains()
    for data in domains:
        print ("Domain: " + data['domain'])
        sslcheck(data['domain'])
        # /api/v1/domainadmin/sslexpire/<hostname>
    return redirect(url_for('sslexpirelist'))

@app.route('/sslexpirelist', methods=['GET'])
@login_required
def sslexpirelist():
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = getProfileExtras()
    for i in profileExtras:
        name=i['name']
    return render_template('sslexpirelist.html',
      email=current_user.email,
      password=current_user.password,
      userlevel=current_user.userlevel,
      userid=current_user.id,
      name=name,
      data=getsslexpirelist(),
      loggedIn = loggedIn
    )

def getsslexpirelist():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/domainadmin/sslexpire/list"
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

# @app.route('/category/<id>', methods=['GET'])
# @login_required
# def categoryId(id):
#     data = read_categories()
#     categories = {}
#     for d in data:
#         categories[id] = d['name']
#     profileExtras = getProfileExtras()
#     for i in profileExtras:
#         name=i['name']
#     if current_user.is_authenticated:
#         return render_template('index.html',
#           pwhash=current_user.password,
#           userlevel=current_user.userlevel,
#           userid=current_user.id,
#           # data=read_markedplace_active(),
#           data=read_category_active(id),
#           # categories=categories,
#           # cats=read_categories(),
#           categories=read_categories(),
#           name=name,
#           userlist=read_userlist(),
#           loggedIn = "1",
#         )
#     else:
#         return render_template('index.html',
#             loggedIn = "0",
#             data=read_markedplace_active(),
#             categories=categories,
#         )

@app.route('/dashboard')
@login_required
def dashboard():
    name = ""
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = getProfileExtras()
    for i in profileExtras:
        if i['name']:
            name=i['name']
    # data = read_categories()
    # categories = {}
    # for d in data:
    #     categories[id] = d['name']
    return render_template('dashboard.html',
      name=name,
      pwhash=current_user.password,
      userlevel=current_user.userlevel,
      userid=current_user.id,
      # data=read_markedplace(),
      data=read_marketplace_my(),
      # categories=categories,
      # categories=read_categories(),
      userlist=read_userlist(),
      loggedIn=loggedIn
      # uploads=read_uploads()
    )

@app.route('/dashboard/offer/<id>')
@login_required
def dashboardOffer(id):
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = getProfileExtras()
    for i in profileExtras:
        name=i['name']
    data = read_markedplace_myoffer(id)
    return render_template('dashboard_offer.html',
      name=name,
      pwhash=current_user.password,
      userlevel=current_user.userlevel,
      userid=current_user.id,
      data=data,
      id=id,
      uploads=read_uploads(),
      categories=read_categories(),
      loggedIn=loggedIn
    )

@app.route('/domain/edit/<id>', methods=['GET'])
@login_required
def dashboardOfferEdit(id):
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = getProfileExtras()
    for i in profileExtras:
        name=i['name']
    # categories = read_categories()
    data = read_domain_data(id)
    # print ("data: " + str(data))
    return render_template('editdomain.html',
      name=name,
      pwhash=current_user.password,
      userlevel=current_user.userlevel,
      userid=current_user.id,
      data=data,
      id=id,
      # categories=categories,
      # userlist=read_userlist(),
      # uploads=read_uploads(),
      loggedIn=loggedIn
    )

@app.route('/domain/save/<id>', methods=['POST'])
@login_required
def dashboardOfferSave(id):
    domain = str(request.form['domain'])
    description = request.form['description']
    registrar = request.form['registrar']
    dnsserver = request.form['dnsserver']
    po = request.form['po']
    techc = request.form['techc']
    ssl = request.form['ssl']
    apiurl = "http://api:4006/api/v1/domainadmin/domain/edit"
    data = {
        'id': id,
        'domain': domain,
        'description': description,
        'registrar': registrar,
        'dnsserver': dnsserver,
        'po': po,
        'techc': techc,
        'ssl': ssl,
        }
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    r = requests.post(apiurl, json=dumps(data), headers=headers)
    return redirect(url_for('index'))

# @app.route('/domain/sslexpire/<hostname>', methods=['GET'])
# @login_required
# def ssl_expiry_datetime(hostname):
#     now = datetime.datetime.now()
#     ssl_dateformat = r'%b %d %H:%M:%S %Y %Z'
#     context = ssl.create_default_context()
#     context.check_hostname = False
#     conn = context.wrap_socket(
#         socket.socket(socket.AF_INET),
#         server_hostname=hostname,
#     )
#     conn.settimeout(5.0)
#     conn.connect((hostname, 443))
#     ssl_info = conn.getpeercert()
#     expire = datetime.datetime.strptime(ssl_info['notAfter'], ssl_dateformat)
#     # expire = ssl_expiry_datetime(domain)
#     diff = expire - now
#     # print ("Domain name: {} Expiry Date: {} Expiry Day: {}".format(domain,expire.strftime("%Y-%m-%d"),diff.days))
#     return print ("Expiry Date: {} Expiry Day: {}".format(expire.strftime("%Y-%m-%d"),diff.days))
#     # return datetime.datetime.strptime(ssl_info['notAfter'], ssl_dateformat)

# if __name__ == "__main__":
#     now = datetime.datetime.now()
#     try:
#         expire = ssl_expiry_datetime(domain)
#         diff = expire - now
#         # print ("Domain name: {} Expiry Date: {} Expiry Day: {}".format(domain,expire.strftime("%Y-%m-%d"),diff.days))
#         print ("Expiry Date: {} Expiry Day: {}".format(expire.strftime("%Y-%m-%d"),diff.days))
#     except Exception as e:
#         print (e)



# @app.route('/upload', methods=['GET', 'POST'])
# def upload_file():
#     if current_user.is_authenticated:
#         loggedIn = "1"
#     profileExtras = getProfileExtras()
#     for i in profileExtras:
#         name=i['name']
#     if request.method == 'POST':
#         # check if the post request has the file part
#         if 'file' not in request.files:
#             flash('No file part')
#             return redirect(request.url)
#         file = request.files['file']
#         # if user does not select file, browser also
#         # submit an empty part without filename
#         if file.filename == '':
#             flash('No selected file')
#             return redirect(request.url)
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             filename = str(current_user.id) + "_" + str(time.time()) + "_" + str(file.filename)
#             print ("Filename: " + filename)
#             save_upload(filename)
#             file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#             return redirect(url_for('upload_file',
#                                     filename=filename))
#     return render_template('upload.html',
#         uploads=read_uploads(),
#         loggedIn=loggedIn,
#         categories=read_categories(),
#         name=name
#     )

@app.route('/logout', methods = ['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegForm()
    if request.method == 'POST':
        print ("Mail: " + form.email.data)
        if form.validate():
            print ("Validated")
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = generate_password_hash(form.password.data, method='sha256')
                # hey = User(form.email.data,hashpass).save()
                hey = User(email=form.email.data,password=hashpass).save()
                login_user(hey)
                iddata = getProfileId(form.email.data)
                for i in iddata:
                    id=i['id']
                print ("ID: " + id )
                verifyhash = generate_password_hash(id, method='sha256')
                profileFieldUpdate(id,'verify',verifyhash)
                profileFieldUpdate(id,'name',id)
                # sendVerifyMail(id,verifyhash,form.email.data)
                return redirect(url_for('dashboard'))
        else:
            print ("Nicht validiert.")
    return render_template('register.html', form=form)

@app.route('/verify/<id>/<hash>', methods=['GET'])
def verifyhash(id,hash):
    # userid verify
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/profile/verify/" + id + "/" + hash
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

@app.route('/register/test', methods=['GET', 'POST'])
def registerTest():
    # form = RegForm()
    existing_user = User.objects(email='test@9it.de').first()
    if existing_user is None:
        hashpass = generate_password_hash('oldwinnt', method='sha256')
        hey = User(email='test@9it.de',password=hashpass).save()
        # login_user(hey)
        iddata = getProfileId('test@9it.de')
        for i in iddata:
            id=i['id']
        print ("ID: " + id )
        profileFieldUpdate(id,'verify',generate_password_hash(id, method='sha256'))
    return ("ID: " + id )

    # if request.method == 'POST':
    #     print ("Mail: " + form.email.data)
    #     if form.validate():
    #         existing_user = User.objects(email=form.email.data).first()
    #         if existing_user is None:
    #             hashpass = generate_password_hash(form.password.data, method='sha256')
    #             # hey = User(form.email.data,hashpass).save()
    #             hey = User(email=form.email.data,password=hashpass).save()
    #             login_user(hey)
    #             id = getProfileId(form.email.data)
    #             profileFieldUpdate(id['id'],'verify',generate_password_hash(id['id'], method='sha256'))
    #             return redirect(url_for('dashboard'))
    # return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated == True:
        return redirect(url_for('dashboard'))
    else:
        loggedIn = True
    form = RegForm()
    if request.method == 'POST':
        if form.validate():
            check_user = User.objects(email=form.email.data).first()
            if check_user:
                if check_password_hash(check_user['password'], form.password.data):
                    login_user(check_user)
                    return redirect(url_for('dashboard'))
    return render_template('login.html', form=form, loggedIn=loggedIn)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(filename):
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/uploads/" + str(current_user.id) + "/" + filename
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_markedplace():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/" + str(current_user.id)
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def sslcheck(domain):
    data = {}
    print ("Check domain: " + domain)
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/domainadmin/sslexpire/" + domain
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_domains():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/domainadmin/list"
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_category_active(id):
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/categoryactive/" + id
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_markedplace_open():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/open"
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def sendVerifyMail(id,verifyhash,mail):
    data = {}
    import urllib, json
    import urllib.request
    userid = current_user.id
    apiurl = "http://api:4006/api/v1/marketplace/profile/sendverify/" + id + "/" + mail + "/" + verifyhash
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def getProfileExtras():
    data = {}
    import urllib, json
    import urllib.request
    userid = current_user.id
    apiurl = "http://api:4006/api/v1/marketplace/profile/extras/" + str(userid)
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def getProfileId(email):
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/profile/id/" + email
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def profileFieldUpdate(id,key,value):
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/profile/setfield/" + id + "/" + key + "/" + value
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_categories():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/categories"
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_domain_data(id):
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/domainadmin/domain/" + id
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_marketplace_my():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/my/" + str(current_user.id)
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_markedplace_myoffer(id):
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/myone/" + id
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

def read_userlist():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/profile/users"
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data


def read_uploads():
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/marketplace/uploads/" + str(current_user.id)
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

if __name__ == "__main__":
  app.run(debug=True,host='0.0.0.0', port=4006)
