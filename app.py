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
import urllib, json
import urllib.request
# import dnspython as dns
import dns.resolver

from domainadmin.Profile import Profile
from domainadmin.Ssl import Ssl
from domainadmin.Tools import Tools
from domainadmin.Api import Api


app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'db': 'domainadmin',
    'host': 'mongodb://mongo/domainadmin?retryWrites=true&w=majority'
}

db = MongoEngine(app)
app.config["SECRET_KEY"] = str(os.environ.get("SECRET_KEY"))
cors = CORS(app, resources={r"/*": {"origins": "*"}})
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Document):
    meta = {'collection': 'users'}
    email = db.StringField(max_length=50)
    password = db.StringField()
    userlevel = db.StringField()

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

class RegForm(FlaskForm):
    email = StringField('email',  validators=[InputRequired(), Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])

@app.route('/')
@login_required
def index():
    for i in Profile.getProfileExtras(current_user.id):
        name=i['name']
    if current_user.is_authenticated:
        return render_template('index.html',
            pwhash=current_user.password,
            userlevel=current_user.userlevel,
            userid=current_user.id,
            data=Api.readApi("http://api:4006/api/v1/domainadmin/list"),
            name=name,
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
    profileExtras = Profile.getProfileExtras(current_user.id)
    for i in profileExtras:
        name=i['name']
    return render_template('profil.html',
        email=current_user.email,
        password=current_user.password,
        userlevel=current_user.userlevel,
        userid=current_user.id,
        profileExtras=profileExtras,
        name=name,
        loggedIn = loggedIn
    )

@app.route('/dashboard/profil/save', methods=['POST'])
@login_required
def dashboardProfilSave():
    name = str(request.form['name'])
    email = request.form['email']
    userid = request.form['userid']
    apiurl = "http://api:4006/api/v1/domainadmin/profil/edit"
    data = {
        'id': userid,
        'name': name,
        'email': email
    }
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    r = requests.post(apiurl, json=dumps(data), headers=headers)
    return redirect(url_for('dashboardProfil'))

@app.route('/newdomain', methods=["GET","POST"])
def addDomain():
    print ("Method: " + str(request.method))
    if request.method == 'POST':
        domain = str(request.form['domain'])
        description = request.form['description']
        registrar = request.form['registrar']
        dnsserver = request.form['dnsserver']
        seller=current_user.id
        apiurl = "http://api:4006/api/v1/domainadmin/add"
        data = {
            'domain': domain,
            'description': description,
            'registrar': registrar,
            'dnsserver': dnsserver,
            }
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(apiurl, json=dumps(data), headers=headers)
        return redirect(url_for('index'))
    else:
        if current_user.is_authenticated:
            loggedIn = "1"
        profileExtras = Profile.getProfileExtras(current_user.id)
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
    profileExtras = Profile.getProfileExtras(current_user.id)
    for i in profileExtras:
        name=i['name']
    # data = read_domain_data(id)
    data = Api.readApi("http://api:4006/api/v1/domainadmin/domain/" + id)
    return render_template('domain.html',
        name=name,
        pwhash=current_user.password,
        userlevel=current_user.userlevel,
        userid=current_user.id,
        data=data,
        id=id,
        loggedIn=loggedIn
    )

@app.route('/sslcheck/all', methods=['GET'])
# @login_required
def sslcheckAll():
    domains = Api.readApi("http://api:4006/api/v1/domainadmin/list")
    for data in domains:
        # print ("Check SSL: " + data['domain'] )
        # if data['ssl'] != "no" or typeof data['ssl'] !== "undefined":
        Ssl.check(data['domain'])
        # else:
            # print ("Wird nicht getestet: " + data['domain'] )
    return redirect(url_for('sslexpirelist'))

@app.route('/sslexpirelist', methods=['GET'])
@login_required
def sslexpirelist():
    if current_user.is_authenticated:
        loggedIn = "1"
    profileExtras = Profile.getProfileExtras(current_user.id)
    for i in profileExtras:
        name=i['name']
    return render_template('sslexpirelist.html',
        email=current_user.email,
        password=current_user.password,
        userlevel=current_user.userlevel,
        userid=current_user.id,
        name=name,
        data=Ssl.expirelist(),
        loggedIn = loggedIn
    )

@app.route('/dns/<domain>', methods=["GET"])
def dns(domain):
    records = Tools.dnsQuery(domain)
    return (str(records) )

@app.route('/domain/edit/<id>', methods=['GET','POST'])
@login_required
def domainEdit(id):
    if request.method == 'POST':
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
    else:
        if current_user.is_authenticated:
            loggedIn = "1"
        profileExtras = Profile.getProfileExtras(current_user.id)
        for i in profileExtras:
            name=i['name']
        # data = read_domain_data(id)
        data = Api.readApi("http://api:4006/api/v1/domainadmin/domain/" + id)
        return render_template('editdomain.html',
            name=name,
            pwhash=current_user.password,
            userlevel=current_user.userlevel,
            userid=current_user.id,
            data=data,
            id=id,
            loggedIn=loggedIn
        )

@app.route('/logout', methods = ['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegForm()
    if request.method == 'POST':
        if form.validate():
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = generate_password_hash(form.password.data, method='sha256')
                hey = User(email=form.email.data,password=hashpass).save()
                login_user(hey)
                iddata = Profile.getProfileId(form.email.data)
                for i in iddata:
                    id=i['id']
                verifyhash = generate_password_hash(id, method='sha256')
                Profile.profileFieldUpdate(id,'verify',verifyhash)
                Profile.profileFieldUpdate(id,'name',id)
                return redirect(url_for('index'))
        else:
            render_template('register.html', form=form)
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated == True:
        return redirect(url_for('index'))
    else:
        loggedIn = True
    form = RegForm()
    if request.method == 'POST':
        # if form.validate():
            check_user = User.objects(email=form.email.data).first()
            if check_user:
                if check_password_hash(check_user['password'], form.password.data):
                    login_user(check_user)
                    return redirect(url_for('index'))
    return render_template('login.html', form=form, loggedIn=loggedIn)


@app.route('/verify/<id>/<hash>', methods=['GET'])
def verifyhash(id,hash):
    data = {}
    import urllib, json
    import urllib.request
    apiurl = "http://api:4006/api/v1/domainadmin/profile/verify/" + id + "/" + hash
    response = urllib.request.urlopen(apiurl)
    data = json.loads(response.read())
    return data

@app.route('/register/test', methods=['GET', 'POST'])
def registerTest():
    existing_user = User.objects(email='test@9it.de').first()
    if existing_user is None:
        hashpass = generate_password_hash('supersecret', method='sha256')
        hey = User(email='test@9it.de',password=hashpass).save()
        iddata = Profile.getProfileId('test@9it.de')
        for i in iddata:
            id=i['id']
        Profile.profileFieldUpdate(id,'verify',generate_password_hash(id, method='sha256'))
    return ("ID: " + id )

if __name__ == "__main__":
  app.run(debug=True,host='0.0.0.0', port=4006)
