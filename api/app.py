from flask import render_template, request, session, redirect, url_for
from flask_jsonpify import jsonify
from flask import Flask, flash, redirect, render_template, request, session, abort, current_app
from flask_restful import Resource, Api
from flask_cors import CORS
from bson.objectid import ObjectId
from bson.json_util import dumps, loads
from datetime import datetime
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
import json
import os,fnmatch
import logging
import requests
import time
import re
import natsort
import pymongo
import socket
import ssl
import datetime
import smtplib

app = Flask(__name__)
app.config["SECRET_KEY"] = "OCML3BRawWEUeaxcuKHLpw"
cors = CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/api/v1/status', methods=["GET"])
def apistatus():
    return jsonify({"status":"ok"})

@app.route('/api/v1/marketplace/profil/edit', methods=["POST"])
def profilUpdate():
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["users"]
    content = json.loads(request.get_json())
    ObjId = content['id']
    x = mycol.update_one(
        { "_id" : ObjectId(ObjId) },
        { "$set": {
            'email': content['email'] }
        } )
    profilExtrasUpdate(content)
    return jsonify({"result":"ok"}), 201

@app.route('/api/v1/marketplace/profile/extras/<id>', methods=["GET"])
def profileExtras(id):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["profile"]
    mydoc = mycol.find({"userid": id})
    list_cur = list(mydoc)
    json_data = dumps(list_cur, indent = 2, default=str)
    return json_data, 200

@app.route('/api/v1/marketplace/profile/users', methods=["GET"])
def profileUser():
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["profile"]
    mydoc = mycol.find()
    list_cur = list(mydoc)
    json_data = dumps(list_cur, indent = 2, default=str)
    return json_data, 200

@app.route('/api/v1/marketplace/profile/id/<email>', methods=['GET'])
def getIdByEmail(email):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["users"]
    # mydoc = mycol.aggregate( [ { "$match" : { "_id" : ObjectId(id) } }, { "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
    mydoc = mycol.aggregate( [ { "$match" : { "email" : email } }, { "$project": {"id": {"$toString": '$_id' } } } ] )
    list_cur = list(mydoc)
    json_data = dumps(list_cur, indent = 2, default=str)
    return json_data, 200

@app.route('/api/v1/marketplace/profile/setfield/<id>/<key>/<value>', methods=['GET'])
def setProfileField(id,key,value):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["profile"]
    print ("Test: " + id )
    x = mycol.update_one(
        { "userid" : id },
        { "$set": {
            key: value }
        },upsert=True )
    return jsonify({"result":"ok"}), 201

@app.route('/api/v1/domainadmin/list', methods=["GET"])
def domain_list():
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["domains"]
    # mydoc = mycol.aggregate([ { "$match" : { "active" : "1" } },{ "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
    mydoc = mycol.aggregate([ { "$project": {"id": {"$toString": '$_id' }, "domain": "$domain", "registrar": "$registrar",
        "dnsserver": "$dnsserver", "description": "$description"} } ] )
    list_cur = list(mydoc)
    json_data = dumps(list_cur, indent = 2, default=str)
    return json_data, 200

@app.route('/api/v1/domainadmin/domain/<id>', methods=["GET"])
def marktplace(id):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["domains"]
    mydoc = mycol.aggregate( [ { "$match" : { "_id" : ObjectId(id) } }, { "$project": {"id": {"$toString": '$_id' },
        "domain": "$domain", "registrar": "$registrar", "dnsserver": "$dnsserver",
        "description": "$description", "dnsserver":"$dnsserver", "po": "$po", "techc": "$techc", "ssl": "$ssl",
        "sslissuer": "$sslissuer", "ssldnsnames": "$ssldnsnames", "sslexpiredate": "$sslexpiredate",
        "sslexpiredays": "$sslexpiredays", "commonname": "$commonname"
         } } ] )
    list_cur = list(mydoc)
    json_data = dumps(list_cur, indent = 2, default=str)
    return json_data, 200

@app.route('/api/v1/domainadmin/sslexpire/list', methods=['GET'])
def sslexpireList():
    # db.domains.aggregate( [ { $sort: { sslexpiredays: 1 } } ] )
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["domains"]
    mydoc = mycol.aggregate( [ { "$sort": { "sslexpiredays": 1 } } ] )
    list_cur = list(mydoc)
    json_data = dumps(list_cur, indent = 2, default=str)
    return json_data, 200

@app.route('/api/v1/domainadmin/domain/edit', methods=["POST"])
def offerUpdate():
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["domains"]
    content = json.loads(request.get_json())
    ObjId = content['id']
    x = mycol.update(
        { "_id" : ObjectId(ObjId) },
        { "$set": {
            'domain': content['domain'],
            'description': content['description'],
            'registrar': content['registrar'],
            'dnsserver': content['dnsserver'],
            'po': content['po'],
            'techc': content['techc'],
            'ssl': content['ssl'],
           }
        } )
    return jsonify({"result":"ok"}), 201

@app.route('/api/v1/domain/add', methods=["POST"])
def addItem():
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["domains"]
    content = request.get_json()
    x = mycol.insert(  json.loads(content) )
    return jsonify({"result":"ok"}), 201

@app.route('/api/v1/marketplace/sendmail/<to>', methods=['GET'])
def sendemail(to):
    msg = MIMEMultipart()
    message = "Test from Python via AuthSMTP"
    password = "zkHycC1zVWmw"
    username = "web05@9it-server.de"
    smtphost = "mail01.9it.de:587"
    msg['From'] = "web05@9it-server.de"
    msg['To'] = to # "ruediger@kuepper.nrw"
    msg['Subject'] = "Test from Python via AuthSMTP"
    msg.attach(MIMEText(message, 'plain'))
    server = smtplib.SMTP(smtphost)
    server.starttls()
    server.login(username, password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()
    return ( "Successfully sent email message to %s:" % (msg['To']) )

@app.route('/api/v1/marketplace/profile/sendverify/<id>/<mail>/<verifyhash>', methods=['GET'])
def sendVerifyMail(id,mail,verifyhash):
    msg = MIMEMultipart()
    message = "Freischaltlink: \nhttp://localhost:8090/verify/" + id + "/" + verifyhash
    password = "zkHycC1zVWmw"
    username = "web05@9it-server.de"
    smtphost = "mail01.9it.de:587"
    msg['From'] = "web05@9it-server.de"
    msg['To'] = mail # "ruediger@kuepper.nrw"
    msg['Subject'] = "Marktplatz Freischaltung "
    msg.attach(MIMEText(message, 'plain'))
    server = smtplib.SMTP(smtphost)
    server.starttls()
    server.login(username, password)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()
    return jsonify({"result":"send mail"}), 201
    # return ( "Successfully sent email message to %s:" % (msg['To']) )

@app.route('/api/v1/marketplace/profile/verify/<id>/<hash>', methods=['GET'])
def profileVerify(id,hash):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["marketplace"]
    mycol = mydb["profile"]
    mydoc = mycol.find({
        "userid": id,
        "verify": hash
        }).count
    print ("mydoc: " + str(mydoc[0]))
    if mydoc == 1:
        result = "True"
    elif mydoc == 0:
        result = "False"
    # list_cur = list(mydoc)
    # showverify = list_cur[0]["verify"]
    # json_data = dumps(list_cur, indent = 2, default=str)
    # print ("json: " + json_data)
    return result, 200

@app.route('/api/v1/domainadmin/sslexpire/<hostname>', methods=['GET'])
def ssl_expiry_datetime(hostname):
    now = datetime.datetime.now()
    ssl_dateformat = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.settimeout(30.0)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    dns = ""
    issuer = ssl_info['issuer']
    subject = ssl_info['subject']
    issuername = str(issuer[1][0][1])
    altnames = ssl_info['subjectAltName']
    commonName = str(subject[0][0][1])
    for alt in altnames:
        dns = dns + " " + alt[1]
    expire = datetime.datetime.strptime(ssl_info['notAfter'], ssl_dateformat)
    diff = expire - now
    domainField(hostname,"sslissuer",issuername)
    domainField(hostname,"ssldnsnames",("{}".format(dns)))
    domainField(hostname,"commonname",("{}".format(commonName)))
    domainField(hostname,"sslexpiredate",expire.strftime("%Y-%m-%d %H:%M:%S"))
    value = domainField(hostname,"sslexpiredays",diff.days)
    return value

def domainField(hostname,key,value):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["domains"]
    x = mycol.update_one(
        { "domain" : hostname },
        { "$set": {
            key: value }
        },upsert=True )
    return jsonify({"result":"ok"}), 201


def profilExtrasUpdate(content):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["profile"]
    # print ("Test: " + content['id'])
    ObjId = content['id']
    x = mycol.update_one(
        { "userid" : ObjId },
        { "$set": {
            'name': content['name'] }
        },upsert=True )
    return jsonify({"result":"ok"}), 201

def profilUpdateField(id,key,value):
    myclient = pymongo.MongoClient("mongodb://mongo:27017/")
    mydb = myclient["domainadmin"]
    mycol = mydb["profile"]
    # print ("Test: " + content['id'])
    ObjId = content['id']
    ObjId = id
    x = mycol.update_one(
        { "userid" : ObjId },
        { "$set": {
            key: value }
        },upsert=True )
    return jsonify({"result":"ok"}), 201

def p_debug(str):
    app.logger.info("Debug: ", str)
    return

def to_pretty_json(value):
    return json.dumps(value, sort_keys=false,
                      indent=4, separators=(',', ': '))

app.jinja_env.filters['tojson_pretty'] = to_pretty_json

if __name__ == "__main__":
  app.run(debug=True,host='0.0.0.0', port=4006)


# @app.route('/api/v1/marketplace/open', methods=["GET"])
# def marktplace_open():
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["offers"]
#     mydoc = mycol.find({"active": "1"})
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200

# @app.route('/api/v1/marketplace/my/<id>', methods=["GET"])
# def marktplace_my(id):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["offers"]
#     # s = "\"seller\": " + id
#     mydoc = mycol.aggregate( [ { "$match" : { "seller" : id } }, { "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
#     # mydoc = mycol.aggregate( [ { "$match" : { "_id" : ObjectId(id) } }, { "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200

# @app.route('/api/v1/marketplace/myone/<id>', methods=["GET"])
# def marktplace_myoffer(id):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["offers"]
#     # s = "\"seller\": " + id
#     # mydoc = mycol.aggregate( [ { "$match" : { "seller" : id } }, { "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
#     mydoc = mycol.aggregate( [ { "$match" : { "_id" : ObjectId(id) } }, { "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200

# @app.route('/api/v1/marketplace/active', methods=["GET"])
# def marktplace_aktive():
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["offers"]
#     mydoc = mycol.aggregate([ { "$match" : { "active" : "1" } },{ "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200

# @app.route('/api/v1/marketplace/categoryactive/<id>', methods=["GET"])
# def category_aktive(id):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["offers"]
#     mydoc = mycol.aggregate([ { "$match" : { "active" : "1", "category": id } },{ "$project": {"id": {"$toString": '$_id' }, "title": "$title", "seller": "$seller", "price": "$price", "type": "$type", "category": "$category", "type": "$type", "image": "$image", "description": "$description", "active":"$active"} } ] )
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200

# @app.route('/api/v1/markplace/<id>', methods=["GET"])
# def marktplaceById(id):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marktplace"]
#     mycol = mydb["offer"]
#     s = "\"_id\": ObjectId('" + id + "')"
#     mydoc = mycol.aggregate([
#       { "$match": { s } },
#     ])
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200

# @app.route('/api/v1/marketplace/<id>', methods=["GET"])
# def marktplaceOffer(id):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["offers"]
#     mydoc = mycol.find({"_id": ObjectId(id) })
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200
#
# @app.route('/api/v1/marketplace/categories', methods=["GET"])
# def marktplaceCategories():
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["categories"]
#     mydoc = mycol.aggregate([ { "$project": {"id": {"$toString": '$_id' }, "active": "$active", "name": "$name" } } ] )
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200
#
# @app.route('/api/v1/marketplace/categories/<id>', methods=["GET"])
# def marktplaceCategoriesId(id):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["categories"]
#     mydoc = mycol.find({"_id": ObjectId(id)})
#     list_cur = list(mydoc)
#     cat_name = list_cur[0]["name"]
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return cat_name, 200
#
# @app.route('/api/v1/marketplace/uploads/<seller>/<filename>', methods=["GET"])
# def save_upload(seller,filename):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["uploads"]
#     mydict = { "seller": seller, "filename": filename }
#     x = mycol.insert_one(mydict)
#     return jsonify({"result":"ok - "}), 200
#
# @app.route('/api/v1/marketplace/uploads/<seller>', methods=["GET"])
# def getUploadBySeller(seller):
#     myclient = pymongo.MongoClient("mongodb://mongo:27017/")
#     mydb = myclient["marketplace"]
#     mycol = mydb["uploads"]
#     mydoc = mycol.find({"seller": seller})
#     list_cur = list(mydoc)
#     json_data = dumps(list_cur, indent = 2, default=str)
#     return json_data, 200
