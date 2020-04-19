import base64
import json
import uuid
from functools import wraps
import requests
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from flask import request, render_template, url_for, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash
from werkzeug.utils import redirect
from application import app
from classes.fakeDB import fakeDB
from classes.crypto_helpers import getPublicKey

auth = HTTPBasicAuth()
DB = fakeDB()

# helper functions

@auth.verify_password
def verify_password(username, password):
    user = DB.getUser(username)
    if user:
        return check_password_hash(user.password, password)
    return False


@auth.error_handler
def auth_error():
    return "Access Denied"


def user_in_tenant_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = DB.getUser(request.authorization.username)
        tenant_id = kwargs.get('tenant_id')
        if not user or not user.tenant == tenant_id:
            return jsonify({"message": "user not in tenant"})
        return f(*args, **kwargs)

    return wrapper


# routes

# The tenant administrator can:
# • Create, view and delete user accounts within their own tenant
# • View all certificates and private keys within their own tenant
# • Encrypt documents for all other users within the tenant as any other user can

# A user can:
# • View their own certificate and private key
# • View all other users within the tenant along with their certificates but not their private keys
# • Encrypt data for any user within their own tenant
# • Decrypt data that was encrypted for them

# Cross-tenant actions is strictly forbidden.
@app.route("/", methods=["GET"])
@auth.login_required
def index():
    currentUsername = request.authorization.username
    currentPassword = request.authorization.password
    auth = (currentUsername, currentPassword)
    user = DB.getUser(currentUsername)
    tenantUsers = None
    me = None
    tenantid = user.tenant
    allUsers = requests.get(url=request.host_url + 'v1/' + tenantid + '/users', auth=auth)
    if allUsers.status_code == 200:
        tenantUsers = json.loads(allUsers.text)['users']
    myUser = requests.get(url=request.host_url + 'v1/' + tenantid + '/users/me', auth=auth)
    if myUser.status_code == 200:
        me = json.loads(myUser.text)

    if currentUsername in DB.getAllAdmins():
        return render_template("adminview.html", tenant=tenantid, me=me, users=tenantUsers, currentUser=currentUsername)

    elif currentUsername in DB.getAllUsers():
        return render_template("userview.html", tenant=tenantid, me=me, users=tenantUsers, currentUser=currentUsername,
                               messages=DB.getMessages(currentUsername))


# The registration API allows an anonymous user to register as a new tenant of the system.
# Inputs: username and password.
# Outputs: tenant-id
# request example: requests.post(url=request.host_url + 'v1/register', json={'username': 'newuser', 'password': 'newpass'})
@app.route("/v1/register", methods=["POST"])
def registerTenant():
    if request.form:
        uname = request.form['username'].strip()
        pword = request.form['password'].strip()
    else:
        json_data = request.get_json(force=True)
        uname = json_data['username'].strip()
        pword = json_data['password'].strip()
    if not uname or not pword:
        return jsonify({"message": "please provide username and password"})
    if uname in DB.getAllUsers():
        return jsonify({"message": "username already exists"})
    tenantID = str(uuid.uuid4())[:4]
    DB.newUser(uname, pword, tenantID)
    DB.makeUserAdmin(uname)
    return jsonify({"message": "you are now the admin of a new tenant", "tenant-id": tenantID})


# The user creation API allows a tenant administrator to create new users for the tenant that they manage
# Inputs: username and password for the new user
# Outputs: a user-id and user-certificate for the new user
# request example: requests.post(url=request.host_url+'v1/2a07/users', json={'username': 'hi2', 'password': 'hi2'},auth=auth)
@app.route("/v1/<tenant_id>/users", methods=["POST"])
@auth.login_required
@user_in_tenant_required
def careteTenantUsers(tenant_id):
    if DB.getTenantAdmin(tenant_id) == DB.getUserId(request.authorization.username):
        if request.form:
            uname = request.form['username'].strip()
            pword = request.form['password'].strip()
            if not uname or not pword or uname in DB.getAllUsers():
                #TODO: display warning in-page
                return render_template("error.html",msg="username already taken")
            user = DB.newUser(uname, pword, tenant_id)
            DB.addUsertoTenant(user)
            return redirect(url_for('index'))
        else:
            json_data = request.get_json(force=True)
            uname = json_data['username'].strip()
            pword = json_data['password'].strip()
        if not uname or not pword:
            return jsonify({"message": "please provide username and password"})
        if uname in DB.getAllUsers():
            return jsonify({"message": "username already exists"})
        user = DB.newUser(uname, pword, tenant_id)
        DB.addUsertoTenant(user)
        return jsonify({"message": "new user created in tenant", "user-id": user.userid,
                        "user-certificate": user.certificate})
    else:
        return jsonify({"message": "only the tenant admin can add users"})


# The user enumeration API allows authenticated users to view all other users and their certificates
# (but not private keys) that belong to the tenant
# Outputs: user-id and user-certificate for all users in the tenant
# request example: requests.get(url=request.host_url+'v1/2a07/users',auth=auth)
@app.route("/v1/<tenant_id>/users", methods=["GET"])
@auth.login_required
@user_in_tenant_required
def getTenantUsers(tenant_id):
    currentUser = DB.getUser(request.authorization.username)
    response = []
    for tenantUser in DB.getTenantUsers(tenant_id):
        user = DB.getUserByID(tenantUser)
        # admin
        if currentUser.userid == DB.getTenantAdmin(tenant_id):
            response.append({'username': user.username, 'userid': user.userid, 'certificate': user.certificate,
                             'privateKey': user.privateKey})
        # user
        else:
            response.append({'username': user.username, 'userid': user.userid, 'certificate': user.certificate})
    return jsonify({'users': response})


# The me API allows a user to view their own certificate and private key
# request example: requests.get(url=request.host_url+'v1/2a07/users/me',auth=auth)
@app.route("/v1/<tenant_id>/users/me", methods=["GET"])
@auth.login_required
@user_in_tenant_required
def getCurrentUser(tenant_id):
    user = DB.getUser(request.authorization.username)
    return jsonify({'certificate': user.certificate, 'privateKey': user.privateKey})


# The delete API allows an admin to delete his users
# request example: requests.delete(url=request.host_url+'v1/2a07/users/2',auth=auth)
@app.route("/v1/<tenant_id>/users/<user_id>", methods=["DELETE"])
@auth.login_required
@user_in_tenant_required
def deleteUser(tenant_id, user_id):
    loogedUser = DB.getUser(request.authorization.username)
    if DB.isUserAdmin(loogedUser.userid, tenant_id) and DB.getUserByID(user_id):
        DB.removeUser(user_id)
        return jsonify({"message": "removed"})
    else:
        return jsonify({"message": "only tenant admin can delete a tenant user"})


# The user encryption API allows users to encrypt data so that other users can read it.
# Inputs: blob - the plaintext that the user wants to encrypt
# Outputs: base64-encoded encrypted blob
@app.route("/v1/<tenant_id>/users/<user_id>/encrypt", methods=["POST"])
@auth.login_required
@user_in_tenant_required
def encrypt(tenant_id, user_id):
    sender = DB.getUser(request.authorization.username)
    receiver = DB.getUserByID(user_id)
    if not receiver or not sender.tenant == receiver.tenant:
        return jsonify({"message": "both users must be in the same tenant"})
    plaintxt = ''
    if request.form:
        plaintxt = request.form['message']
    else:
        json_data = request.get_json(force=True)
        plaintxt = json_data['body']
    if not plaintxt:
        return jsonify({"message": "no message sent"})
    try:
        encryptionKey = receiver.certificate
        receiverPubKey = RSA.importKey(getPublicKey(encryptionKey))
        encryptor = PKCS1_OAEP.new(receiverPubKey)
        encrypted = encryptor.encrypt(plaintxt.encode('utf-8'))
        # save as string
        encryptedMsg = base64.b64encode(encrypted).decode('utf-8')
        DB.addMessage(receiver.username, request.authorization.username, encryptedMsg)
        return encryptedMsg
    except:
        return jsonify({"message": "Unexpected error, can't encrypt "})


# The user decryption API allows users to decrypt data sent to them
# Inputs: basey64-encoded encrypted blob - the encrypted data that the user wants to decrypt
# Outputs: decrypted blob
@app.route("/v1/<tenant_id>/users/me/decrypt", methods=["POST"])
@auth.login_required
@user_in_tenant_required
def decrypt(tenant_id):
    me = DB.getUser(request.authorization.username)
    encryptedText = ''
    if request.form:
        encryptedText = request.form['decrypt']
    else:
        json_data = request.get_json(force=True)
        encryptedText = json_data['body']
    try:
        privateKey = RSA.import_key(me.privateKey)
        cipher = PKCS1_OAEP.new(privateKey)
        encryptedText = base64.b64decode(encryptedText)
        message = cipher.decrypt(encryptedText).decode('utf-8')
        return message
    except:
        return jsonify({"message": "Unexpected error, can't decrypt "})


@app.route("/logout")
def logout():
    return abort(401)

@app.route('/error')
def error(msg):
    render_template("error.html")