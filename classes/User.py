import uuid
from werkzeug.security import generate_password_hash

from classes.crypto_helpers import cert_gen


class User:
    userid = ''
    username = ''
    password = ''
    tenant = ''
    certificate = ''
    privateKey = ''

    def __init__(self, username, password, tenant):
        openssl = cert_gen()
        self.userid = str(uuid.uuid4())[:6]
        self.username = username
        self.password = generate_password_hash(password)
        self.tenant = tenant
        self.certificate = openssl[0]
        self.privateKey = openssl[1]
