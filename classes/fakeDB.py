from classes.User import User
from classes.Message import Message


class fakeDB:
    def __init__(self):
        # key=username, value=user object
        self.users = {}
        # userid-name
        self.IDtoName = {}
        # key= tenantid, value=admin: adminUserId, users: set of userIDs that are part of the tenant
        self.tenants = {}
        self.admins = {}
        # key= userID that can decrypt the data, value: list of data
        self.messages = {}

    # user functions
    def getUserId(self, username):
        if username in self.users.keys():
            return self.users[username].userid
        else:
            return None

    def getUserByID(self, userid):
        if userid in self.IDtoName.keys() and self.IDtoName[userid] in self.users.keys():
            return self.users[self.IDtoName[userid]]
        else:
            return None

    def newUser(self, username, password, tenant):
        user = User(username, password, tenant)
        self.users[username] = user
        self.IDtoName[user.userid] = username
        return user

    def getUser(self, username):
        if username in self.users.keys():
            return self.users[username]
        else:
            return None

    def makeUserAdmin(self, username):
        user = self.users[username]
        self.tenants[user.tenant] = {"admin": user.userid, "users": set()}
        self.admins[username] = user.userid

    def isUserAdmin(self, userid, tenantid):
        return self.tenants[tenantid]['admin'] == userid

    def getAllUsers(self):
        return self.users.keys()

    def removeUser(self, userid):
        user = self.getUserByID(userid)
        self.tenants[user.tenant]['users'].discard(userid)
        self.users.pop(user.username, None)
        self.IDtoName.pop(userid, None)
        self.messages.pop(user.username, None)

    # tenant functions
    def tenantExists(self, tenantid):
        return tenantid in self.tenants.keys()

    def addUsertoTenant(self, user):
        if self.tenantExists(user.tenant):
            self.tenants[user.tenant]['users'].add(user.userid)

    def getTenantAdmin(self, tenantid):
        if self.tenantExists(tenantid):
            return self.tenants[tenantid]['admin']
        else:
            return None

    def isUserInTenant(self, userid, tenantid):
        if self.tenantExists(tenantid):
            return userid in self.tenants[tenantid]['users']
        else:
            return None

    def getTenantUsers(self, tenantid):
        if self.tenantExists(tenantid):
            return self.tenants[tenantid]['users']
        else:
            return None

    # message functions
    def addMessage(self, username, sender, text):
        msg = Message(sender, text)
        if self.messages.get(username) is None:
            self.messages[username] = []
        self.messages[username].append(msg)

    def getMessages(self, username):
        if self.messages.get(username):
            return self.messages.get(username)

    # admins
    def getAllAdmins(self):
        return self.admins.keys()
