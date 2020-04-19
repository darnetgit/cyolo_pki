import datetime


class Message:
    sender = ''
    time = ''
    encText = ''

    def __init__(self, sender, text):
        currentDT = datetime.datetime.now()
        self.sender = sender
        self.encText = text
        self.time = currentDT.strftime("%Y-%m-%d %H:%M:%S")
