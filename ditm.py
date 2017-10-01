import os
from sys import argv,exit,stderr
import traceback
import ssl
import socket
import mailbox
import email.parser
import re
import getopt
from base64 import b64decode
import logging
from subprocess import Popen,PIPE

class popclient:
    def __init__(self, hostname, port, mbox_dir, debug=False, gpghome=None):
        self.hostname = hostname
        self.port = port
        self.mbox_dir = mbox_dir
        self.mbox_file = ''
        self.leftovers = b''
        self.ep = email.parser.BytesParser()
        self.debug = debug
        self.log = logging.getLogger('ditm.popclient')
        self.log.setLevel(logging.DEBUG)
        self.gpghome = gpghome

    def connect(self):
        # make sure we can connect to POP server
        self.ssl_context = ssl.create_default_context()
        self.rawsock = socket.socket()
        self.sock = self.ssl_context.wrap_socket(self.rawsock, server_hostname=self.hostname)
        try:
            self.sock.connect((self.hostname,self.port))
        except ssl.SSLError as e:
            self.log.error('SSL error connecting to '+self.hostname+': '+str(e))
            self.connected = False
            return
        except OSError as e:
            self.log.error('received OSError trying to connect: '+str(e))
            self.connected = False
            return
        status,message = self.get_response()
        self.connected = status

    def login(self,username,password):
        username = username if type(username) == bytes else username.encode('utf8')
        password = password if type(password) == bytes else password.encode('utf8')
        # store the username as our mbox_file
        self.mbox_file = username.decode('utf8')
        # pass username to server
        self.send_data(b'USER '+username+b'\r\n')
        status,message = self.get_response()
        if not status:
            self.handle_error(message)
            return status
        self.log.debug('remote USER returned '+str(status))
        # pass password to server
        self.send_data(b'PASS '+password+b'\r\n')
        status,message = self.get_response()
        if not status: self.handle_error(message)
        self.log.debug('remote PASS returned '+str(status))
        return status

    def download_all_messages(self):
        # get uid's of all messages
        self.send_data(b'UIDL\r\n')
        status,message,body = self.get_response(multiline=True)
        if not status:
            self.handle_error(message)
            return status
        if len(body) == 0:
            return True
        mdict = { l.split()[0]:l.split()[1] for l in body.split(b'\n') }
        mbox = mailbox.mbox(self.mbox_dir+'/'+self.mbox_file)
        try:
            mbox.lock()
        except:
            self.log.error('mbox file locked for popclient, unable to operate')
            return False
        downloaded_emails = []
        retval = True
        try:
            for index,uid in mdict.items():
                # retrieve each email from the server
                self.send_data(b'RETR '+index+b'\r\n')
                status,message,body = self.get_response(multiline=True)
                if not status:
                    retval = False
                    self.handle_error(message)
                # decrypt the email
                decrypted = self.gpg_decrypt_bytes(body)
                if not decrypted:
                    self.handle_error('couldn\'t decrypt!')
                    # neither delete this email from remote nor add it to local
                    continue
                new_email = self.ep.parsebytes(decrypted)
                # store the UID in a header in the email
                new_email.add_header('X-DITM-UID',uid.decode('utf8'))
                # add new_email to list of new emails
                downloaded_emails.append(new_email)
                # delete original message from server
                self.send_data(b'DELE '+index+b'\r\n')
                status,message = self.get_response()
                if not status: self.handle_error(message)
        except:
            self.log.exception('unknown exception')
            retval = False
        try:
            for m in downloaded_emails:
                # add email to mbox file
                mbox.add(m)
            mbox.flush()
        except:
            self.log.exception('error adding emails to mbox')
            reval = False
        mbox.unlock()
        mbox.close()
        return retval

    def quit(self):
        self.send_data(b'QUIT\r\n')
        status,message = self.get_response()
        self.sock.close()

    def gpg_decrypt_bytes(self,data):
        if b'-----BEGIN PGP MESSAGE-----' not in data.strip().split(b'\n')[0] or \
                b'-----END PGP MESSAGE-----' not in data.strip().split(b'\n')[-1]:
            # if its already decrypted... don't mess with it.
            return data
        gpgargs = ['gpg','-d','-q','--batch']
        if self.gpghome:
            gpgargs.append('--homedir')
            gpgargs.append(self.gpghome)
        h = Popen(gpgargs,stdin=PIPE,stdout=PIPE,stderr=PIPE)
        # write data
        h.stdin.write(data)
        h.stdin.close()
        # read data
        out = h.stdout.read()
        err = h.stderr.read()
        # end the program
        ret = h.wait()
        if ret == 0:
            return out
        else:
            self.log.error('GPG says:\n'+str(err))
            return None


    def get_response(self,multiline=False):
        # start by using what was leftover after the last response
        resp = self.leftovers
        # decide how we know when we are done reading the response
        endtoken = b'\r\n'
        # read from socket until we get the whole response
        while resp.find(endtoken) < 0:
            ret = self.sock.read()
            if len(ret) == 0:
                raise ConnectionError('Broken connection')
            resp += ret
            # if we have an OK message and we are multiline, keep reading
            if multiline and resp[:3] == b'+OK':
                endtoken = b'\r\n.\r\n'
        # split up leftovers from the response
        endtokenpos = resp.find(endtoken)
        leftovers = resp[endtokenpos+len(endtoken):]
        resp = resp[:endtokenpos]
        self.log.debug('received: '+resp.decode('utf8'))
        # now split up the status, the message, and the body (for multiline)
        splitresp = resp.split(b'\r\n')
        tokens = splitresp[0].split()
        status = True if tokens[0] == b'+OK' else False
        message = None if len(tokens) == 1 else b' '.join(tokens[1:])
        if multiline:
            # start the unpacking of POP format by using just '\n'
            body = b'\n'.join(splitresp[1:])
            # unpack the double periods at beginning of lines
            body = re.sub(b'\\n\\.\\.',b'\\n.',body)
            body = re.sub(b'^\\.\\.',b'.',body)
            return status, message, body
        else:
            return status, message

    def send_data(self, data):
        self.log.debug('sent: '+data.strip().decode('utf8'))
        self.sock.sendall(data)

    def handle_error(self, message):
        self.log.error(message)


class popserver:
    def __init__(self,hostname,remoteport,localport,mbox_dir,debug=False,gpghome=None):
        self.mbox_dir = mbox_dir
        self.mbox_file = ''
        self.hostname = hostname
        self.remoteport = remoteport
        self.port = localport
        self.mbox_dir = mbox_dir
        self.leftovers = b''
        self.debug = debug
        self.popclient = popclient(self.hostname,self.remoteport,self.mbox_dir,debug,gpghome)
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            self.ssl_context.load_cert_chain(
                    certfile=mbox_dir+"/splintermail-snakeoil-cert.pem",
                    keyfile=mbox_dir+"/splintermail-snakeoil-key.pem")
            self.can_ssl = True
        except:
            self.can_ssl = False
        self.listener = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('localhost',self.port))
        self.listener.listen(1)
        self.log = logging.getLogger('ditm.popserver')
        self.log.setLevel(logging.DEBUG)
        self.log.info('Decrypter-in-the-middle ready!')
        self.log.debug('Listening on port '+str(self.port) \
                +' and caching emails in '+self.mbox_dir)
        self.log.debug('Watch out! --debug mode shows passwords in the clear')
        while True:
            try:
                self.rawconn,self.addr = self.listener.accept()
                self.conn = self.rawconn
                self.log.debug('received connection')
                self.handle_connection()
            except KeyboardInterrupt:
                self.log.info('exiting due to user input')
                break
            except ConnectionError as e:
                # in all cases, we should at least close the connection
                self.conn.close()
                self.rawconn.close()
                self.log.exception('connection error')
            except ssl.SSLError as e:
                # in all cases, we should at least close the connection
                self.conn.close()
                self.rawconn.close()
                if e.errno == ssl.SSL_ERROR_SSL:
                    self.log.debug('a client is probably bemoaning our self-signed'+
                            ' local-only certificate')
                else:
                    # not sure why this would happen, log traceback and start over
                    self.log.exception('unrecognized ssl error')
            except Exception as e:
                # in all cases, we should at least close the connection
                self.conn.close()
                self.rawconn.close()
                # not sure why this would happen, log traceback and start over
                self.log.exception('unknown error')
        self.listener.close()
        # huh. for some reason this helps close out the port.
        try:
            temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp.connect(('localhost',self.port))
            temp.close()
        except:
            pass

    def handle_connection(self):
        # before responding, make sure we can connect to remote host
        self.popclient.connect()
        if not self.popclient.connected:
            self.handle_error('Couldn\'t connect to remote!')
            self.send_data(b'-ERR DITM could not connect to remote server\r\n')
            self.conn.close()
            return
        self.send_data(b'+OK DITM ready.\r\n')
        self.auth_state()
        # after auth_state() exits, we are done
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.conn.close()

    def auth_state(self):
        passok = False
        starttls = False
        username = b''
        password = b''
        while True:
            command,args = self.get_command()
            self.log.debug('command received: '+command.decode('utf8')+' ' \
                    +(b' '.join(args)).decode('utf8'))
            if command == b'USER':
                if len(args) == 0:
                    self.send_data(b'-ERR USER command missing argument\r\n')
                    continue
                username = args[0]
                self.send_data(b'+OK\r\n')
                passok = True
                continue
            if command == b'PASS':
                if not passok:
                    self.send_data(b'-ERR PASS must follow successful USER command\r\n')
                    continue
                passok = False
                if len(args) == 0:
                    self.send_data(b'-ERR PASS command missing argument\r\n')
                    continue
                password = args[0]
                # store the username as our mbox_file
                self.mbox_file = username.decode('utf8')
                loggedin = self.popclient.login(username,password)
                if not loggedin:
                    self.send_data(b'-ERR Unable to authenticate\r\n')
                    continue
                self.send_data(b'+OK Logged in.\r\n')
                self.transaction_state()
                # we don't stay in auth state when that exits
                break
            if command == b'STLS' and self.can_ssl:
                starttls = True
                self.send_data(b'+OK Begin TLS negotiation now..\r\n')
                self.conn = self.ssl_context.wrap_socket(self.rawconn,server_side=True)
                continue
            if command == b'CAPA':
                if starttls or self.can_ssl is False:
                    self.send_data(b'+OK Capability List Follows.\r\n'+
                                      b'TOP\r\nUSER\r\nUIDL\r\n.\r\n')
                else:
                    self.send_data(b'+OK Capability List Follows.\r\n'+
                                      b'TOP\r\nSTLS\r\nUSER\r\nUIDL\r\n.\r\n')
                continue
            if command == b'QUIT':
                self.send_data(b'+OK '+b64decode(b'RmluZSwgZnVjayB5b3Uu')+b'\r\n')
                # just exit
                break
            # if we are here, we received an illegal command
            self.send_data(b'-ERR Unallowed command during AUTHORIZATION state\r\n')

    def transaction_state(self):
        # before accepting commands, download remote messages
        download_worked = self.popclient.download_all_messages()
        self.popclient.quit()
        if download_worked == False:
            # to be POP compliant, I think it is better fail silently
            # but we will log it
            self.log.error('failed to download, killing POP connection')
            return
        # and here we cache some data we need for transaction state
        mbox = mailbox.mbox(self.mbox_dir+'/'+self.mbox_file)
        try:
            mbox.lock()
        except:
            self.log.error('mbox file locked for popserver, unable to operate')
            return
        try:
            deletions = [False for m in mbox]
            # POP standard dictates passing lengths as if all lines ended in '\r\n'
            # ... but we don't want to double count if '\r\n' is already there, either
            lengths = [ len(m.as_bytes()) + m.as_bytes().count(b'\n')
                            - m.as_bytes().count(b'\r\n') for m in mbox.values() ]
            uids = [ m['X-DITM-UID'].encode('utf8') for m in mbox.values() ]
            while True:
                command,args = self.get_command()
                self.log.debug('command received: '+command.decode('utf8')+' ' \
                        +(b' '.join(args)).decode('utf8'))
                if command == b'STAT':
                    z = zip(lengths,deletions)
                    self.send_data(b'+OK %d %d\r\n'% \
                            (len(mbox)-sum(deletions),sum([l for l,d in z if not d])))
                    continue
                if command == b'LIST':
                    if len(args) == 0:
                        z = [z for z in zip(range(len(mbox)),lengths,deletions)]
                        preresponse = b'+OK %d messages (%d octets)\r\n'% \
                                (len(mbox)-sum(deletions),sum([l for i,l,d in z if not d]))
                        response = [b'%d %d\r\n'%(i+1,l) for i,l,d in z if not d]
                        self.send_data(preresponse+b''.join(response)+b'.\r\n')
                        continue
                    # if we are here then we have an index for LIST
                    try:
                        index = int(args[0]) - 1
                    except:
                        self.send_data(b'-ERR LIST command bad argument\r\n')
                        continue
                    if index >= len(mbox) or deletions[index]:
                        self.send_data(b'-ERR No such message\r\n')
                        continue
                    self.send_data(b'+OK %d %d\r\n'%(index+1,lengths[index]))
                    continue
                if command == b'RETR':
                    if len(args) == 0:
                        self.send_data(b'-ERR RETR command missing argument\r\n')
                        continue
                    try:
                        index = int(args[0]) - 1
                    except:
                        self.send_data(b'-ERR RETR command bad argument\r\n')
                        continue
                    if index >= len(mbox) or deletions[index]:
                        self.send_data(b'-ERR No such message\r\n')
                        continue
                    preresponse = b'+OK %d %d octets\r\n'%(index+1,lengths[index])
                    response = mbox[index].as_bytes()
                    # make all '\n' into '\r\n'
                    re.sub(b'([^\\r])\\n',b'\\1\\r\\n',response)
                    re.sub(b'^\\n',b'\\r\\n',response)
                    # make all '.' beginning lines into '..'
                    re.sub(b'\\n\\.',b'\\n..',response)
                    re.sub(b'^\\.',b'..',response)
                    self.send_data(preresponse+response+b'\r\n.\r\n')
                    continue
                if command == b'DELE':
                    if len(args) == 0:
                        self.send_data(b'-ERR DELE command missing argument\r\n')
                        continue
                    try:
                        index = int(args[0]) - 1
                    except:
                        self.send_data(b'-ERR DELE command bad argument\r\n')
                        continue
                    if index >= len(mbox) or deletions[index]:
                        self.send_data(b'-ERR No such message\r\n')
                        continue
                    deletions[index] = True
                    self.send_data(b'+OK message deleted.\r\n')
                    continue
                if command == b'NOOP':
                    self.send_data(b'+OK try doing something with your life for once.\r\n')
                    continue
                if command == b'RSET':
                    deletions = [False for m in mbox]
                    self.send_data(b'+OK maildrop has %d messages (%d octets)\r\n'%\
                            (len(mbox),sum(lengths)))
                    continue
                if command == b'QUIT':
                    self.send_data(b'+OK '+b64decode(b'RmluZSwgZnVjayB5b3Uu')+b'\r\n')
                    break
                if command == b'TOP':
                    if len(args) < 2:
                        self.send_data(b'-ERR TOP command missing argument\r\n')
                        continue
                    try:
                        index = int(args[0]) - 1
                        numlines = int(args[1])
                    except:
                        self.send_data(b'-ERR TOP command bad argument\r\n')
                        continue
                    if numlines < 0:
                        self.send_data(b'-ERR TOP command bad argument\r\n')
                        continue
                    if index >= len(mbox) or deletions[index]:
                        self.send_data(b'-ERR No such message\r\n')
                        continue
                    # separate header from body
                    data = mbox[index].as_bytes()
                    # but start with consistent line endings...
                    data = re.sub(b'\\r\\n',b'\\n',data)
                    header = data[:data.index(b'\n\n')+2]
                    body = data[data.index(b'\n\n')+2:]
                    response = header+b'\n'.join(body.split(b'\n')[:numlines])
                    # make all '\n' into '\r\n'
                    re.sub(b'([^\\r])\\n',b'\\1\\r\\n',response)
                    re.sub(b'^\\n',b'\\r\\n',response)
                    # make all '.' beginning lines into '..'
                    re.sub(b'\\n\\.',b'\\n..',response)
                    re.sub(b'^\\.',b'..',response)
                    self.send_data(b'+OK\r\n'+response+b'\r\n.\r\n')

                    continue
                if command == b'UIDL':
                    if len(args) == 0:
                        z = zip(range(len(mbox)),uids,deletions)
                        preresponse = b'+OK\r\n'
                        response = [b'%d %s\r\n'%(i+1,u) for i,u,d in z if not d]
                        self.send_data(preresponse+b''.join(response)+b'.\r\n')
                        continue
                    # if we are here then we have an index for UIDL
                    try:
                        index = int(args[0]) - 1
                    except:
                        self.send_data(b'-ERR UIDL command bad argument\r\n')
                        continue
                    if index >= len(mbox) or deletions[index]:
                        self.send_data(b'-ERR No such message\r\n')
                        continue
                    self.send_data(b'+OK %d %s\r\n'%(index+1,uids[index]))
                    continue
                if command == b'CAPA':
                    self.send_data(b'+OK Capability List Follows.\r\n'+
                                      b'TOP\r\nUIDL\r\n.\r\n')
                    continue
                # if we are here, we received an illegal command
                self.send_data(b'-ERR Unallowed command during TRANSACTION state\r\n')
        except:
            self.log.exception('unknown exception')
        # delete messages marked for deletion
        for i,d in enumerate(deletions):
            if d:
                mbox.discard(i)
        mbox.flush()
        mbox.unlock()
        mbox.close()

    def get_command(self):
        # start by using what was leftover after the last response
        resp = self.leftovers
        endtoken = b'\n'
        # read from socket until we get the whole response
        while resp.find(endtoken) < 0:
            ret = self.conn.recv(4096)
            if len(ret) == 0:
                self.log.debug('broken connection')
                raise ConnectionError('Broken connection')
            resp += ret
        # split up leftovers from the response
        endtokenpos = resp.find(endtoken)
        leftovers = resp[endtokenpos+len(endtoken):]
        resp = resp[:endtokenpos].strip()
        self.log.debug('received: '+resp.decode('utf8'))
        # sort out commands and arguments
        splitresp = resp.split()
        command = splitresp[0]
        args = splitresp[1:]
        return command.upper(), args

    def send_data(self,data):
        self.log.debug('sent: '+data.strip().decode('utf8'))
        self.conn.sendall(data)

    def handle_error(self, message):
        self.log.error(message)

def print_usage():
    print(
'''ditm.py: Decrypter-in-the-Middle (DITM) python implementation
    ditm.py will connect to splintermail.com over ssl, receive your fully
    encrypted emails, decrypt them locally, and pass them to you mail client
    over a local POP interface.  ditm is necessary for standard email clients
    to work with splintermail's complete encryption of emails.

usage: python3 ditm.py [OPTIONS]

OPTIONS:

-h, --help              Show this help text

-m, --maildir DIR       Have ditm.py store decrypted emails in DIR until your
                        email client can fetch them
                        Default location: ~/.ditm

-p, --port PORT         Specify which local port ditm.py uses to present a
                        local POP3 interface
                        Default port: 1995

-d, --debug             Show more verbose output at command line, note that
                        this option will print raw passwords

-l, --logfile FILE      Specify the location of the log file
                        Default: ${maildir}/ditm_log

-L, --no-log-file       Specify that no log file should be kept

-g, --gpg-homedir DIR   Specify the gnupg home directory
                        Default: None (allow gpg to choose)
''')

# entry point for other python programs, threading.Thread, multiprocessing.Process, etc.
def start_ditm(port=1995,maildir='~/.ditm',debug=False,logfile='~/.ditm/ditm_log',gpghome=None):
    maildir = os.path.expanduser(maildir)
    if gpghome: gpghome = os.path.expanduser(gpghome)
    if logfile: logfile = os.path.expanduser(logfile)
    try:
        # if folder doesn't exist, create it
        if not os.path.isdir(maildir):
            os.mkdir(maildir)
        # make sure we can read/write the file
        open(maildir+'/touch','a').close()
        open(maildir+'/touch','r').close()
        os.remove(maildir+'/touch')
    except:
        print('unable to open ditm directory "%s" for reading and writing'
                %maildir,file=stderr)
        print('please make sure parent directory exists and file permissions are correct',
                file=stderr)
        exit(2)

    formatter = logging.Formatter('%(asctime)s|%(levelname)s|%(name)s|%(message)s',"%s")

    log = logging.getLogger('ditm')
    log.setLevel(logging.DEBUG)

    # format stdout printing
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG if debug else logging.INFO)
    sh.setFormatter(formatter)
    log.addHandler(sh)

    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        log.addHandler(fh)

    ps = popserver('splintermail.com',995,port,maildir,debug,gpghome)

# entry point for command line usage
if __name__ == '__main__':
    try:
        opts,args = getopt.gnu_getopt(argv[1:],'p:m:hdl:Lg:',['port=','maildir=','help','debug','logfile=','no-logfile','gpg-homedir='])
    except getopt.GetoptError as e:
        print(e,file=stderr)
        print('try `python3 ditm.py --help` for information and usage',file=stderr)
        exit(1)
    if len(args) > 0:
        print('Incorrect usage',file=stderr)
        print('try `python3 ditm.py --help` for information and usage',file=stderr)
        exit(1)
    if '-h' in [ o[0] for o in opts ] or '--help' in [ o[0] for o in opts ]:
        print_usage()
        exit(0)

    debug = '-d' in [ o[0] for o in opts ] or '--debug' in [ o[0] for o in opts ]

    portopt = [ o[1] for o in opts if o[0] == '-p' or o[0] == '--port' ]

    try:
        port = 1995 if len(portopt) == 0 else int(portopt[-1])
    except:
        print('bad port specification: "%s"'%portopt[-1],file=stderr)
        print('try `python3 ditm.py --help` for information and usage',file=stderr)
        exit(1)

    maildiropt = [ o[1] for o in opts if o[0] == '-m' or o[0] == '--maildir' ]
    maildir = '~/.ditm' if len(maildiropt) == 0 else maildiropt[-1]

    nologfile = '-L' in [ o[0] for o in opts ] or '--no-log-file' in [ o[0] for o in opts ]
    if nologfile:
        logfile = None
    else:
        logfileopt = [ o[1] for o in opts if o[0] == '-l' or o[0] == '--logfile' ]
        logfile = maildir+'/ditm_log' if  len(logfileopt) == 0 else logfileopt[-1]

    gpghomeopt = [ o[1] for o in opts if o[0] == '-g' or o[0] == '--gpg-homedir' ]
    gpghome = None if len(gpghomeopt) == 0 else gpghomeopt[-1]

    start_ditm(port,maildir,debug,logfile,gpghome)
