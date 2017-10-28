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
from multiprocessing.pool import ThreadPool

def readall(readobj):
    return readobj.read()

class popclient:
    def __init__(self, hostname, port):
        self.log = logging.getLogger('ditm.popclient')
        self.hostname = hostname
        self.port = port

    def connect(self):
        # make sure we can connect to POP server
        self.ssl_context = ssl.create_default_context()
        self.rawsock = socket.socket()
        self.sock = self.ssl_context.wrap_socket(self.rawsock, server_hostname=self.hostname)
        self.leftovers = b''
        self.sock.connect((self.hostname,self.port))
        status,message = self.get_response()
        return status

    def username(self,username):
        self.send_data(b'USER '+username+b'\r\n')
        status,message = self.get_response()
        if not status:
            self.log.error(message)
        return status

    def password(self,password):
        self.send_data(b'PASS '+password+b'\r\n')
        status,message = self.get_response()
        if not status: self.log.error(message)
        return status

    def retrieve(self,index):
        if type(index) == int:
            index = str(index).encode('utf8')
        self.send_data(b'RETR '+index+b'\r\n')
        status,message,body = self.get_response(multiline=True)
        if not status:
            self.log.error(message)
            return False, None
        return True, body

    def uidl(self):
        self.send_data(b'UIDL\r\n')
        status,message,body = self.get_response(multiline=True)
        if not status:
            self.log.error(message)
            return False, None
        if len(body) == 0:
            return True, {}
        return True, { l.split()[0]:l.split()[1] for l in body.split(b'\n') }

    def delete(self,index):
        if type(index) == int:
            index = str(index).encode('utf8')
        self.send_data(b'DELE '+index+b'\r\n')
        status,message = self.get_response()
        if not status: self.log.error(message)
        return status

    def reset(self):
        # send reset to server
        self.send_data(b'RSET\r\n')
        status,message = self.get_response()
        if not status: self.log.error(message)
        return status

    def quit(self):
        self.send_data(b'QUIT\r\n')
        status,message = self.get_response()
        self.sock.close()
        return status

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
        self.leftovers = resp[endtokenpos+len(endtoken):]
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

class popserver:
    def __init__(self,port,ssl_dir,
            starthook=None,
            loginhook=None,
            stathook=None,
            listhook=None,
            retrievehook=None,
            deletehook=None,
            resethook=None,
            tophook=None,
            uidlhook=None,
            updatehook=None,
            donehook=None):
        if None in [ starthook, loginhook, stathook, listhook,
                     retrievehook, deletehook, resethook, tophook,
                     uidlhook, updatehook, donehook]:
            raise ValueError('all hooks must be defined')
        self.starthook = starthook
        self.loginhook = loginhook
        self.stathook = stathook
        self.listhook = listhook
        self.retrievehook = retrievehook
        self.deletehook = deletehook
        self.resethook = resethook
        self.tophook = tophook
        self.uidlhook = uidlhook
        self.updatehook = updatehook
        self.donehook = donehook
        self.log = logging.getLogger('ditm.popserver')
        self.log.setLevel(logging.DEBUG)
        self.port = port
        self.leftovers = b''
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            self.ssl_context.load_cert_chain(
                    certfile=ssl_dir+"/splintermail-snakeoil-cert.pem",
                    keyfile=ssl_dir+"/splintermail-snakeoil-key.pem")
            self.can_ssl = True
            self.log.debug('ssl enabled')
        except:
            self.can_ssl = False
            self.log.debug('ssl unavailable')
        self.listener = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('localhost',self.port))
        self.listener.listen(1)

    def main(self):
        should_continue = True
        while should_continue:
            try:
                self.starthookcalled = False
                self.rawconn,self.addr = self.listener.accept()
                self.conn = self.rawconn
                self.log.debug('received connection')
                self.handle_connection()
            except KeyboardInterrupt:
                self.log.info('exiting due to user input')
                should_continue = False
            except ConnectionError as e:
                self.log.exception('connection error')
            except ssl.SSLError as e:
                if e.errno == ssl.SSL_ERROR_SSL:
                    self.log.debug('a client is probably bemoaning our self-signed'+
                            ' local-only certificate')
                else:
                    # not sure why this would happen, log traceback and start over
                    self.log.exception('unrecognized ssl error')
            except Exception as e:
                # not sure why this would happen, log traceback and start over
                self.log.exception('unknown error')
            # call donehook only if we had an open server running (based on starthookcalled)
            if self.starthookcalled:
                self.starthookcalled == False
                # call hook
                self.donehook()
            self.kill_connection()
        self.listener.close()
        # huh. for some reason this helps close out the port.
        try:
            temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp.connect(('localhost',self.port))
            temp.close()
        except:
            pass

    def handle_connection(self):
        self.state = 'authorization'
        self.pass_ready = False
        self.starttls = False
        self.username = b''
        self.password = b''
        self.leftovers = b''
        enter_loop = True
        # call hook
        if self.starthook():
            self.send_data(b'+OK DITM Ready\r\n')
            self.starthookcalled = True
        else:
            self.send_data(b'-ERR failed to establish remote connection\r\n')
            enter_loop = False
        while enter_loop:
            command, args = self.get_command()
            self.log.debug('command received: '+command.decode('utf8')+' ' \
                    +(b' '.join(args)).decode('utf8'))
            if command.upper() == b'USER':
                if self.state != 'authorization':
                    self.send_data(b'-ERR illegal command outside of AUTHORZATION state\r\n')
                    continue
                if len(args) != 1:
                    self.send_data(b'-ERR command requires exactly 1 argument\r\n')
                    continue
                self.username = args[0]
                self.pass_ready = True
                self.send_data(b'+OK\r\n')
            elif command.upper() == b'PASS':
                if self.state != 'authorization':
                    self.send_data(b'-ERR illegal command outside of AUTHORZATION state\r\n')
                    continue
                if not self.pass_ready:
                    self.send_data(b'-ERR command must follow successful USER command\r\n')
                    continue
                self.pass_ready = False
                if len(args) != 1:
                    self.send_data(b'-ERR command requires exactly 1 argument\r\n')
                    continue
                self.password = args[0]
                # call hook
                login_status, download_status = self.loginhook(self.username,self.password)
                if not download_status:
                    # in this case, to be POP compliant, we will just hard fail
                    break
                if not login_status:
                    self.send_data(b'-ERR logged in failed\r\n')
                    continue
                self.send_data(b'+OK logged in\r\n')
                self.state = 'transaction'
            elif command.upper() == b'STLS' and self.can_ssl:
                if self.state != 'authorization':
                    self.send_data(b'-ERR illegal command outside of AUTHORZATION state\r\n')
                    continue
                if self.starttls:
                    self.send_data(b'-ERR this session is already encrypted\r\n')
                    continue
                starttls = True
                self.popserver.send_data(b'+OK Begin TLS negotiation now..\r\n')
                self.conn = self.ssl_context.wrap_socket(self.rawconn,server_side=True)
            elif command.upper() == b'CAPA':
                if not self.can_ssl or self.starttls:
                    self.send_data(b'+OK Capability List Follows.\r\n'+
                                      b'TOP\r\nUIDL\r\n.\r\n')
                else:
                    self.send_data(b'+OK Capability List Follows.\r\n'+
                                      b'TOP\r\nUIDL\r\nSTLS\r\n.\r\n')
            elif command.upper() == b'STAT':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                # call hook
                self.send_response( *self.stathook() )
            elif command.upper() == b'LIST':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                if len(args) not in [0,1]:
                    self.send_data(b'-ERR command requires exactly 0 or 1 argument\r\n')
                    continue
                if len(args) == 1:
                    try:
                        index = int(args[0]) - 1
                    except:
                        self.send_data(b'-ERR bad argument\r\n')
                        continue
                else:
                    index = None
                # call hook
                self.send_response( *self.listhook(index) )
            elif command.upper() == b'RETR':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                if len(args) != 1:
                    self.popserver.send_data(b'-ERR command requires exactly 1 argument\r\n')
                try:
                    index = int(args[0]) - 1
                except:
                    self.send_data(b'-ERR bad argument\r\n')
                    continue
                # call hook
                self.send_response( *self.retrievehook(index) )
            elif command.upper() == b'DELE':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                if len(args) != 1:
                    self.popserver.send_data(b'-ERR command requires exactly 1 argument\r\n')
                try:
                    index = int(args[0]) - 1
                except:
                    self.send_data(b'-ERR bad argument\r\n')
                    continue
                # call hook
                self.send_response( *self.deletehook(index) )
            elif command.upper() == b'RSET':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                if len(args) != 0:
                    self.send_data(b'-ERR command requires no arguments\r\n')
                    continue
                # call hook
                self.send_response( *self.resethook())
            elif command.upper() == b'NOOP':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                if len(args) != 0:
                    self.send_data(b'-ERR command requires no arguments\r\n')
                    continue
                self.send_data(b'+OK\r\n')
            elif command.upper() == b'TOP':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                if len(args) != 2:
                    self.send_data(b'-ERR command requires exactly 2 arguments\r\n')
                    continue
                try:
                    index = int(args[0]) - 1
                    lines = int(args[1])
                except:
                    self.send_data(b'-ERR bad argument\r\n')
                    continue
                if lines < 0:
                    self.send_data(b'-ERR number of lines must be non-negative\r\n')
                    continue
                # call hook
                self.send_response( *self.tophook(index, lines) )
            elif command.upper() == b'UIDL':
                if self.state != 'transaction':
                    self.send_data(b'-ERR illegal command outside of TRANSACTION state\r\n')
                    continue
                if len(args) not in [0,1]:
                    self.send_data(b'-ERR command requires exactly 0 or 1 argument\r\n')
                    continue
                if len(args) == 1:
                    try:
                        index = int(args[0]) - 1
                    except:
                        self.send_data(b'-ERR bad argument\r\n')
                        continue
                else:
                    index = None
                # call hook
                self.send_response( *self.uidlhook(index) )
                pass
            elif command.upper() == b'QUIT':
                if self.state == 'authorization':
                    self.send_data(b'+OK '+b64decode(b'RmluZSwgZnVjayB5b3Uu')+b'\r\n')
                    break
                elif self.state == 'transaction':
                    # call hook
                    self.updatehook()
                    self.send_data(b'+OK '+b64decode(b'RmluZSwgZnVjayB5b3Uu')+b'\r\n')
                    break
            else:
                self.send_data(b'-ERR unrecognized command\r\n')
                continue

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
        self.leftovers = resp[endtokenpos+len(endtoken):]
        resp = resp[:endtokenpos]
        self.log.debug('received: "'+resp.decode('utf8')+'"')
        # sort out commands and arguments
        splitresp = resp.strip().split()
        if len(splitresp) == 0:
            return b'',[]
        command = splitresp[0]
        if command.upper() == 'pass':
            args = resp[5:]
        else:
            args = splitresp[1:]
        self.log.debug('args = "'+'", "'.join([a.decode('utf8') for a in args])+'"')
        return command.upper(), args

    def send_response(self,status,message,response=None):
        if response is not None:
            if response == b'':
                response = b'.\r\n'
            else:
                # make all '\n' into '\r\n'
                response = re.sub(b'([^\\r])\\n',b'\\1\\r\\n',response)
                response = re.sub(b'^\\n',b'\\r\\n',response)
                # make all '.' beginning lines into '..'
                response = re.sub(b'\\n\\.',b'\\n..',response)
                response = re.sub(b'^\\.',b'..',response)
                response = response + b'\r\n.\r\n'
        else:
            response = b''
        status = b'+OK ' if status else b'-ERR '
        self.send_data(status+message+b'\r\n'+response)

    def send_data(self,data):
        self.log.debug('sent: '+data.strip().decode('utf8'))
        self.conn.sendall(data)

    def kill_connection(self):
        # close the connection
        self.conn.close()
        self.rawconn.close()


class ditm:
    def __init__(self, hostname, port, localport, mbox_dir, gpghome=None, gpg='gpg'):
        self.mbox_dir = mbox_dir
        self.gpg = gpg
        self.gpghome = gpghome
        self.ep = email.parser.BytesParser()
        self.popclient = popclient(hostname, port)
        self.popserver = popserver(localport,self.mbox_dir,
                                       starthook=self.starthook,
                                       loginhook=self.loginhook,
                                       stathook=self.stathook,
                                       listhook=self.listhook,
                                       retrievehook=self.retrievehook,
                                       deletehook=self.deletehook,
                                       resethook=self.resethook,
                                       tophook=self.tophook,
                                       uidlhook=self.uidlhook,
                                       updatehook=self.updatehook,
                                       donehook=self.donehook)
        self.entered_transaction_state = False
        self.mbox = None
        self.log = logging.getLogger('ditm')
        self.log.setLevel(logging.DEBUG)
        self.log.info('Decrypter-in-the-middle ready!')
        self.log.debug('Listening on port '+str(localport) \
                +' and caching emails in '+self.mbox_dir)
        self.log.debug('Watch out! --debug mode shows passwords in the clear')
        self.threadpool = ThreadPool(processes=1)

    def main(self):
        self.popserver.main()

    def download_new_messages(self):
        # get uid's of all messages
        status, self.remote_indicies_uids = self.popclient.uidl()
        downloaded_emails = []
        olduids = [ m['X-DITM-UID'].encode('utf8') for m in self.mbox ]
        retval = True
        try:
            for index,uid in self.remote_indicies_uids.items():
                if uid not in olduids:
                    # retrieve each email from the server
                    status,body = self.popclient.retrieve(index)
                    if not status:
                        retval = False
                        self.log.error(message)
                        continue
                    # decrypt the email
                    decrypted = self.gpg_decrypt_bytes(body)
                    if not decrypted:
                        self.log.error('couldn\'t decrypt!')
                        # neither delete this email from remote nor add it to local
                        continue
                    new_email = self.ep.parsebytes(decrypted)
                    # record the POP length, store in header
                    # POP standard dictates passing lengths as if all lines ended in '\r\n'
                    # ... but we don't want to double count if '\r\n' is already there
                    length = len(new_email.as_bytes()) + new_email.as_bytes().count(b'\n')\
                        - new_email.as_bytes().count(b'\r\n')
                    new_email.add_header('X-DITM-LENGTH',str(length))
                    # store the UID in a header in the email
                    new_email.add_header('X-DITM-UID',uid.decode('utf8'))
                    # add new_email to list of new emails
                    downloaded_emails.append(new_email)
        except:
            self.log.exception('unknown exception')
            retval = False
        try:
            for m in downloaded_emails:
                # add email to mbox file
                self.mbox.add(m)
            self.mbox.flush()
        except:
            self.log.exception('error adding emails to mbox')
            reval = False
        return retval

    def starthook(self):
        # before responding, make sure we can connect to remote host
        if not self.popclient.connect():
            self.log.error('Couldn\'t connect to remote!')
            return False
        return True

    def loginhook(self,username,password):
        login_success = False
        download_success = False
        # try and login
        if not self.popclient.username(username):
            return login_success, download_success
        if not self.popclient.password(password):
            return login_success, download_success
        login_success = True
        # if we logged in, open/lock mbox file
        self.mbox = mailbox.mbox(self.mbox_dir+'/'+username.decode('utf8'))
        try:
            self.mbox.lock()
        except:
            self.log.error('mbox file locked for popserver, unable to operate')
            return login_success, download_success
        download_worked = self.download_new_messages()
        # before accepting commands, download remote messages
        if download_worked == False:
            # to be POP compliant, I think it is better fail silently
            # but we will log it
            self.log.error('failed to download, killing POP connection')
            return login_success, download_success
        # and here we cache some data we need for transaction state
        self.deletions = [False for m in self.mbox]
        self.lengths = [ int(m['X-DITM-LENGTH']) for m in self.mbox.values() ]
        self.uids = [ m['X-DITM-UID'].encode('utf8') for m in self.mbox.values() ]
        # store the username as our mbox_file
        self.mbox_file = username.decode('utf8')
        download_success = True
        self.entered_transaction_state = True
        return login_success, download_success

    def stathook(self):
        z = zip(self.lengths,self.deletions)
        return True, b'%d %d'%\
                (len(self.mbox)-sum(self.deletions),sum([l for l,d in z if not d]))

    def listhook(self,index):
        if index is None:
            z = [z for z in zip(range(len(self.mbox)),self.lengths,self.deletions)]
            preresponse = b'%d messages (%d octets)'% \
                    (len(self.mbox)-sum(self.deletions),sum([l for i,l,d in z if not d]))
            response = [b'%d %d'%(i+1,l) for i,l,d in z if not d]
            return True, preresponse, b'\n'.join(response)
        if index >= len(self.mbox) or self.deletions[index]:
            return False, b'No such message', None
        return True, b'%d %d'%(index+1,self.lengths[index]), None

    def retrievehook(self,index):
        if index >= len(self.mbox) or self.deletions[index]:
            return False, b'No such message', None
        preresponse = b'%d %d octets'%(index+1,self.lengths[index])
        message = self.mbox[index]
        del message['X-DITM-UID']
        del message['X-DITM-LENGTH']
        response = message.as_bytes()
        return True, preresponse, response

    def deletehook(self,index):
        if index >= len(self.mbox) or self.deletions[index]:
            return False, b'No such message'
        uid = self.mbox[index]['X-DITM-UID'].encode('utf8')
        # delete original message from server
        rem_index = [ i for i,u in self.remote_indicies_uids.items() if u == uid ]
        if len(rem_index) == 0:
            self.log.error('UID '+uid.decode('utf8')+' not found in remote uids')
        if len(rem_index) > 1:
            self.log.error('UID '+uid.decode('utf8')+' is duplicated in remote uids')
        success = True
        for ri in rem_index:
            status = self.popclient.delete(ri)
            success = status and success
        if not success:
            return False, b'message not deleted for unknown reason'
        self.log.debug('deleting '+', '.join(str(index)))
        self.deletions[index] = True
        return True, b'message deleted'

    def resethook(self):
        success = self.popclient.reset()
        if not success:
            return False, b'reset failed for unknown reason'
        self.deletions = [False for m in self.mbox]
        return True, b'maildrop has %d messages (%d octets)'% \
                (len(self.mbox),sum(self.lengths))

    def tophook(self,index,lines):
        if index >= len(self.mbox) or self.deletions[index]:
            return False, b'No such message', None
        # separate header from body
        data = self.mbox[index].as_bytes()
        # but start with consistent line endings...
        data = re.sub(b'\\r\\n',b'\\n',data)
        header = data[:data.index(b'\n\n')+2]
        body = data[data.index(b'\n\n')+2:]
        response = header+b'\n'.join(body.split(b'\n')[:lines])
        return True, b'', response

    def uidlhook(self,index):
        if index is None:
            z = zip(range(len(self.mbox)),self.uids,self.deletions)
            response = [b'%d %s'%(i+1,u) for i,u,d in z if not d]
            return True, b'', b'\n'.join(response)
        # if we are here then we have an index for UIDL
        if index >= len(self.mbox) or self.deletions[index]:
            return False, b'No such message'
        return True, b'%d %s'%(index+1,self.uids[index])

    def updatehook(self):
        # make sure we can enter update state on server
        if not self.popclient.quit():
            return
        # delete messages marked for deletion
        for i,d in enumerate(self.deletions):
            if d:
                self.mbox.discard(i)

    def donehook(self):
        if self.mbox is not None:
            self.mbox.flush()
            self.mbox.unlock()
            self.mbox.close()
            self.mbox = None

    def gpg_decrypt_bytes(self,data):
        if b'-----BEGIN PGP MESSAGE-----' not in data.strip().split(b'\n')[0] or \
                b'-----END PGP MESSAGE-----' not in data.strip().split(b'\n')[-1]:
            # if its already decrypted... don't mess with it.
            return data
        gpgargs = [self.gpg,'-d','-q','--batch']
        if self.gpghome:
            gpgargs.append('--homedir')
            gpgargs.append(self.gpghome)
        self.log.debug('starting gpg')
        h = Popen(gpgargs,stdin=PIPE,stdout=PIPE,stderr=PIPE,bufsize=0)
        # start async read to handle large files
        readhandle = self.threadpool.apply_async(readall,[h.stdout])
        # write data
        h.stdin.write(data)
        h.stdin.close()
        # read data
        out = readhandle.get()
        err = h.stderr.read()
        # end the program
        ret = h.wait()
        self.log.debug('gpg finished')
        if ret == 0:
            return out
        else:
            self.log.error('GPG says:\n'+str(err))
            return None

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

-L, --no-logfile        Specify that no log file should be kept

--gpg-homedir DIR       Specify the gnupg home directory
                        Default: None (allow gpg to choose)

--gpg-bin BIN           explicitly specify gpg binary.  This can be either
                        the name of a file on your PATH, such as `gpg2`, or
                        it can be a full PATH
                        Default: gpg (will search your PATH variable)
''')

# entry point for other python programs, threading.Thread, multiprocessing.Process, etc.
def start_ditm(port=1995,maildir='~/.ditm',debug=False,logfile='~/.ditm/ditm_log',gpghome=None,gpg='gpg'):
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
        exit(5)

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

    d = ditm('splintermail.com',995,port,maildir,gpghome,gpg)
    d.main()

# entry point for command line usage
if __name__ == '__main__':
    try:
        opts,args = getopt.gnu_getopt(argv[1:],'p:m:hdl:Lg:',['port=','maildir=','help','debug','logfile=','no-logfile','gpg-homedir=','gpg-bin='])
    except getopt.GetoptError as e:
        print(e,file=stderr)
        print('try `python3 ditm.py --help` for information and usage',file=stderr)
        exit(1)
    if len(args) > 0:
        print('Incorrect usage',file=stderr)
        print('try `python3 ditm.py --help` for information and usage',file=stderr)
        exit(2)
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
        exit(3)

    maildiropt = [ o[1] for o in opts if o[0] == '-m' or o[0] == '--maildir' ]
    maildir = '~/.ditm' if len(maildiropt) == 0 else maildiropt[-1]

    nologfile = '-L' in [ o[0] for o in opts ] or '--no-logfile' in [ o[0] for o in opts ]
    if nologfile:
        logfile = None
    else:
        logfileopt = [ o[1] for o in opts if o[0] == '-l' or o[0] == '--logfile' ]
        logfile = maildir+'/ditm_log' if  len(logfileopt) == 0 else logfileopt[-1]

    gpghomeopt = [ o[1] for o in opts if o[0] == '-g' or o[0] == '--gpg-homedir' ]
    gpghome = None if len(gpghomeopt) == 0 else gpghomeopt[-1]

    gpgopt = [ o[1] for o in opts if o[0] == '--gpg-bin' ]
    gpg = 'gpg' if len(gpgopt) == 0 else gpgopt[-1]

    start_ditm(port,maildir,debug,logfile,gpghome,gpg)
