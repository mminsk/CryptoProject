from message import Message
import base64
from time import sleep
from threading import Thread
from RSA_pub_keys import RSAKeys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from base64 import b64encode, b64decode
from Crypto import Random
import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from base64 import b64encode
from base64 import b64decode
import os


class Conversation:


    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation (integer)
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True
        self.needs_key = True
        self.key_created_time = ""
        self.num_processed_msgs = 0

    # convert a hex string h to a binary string
    def hex_to_bin(self, h):
        if (len(h)%2 == 1):
            h = '0' + h
        length = len(h)//2
        b = ""
        for i in range(length):
            c = h[2*i:2*i+2]
            b += chr(int(c, 16))
        return b

    # convert an integer n (int or long) to binary representation encoded on w bytes 
    def int_to_bin(self, n, w):
        b = ""
        for i in range(w):
            b = chr(n%256) + b
            n = n//256
        return b

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)


    def setup_conversation(self):

        '''
        Prepares the conversation for usage
        Creates send state files, receive state files, key state files 
        '''
        self.needs_key = True
        self.num_processed_msgs = 0

        # get conversation specifics 
        users = self.manager.get_other_users()
        manager_name = self.manager.user_name
        conversationID = self.id

        # create send states directory 
        if not os.path.exists("send_states"):
            os.makedirs("send_states")

        # open and write send states file
        if not os.path.exists("send_states/" + str(manager_name) + "_" + str(conversationID) + "_sndstates.txt"):
            file = open("send_states/" + str(manager_name) + "_" + str(conversationID) + "_sndstates.txt",'w')
            for user in users:
                if user != manager_name:
                    file.write(user[:4] + "_snd: 0")
                    file.write("\n")
            file.close()

        # create receive states file
        if not os.path.exists("receive_states"):
            os.makedirs("receive_states")

        # open and write receive states file
        file = open("receive_states/" + str(manager_name) + "_"+ str(conversationID) + "_" + "rcvstates.txt",'w')
        for user in users:
            if user != manager_name:
                file.write(user[:4] + "_rcv: 0")
                file.write("\n")
        file.close()


        # create key states file
        if not os.path.exists("key_states"):
            os.makedirs("key_states")


    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        self.num_processed_msgs += 1

        '''
                Process incoming messages
                :param msg_raw: the raw message
                :param msg_id: ID of the message
                :param owner_str: user name of the user who posted the message
                :param user_name: name of the current user
                :param print_all: is the message part of the conversation history?
                :return: None
                '''
        # basic message processing
        msg = base64.decodestring(msg_raw)

        # if received a compromised alert, print to screen and exit method
        if (msg[0:12] == "COMPROMISED:"):
            print msg[12:]
            return 

        # if received a key exchange message, parse information
        if (msg[0:14] == "BeginChatSetup"):

            # BeginChatSetup|B|A|[Ta | PubEncKb(A|K) | Sigka(B|Ta|PubEnckB(A|K)]
            len_msg = len(msg)
            header = msg[0:14]
            name_position = 14 + len(self.manager.user_name)

            # if BeginChatSetup message directed at current user
            if (msg[14:name_position] == self.manager.user_name):
                # parse message
                to_user = msg[14:name_position]
                from_user = msg[name_position:-538]
                timestamp = msg[-538:-512]
                self.key_created_time = timestamp
                msg_to_decrypt = msg[-512:-256]
                sign_to_check = msg[-256:]

                is_fresh = self.ensure_key_freshness(timestamp)

                if is_fresh:
                    # if key is fresh, check signature
                    shared_secret = self.extract_shared_secret(msg_to_decrypt)
                    verified = self.verify_signature(to_user, from_user, timestamp, msg_to_decrypt, sign_to_check)

                    # if the signature verifies setup shared secret and enc/mac keys
                    if verified:
                        self.setup_shared_secret(shared_secret)
                        fresh_random = "BeginChatSetup" + str(from_user) + str(shared_secret)
                        self.generate_keyfiles(fresh_random, shared_secret)

                    else:
                        # the user cannot decrypt key - chat compromised
                        msg_to_send = self.generate_compromised_msg()
                        self.process_outgoing_message(msg_to_send)
                        return
                else:
                    # the user cannot decrypt key - chat compromised 
                    msg_to_send = self.generate_compromised_msg()
                    self.process_outgoing_message(msg_to_send)
                    return
            else:
                # if BeginChatSetup message is not for current user, do nothing
                pass

        else:
            # if not a BeginChatSetup message, proceed as if normal message 

            # if key path DNE, system compromised - return
            if not os.path.exists('key_states/' + str(self.manager.user_name) + '_' + str(self.id) + '_keystates.txt'):
                return

            # get receive sequences, check and decode message
            num_other_users = len(self.manager.get_other_users())
            sequences = {}
            rcvsqn = self.get_rcv_sequences(owner_str, sequences)
            payload = self.decode_message(msg, rcvsqn)
            
            # save state 
            self.save_rcv_states(sequences)

            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=payload,
                owner_str=owner_str
            )

        # every 100 messages update keyfiles
        if (self.num_processed_msgs % 5 == 0):
            self.update_keyfiles()


    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server

        '''
        # if sending a compromised message
        if (msg_raw[0:11] == "COMPROMISED"):
            valid = self.check_compromised_msg(msg_raw)
            user_compromised = msg_raw[37:-256]

            if valid:
                # post compromised message to the conversation
                encoded_msg = base64.encodestring("COMPROMISED:" + user_compromised + " is compromised. Proceed at your own risk.")
                self.manager.post_message_to_conversation(encoded_msg)
                return
            else:
                # someone has tried to replay a compromised message, do nothing
                return


        if (self.needs_key):
            # generate a shared secret
            keystring = self.generate_shared_secret()

            # generate enc and mac keys from shared secret
            fresh_random = "BeginChatSetup" + str(self.manager.user_name) + str(keystring)
            self.generate_keyfiles(fresh_random, keystring)

            # send secret to other users
            self.send_begin_chat(keystring)

        # create array to store send sequences
        sequences = {}
        sndsqn = self.get_snd_sequences(sequences)

        processed_msg = self.encode_message(msg_raw, sndsqn)

        self.save_snd_states(sequences)

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=processed_msg
            )
            self.printed_messages.append(m)

            # process outgoing message here
        # example is base64 encoding, extend this with any crypto processing of your protocol
        encoded_msg = base64.encodestring(processed_msg)

        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)


    def send_begin_chat(self, keystring):
        # MESSAGE FORMAT:
        # BeginChatSetup|B|A|[Ta | PubEncKb(A|K) | Sigka(B|Ta|PubEnckB(A|K)] )

        # PART 1
        # PubEncKb(A|K): RSA encryption using public key of user
        list_of_users = self.manager.get_other_users()
        for user in list_of_users:
            for person in RSAKeys:
                if person["user_name"] == user:
                    pubkey_file = person["RSA_public_key"]

                    kfile = open(pubkey_file)
                    keystr = kfile.read()
                    kfile.close()

                    pubkey = RSA.importKey(keystr)
                    cipher = PKCS1_OAEP.new(pubkey)

                    # plength = 214 - (len(msg) % 214)
                    # msg += chr(plength) * plength
                    msg = str(self.manager.user_name) + str(keystring)

                    encoded_msg = cipher.encrypt(msg)

                    # B|Timstamp of manager|PubEncKB(A|K)
                    time = datetime.datetime.now()
                    msg_to_sign = str(user) + str(time) + encoded_msg

                    # Generate signature with own private key
                    kfile = open('private_keys/private_key_' + self.manager.user_name + '.pem')
                    keystr = kfile.read()
                    kfile.close()
                    key = RSA.importKey(keystr)

                    signer = PKCS1_v1_5.new(key)
                    digest = SHA256.new()
                    digest.update(msg_to_sign)
                    sign = signer.sign(digest)
                    msg_to_send = "BeginChatSetup" + str(user) + str(self.manager.user_name) + str(
                        time) + encoded_msg + sign
                    encoded_msg = base64.encodestring(msg_to_send)

                    # post the message to the conversation
                    self.manager.post_message_to_conversation(encoded_msg)
        self.needs_key = False

    def encode_message(self, msg_raw, sndsqn):
        # read the content of the key file to get keys
        keyfile = 'key_states/' + str(self.manager.user_name) + '_' + str(self.id) + '_keystates.txt'
        ifile = open(keyfile, 'rb')
        line = ifile.readline()
        enckey = line[len("enckey: "):len("enckey: ") + 32]
        enckey = self.hex_to_bin(enckey)
        line = ifile.readline()
        mackey = line[len("mackey: "):len("mackey: ") + 32]
        mackey = self.hex_to_bin(mackey)
        ifile.close()

        #set payload
        payload = msg_raw

        # compute padding
        payload_length = len(payload)
        padding_length = AES.block_size - payload_length%AES.block_size
        padding = chr(1) + chr(0)*(padding_length-1)

        mac_length = 32  # SHA256 hash value is 32 bytes long

        # compute message length...
        # header: 9 bytes
        #    version: 2 bytes
        #    type:    1 btye
        #    length:  2 btyes
        #    sqn:     4 bytes
        # iv: AES.block_size
        # payload: payload_length
        # padding: padding_length
        # mac: mac_length
        msg_length = 9 + AES.block_size + payload_length + padding_length + mac_length

        # create header
        header_version = "\x04\x06"                # protocol version 4.6
        header_type = "\x01"                       # message type 1
        header_length = self.int_to_bin(msg_length, 2)  # message length (encoded on 2 bytes)
        header_sqn = self.int_to_bin(sndsqn + 1, 4)     # next message sequence number (encoded on 4 bytes)
        header = header_version + header_type + header_length + header_sqn

        # encrypt what needs to be encrypted (payload + padding)
        iv = Random.new().read(AES.block_size)
        ENC = AES.new(enckey, AES.MODE_CBC, iv)
        encrypted = ENC.encrypt(payload + padding)

        # compute mac on header and encrypted payload
        H = SHA256.new()
        MAC = HMAC.new(mackey, digestmod = H)
        MAC.update(header)
        MAC.update(iv)
        MAC.update(encrypted)
        mac = MAC.digest()

        processed_msg = header + iv + encrypted + mac

        return processed_msg




    def decode_message(self, msg, rcvsqn):
        # getting enc and mac keys 
        keyfile = 'key_states/' + str(self.manager.user_name) + '_' + str(self.id) + '_keystates.txt'
        ifile = open(keyfile, 'rb')
        line = ifile.readline()
        enckey = line[len("enckey: "):len("enckey: ") + 32]
        enckey = self.hex_to_bin(enckey)
        line = ifile.readline()
        mackey = line[len("mackey: "):len("mackey: ") + 32]
        mackey = self.hex_to_bin(mackey)
        ifile.close()

        # parse the message
        header_length = 9  # header is 9 bytes long
        header = msg[0:header_length]
        iv = msg[header_length:header_length + AES.block_size]  # iv is AES.block_size bytes long
        mac_length = 32  # SHA256 hash is 32 bytes long
        encrypted = msg[header_length + AES.block_size:-mac_length]  # encrypted part is between iv and mac
        mac = msg[-mac_length:]  # last mac_length bytes form the mac
        header_version = header[0:2]  # version is encoded on 2 bytes
        header_type = header[2:3]  # type is encoded on 1 byte
        header_length = header[3:5]  # msg length is encoded on 2 bytes
        header_sqn = header[5:9]  # msg sqn is encoded on 4 bytes

        # check the msg length
        if (len(msg) != int(header_length.encode("hex"), 16)):
            print "Warning: Message length value in header is wrong!"
            print "Processing is continued nevertheless..."

        # check the sequence number
        sndsqn = long(header_sqn.encode("hex"), 16)

        #POSSIBLE ATTACK:
        #if (True):
        if (sndsqn <= rcvsqn ):
            print "Error: Message sequence number is too old!"
            print "Processing completed."
            sys.exit(1)

        # verify the mac
        # print "MAC verification is being performed..."
        H = SHA256.new()
        MAC = HMAC.new(mackey, digestmod=H)
        MAC.update(header)
        MAC.update(iv)
        MAC.update(encrypted)
        comp_mac = MAC.digest()

        if (comp_mac != mac):
            print "Error: MAC verification failed!"
            print "Processing completed."
            sys.exit(1)

        # decrypt the encrypted part
        ENC = AES.new(enckey, AES.MODE_CBC, iv)
        decrypted = ENC.decrypt(encrypted)

        # remove and check padding
        i = -1
        while (decrypted[i] == '\x00'): i -= 1
        padding = decrypted[i:]
        payload = decrypted[:i]

        if (padding[0] != '\x01'):
            print "Error: Wrong padding detected!"
            print "Processing completed."
            sys.exit(1)

        return payload

    def check_compromised_msg(self, msg_raw):
        sign_to_check = msg_raw[-256:]
        timestamp = msg_raw[11:37]
        time_compromised = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
        user_compromised = msg_raw[37:-256]

        # verify signature
        kfile = open('public_keys/public_key_' + user_compromised + '.pem')
        pub_key = kfile.read()
        kfile.close()
        rsakey = RSA.importKey(pub_key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        data = "COMPROMISED" + str(timestamp) + str(user_compromised)

        digest.update(data)
        
        all_counter_zero = self.check_counters("send")
        time_key_created = datetime.datetime.strptime(self.key_created_time, "%Y-%m-%d %H:%M:%S.%f")

        # if signature verifies, compromised sent after key created, and no messages have been sent
        return (signer.verify(digest, sign_to_check) and (time_key_created < time_compromised) and all_counter_zero)

    def generate_shared_secret(self):
        '''
        Generates and saves shared secret 
        :return: String
        '''
        keystring = Random.get_random_bytes(32)
        self.setup_shared_secret(keystring)
        return keystring

    def extract_shared_secret(self, msg_to_decrypt):
        '''
        Extracts shared secret from encrypted BeginChatSetup message
        :return: String
        '''
        kfile = open('private_keys/private_key_'+ self.manager.user_name + '.pem')
        kstr = kfile.read()
        kfile.close()
        key = RSA.importKey(kstr)
        cipher = PKCS1_OAEP.new(key)
        buffer = msg_to_decrypt
        decrypted_msg = cipher.decrypt(buffer)

        shared_secret = decrypted_msg[-32:]

        return shared_secret

    def verify_signature(self, to_user, from_user, timestamp, msg_to_decrypt, sign_to_check):
        '''
        Checks the signature with the public key of the user who sent 
        the BeginChatSetup message
        :return: boolean
        '''
        kfile = open('public_keys/public_key_' + from_user + '.pem')
        pub_key = kfile.read()
        kfile.close()
        rsakey = RSA.importKey(pub_key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()

        #POSSIBLE ATTACK: MODIFIED MESSAGE
        #data = str(to_user + timestamp + msg_to_decrypt + "Attack")
        data = str(to_user + timestamp + msg_to_decrypt)

        digest.update(data)

        return signer.verify(digest, sign_to_check)

    def ensure_key_freshness(self, timestamp):
        time_object = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
        
        #POSSIBLE ATTACK: OLD KEY
        #time_object = time_object - datetime.timedelta(hours=48)

        time_24hours = datetime.datetime.now() - datetime.timedelta(hours=24)
        all_counter_zero = self.check_counters("receive")

        return (all_counter_zero and (time_object > time_24hours))

    def get_snd_sequences(self, sequences):

        statefile = 'send_states/' + str(self.manager.user_name) + '_' + str(self.id) + '_sndstates.txt'
        ifile = open(statefile, 'rb')
        line = ifile.readline()
        i = 0

        num_other_users = len(self.manager.get_other_users())
        # get send sequenses from the state file
        while(i < num_other_users):
            sndsqn = line[len("0000_snd: "):]
            sndsqn = long(sndsqn)
            # assign sequence number to user in dictionary
            sequences[line[:4]] = sndsqn
            line = ifile.readline()
            i += 1

        ifile.close()

        return sndsqn

    def save_snd_states(self, sequences):
        statefile = "send_states/" + self.manager.user_name + "_" + str(self.id) + "_sndstates.txt"

        # save state
        list_of_users = self.manager.get_other_users()
        state = ""
        i = 0
        for user in list_of_users:
            userStr = str(user)
            userStr = userStr[:4]
            state = state + userStr + "_snd: " + str(sequences[userStr] + 1) + '\r\n'
            i += 1

        ofile = open(statefile, 'wb')
        ofile.write(state)
        ofile.close()


    def get_rcv_sequences(self, owner_str, sequences):
        
        # read in rcv sequences
        statefile = 'receive_states/' + str(self.manager.user_name) + '_' + str(self.id) + '_rcvstates.txt'
        ifile = open(statefile, 'rb')
        line = ifile.readline()

        i = 0
        num_other_users = len(self.manager.get_other_users())
        rcvsqn = 0
        while (i < num_other_users):
            if (line[1:4] == owner_str[1:4]):
                rcvsqn = line[len("0000_rcv: "):]
                rcvsqn = long(rcvsqn)
                sequences[line[:4]] = rcvsqn + 1
            else:
                rcvsqnHolder = line[len("0000_rcv: "):]
                rcvsqnHolder = long(rcvsqnHolder)
                sequences[line[:4]] = rcvsqnHolder

            line = ifile.readline()
            i += 1

        ifile.close()

        return rcvsqn

    def save_rcv_states(self, sequences):
        # save state
        list_of_users = self.manager.get_other_users()
        i = 0
        state = ""
        for user in list_of_users:
            state = state + str(user[:4]) + "_rcv: " + str(sequences[user[:4]]) + '\r\n'
            i += 1

        ofile = open("receive_states/" + self.manager.user_name + "_" + str(self.id) + "_rcvstates.txt", 'wb')
        ofile.write(state)
        ofile.close()


    def setup_shared_secret(self, shared_secret):
        '''
        Writes shared secret file
        :return: None
        '''
        self.needs_key = False

        if not os.path.exists(self.manager.user_name + "_shared_secrets"):
            os.makedirs(self.manager.user_name + "_shared_secrets")

        # open and write shared secret file
        file = open(self.manager.user_name + "_shared_secrets/" + str(self.id) + ".txt", 'w')

        file.write("shared secret: " + shared_secret)
        file.close()

    def generate_keyfiles(self, fresh_rand, shared_secret):
        '''
        Generates keyfiles based on fresh random and the shared secret 
        :return: None
        '''
        #ENC KEY
        h = HMAC.new(shared_secret)
        hash = SHA256.new()
        hash.update(fresh_rand)
        fresh_random = hash.digest()
        h.update(fresh_random)
        label = "Encryption Key"
        h.update(label)
        h.digest_size=32
        enc_key = h.hexdigest()

        #MAC KEY
        h = HMAC.new(shared_secret)
        hash = SHA256.new()
        hash.update(fresh_rand)
        fresh_random = hash.digest()
        h.update(fresh_random)
        label = "MAC key"
        h.update(label)
        h.digest_size=32
        mac_key = h.hexdigest()

        file = open("key_states/" + str(self.manager.user_name) + "_" + str(self.id) + "_" + "keystates.txt", 'w')
        file.write("enckey: " + enc_key + "\n")
        file.write("mackey: " + mac_key)
        file.close()

    def update_keyfiles(self):
        # getting fresh random
        file = open("key_states/" + str(self.manager.user_name) + "_" + str(self.id) + "_" + "keystates.txt", 'rb')
        line = file.readline()
        enckey = line[len("enckey: "):len("enckey: ")+32]
        enckey = self.hex_to_bin(enckey)
        line = file.readline()
        mackey = line[len("mackey: "):len("mackey: ")+32]
        mackey = self.hex_to_bin(mackey)
        fresh_random = str(enckey + mackey)
        file.close()

        # getting shared secret
        file = open(self.manager.user_name + "_shared_secrets/" + str(self.id) + ".txt", 'rb')
        line = file.readline()
        shared_secret = line[len("shared secret: "):len("shared secret: ")+32]
        file.close()

        self.generate_keyfiles(fresh_random, shared_secret)


    def check_counters(self, file):
        '''
        Returns true if all counters in state file are 0
        :return: boolean
        '''
        all_counter_zero = True

        # determine which file to check, if none specified return False
        if (file == "receive"):
            file = open("receive_states/" + str(self.manager.user_name) + "_" + str(self.id) + "_rcvstates.txt", "rb")

        elif (file == "send"):
            file = open("send_states/"+ str(self.manager.user_name) + "_" + str(self.id) + "_sndstates.txt", "rb")

        else:
            return False

        # check file
        line = file.readline()
        i = 0
        num_other_users = len(self.manager.get_other_users())

        while(i < num_other_users):
            sqn = line[len("0000_sqn: "):]
            sqn = long(sqn)
            if (sqn != 0):
                all_counter_zero = False
            line = file.readline()
            i+=1
        file.close()

        return all_counter_zero

    def generate_compromised_msg(self):
        '''
        Creates message that current user has been compromised
        :return: String
        '''
        time = str(datetime.datetime.now())

        compromised_msg = "COMPROMISED" + time +str(self.manager.user_name)

        # sign compromised message
        kfile = open('private_keys/private_key_' + str(self.manager.user_name) + '.pem')
        keystr = kfile.read()
        kfile.close()
        key = RSA.importKey(keystr)

        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(compromised_msg)

        compromised_sign = signer.sign(digest)
        msg_to_send = "COMPROMISED" + time + str(self.manager.user_name) + str(compromised_sign)

        return msg_to_send


    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages and owner_str != self.manager.user_name:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)