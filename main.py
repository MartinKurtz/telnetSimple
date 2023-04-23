import binascii
import msvcrt
from queue import Queue
import socket
import hashlib
import subprocess
import os
import threading

import select
def readstdout(outstream,queue):
    while True:
        queue.put(outstream.readline())



def binary_to_octal(binary_string):
    decimal_value = int(binary_string, 2)  # convert binary to decimal
    octal_string = oct(decimal_value)[2:]  # convert decimal to octal and remove '0o' prefix
    return octal_string.zfill(1)  # pad with zero if necessary


def binary_to_hex(binary_string):
    decimal_value = int(binary_string, 2)  # convert binary to decimal
    hex_string = hex(decimal_value)[2:].upper()  # convert decimal to hexadecimal and remove '0x' prefix
    return hex_string.zfill(2)  # pad with zero if necessary


def handlebaddata(data, client_address, client_socket):
    print(f'Non-{settings["client_encoding"]} input received from client {client_address}')
    print("bin: " + ' '.join(format(byte, '08b') for byte in data))
    # TODO make sure it actually gets the proper octal
    # print("octal: "+''.join(binary_to_octal(format(byte, '03b')) for byte in data))
    print("hex: " + ' '.join(binary_to_hex(format(byte, '08b')) for byte in data))
    client_socket.send(bytes(
        ('There seems to have been a non-' + (settings['client_encoding']) + ' character in there, ').encode(
            settings['client_encoding'])))

    try:
        # TODO fix dis
        thestring = ''.join(format(byte, '08b') for byte in data)
        thestring = thestring.encode('utf8')
        thestring.decode('utf8')
        print("utf8: " + thestring)
    except:
        print("utf8 decoding also failed")


def handleauth(server_socket):
    # Handle client authentification
    while True:
        client_socket, client_address = server_socket.accept()
        print(f'Client connected from {client_address}')

        # Send login prompt to client
        client_socket.send(b'Please log in...\r\n')
        print(f'Server {server_socket.getsockname()} sent: b\'Please log in...\\r\\n\'')

        # Handle client authentication
        authenticated = False
        hasuser = False
        haspassword = False
        while not authenticated:
            # Receive client username

            if hasuser is False:
                client_socket.send(b'Username: ')
                print(f'Server {server_socket.getsockname()} sent: b\' Username: \'')
                try:
                    data = client_socket.recv(int(settings["recieve_packetsize"]))
                    username = data.decode(settings['client_encoding']).strip()
                    if not username:
                        continue

                    print("Username=" + username)
                    hasuser = True
                    print(hasuser, haspassword)

                # Handle non-ASCII input
                except UnicodeDecodeError:
                    handlebaddata(data, client_address, client_socket)

            if hasuser == True and haspassword == False:
                # Receive client password
                client_socket.send(b'Password: ')
                print(f'Server {server_socket.getsockname()} sent: b\' Password: \'')
                try:
                    data = client_socket.recv(int(settings["recieve_packetsize"]))
                    password = data.decode(settings['client_encoding']).strip()
                    if not password:
                        continue
                    haspassword = True
                    print("password recieved")


                # Handle non-ASCII input
                except UnicodeDecodeError:
                    handlebaddata(data, client_address, client_socket)

            if hasuser and haspassword:
                # Check user credentials
                print(str(username in users),
                      users[username] + "|" + hashlib.sha256(password.encode('utf8')).hexdigest())
                if username in users and users[username] == hashlib.sha256(password.encode('utf8')).hexdigest():
                    authenticated = True
                    client_socket.send(b'Authentication successful!\r\n')
                    print(f'Server {server_socket.getsockname()} sent: b\'Authentication successful!\\r\\n\'')

                else:
                    client_socket.send(b'Authentication failed. Please try again.\r\n')
                    print(
                        f'Server {server_socket.getsockname()} sent: b\'Authentication failed. Please try again.\\r\\n\'')
                    hasuser = False
                    haspassword = False
                    username = None
                    password = None
                    print(password_hash)
        return client_socket, client_address


# Load user credentials from file
users = {}
settings = {}
data = None
outputqueue = Queue()

with open('users.txt', 'r') as f:
    for line in f:
        username, password_hash = line.strip().split(':')
        users[username] = password_hash

with open('settings.txt', 'r') as g:
    for line in g:
        setting, settingdata = line.strip().split('=')
        print(setting, settingdata)
        settings[setting] = settingdata

print(settings['client_encoding'])

# Set up the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 23))
server_socket.listen(1)

print('Telnet server listening on port 23...')
client_socket, client_address = handleauth(server_socket)

# Handle client input after auth
powershell_process = subprocess.Popen(["powershell.exe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
psready = False
output = ''
thread = threading.Thread(target=readstdout, args=(powershell_process.stdout, outputqueue))
thread.start()


running = True
while running:
    #   data = client_socket.recv(int(settings["recieve_packetsize"]))
    #   # Try to decode input as ASCII
    #   try:
    #       print(data)
    #       line = data.decode(settings['client_encoding'])
    #       print(f'Client {client_address} sent: {line.encode()}')
    #       output = powershell_process.communicate(line)
    #       print(output)
    #   except:
    #       handlebaddata(data,client_address,client_socket)

    print(powershell_process.poll())
    if powershell_process.poll() is not None:
        running = False
    # Receive client input
    data = client_socket.recv(int(settings["recieve_packetsize"]))
    # Try to decode input as ASCII
    try:
        line = data.decode(settings['client_encoding'])
        print(f'Client {client_address} sent: {line.encode()}')
        powershell_process.stdin.write(str(line + '\n\r').encode())
        powershell_process.stdin.flush()
    # Handle non-ASCII input
    except UnicodeDecodeError:
        handlebaddata(data, client_address, client_socket)
    while outputqueue.empty() is False:
        output=outputqueue.get()
        client_socket.send(output)
        print(f'Server {server_socket.getsockname()} sent: '+str(output))


    # Echo input back to client
    # client_socket.send(data)

# Clean up client connection
client_socket.send(b'Closing Connection')
powershell_process.kill()
client_socket.close()
print(f'Client disconnected from {client_address}')
