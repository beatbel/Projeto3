"""
TFTPy - This module implements an interactive and command line TFTP client.
It also takes command line options to get/send files.
 
This client accepts the following options:
    $ python3 client.py [-p serv_port] server
    $ python3 client.py get [-p serv_port] server remote_file [local_file]
    $ python3 client.py put [-p serv_port] server local_file [remote_file]
    $ python3 client.py dir [-p serv_port] server
 
"""
 
import os
import sys
import textwrap
from docopt import docopt
from tftp import get_file, put_file, check_file_existence
from tftp import check_server_status, gethostbyname
 
 
def main():
    doc = """\
    TFTPy: A TFTP client written in Python.
 
    Usage:
        client.py [-p SERV_PORT] <server>
        client.py get [-p SERV_PORT] <server> <remote_file> [<local_file>]
        client.py put [-p SERV_PORT] <server> <local_file> [<remote_file>]
        client.py dir [-p SERV_PORT] <server>
 
    Options:
        -h, --help                      Show this help message
        -p SERV_PORT, --port=SERV_PORT  Port number [default: 69]
    """
    args = docopt(doc)
    server_name = args["<server>"]
    server_port = int(args["--port"])
    server_address = check_server_status(server_name, server_port)
 
 
    if args["get"]:
        remote_file = args["<remote_file>"]
        local_file = args["<local_file>"]
        if args["<local_file>"] == None:
            local_file = args["<remote_file>"]
        # Check if the remote file exists before attempting to get it
        if not check_file_existence(server_address, remote_file):
            print(f"Error: The remote file '{remote_file}' does not exist on the server.")
            sys.exit(1)
 
        get_file(server_address, remote_file, local_file)
 
 
    elif args["put"]:
        local_file = args["<local_file>"]
        remote_file = args["<remote_file>"] if args["<remote_file>"] else args["<local_file>"]
         # Check if the local file exists before attempting to put it
        if not os.path.exists(local_file):
            print(f"Error: The local file '{local_file}' does not exist.")
            sys.exit(1)
        put_file(server_address, local_file, remote_file)
 
    else:
        exec_tftp_shell(server_name, server_port, server_address)
 
def exec_tftp_shell(server, server_port, server_address):
 
    print(f"Connecting to the server '{server}' (IP address: {server_address[0]})")
    print(f"The server port is {server_port}\n")
 
    while True:
        try:
            cmd = input("tftp client> ")
 
            if cmd.startswith("get"):
                _, *args = cmd.split()
                if len(args) == 0:
                    print("Usage: get remote_file [local_file]")
                    continue
 
                remote_file = args[0]
                local_file = args[1] if len(args) > 1 else remote_file
                if check_server_status(server, server_port) == True:
                    continue
 
                if not check_file_existence(server_address, remote_file):
                    print(f"Error: The remote file '{remote_file}' does not exist on the server.")
                    continue
 
                get_file(server_address, remote_file, local_file)
 
            elif cmd.startswith("put"):
                _, *args = cmd.split()
                if len(args) == 0:
                    print("Usage: put local_file [remote_file]")
                    continue
 
                local_file = args[0]
                remote_file = args[1] if len(args) > 1 else local_file
                if not os.path.exists(local_file):
                    print(f"Error: The local file '{local_file}' does not exist.")
                    continue
                if check_server_status(server, server_port) == True:
                    continue
 
                put_file(server_address, local_file, remote_file)
 
 
            elif cmd == "help":
                print(
                    textwrap.dedent(
                        """
                        Commands:
                            get remote_file [local_file] - get a file from the server and save it as local_file
                            put local_file [remote_file] - send a file to the server and store it as remote_file
                            dir                          - list files in the current working directory on the server
                            quit                         - exit the TFTP client
                        """
                    )
                )
 
            elif cmd == "quit":
                print("Exiting the TFTP client.")
                print("Goodbye!")
                sys.exit(0)
 
            else:
                print(f"Invalid command: '{cmd}'")
 
        except Exception as e:
            print(f"Error: {e}")
 
if __name__ == "__main__":
    main()

