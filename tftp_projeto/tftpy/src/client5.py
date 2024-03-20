import sys
from docopt import docopt
from tftp1 import verif_estado_server, get_file, put_file, verif_ficheiro_existente
import textwrap
import os


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

    argumento = docopt(doc)
    server_name = argumento["<server>"]
    server_port = int(argumento["--port"])
    server_address = verif_estado_server(server_name, server_port)
 
 
    if argumento["get"]:
        destination_file = argumento["<remote_file>"]
        source_file = argumento["<local_file>"]
        if argumento["<local_file>"] == None:
            source_file = argumento["<remote_file>"]

        if not verif_ficheiro_existente(server_address, destination_file):
            print(f"Error: The remote file '{destination_file}' does not exist on the server.")
            sys.exit(1)
        get_file(server_address, destination_file, source_file)
 
 
    elif argumento["put"]:
        source_file = argumento["<local_file>"]
        destination_file = argumento["<remote_file>"]

        if argumento["<remote_file>"] == None:
            destination_file = argumento["<local_file>"]

        if not os.path.exists(source_file):
            print(f"Error: The local file '{source_file}' does not exist.")
            sys.exit(1)
        put_file(server_address, destination_file, source_file)
 
    else:
        exec_tftp_shell(server_name, server_port, server_address)   


def exec_tftp_shell(server, server_port, server_address):
 
    print(f"Connecting to the server '{server}' (IP address: {server_address[0]})")

    print(f"The server port is {server_port}\n")
 
    while True:

        try:

            comando = input("tftp client> ")
 
            if comando.startswith("get"):
                _, *args = comando.split()
                if len(args) == 0:
                    print("Usage: get remote_file [source_file]")
                    continue
 
                destination_file = args[0]
                source_file = args[1] if len(args) > 1 else destination_file

                if verif_estado_server(server, server_port) == True:
                    continue
 
                if not verif_ficheiro_existente(server_address, destination_file):
                    print(f"Error: The remote file '{destination_file}' does not exist on the server.")
                    continue

                get_file(server_address, destination_file, source_file)
 
            elif comando.startswith("put"):
                _, *args = comando.split()
                if len(args) == 0:
                    print("Usage: put local_file [destination_file]")
                    continue
 
                source_file = args[0]
                destination_file = args[1] if len(args) > 1 else source_file
                if not os.path.exists(source_file):
                    print(f"Error: The local file '{source_file}' does not exist.")
                    continue

                if verif_estado_server(server, server_port) == True:
                    continue
 
                put_file(server_address, source_file, destination_file)
 
            elif comando == "help":
                print(
                    textwrap.dedent(
                        """
                        Commands:

                            get remote_file [local_file] - get a file from the server and save it as local_file
                            put local_file [remote_file] - send a file to the server and store it as remote_file
                            quit                         - exit the TFTP client
                        """
                    )
                )

            elif comando == "quit":
                print("Exiting the TFTP client.")
                print("Goodbye!")
                sys.exit(0)

            else:
                print(f"Invalid command: '{comando}'")
 
        except Exception as e:
            print(f"Error: {e}")



if __name__ == "__main__":
    main()            
