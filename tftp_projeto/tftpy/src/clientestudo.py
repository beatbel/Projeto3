import sys
from tftp1 import get_file, put_file, NetworkError, ProtocolError, Err, TFTPValueError
from docopt import docopt
from tftp1 import check_server_status
import textwrap

def print_error(error):
        print(f"Error: {error}")
 
def get_user_input(prompt):
        return input(f"{prompt}: ").strip()

def interactive_mode():
        print("Welcome to TFTP!")

def main():
    doc = docopt(f"""
    TFTPy: A TFTP client written in Python.
 
    Usage:
        client.py [-p SERV_PORT] <server>
        client.py get [-p SERV_PORT] <server> <remote_file> [<local_file>]
        client.py put [-p SERV_PORT] <server> <local_file> [<remote_file>]
        client.py dir [-p SERV_PORT] <server>
 
    Options:
        -h, --help                      Show this help message
        -p SERV_PORT, --port=SERV_PORT  Port number [default: 69]
    """)
    
    server_name = doc["<server>"]
    server_port = int(doc["--port"])
    server_address = check_server_status(server_name, server_port)

    
   
    while True:
        action = input("tftp client> ")
       
        if action not in ['get', 'put', 'help', 'quit']:
            print("Invalid operation. Use 'get','put', 'quit' or 'help'")
            continue
       

        try:
            if action == 'get':
                remote_filename = get_user_input("Enter remote filename")
                get_file((server_address, server_port), remote_filename)
            elif action == 'put':
                local_filename = get_user_input("Enter local filename")
                put_file((server_address, server_port), local_filename, remote_filename)
            elif action == 'help':
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
            elif action == 'quit':
                print("Exiting the TFTP client.")
                print("Goodbye!")
                sys.exit(0)
                
            print(f"Operation '{action}' completed successfully.")
        except (NetworkError, ProtocolError, Err, TFTPValueError) as e:
            print_error(str(e))
        except Exception as e:
            print_error(f"Unexpected error: {e}")
 
        user_input = get_user_input("Do you want to perform another operation? (yes/no)").lower()
        if user_input != 'yes':
            break
 
if __name__ == "__main__":
    main()
 