# No arquivo tftp_client.py
 
import sys
import textwrap
from docopt import docopt
from tftp import get_file, put_file
 
def main():
    args = docopt("""\
TFTPy: A TFTP client written in Python.

Usage:
    client.py [-p SERV_PORT] <server>
    client.py get [-p SERV_PORT] <server> <remote_filename> [<local_file>]
    client.py put [-p SERV_PORT] <server> <local_filename> [<remote_file>]

    
Options:
    -h, --help                             show this help message
    -p SERV_PORT, --port=SERV_PORT         Port number [default: 69] 
"""
    )

    #print(args)


    if  args['get']:
    
        get_file((args['<server>'], int(args['--port'])), args['<remote_filename>'])
    elif args['put']:
        put_file((args['<server>'], int(args['--port'])), args['<local_filename>'])
    else:
        exec_tftp_shell(args['<server>'], int(args['--port']))

"""  args = docopt(doc)
    if args['get']:
        print("GET")
        remote_file = args['<remote_file>']
        local_file = args['<local_file>']
        try:
            get_file((args['<server>'], int(args['--port'])), remote_file, local_file)
            print("Arquivo obtido com sucesso!")
        except Exception as e:
            print(f"Erro ao obter arquivo: {e}")
    elif args['put']:
        print("PUT")
        local_file = args['<local_file>']
        remote_file = args['<remote_file>']
        try:
            put_file(args['<server>'], local_file, remote_file)
            print("Arquivo enviado com sucesso!")
        except Exception as e:
            print(f"Erro ao enviar arquivo: {e}")
    else:
        exec_tftp_shell(args['<server>'], int(args['--port']))
 """
def exec_tftp_shell(server: str, server_port: int):
    server_addr = (server,server_port)
    print(f"Trocar arquivos com o servidor '{server}' (<ip do servidor>)")
    print(f"Porta do servidor: {server_port}\n")
    while True:
        cmd = input("tftp client> ")
        match cmd:
            case 'get':
                print("GET (shell)")
                remote_file = input("Nome do arquivo remoto: ")
                local_file = input("Nome do arquivo local (opcional): ")
                try:
                    get_file(server_addr, remote_file)
                    print("Arquivo obtido com sucesso!")
                except Exception as e:
                    print(f"Erro ao obter arquivo: {e}")
            case 'put':
                print("PUT (shell)")
                local_file = input("Nome do arquivo local: ")
                remote_file = input("Nome do arquivo remoto (opcional): ")
                try:
                    put_file(server_addr, local_file)
                    print("Arquivo enviado com sucesso!")
                except Exception as e:
                    print(f"Erro ao enviar arquivo: {e}")
            case 'help':
                print(textwrap.dedent(
                    """
                    Comandos:
                        get remote_file [local_file] - obter um arquivo do servidor e salvá-lo como local_file
                        put local_file [remote_file] - enviar um arquivo para o servidor e armazená-lo como remote_file
                        dir                         - obter uma lista de arquivos remotos
                        quit                        - sair do cliente TFTP
                    """
                ))
            case 'quit':
                print("Sair do cliente TFTP")
                print("Adeus!")
                sys.exit(0)
            case _:
                print(f"Comando inválido: '{cmd}'")
 
if __name__ == '__main__':
    main()

