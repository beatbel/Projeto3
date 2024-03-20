import os
import sys
import struct
import socket
import textwrap
from docopt import docopt
 
class TFTPClient:
    def __init__(self, server_name, server_port=69):
        self.server_name = server_name
        self.server_port = server_port
        self.server_address = (self.server_name, self.server_port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.settimeout(60)  # 60 segundos de timeout
 
    def send_data_packet(self, block_number, data):
        data_packet = struct.pack(f'!HH{len(data)}s', 3, block_number, data)
        self.client_socket.sendto(data_packet, self.server_address)
 
    def receive_data_packet(self, buffer_size=516):
        data_packet, server_address = self.client_socket.recvfrom(buffer_size)
        return data_packet
 
    def get_file(self, remote_file, local_file=None):
        if local_file is None:
            local_file = os.path.basename(remote_file)
 
        with open(local_file, 'wb') as file:
            block_number = 1
 
            while True:
                ack_received = False
                self.send_data_packet(block_number, b'')  # Enviar pacote ACK
 
                while not ack_received:
                    try:
                        data_packet = self.receive_data_packet()
                    except socket.timeout:
                        print("Server not responding...")
                        sys.exit(1)
 
                    opcode = struct.unpack('!H', data_packet[:2])[0]
 
                    if opcode == 3:  # Pacote de dados
                        block_number = struct.unpack('!H', data_packet[2:4])[0]
                        file.write(data_packet[4:])
                        ack_received = True
                    elif opcode == 5:  # Pacote de erro
                        error_code = struct.unpack('!H', data_packet[2:4])[0]
                        error_msg = data_packet[4:].decode('utf-8')
                        raise Exception(f"Error {error_code}: {error_msg}")
                    else:
                        raise Exception(f"Unexpected packet received: {data_packet}")
 
                if len(data_packet) < 516:
                    break  # Fim do arquivo
 
        print(f"File '{remote_file}' downloaded as '{local_file}'.")
 
    def put_file(self, local_file, remote_file=None):
        if remote_file is None:
            remote_file = os.path.basename(local_file)
 
        with open(local_file, 'rb') as file:
            block_number = 1
 
            while True:
                data = file.read(512)
                if not data:
                    break  # Fim do arquivo
 
                ack_received = False
 
                while not ack_received:
                    self.send_data_packet(block_number, data)
 
                    try:
                        ack_packet = self.receive_data_packet()
                    except socket.timeout:
                        print("Server not responding...")
                        sys.exit(1)
 
                    opcode = struct.unpack('!H', ack_packet[:2])[0]
 
                    if opcode == 4:  # Pacote ACK
                        ack_received = True
                        block_number += 1
                    elif opcode == 5:  # Pacote de erro
                        error_code = struct.unpack('!H', ack_packet[2:4])[0]
                        error_msg = ack_packet[4:].decode('utf-8')
                        raise Exception(f"Error {error_code}: {error_msg}")
                    else:
                        raise Exception(f"Unexpected packet received: {ack_packet}")
 
        print(f"File '{local_file}' uploaded as '{remote_file}'.")
 
    def dir(self):
        self.send_data_packet(0, b'')  # Solicitar listagem de arquivos
        # Implementar lógica para receber e exibir a listagem de arquivos
 
    def quit(self):
        self.client_socket.close()
 
def main():
    doc = """\
TFTPy: A TFTP client written in Python.
 
Usage:
    client.py (get|put) [-p serv_port] <server> <source_file> [<dest_file>]
    client.py [-p serv_port] <server>
 
Options:
    -h, --help                             Show this help message
    -p SERV_PORT, --port=SERV_PORT         Port number [default: 69]
"""
 
    args = docopt(doc)
 
    server = args['<server>']
    serv_port = int(args['--port'])
 
    client = TFTPClient(server, serv_port)
 
    if args['get']:
        source_file = args['<source_file>']
        dest_file = args['<dest_file>'] if args['<dest_file>'] else source_file
        try:
            client.get_file(source_file, dest_file)
        except Exception as e:
            print(e)
    elif args['put']:
        source_file = args['<source_file>']
        dest_file = args['<dest_file>'] if args['<dest_file>'] else source_file
        try:
            client.put_file(source_file, dest_file)
        except Exception as e:
            print(e)
    else:
        print("Unknown command. Please use 'get' or 'put'.")
 
    client.quit()
 
if __name__ == '__main__':
    main()

    