import os
import struct
import socket
 
class TFTPClient:
    def __init__(self, server_name, server_port=6969):
        self.server_name = server_name
        self.server_port = server_port
        self.server_address = (self.server_name, self.server_port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 
    def send_data_packet(self, block_number, data):
        data_packet = struct.pack(f'!HH{len(data)}s', 3, block_number, data)
        self.client_socket.sendto(data_packet, self.server_address)
 
    def receive_data_packet(self, buffer_size=516):
        data_packet, server_address = self.client_socket.recvfrom(buffer_size)
        return data_packet
 
    def get(self, remote_file, local_file=None):
        if local_file is None:
            local_file = os.path.basename(remote_file)
 
        local_file = os.path.expanduser(local_file)
 
        with open(local_file, 'wb') as file:
            block_number = 1
 
            while True:
                ack_received = False
                self.send_data_packet(block_number, b'')  # Sending ACK packet
 
                while not ack_received:
                    data_packet = self.receive_data_packet()
                    opcode = struct.unpack('!H', data_packet[:2])[0]
 
                    if opcode == 3:  # Data packet
                        block_number = struct.unpack('!H', data_packet[2:4])[0]
                        file.write(data_packet[4:])
                        ack_received = True
                    elif opcode == 5:  # Error packet
                        error_code = struct.unpack('!H', data_packet[2:4])[0]
                        error_msg = data_packet[4:].decode('utf-8')
                        raise Exception(f"Error {error_code}: {error_msg}")
                    else:
                        raise Exception(f"Unexpected packet received: {data_packet}")
 
                if len(data_packet) < 516:
                    break  # End of file
 
    def put(self, local_file, remote_file=None):
        if remote_file is None:
            remote_file = os.path.basename(local_file)
 
        with open(local_file, 'rb') as file:
            block_number = 1
 
            while True:
                data = file.read(512)
                if not data:
                    break  # End of file
 
                ack_received = False
 
                while not ack_received:
                    self.send_data_packet(block_number, data)
 
                    ack_packet = self.receive_data_packet()
                    opcode = struct.unpack('!H', ack_packet[:2])[0]
 
                    if opcode == 4:  # ACK packet
                        ack_received = True
                        block_number += 1
                    elif opcode == 5:  # Error packet
                        error_code = struct.unpack('!H', ack_packet[2:4])[0]
                        error_msg = ack_packet[4:].decode('utf-8')
                        raise Exception(f"Error {error_code}: {error_msg}")
                    else:
                        raise Exception(f"Unexpected packet received: {ack_packet}")
 
    def quit(self):
        self.client_socket.close()
 
    def help(self):
        print("Available commands:")
        print("  get <remote_file> [local_file]")
        print("  put <local_file> [remote_file]")
        print("  quit")
        print("  help")
 
    def dir(self):
        print("Not implemented yet")
 
# Exemplo de uso
client = TFTPClient('192.168.1.2', 6969)
client.get('nginx.pdf', '~/Desktop/tftp_projeto/my_nginx.pdf')
# estou a pedir o arquivo ao servidor mas irei gravar no meu diretorio com outro nome
# Enviando o arquivo para o servidor
client.put('~/Desktop/tftp_projeto/my_nginx.pdf', 'nginx.pdf')
 
 
client.help()
client.quit()

