"""
This module handles all TFTP related "stuff": data structures, packet
definitions, methods and protocol operations.
"""
import os
import socket
import string
import struct
import ipaddress
import re
import sys
import subprocess

###############################################################
##                                                           ##
##              PROTOCOL CONSTANTS AND TYPES                 ##
##                                                           ##     
###############################################################
 
MAX_DATA_LEN = 512           # bytes    
MAX_BLOCK_NUMBER = 2**16 - 1 # 0..65535
INACTIVITY_TIMEOUT = 60.0    # segs
DEFAULT_MODE = 'octet'
DEFAULT_BUFFER_SIZE = 1024   # bytes
 
 
# TFTP message opcodes
 
RRQ = 1 # Read Request
WRQ = 2 # Write Request
DAT = 3 # Data Transfer
ACK = 4 # Acknowledge
ERR = 5 # Error packet: what the server responds if a read/write
        # can't be processed, read and write errors during file
        # transmission also cause this message to be sent, and
        # transmission is then terminated. The error number gives a
        # numeric error code, followed by and ASCII error message that
        # might contain additional, operating system specific
        # information.
 
 
ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
DISK_FULL_OR_ALLOC_EXC = 3
ILLEGAL_TFTP_OP = 4
UNKOWN_TRANSF_ID = 5
FILE_ALREADY_EXISTS = 6
NO_SUCH_USER = 7
 
ERROR_MESSAGES = {
    ERR_NOT_DEFINED: 'Not defined, see error message(if any).',
    ERR_FILE_NOT_FOUND: 'File not found',
    ERR_ACCESS_VIOLATION: 'Access violation',
    DISK_FULL_OR_ALLOC_EXC: 'Disk full or allocation exceeded.',
    ILLEGAL_TFTP_OP: 'Illegal TFTP operation',
    UNKOWN_TRANSF_ID: 'Unkown Transfer ID',
    FILE_ALREADY_EXISTS: 'File already exists',
    NO_SUCH_USER: 'No such user'
 
}
 
 
INET4Address = tuple[str, int]        # TCP/UDP address => IPv4 and port
 

def verif_ficheiro_existente (server_addr: INET4Address, remote_filename: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(INACTIVITY_TIMEOUT)
            rrq = pack_rrq(remote_filename)
            sock.sendto(rrq, server_addr)  # Assuming TFTP server runs on port 69

            while True:
                packet, _ = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                opcode = unpack_opcode(packet)

                if opcode == DAT:
                    # File exists, as the server responded with data
                    return True

                elif opcode == ERR:
                    error_code, _ = unpack_err(packet)
                    if error_code == ERR_FILE_NOT_FOUND:
                        # File not found, as the server responded with an error
                        return False
                    else:
                        # Other error, raise an exception
                        raise Err(error_code, "File existence check error")

                else:
                    # Unexpected packet, raise a protocol error
                    raise ProtocolError(f"Unexpected opcode {opcode}. Expected DAT or ERR")

    except socket.timeout:
        # Timeout occurred, assume the file does not exist
        return False
    

###############################################################
##                                                           ##
##                 SEND AND RECEIVE FILES                    ##
##                                                           ##     
###############################################################
 

def get_file(server_addr: INET4Address, source_filename: str, destination_filename: str = None):
    """
    Get the remote file given by 'filename' through a TFTP RRQ
    connection to remote server at 'server_addr'.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        
        with open(destination_filename, 'wb') as out_file:
            rrq = pack_rrq(source_filename)
            sock.sendto(rrq, server_addr)             
            
            next_block_number = 1
            total_file_size = 0
            
            while True:
                packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                opcode = unpack_opcode(packet)
                
                if opcode == DAT:
                    block_number, data = unpack_dat(packet)
                    
                    if block_number != next_block_number and block_number != next_block_number - 1:
                        error_msg = (
                            f"Unexpected block number: {block_number}. Expecting one of"
                            f" {next_block_number} or {next_block_number - 1}"
                        )
                        raise ProtocolError(error_msg)
                        
                    if block_number == next_block_number:
                        out_file.write(data)
                        next_block_number += 1
                        total_file_size += len(data)
                       

                        ack = pack_ack(block_number)
                        sock.sendto(ack, server_addr)
                        progress = out_file.tell() / total_file_size
                        print(f"\r[{int(progress * 100)}%] {'=' * int(progress * 20)}", end='', flush=True)

                        if len(data) < MAX_DATA_LEN:
                            print(f"\rRecebido... '{source_filename}' ({total_file_size} bytes) - ")
                               
                            break

                elif opcode == ERR:
                    error_code, error_msg = unpack_err(packet)
                    raise Err(error_code, error_msg)
                
                else:
                    error_msg = f"Invalid packet opcode: {opcode}. Expecting {DAT=}."
                    raise ProtocolError(error_msg)

       
#:
 
# def get_file(server_addr: INET4Address, filename: str):    
    # 1. Criar um socket DGRAM para comunicar com servidor em server_addr
    # 2. Abrir um ficheiro local com nome 'filename' para escrita binária
    # 3. Enviar RRQ para o servidor em server_addr
    # 4. Esperar por pacote enviado pelo servidor [1]
    #         4.1 Extrair opcode do pacote recebido
    #         4.2 Se opcode for DAT:
    #             a) Obter block_number e data (ie, o bloco de dados) (UNPACK)
    #             b) Se block_number não for next_block_number ou
    #                next_block_number - 1 => ERRO de protocolo [2]
    #             c) Se block_number == next_block_number [3], gravamos
    #                bloco de dados no ficheiro e incrementamos next_block_number
    #             d) Enviar ACK reconhecendo o último pacote recebido
    #             e) Se bloco de dados < 512, terminar o RRQ
    #          4.3 Se pacote for ERR: assinalar o erro lançando a excepção apropriada
    #          4.4 Se for outro tipo de pacote: assinalar ERRO de protocolo
    #          4.5 Voltar a 4
    #
    # [1] Terminar quando dimensão do bloco de dados do pacote
    #     DAT for < 512 bytes (ou se ocorrer um erro)
    # [2] next_block_number indica o próximo block_number, contador
    #     inicializado a 1 antes do passo 4.
    # [3] Isto quer dizer que recebemos um novo DAT.
#:
 
def put_file(server_addr: INET4Address, source_filename: str, destination_filename: str = None):
    """
    Put the local file given by 'filename' to the remote server at 'server_addr'
    through a TFTP WRQ connection.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Generalize for global timeout
        sock.settimeout(INACTIVITY_TIMEOUT)
        with open(source_filename, 'rb') as in_file:
            wrq = pack_wrq(destination_filename)
            sock.sendto(wrq, server_addr)
            block_number = 0
 
            file_size = os.path.getsize(source_filename)
            print(f"Enviado... '{source_filename}' ({file_size} bytes) para o servidor em {server_addr}...")
 
            while True:
                ack_packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                ack_opcode = unpack_opcode(ack_packet)
 
                if ack_opcode == ACK:
                    ack_block_number = unpack_ack(ack_packet)
                    if ack_block_number == block_number:
                        block_number += 1
                    else:
                        error_msg = (
                            f"Unexpected ACK block number: {ack_block_number}."
                            f"Expecting: {block_number}."
                        )
                        raise ProtocolError(error_msg)
 
                    data = in_file.read(MAX_DATA_LEN)
                    dat_packet = pack_dat(block_number, data)
                    sock.sendto(dat_packet, server_addr)
 
                    progress = in_file.tell() / file_size
                    print(f"\r[{int(progress * 100)}%] {'=' * int(progress * 20)}", end='', flush=True)
 
                    if len(data) < MAX_DATA_LEN:
                        print("Envio completo.")
                        break
 
                elif ack_opcode == ERR:
                    error_code, error_msg = unpack_err(ack_packet)
                    raise Err(error_code, error_msg)
 
                else:
                    error_msg = (
                        f"Invalid packet opcode: {ack_opcode}."
                        f"Expecting {ACK=} or {ERR=}."
                    )
                    raise ProtocolError(error_msg)
 
#:
    
##############################################################
##                                                          ##
##              PACKET PACKING AND UNPACKING                ##
##                                                          ##
##############################################################
 
def pack_rrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rrq_wrq(RRQ, filename, mode)
#:
 
#def pack_rrq(filename):
#    return struct.pack(f"!H{len(filename)}s", Opcode.RRQ.value, filename.encode())
#:
 
 
def _pack_rrq_wrq(opcode: int, filename: str, mode: str = DEFAULT_MODE) -> bytes:
    if not is_ascii_printable(filename):
        raise TFTPValueError(f"Invalid filename: {filename}. Not ASCII printable")
    filename_bytes = filename.encode() + b'\x00'
    mode_bytes = mode.encode() + b'\x00'
    fmt = f'!H{len(filename_bytes)}s{len(mode_bytes)}s'
    return struct.pack(fmt, opcode, filename_bytes, mode_bytes)
#:
 
def unpack_rrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rrq_wrq(RRQ, packet)
#:
 
def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rrq_wrq(WRQ, packet)
#:
 
def _unpack_rrq_wrq(opcode: int, packet: bytes) -> tuple[str, str]:
    received_opcode = unpack_opcode(packet)
    if opcode != received_opcode:
        raise TFTPValueError(f'Invalid opcode: {received_opcode}. Expected opcode: {opcode}')
    delim_pos = packet.index(b'\x00', 2)
    filename = packet[2: delim_pos].decode()
    mode = packet[delim_pos + 1:-1].decode()
    return filename, mode
#:
 
def pack_dat(block_number:int, data: bytes) -> bytes:
    if not 0 <= block_number <= MAX_BLOCK_NUMBER:
        err_msg = f'Block number {block_number} larger than allowed ({MAX_BLOCK_NUMBER})'
        raise TFTPValueError(err_msg)
    if len(data) > MAX_DATA_LEN:
        err_msg = f'Data size {block_number} larger than allowed ({MAX_DATA_LEN})'
        raise TFTPValueError(err_msg)
    
    fmt = f'!HH{len(data)}s'
    return struct.pack(fmt, DAT, block_number, data)
#:
 
def unpack_dat(packet: bytes) -> tuple[int, bytes]:
    opcode, block_number = struct.unpack('!HH', packet[:4])
    if opcode != DAT:
        raise TFTPValueError(f'Invalid opcode {opcode}. Expecting {DAT=}.')
    return block_number, packet[4:]
#:
 
def pack_ack(block_number: int) -> bytes:
    if not 0 <= block_number <= MAX_BLOCK_NUMBER:
        err_msg = f'Block number {block_number} larger than allowed ({MAX_BLOCK_NUMBER})'
        raise TFTPValueError(err_msg)
    
    return struct.pack(f'!HH', ACK, block_number)
#:
 
def unpack_ack(packet: bytes) -> int:
    opcode, block_number = struct.unpack('!HH', packet)
    if opcode != ACK:
        raise TFTPValueError(f'Invalid opcode {opcode}. Expecting {DAT=}.')
    return block_number
#:
 
def pack_err(error_code: int, error_msg: str | None = None) -> bytes:
    if error_code not in ERROR_MESSAGES:
        raise TFTPValueError(f'Invalid error code {error_code}')
    if error_msg is None:
        error_msg = ERROR_MESSAGES[error_code]
    error_msg_bytes = error_msg.encode() + b'\x00'
    fmt = f'!HH{len(error_msg_bytes)}s'
    return struct.pack(fmt, ERR, error_code, error_msg_bytes)
#:
 
def unpack_err(packet: bytes) -> tuple[int, str]:
    opcode, error_code = struct.unpack('!HH', packet[:4])
    if opcode != ERR:
        raise TFTPValueError(f'Invalid opcode: {opcode}. Expected opcode: {ERR=}')
    return error_code, packet[4:-1].decode()
#:
 
def unpack_opcode(packet: bytes) -> int:
    opcode, *_ = struct.unpack('!H', packet[:2])
    if opcode not in (RRQ, WRQ, DAT, ACK, ERR):
        raise TFTPValueError(f'Invalid opcode {opcode}')
    return opcode
#:
def pack_wrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rrq_wrq(WRQ, filename, mode)
 
def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rrq_wrq(WRQ, packet)
 

 
###############################################################
##                                                           ##
##                  ERRORS AND EXCEPTIONS                    ##
##                                                           ##     
###############################################################
 
class TFTPValueError(ValueError):
    pass
#:
 
class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """
#:
    
class ProtocolError(NetworkError):
    """
    A protocol error like unexpected or invalid opcode, wrong block
    number, or any other invalid protocol parameter.
    """
#:
    
class Err(Exception):
    """
    An error sent by the server. It may be caused because a read/write
    can't be processed. Read and write errors during file transmission
    also cause this message to be sent, and transmission is then
    terminated. The error number gives a numeric error code, followed
    by an ASCII error message that might contain additional, operating
    system specific information.
    """
    def __init__(self, error_code: int, error_msg: str):
        super().__init__(f'TFTP Error {error_code}')
        self.error_code = error_code
        self.error_msg = error_msg
    #:
#:
###############################################################
##                                                           ##
##                     COMMON UTILITIES                      ##
##              Mostly related to network tasks              ##
##                                                           ##     
###############################################################
 
# Funções auxiliares: podemos colocar num módulo à parte chamado "utils.py"
 
def _make_is_valid_hostname():
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname):
        """
        From: http://stackoverflow.com/quesions/2532053/validate-a-hostname-string
        See also: https://en.wikipedia.org/wiki/Hostname (and the RFC
        referenced there)
        """
        if not 0 < len(hostname) <= 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname
#:
is_valid_hostname = _make_is_valid_hostname()
 
 
def get_host_info(server_addr: str) -> tuple[str, str]:
    """
    Returns the server IP and hostname for server_addr. This parameter may
    either be an IP address, in which case this function tries to query
    its hostname, or vice-versa.
    
    Raises:
        ValueError: If the host name in server_addr is ill-formed.
        NetworkError: If an IP address cannot be obtained for the given host name.
    """
    try:
        ipaddress.ip_address(server_addr)
        server_ip = server_addr
        try:
            # Attempt to get the hostname from the IP address
            server_name = socket.gethostbyaddr(server_ip)[0]
        except socket.error:
            server_name = ''
    except ValueError:
        # server_addr is not a valid IP address, then it might be a valid hostname
        if not is_valid_hostname(server_addr):
            raise ValueError(f"Invalid hostname: {server_addr}.")
        server_name = server_addr
        try:
            # gethostbyname_ex returns the following tuple:
            # (hostname, aliaslist, ipaddrlist)
            server_ip = socket.gethostbyname_ex(server_name)[2][0]
        except socket.gaierror:
            raise NetworkError(f"Unknown server: {server_name}.")
 
    return server_ip, server_name
 
 
def is_ascii_printable(txt: str) -> bool:
    return set(txt).issubset(string.printable)
    # ALTERNATIVA: return not set(txt) - set(string.printable)


def server_on(server_name):
    try:
        subprocess.check_output(["ping", "-c", "1", server_name])
        return True
    except subprocess.CalledProcessError:
        return False

def ip_valido(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def resolve_server_address(server_name, server_port):
    if not ip_valido(server_name):
        try:
            server_ip = socket.gethostbyname(server_name)
            return server_ip, server_port
        except socket.error as e:
            print(f"Error: Unable to resolve the server address for {server_name}")
            sys.exit(1)
    else:
        return server_name, server_port

def verif_estado_server(server_name, server_port):
    server_address = resolve_server_address(server_name, server_port)
    if not server_on(server_address[0]):
        print("Server not responding. Exiting.")
        sys.exit(1)
    return server_address



