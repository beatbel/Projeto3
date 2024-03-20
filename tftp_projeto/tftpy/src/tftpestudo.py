
"""
Este modulo handles all TFTP related "stuff": data structures, packet definitions,
methods and protocol operations
"""
import sys
import os
import string
import struct
import ipaddress
import re
import socket
import subprocess

############################################################################
##
##          PROTOCOL CONSTANTS AND TYPES
##
############################################################################

MAX_DATA_LEN = 512            #bytes
MAX_BLOCK_NUMBER = 2**16 - 1  #0..65535
INACTIVITY_TIMEOUT = 60.0     #segs
DEFAULT_MODE = 'octet'
DEFAULT_BUFFER_SIZE = 8192    #bytes

#TFTP message opcodes
RRQ = 1     #READ REQUEST
WRQ = 2     #WRITE REQUEST
DAT = 3     #DATA TRANSFER
ACK = 4     #ACKNOWLEDGE
ERR = 5     #ERROR PACKET; what the server responds if a read/write
              #cant be processed, read and write errors during file
              #transmission also cause this message to be sent, and
              #transmission is then terminated. The error number gives
              #numeric error code, followed by an ASCII error message that
              #might contain additional, operating system specific
              #information.


ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
DISK_FULL_OR_ALLOC_EXC = 3
ILLEG_TFTP_OPERAT = 4
UNK_TRANSF_ID = 5
FILE_ALR_EXISTS = 6
NO_SUCH_USER = 7

ERROR_MESSAGES = {
    ERR_NOT_DEFINED: 'Not defined, see error message (if any).',
    ERR_FILE_NOT_FOUND: 'File not found.',
    ERR_ACCESS_VIOLATION: 'Access violation.',
    DISK_FULL_OR_ALLOC_EXC: 'Disk full or allocation exceeded.',
    ILLEG_TFTP_OPERAT: 'Illegal TFTP operation.',
    UNK_TRANSF_ID: 'Unknown transfer ID.',
    FILE_ALR_EXISTS: 'File already exists.',
    NO_SUCH_USER: 'No such user.'
}

INET4Address = tuple[str, int]          #TCP/UDP address => IPv4 and port

def check_file_existence(server_addr: INET4Address, remote_filename: str) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        rrq = pack_rrq(remote_filename)
        sock.sendto(rrq, server_addr)
 
        try:
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
                    raise ProtocolError(f"Unexpected opcode {opcode}. Expected {DAT=} or {ERR=}")
 
        except socket.timeout:
            # Timeout occurred, assume the file does not exist
            return False


############################################################################
##
##          SEND AND RECEIVE FILES
##
############################################################################

def get_file(server_addr: INET4Address, remote_filename: str, local_filename: str = None):
    """
    Get the file named 'remote_filename' from the remote server at 'server_addr'
    through a TFTP RRQ connection.

    If 'local_filename' is not provided, the local file will have the same name as the remote file.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Generalize for global timeout
            sock.settimeout(INACTIVITY_TIMEOUT)

            if local_filename is None:
                local_filename = remote_filename

            rrq = pack_rrq(remote_filename)
            sock.sendto(rrq, server_addr)

            with open(local_filename, 'wb') as out_file:
                print(f"Downloading '{remote_filename}' from server at {server_addr}...")

                block_number = 1
                while True:
                    dat_packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                    dat_opcode = unpack_opcode(dat_packet)

                    if dat_opcode == DAT:
                        dat_block_number, data = unpack_dat(dat_packet)
                        if dat_block_number == block_number:
                            out_file.write(data)
                            ack_packet = pack_ack(block_number)
                            sock.sendto(ack_packet, server_addr)
                            block_number += 1

                            # Print progress
                            print(f"\rReceived {len(data)} bytes.", end='', flush=True)

                            if len(data) < MAX_DATA_LEN:
                                print("\nDownload complete.")
                                print(f"File '{remote_filename}' saved as '{local_filename}'")
                                break

                        else:
                            error_msg = (
                                f"Unexpected DAT block number: {dat_block_number}."
                                f"Expecting: {block_number}."
                            )
                            raise ProtocolError(error_msg)

                    elif dat_opcode == ERR:
                        error_code, error_msg = unpack_err(dat_packet)
                        raise Err(error_code, error_msg)

                    else:
                        error_msg = (
                            f"Invalid packet opcode: {dat_opcode}."
                            f"Expecting {DAT=} or {ERR=}."
                        )
                        raise ProtocolError(error_msg)

    except socket.timeout:
        print("\nServer not responding. Exiting.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


#:
    
    print(f"Descarregar ficheiro a partir de {server_addr}")



    #1.Criar um socket DGRAM para comunicar com o servidor em server_addr
    #2. Abrir um ficheiro local com nome 'filename' para escrita binária
    #3. Enviar um RRQ para o servidor em server_addr
    #4. Esperar por pacote enviado pelo servidor [1]
    #   4.1 Extrair opcode ao pacote recebido
    #   4.2 Se opcode for DAT:
    #       a)Obter block_number e data (ie, o bloco de dados) (UNPACK)
    #       b)Se o block_number nao for next_block_number ou next_block_number -1 => ERRO
    #       de protocolo [2]
    #       c) Se block_number == next_block_number [3], gravamos bloco de dados no ficheiro
    #       e incrementamos next_block_number
    #       d) Enviar ACK reconhecendo o último pacote recebido
    #       e) Se bloco de dados < 512, terminar o RRQ
    #   4.3 Se pacote for ERR: assinalar o erro lançando a excepção apropriada
    #   4.4 Se for outro tipo de pacote: assinalar ERRO de protocolo
    #   4.5 Voltar a 4
    #
    #
    # [1] Terminar quando dimensao do bloco de dados do pacote
    #       DAT for < 512 bytes (ou se ocorrer um erro)
    # [2] next_block_number indica o proximo block_number, contador
    #       inicializado a 1 antes do passo 4.
    # [3] Isto quer dizer que recebemos um novo DAT
#:

def put_file(server_addr: INET4Address, local_filename: str, remote_filename: str = None):
    """
    Put the local file given by 'local_filename' to the remote server at 'server_addr'
    through a TFTP WRQ connection.
 
    If 'remote_filename' is not provided, the remote file will have the same name as the local file.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Generalize for global timeout
            sock.settimeout(INACTIVITY_TIMEOUT)
            with open(local_filename, 'rb') as in_file:
                wrq = pack_wrq(remote_filename)
                sock.sendto(wrq, server_addr)
                block_number = 0
 
                file_size = os.path.getsize(local_filename)
                print(f"Uploading '{local_filename}' ({file_size} bytes) to server at {server_addr}...")
 
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
                        percentage = int(progress * 100)
 
                        # Print both percentage progress and bytes-sent bar
                        print(f"\r[{percentage}%] {'#' * int(progress * 20)} [{in_file.tell()}/{file_size} bytes]", end='', flush=True)
 
                        if len(data) < MAX_DATA_LEN:
                            print(f"\nUpload complete.")
                            print(f"File '{local_filename}' uploaded as '{remote_filename}'")
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
 
    except FileNotFoundError:
        print(f"Error: The local file '{local_filename}' does not exist.")
        sys.exit(1)
    except socket.timeout:
        print("\nServer not responding. Exiting.")
        sys.exit(1)
 
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)



#:
    print(f"Enviar ficheiro para {server_addr}")

############################################################################
##
##          PACKET PACKING AND UNPACKING
##
############################################################################


def pack_rrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rrq_wrq(RRQ, filename, mode)
#:

def pack_wrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rrq_wrq(WRQ, filename, mode)
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
    if opcode != unpack_opcode:
        raise TFTPValueError(f'Invalid opcode: {received_opcode}. Expected opcode: {opcode}')
    delim_pos = packet.index(b'\x00', 2)
    filename = packet[2: delim_pos].decode()
    mode = packet[delim_pos + 1:-1].decode()
    return filename, mode
#:


def pack_dat(block_number: int, data: bytes) -> bytes:
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
       raise TFTPValueError(F"Invalid opcode {opcode}")
    return opcode
#:



############################################################################
##
##          ERRORS AND EXCEPTIONS
##
############################################################################

class TFTPValueError(ValueError):
    pass


class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts,etc.
    """
#:
    

class ProtocolError(NetworkError):
    """
    A protocol error like unexpected or invalid opcode, wrong block number, or any other
    invalid protocol parameter.
    """
#:
    

class Err(Exception):
    """
    An error sent by the server. It may be caused because a read/write
    can't be processed. Read and write errors during file transmission 
    also cause this message to be sent, and transmission in then
    terminated. The error number gives a numeric error code, 
    followed by an ASCII error message that might contain additional, operating
    system spcific information.
    """


    def __init__(self, error_code: int, error_msg:str):
        super().__init__(f'TFTP Error {error_code}')
        self.error_code = error_code
        self.error_msg = error_msg
    #:
#:
        

############################################################################
##
##          COMMON UTILITIES
##          Mostly related to network tasks
##
############################################################################

def _make_is_valid_hostname():
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname):
        """
        From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        see also: https://en.wikipedia.org/wiki/Hostname (and the RFC
        referenced there)
        """
        if not 0 < len(hostname) <= 255:
            return False
        if hostname[-1] == ".":
            #strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname
#:
is_valid_hostname = _make_is_valid_hostname()


def get_host_info(server_addr: str) -> tuple[str, str]:
    """
    Returns the server ip and hostname for server_addr. This parameter
    may either be an IP address, in which case this function tries to query
    its hostname, or vice-versa.
    This functions raises a ValueError exception if the host name in 
    server_addr is ill-formed, and raises NetworkError if we can't get
    an IP address for that host name.
    TODO: refactor code...
    """
    try:                                                                             
        ipaddress.ip_address(server_addr)                                                             
    except ValueError:                                                                 
        #server_addr not a valid ip address, then it might be a                         
        #valid hostname                                                                     
        #pylint: disable=raise-missing-from                                             
        if not is_valid_hostname(server_addr):                                          
            raise ValueError(f"Invalid hostname: {server_addr},")                   
        server_name = server_addr                                                   
        try:                                                                        
            #gethostbyname_ex returns the following tuple:                          
            # (hostname, aliaslist, ipaddrlist)                                     
            server_ip = socket.gethostbyname_ex(server_name)[2][0]                     
        except socket.gaierror:                                                                
            raise NetworkError(f"Unknown server: {server_name},")                           
    else:                                                                          
        #server_addr is a valid ip address, get the hostname                       
        #if possible                                                            
        server_ip = server_addr                                                 
        try:                                                                    
            #returns a tuple like gethostbyname_ex                              
            server_name = socket.gethostbyaddr(server_ip)[0]                        
        except socket.herror:                                                       
            server_name = ''                                                        
    return server_ip, server_name                                                   
#:



def is_ascii_printable(txt: str) -> bool:
    return set(txt).issubset(string.printable)
    #ALTERNATIVA: return not set(txt) - set(string.printable)
#:


def gethostbyname(hostname: str) -> tuple:

    """

    Get the IP address of a host by its name.
 
    Args:

        hostname (str): The hostname to resolve.
 
    Returns:

        tuple: A tuple containing the IP address and the original hostname.

    """

    try:

        ip_address = socket.gethostbyname(hostname)

        return ip_address, hostname

    except socket.error as e:

        print(f"Error resolving hostname {hostname}: {e}")

        return None, None
 
def is_server_online(server_name):

    try:

        subprocess.check_output(["ping", "-c", "1", server_name])

        return True

    except subprocess.CalledProcessError:

        return False
 
def is_valid_ip(ip):

    try:

        socket.inet_aton(ip)

        return True

    except socket.error:

        return False
 
def resolve_server_address(server_name, server_port):

    if not is_valid_ip(server_name):

        try:

            server_ip = socket.gethostbyname(server_name)

            return server_ip, server_port

        except socket.error as e:

            print(f"Error: Unable to resolve the server address for {server_name}")

            sys.exit(1)

    else:

        return server_name, server_port
 
def check_server_status(server_name, server_port):

    server_address = resolve_server_address(server_name, server_port)
 
    if not is_server_online(server_address[0]):

        print("Server not responding. Exiting.")

        sys.exit(1)
 
    return server_address



