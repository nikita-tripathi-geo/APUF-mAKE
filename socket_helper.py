"""Standard helper functions for socket programming
"""
import socket
from typing import Optional


def close_socket(sock):
    """A helper function to close sockets"""
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    return None


def create_socket(ip:str, port:int,
                  listen:bool = False) -> Optional[socket.socket]:
    """Creates a socket at the specified ip and port.

    Creates a TCP/IP socket at the specified port, and does the setup
    necessary to turn it into a connecting or receiving socket.
    Does not actually send or receive data here.
    
    Args:
        ip (str):A string representing the IP address to connect/bind to.
        port (int): An integer representing the port to connect/bind to.
        listen (bool): A boolean that flags whether or not to set the socket up
            for connecting or receiving.
    
    Returns:
        If successful, a socket object that's been prepared according to 
        the instructions. Otherwise, return None.

    Raises:
        AssertionError: If `d` is not a positive integer, of `weight_mean`
            is not a float, or if `weight_std` is not a non-negative float.
    """

    assert isinstance(ip, str)
    assert isinstance(port, int)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        if listen:
            sock.bind( (ip, port) )
            sock.listen(2)
        else:
            sock.connect( (ip, port) )

        return sock
    except OSError:
        print("OSError: problem with create_socket")
        return None


def send(sock: socket.socket, data: bytes) -> int:
    """Reliably send provided data across the given socket.
     
    This is a 'reliable' send - the function retries sending until either 
    a) all data has been sent, or b) the socket closes.

    Args:
        sock (socket.socket): A socket object used for sending and receiving.
        data (bytes): A bytes object containing the data to send.

    Returns:
        The number of bytes sent. If this value is less than len(data),
        the socket is dead plus an unknown amount of the data was transmitted.
    """

    assert isinstance(sock, socket.socket)
    assert isinstance(data, bytes)


    sent = 0
    while sent < len(data):
        try:
            out = sock.send(data[sent:])
        except OSError:
            return sent

        if out <= 0:
            return sent
        sent += out

    return sent


def receive(sock: socket.socket, length: int) -> bytes:
    """Receive data with known length across the given socket.
    
    This is a 'reliable' receive - the function never returns until either
    a) the specified number of bytes was received, or b) the socket closes.
    Never returning is an option.

    Args:
        sock (socket.socket): A socket object to use for sending and receiving.
        length (int): A positive integer - the number of bytes to receive.

    Returns:
        A bytes object containing the received data. If this value is less than 
        length, the socket is dead.
    """

    assert isinstance(sock, socket.socket)
    assert length > 0

    receieved = b""

    while len(receieved) < length:
        rem = length - len(receieved)
        try:
            input_ = sock.recv(min(rem, 8192))
            # TODO set bufsize to some large number
        except OSError:
            return receieved

        if input_ == b"":
            return receieved

        receieved = receieved + input_

    return receieved
