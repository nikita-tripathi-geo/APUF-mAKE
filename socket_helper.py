"""Small helpers for length-prefixed, big-endian TCP messages.
"""
import socket
import struct

# CONFIGURATION
DEFAULT_TIMEOUT = 100.0     # seconds for connect/recv/send
_LEN_HDR = 4              # 4-byte length prefix (uint32, big-endian)

# EXCEPTIONS
class SocketIOError(Exception):
    """Raised on any failure in our socket I/O helpers."""

# SOCKET LIFECYCLE
def create_socket(ip: str, port: int, listen: bool = False) -> socket.socket:
    """Creates a socket at the specified ip and port.

    Creates a TCP/IP socket at the specified port, and does the setup
    necessary to turn it into a connecting or receiving socket.
    
    Args:
        ip (str): A string representing the IP address to connect/bind to.
        port (int): An integer representing the port to connect/bind to.
        listen (bool): A boolean that flags whether or not to set the socket up
            for connecting or receiving.
    
    Returns:
        If successful, a socket object that's been prepared according to 
        the `listen` flag.

    Raises:
        ValueError: If `ip` is not a string or `port` is not an int.
        SocketIOError: If socket creation fails at the OS level.
    """

    if not isinstance(ip, str) or not isinstance(port, int):
        raise ValueError("create_socket: ip must be str, port must be int")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)

    try:
        if listen:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((ip, port))
            sock.listen(2)
        else:
            sock.connect((ip, port))
    except OSError as e:
        sock.close()
        raise SocketIOError(f"create_socket failed: {e}") from e

    return sock


def close_socket(sock: socket.socket) -> None:
    """Shutdown and close, ignoring errors."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        sock.close()


# CORE I/O HELPERS
def send_msg(sock: socket.socket, payload: bytes) -> None:
    """Send a single length-prefixed message over the socket.

    The format is:
      4-byte big-endian uint (length) || payload bytes

    Args:
        sock (socket.socket): The connected TCP socket.
        payload (bytes): The message body to send.

    Raises:
        ValueError: If `payload` is not bytes-like.
        SocketIOError: On timeout or any OS level socket error during send.
    """

    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("send_msg: payload must be bytes or bytearray")

    # Convert length to big-endian uint (4-bytes)
    length = struct.pack(">I", len(payload))

    try:
        sock.sendall(length + payload)
    except socket.timeout as e:
        raise SocketIOError(
            f"timeout sending message of length {len(payload)}"
        ) from e
    except OSError as e:
        raise SocketIOError(f"socket error during send: {e}") from e


def _recvall(sock: socket.socket, goal: int) -> bytes:
    """Receive exactly `goal` bytes.

    This function repeatedly calls recv() until the requested number
    of bytes have been read or an error/timeout occurs.

    Args:
        sock (socket.socket): The connected TCP socket.
        goal (int): The total number of bytes to read. Must be non-negative.

    Returns:
        A bytes object of length exactly `goal`.

    Raises:
        ValueError: If `goal` is not a non-negative int.
        SocketIOError: If the connection closes prematurely, a timeout
                       occurs, or any socket error happens.
    """

    if not isinstance(goal, int) or goal < 0:
        raise ValueError("_recvall: goal must be non-negative")

    # Empty buffer
    buf = b""
    # Remaining bytes to receive
    rem = goal

    try:
        while rem > 0:
            # Receive at most 8192-byte chunks (TODO: set higher?)
            chunk = sock.recv(min(rem, 8192))
            if not chunk:
                raise SocketIOError(
                    f"Connection closed, got {goal - rem}/{goal} bytes"
                )
            # Update buffer and remaining bytes
            buf += chunk
            rem -= len(chunk)
    except socket.timeout as e:
        raise SocketIOError(
            f"Timeout while receiving data ({goal - rem}/{goal})"
        ) from e
    except OSError as e:
        raise SocketIOError(f"Socket error during recv: {e}") from e

    return buf


def recv_msg(sock: socket.socket) -> bytes:
    """Receive a single length-prefixed message and return its payload.

    The function first reads a 4-byte big-endian length prefix, then
    reads exactly that many bytes as the payload.

    Args:
        sock (socket.socket): The connected TCP socket.

    Returns:
        The payload bytes of the incoming message.

    Raises:
        SocketIOError: On any I/O error, timeout, or if the declared
                       length is unreasonably large (>100MB).
    """
    # 1) Read the 4-byte size header
    raw_len = _recvall(sock, _LEN_HDR)
    (length, ) = struct.unpack(">I", raw_len)

    # guard against absurdly large allocations (100MB = 100 * 2^20 B)
    if length > (100 * 2**20):
        raise SocketIOError(f"unreasonable message length: {length}")

    # 2) Read the payload
    return _recvall(sock, length)
