import socket
import sys
import threading
import isotp
import diag


def main():
    mutex = threading.Lock()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 11231))

    sock.listen(10)

    while True:
        conn, address = sock.accept()
        threading.Thread(target = diag.Diag,args = (conn, address[0], mutex)).start()

if __name__ == '__main__':
	main()        