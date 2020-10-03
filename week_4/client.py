from socket import *
import threading
import time
from Crypto.Cipher import AES


def pad(s: str):
    """

    :param s: padding할 평문
    :return: padding한 문자열
    """
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    """

    :param s: padding된 문자열
    :return: padding되지 않은 평문
    """
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes) -> bytes:
    """

    :param data: 평문
    :param key: 16 bytes key (암복호화할 때 같아야 함)
    :return: initial vector + 암호화된 평문 data
    """
    #  TODO: 구현할 부분 (data.encode('utf-8') 도 변경해도 됨)
    data = pad(data)
    iv = pad('initialvector').encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv )
    data = iv + cipher.encrypt(data.encode('utf-8'))

    return data


def decrypt(data: bytes, key: bytes) -> str:
    """

    :param data: initial vector(16) + 암호화된 data
    :param key: 16 bytes key (암복호화할 때 같아야 함)
    :return: 평문 (parameter data에서 initial vector를 제외하고 남은 부분을 복호화한 문자열)
    """
    #  TODO: 구현할 부분 (data.decode('utf-8') 도 변경해도 됨)
    iv, data = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    data = unpad(cipher.decrypt(data))
    
    return data.decode('utf-8')


def send(sock, key):
    """
    함수설명: 사용자의 입력을 계속 기다린다. 사용자가 데이터를 입력하면 key와 함께 암호화하여 sock을 통해 보낸다.

    :param sock: 클라이언트 소켓 객체
    :param key: byte 형식, 16 bytes로 인코딩된 key
    """
    while True:
        send_data = input('>>>')
        sock.send(encrypt(send_data, key))


def receive(sock, key):
    """
    # socket.recv(1024) : socket의 버퍼에서 1024 bytes만큼의 데이터를 읽는다. 없다면 올 때까지 기다린다.
    함수설명: sock에서 읽을 데이터가 있을 때까지(버퍼) 계속 기다린다. sock의 버퍼에 데이터가 생기면 key를 이용해 복호화한 후 출력한다.

    :param sock: 클라이언트 소켓 객체
    :param key: byte 형식, 16 bytes로 인코딩된 key
    """
    while True:
        recv_data = sock.recv(1024)
        print('상대방 :', decrypt(recv_data, key))


port = 8081

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect(('127.0.0.1', port))

print('접속 완료')

key = input('key를 입력해주세요: ')
sender = threading.Thread(target=send, args=(clientSock, key.encode('utf-8')))
receiver = threading.Thread(target=receive, args=(clientSock, key.encode('utf-8')))

sender.start()
receiver.start()

while True:
    time.sleep(1)
    pass
