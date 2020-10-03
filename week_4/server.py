from socket import *
import threading
import time


def send(sock, send_data):
    """
    함수설명: sock으로 send_data를 전송한다.

    :param sock: 데이터를 보낼 소켓
    :param send_data: sock으로 전송할 데이터. byte 형식. 암호화되어있어 읽을 수 없다.
    """
    sock.send(send_data)


def receive(sock, addr, dst):
    """
    # socket.recv(1024) : socket의 버퍼에서 1024 bytes만큼의 데이터를 읽는다. 없다면 올 때까지 기다린다.
    함수설명: sock 소켓으로 데이터가 오는지 기다린다(sock.recv). 데이터가 온다면 보낸 클라이언트의 주소와 데이터를 출력한 후, dst 소켓으로 데이터를 보낸다.

    :param sock: 데이터를 읽을 소켓. 이 소켓으로 오는 데이터를 읽는다.
    :param addr: 데이터를 읽을 소켓의 주소
    :param dst: 받은 데이터를 전송할 소켓
    """
    while True:
        recv_data = sock.recv(1024)
        try:
            print(f'{addr} :', recv_data.decode('utf-8'))
        except:
            print(f'{addr} :', recv_data)
        send(dst, recv_data)


port = 8081

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.bind(('', port))
serverSock.listen(2)

print('%d번 포트로 접속 대기중...'%port)

connectionSock1, addr1 = serverSock.accept()
connectionSock2, addr2 = serverSock.accept()

print(str(addr1), '에서 접속되었습니다.')
print(str(addr2), '에서 접속되었습니다.')

receiver1 = threading.Thread(target=receive, args=(connectionSock1,addr1, connectionSock2))
receiver2 = threading.Thread(target=receive, args=(connectionSock2,addr2, connectionSock1))

receiver1.start()
receiver2.start()

try:
    while True:
        time.sleep(1)
        pass
except KeyboardInterrupt:
    serverSock.close()
