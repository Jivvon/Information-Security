from socket import *
import threading
import time
from hashlib import sha256


def send(sock, send_data):
    sock.send(send_data)


def receive(sock, addr, dst):
    while True:
        recv_data = sock.recv(1024)
        try:
            print(f'{addr} :', recv_data.decode('utf-8'))
        except:
            print(f'{addr} :', recv_data)
        send(dst, recv_data)


def load_db():
    return [
        {
            'id': 'a',
            'password': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'  # a
        },
        {
            'id': 'information',
            'password': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'  # abc
        },
        {
            'id': 'security',
            'password': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'  # password
        },
        {
            'id': '201950219',
            'password': '6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090'  # ?
        }
    ]


def verify_login(db, user_id, password) -> bool:
    """
    TODO: db에 있는 user id와 password의 해시값을 통해 입력받은 id와 password 값이 옳은 지 검증
    로그인 실패 시
    :param db: user들의 id와 password가 들어있는 정보 (list)
    :param user_id: 검증하고자하는 user id
    :param password: 검증하고자하는 password
    :return: db에 user_id와 그에 맞는 password가 있는지의 결과. 있다면 True 없다면 False
    """
    if {'id': user_id, 'password': sha256(password[:16].encode('utf-8')).hexdigest()} in db:
        print(f'{user_id} 로그인 성공')
        return True
    return False


def connect_socket():
    port = 8081
    db = load_db()
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(('', port))
    server_socket.listen(2)

    print('%d번 포트로 접속 대기중...' % port)

    connection_socket1, addr1 = server_socket.accept()
    connection_socket2, addr2 = server_socket.accept()

    print(str(addr1), '에서 접속되었습니다.')
    print(str(addr2), '에서 접속되었습니다.')

    # TODO: 두 클라이언트의 login 확인
    # 한 클라이언트라도 로그인 실패 시 server_socket.close() 호출 후 종료

    id1, pw1 = connection_socket1.recv(1024).decode(), connection_socket1.recv(1024).decode()
    id2, pw2 = connection_socket2.recv(1024).decode(), connection_socket2.recv(1024).decode()
    if not verify_login(db, id1, pw1) or not verify_login(db, id2, pw2):
        print('로그인 실패')
        server_socket.close()
        return

    # TODO: 두 클라이언트 public key 전달
    send(connection_socket1, connection_socket2.recv(1024))
    send(connection_socket2, connection_socket1.recv(1024))

    receiver1 = threading.Thread(target=receive, args=(connection_socket1, addr1, connection_socket2))
    receiver2 = threading.Thread(target=receive, args=(connection_socket2, addr2, connection_socket1))

    receiver1.start()
    receiver2.start()

    try:
        while True:
            time.sleep(1)
            pass
    except KeyboardInterrupt:
        server_socket.close()


if __name__ == '__main__':
    connect_socket()
    # print(sha256('a'.encode('utf-8')).hexdigest())
    # print(sha256('password'.encode('utf-8')).hexdigest())
