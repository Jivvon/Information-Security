from typing import Dict, List

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def pad(s: str):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes or None) -> bytes:
    if key is None:
        return data.encode('utf-8')
    data = pad(data).encode('utf-8')
    aes = AES.new(key, AES.MODE_CBC)
    iv = aes.iv
    enc = aes.encrypt(data)
    return iv + enc


def decrypt(data: bytes, key: bytes) -> str:
    if key is None:
        return data.decode('utf-8')
    iv = data[:16]
    enc = data[16:]
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    dec = aes.decrypt(enc)
    return unpad(dec).decode('utf-8')


class Proxy:
    def __init__(self):
        self._linked_ip: Dict[str, "Client"] = {}
        self.msg_list: List[str] = []

    def link(self, client: "Client"):
        self._linked_ip[client.ip] = client

    def public_key(self, target_ip: str):
        """
        Public key는 올바르게 전송해줌을 가정합니다.
        :param target_ip: 공개키를 얻을 ip. self._linked_ip에서 가져온다
        :return: target_ip의 공개키
        """
        return self._linked_ip[target_ip].key.publickey()

    def request(self, source_ip: str, target_ip: str, msg: bytes):
        try:
            self.msg_list.append(msg.decode('utf-8'))
        except UnicodeDecodeError:
            print("Can't read Data in proxy")

        self._linked_ip[target_ip].receive(msg, source_ip)

    def client(self, ip: str) -> "Client":
        """
        상대 client를 ip값과 proxy를 통해 얻을 수 있음
        :param ip: 상대 client ip
        :return: 상대 Client 객체
        """
        return self._linked_ip[ip]


class Client:
    def __init__(self, ip: str, rsa_key=None):
        self.ip = ip
        self.session_key: Dict[str, bytes] = {}   # { ip : session key }
        if rsa_key is None:
            self.key = RSA.generate(2048)             # RSA Key
        else:
            self.key = rsa_key
        self.msg_list: List[str] = []

    def request(self, proxy: Proxy, target_ip: str, msg: str):
        """
        TODO 함수 설명:
        상대방의 공개키로 메세지를 암호화하여 프록시서버를 통해 보낸다.
        target_ip에 암호화한 메세지를 보내도록 프록시 서버에 request를 요청한다.
        :param proxy: 상대방 Client에게 메세지를 전송해주는 중간 프록시 서버
        :param target_ip: 최종적으로 메세지를 전송할 상대방 ip
        :param msg: target_ip로 전송할 메세지
        :return:
        """
        if not self.session_key.get(target_ip):
            self.handshake(proxy, target_ip)

        enc = encrypt(msg, self.session_key[target_ip])
        proxy.request(self.ip, target_ip, enc)

    def receive(self, msg: bytes, source_ip: str):
        """
        TODO 함수설명:
        상대방(source_ip)이 보낸 암호화된 메세지를 받는다. 이 메세지는 현재 Client의 공개키로 암호화되어 온다.
        proxy에서 호출한다.
        이전에 handshake 과정을 거쳐서 session key를 공유한 상황이어야 함
        :param msg: 전송된(받은) 메세지
        :param source_ip: 메세지를 보낸 곳(상대방)
        :return:
        """
        dec = decrypt(msg, self.session_key[source_ip])
        self.msg_list.append(dec)

    def handshake(self, proxy: Proxy, target_ip: str, session_key: bytes or None = None):
        """
        상대 ip에 대한 session key가 없을 경우 사용하는 함수
        target ip 주소의 client의 public key를 받아와 public key 로 암호화한 session key를 전송
        공유한 session key는 self.session_key 에 ip와 매핑하여 저장

        session key를 입력받았을 때는 암호화된 session_key를 받았음을 가정한다. test code 참고
        session key를 받지 않았을 경우 session key를 생성해 session key를 상대의 공개키로 암호화하여 handshake 진행
        :param proxy: 프록시 서버
        :param target_ip: session_key를 공유할 상대 ip
        :param session_key: 암호화된 session key. 상대방과 같은 대칭키로, 이를 이용하여 메세지를 암호화한다.
        :return:
        """
        # TODO: mode에 따라 각각 구현
        # handshake를 하는 상대도 session key를 저장해야 함
        if session_key is None:
            session_key = get_random_bytes(16)
            target = proxy._linked_ip[target_ip]
            target_pub = PKCS1_OAEP.new(proxy.public_key(target_ip))
            target.handshake(proxy, self.ip, target_pub.encrypt(session_key))
            self.session_key[target_ip] = session_key
        else:
            private = PKCS1_OAEP.new(self.key)
            self.session_key[target_ip] = private.decrypt(session_key)
