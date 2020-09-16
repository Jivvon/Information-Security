from Crypto.Cipher import DES

def encrypt_des(message: str, key: str, mode: int, iv=None) -> (bytes, bytes):
    """

    :param message: 암호화할 평문
    :param key: 대칭키.
    :param mode: 블록 암호 모드. 평문 블록과 암호 알고리즘의 출력을 XOR하여 암호문 블록을 만들어내는 OFB(Output-FeedBack mode)를 사용한다.
    :param iv: initial vector, 특정 계산함수를 반복 수행하는 DES에서는 첫 연산은 이전 연산값이 없으므로 이를 대신한다.
    :return:
    """
    cipher = DES.new(bytes(key, 'utf-8'), mode, iv=iv) # bytes 객체로 변환한 key와 mode, iv로 암호화하기 위한 DES 객체를 만든다.
    return cipher.iv, cipher.encrypt(bytes(message, 'utf-8')) # cipher 객체를 사용하여 message를 암호화하여 iv와 함께 반환한다.


def decrypt_des(encrypted: bytes, key: str, mode: int, iv: bytes) -> str:
    """

    :param encrypted: 암호화된 bytes 객체
    :param key: 대칭키
    :param mode: 블록 암호 모드. 평문 블록과 암호 알고리즘의 출력을 XOR하여 암호문 블록을 만들어내는 OFB(Output-FeedBack mode)를 사용한다.
    :param iv: initial vector, 이를 이용해서 암호화를 시작하였으므로, 복호화할 때에도 필요하다
    :return: key와 iv를 이용하여 encrypted를 복호화한 값
    """
    cipher = DES.new(bytes(key, 'utf-8'), mode, iv=iv) # bytes 객체로 변환한 key와 mode, iv로 복호화하기 위한 DES 객체를 만든다.
    return cipher.decrypt(encrypted).decode('utf-8') # cipher 객체를 사용하여 암호화된 encrypted를 복호화하여 반환한다. 이 때, DES 객체의 iv와 key를 사용한다.
