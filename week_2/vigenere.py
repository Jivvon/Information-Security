import string
from enum import Enum

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


class EncryptionMode(Enum):
    ENC = 'ENCRYPT'
    DEC = 'DECRYPT'


def vigenere_encrypt_decrypt(text: str, key: str, mode: EncryptionMode) -> str:
    """
    비제네르 암호를 이용하여 암호화 혹은 복호화를 수행하는 암호 알고리즘
    :param text: 암호화할 문자열
    :param key: 암호화에 사용할 key의 배열
    :param mode: 암호화할 지 복호화할 지 구분하기 위한 값
    :return: 비제네르 암호를 이용한 암호문 혹은 복호화된 문자열
    """

    key2ord = list(map(lambda x:ord(x)-ord('a') if x in lower_alphabet_list else ord(x) - ord('A'),key))
    answer = ''
    tmp = 0

    if mode == EncryptionMode.ENC:
        for idx, ch in enumerate(text):
            if ch in lower_alphabet_list:
                tmp = (ord(ch) + key2ord[idx % len(key)] - ord('a')) % 26 + ord('a')
            elif ch in upper_alphabet_list:
                tmp = (ord(ch) + key2ord[idx % len(key)] - ord('A')) % 26 + ord('A')
            elif ch in number_list:
                tmp = (ord(ch) + key2ord[idx % len(key)] - ord('0')) % 10 + ord('0')
            answer += chr(tmp)
    elif mode == EncryptionMode.DEC:
        for idx, ch in enumerate(text):
            if ch in lower_alphabet_list:
                tmp = (ord(ch) - key2ord[idx % len(key)] - ord('a')) % 26 + ord('a')
            elif ch in upper_alphabet_list:
                tmp = (ord(ch) - key2ord[idx % len(key)] - ord('A')) % 26 + ord('A')
            elif ch in number_list:
                tmp = (ord(ch) - key2ord[idx % len(key)] - ord('0')) % 10 + ord('0')
            answer += chr(tmp)
    return answer
