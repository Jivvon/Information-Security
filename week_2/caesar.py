import string

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


def caesar_encrypt_decrypt(text: str, key: int) -> str:
    """
    시저 암호를 이용하여 암호화 혹은 복호화를 수행하는 암호 알고리즘
    :param text: 암호화할 문자열
    :param key: 암호화에 사용할 key
    :return: 시저 암호를 이용한 암호문 혹은 복호화된 문자열
    """

    answer = ''
    for ch in text:
        if ch in lower_alphabet_list:
            tmp = (ord(ch) - ord('a') + key) % 26 + ord('a')
        elif ch in upper_alphabet_list:
            tmp = (ord(ch) - ord('A') + key) % 26 + ord('A')
        elif ch in number_list:
            tmp = (ord(ch) - ord('0') + key) % 10 + ord('0')
        answer += chr(tmp)

    return answer

