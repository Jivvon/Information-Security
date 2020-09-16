from typing import List
from bitarray import bitarray

def string_to_bits(string: str) -> List[bool]:
    bits = bitarray()
    bits.frombytes(string.encode('utf-8'))
    return bits.tolist()


def bits_to_string(bits: List[bool]) -> str:
    return bitarray(bits).tobytes().decode('utf-8')


def xor_encrypt_decrypt(message: str, key: str) -> str:
    """

    :param message: 암호화, 복호화할 평문.
    :param key: 암호화, 복호화할 때 사용할 key.
    :return: 암호화, 복호화한 문자열.
    """
    message_bits = string_to_bits(message)
    key_bits = string_to_bits(key)
    
    answer = []
    for i, ch in enumerate(message_bits): # 평문을 bit로 바꾼 것을 순회한다.
        # 각 문자 순서대로, key를 bit로 바꾼 key_bits 또한 순서대로 순회하며 XOR 연산을 하고 answer에 값을 넣어준다.
        answer.append(ch ^ key_bits[i % len(key_bits)])

    return bits_to_string(answer)
        
    
