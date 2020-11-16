import copy
from dataclasses import dataclass
from typing import List

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


@dataclass
class Cert:
    issuer: bytes
    public: bytes
    sign: bytes


class Issuer:
    def __init__(self, key: bytes, cert_chain=None):
        if cert_chain is None:
            cert_chain = []
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain: List[Cert] = cert_chain

    def change_secret(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain = []

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def issue(self, pub_key: bytes):
        """
        TODO:
        자신의 certificate chain 과
        issuer의 public key, holder의 public key와 public key의 Hash에 대한 서명을 가진 dictionary 반환

        :param pub_key: 서명하고자하는 메세지 (여기서는 pub_key만 서명한다)
        :return: cert_chain: 현재 Issuer의 공개키와 서명한 pub_key, pub_key에 서명 한 결과를 추가한 certification chain
         [ { issuer: pub_key0, public_key: pub_key1, sign: Signature0(Hash(pub_key1)) }, ... ]
        """
        hash_val = SHA256.new(pub_key)
        signer = DSS.new(self.__secret, 'fips-186-3') # 개인키를 이용하여 서명하기 위한 DSS 객체 생성
        signature = signer.sign(hash_val) # signer의 키(개인키)를 이용하여 hash_val에 서명
        certs = copy.deepcopy(self.cert_chain)
        certs.append(Cert(self.public_key(), pub_key, signature))
        return certs


class Holder:
    def __init__(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert: List[Cert] = []

    def set_cert(self, cert: List[Cert]):
        self.cert = cert

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def present(self, nonce: bytes) -> (List[Cert], bytes):
        """
        TODO:

        자신이 발급받아온 cert chain을 통해
        :param nonce: 랜덤 값
        :return: cert_chain, sign(nonce)
        """
        hash_val = SHA256.new(nonce)
        signer = DSS.new(self.__secret, 'fips-186-3') # 개인키를 이용하여 서명하기 위한 DSS 객체 생성
        signature = signer.sign(hash_val) # signer의 키(개인키)를 이용하여 nonce 서명
        return self.cert, signature




class Verifier:
    def __init__(self, root_pub: bytes):
        self.root = root_pub

    def verify(self, cert_chain: List[Cert], pub_key: bytes, nonce: bytes, sign: bytes):
        """
        TODO:

        cert_chain을 검증하고 pub_key의 서명을 확인함

        root issuer는 저장된 root ca에 대한 정보를 이용하여 확인

        cert chain 검증 결과 root ca로부터 연결된 신뢰 관계를 갖고 있을 경우 True 반환

        :param cert_chain: 검증하고자하는 certification chain
        :param public_key: holder의 공개
        :param nonce: 송신자 확인을 위한 랜덤값
        :param sign: holder의 개인키로 nonce를 암호화한 서명
        :return: cert_chain의 최상단이 root로 검증되면 True 아니면 False.
        """
        try:
            public_key = ECC.import_key(pub_key)
            verifier = DSS.new(public_key, 'fips-186-3') # 공개키를 이용하여 서명을 검증하기 위한 DSS 객체 생성
            hash_val = SHA256.new(nonce)
            verifier.verify(hash_val, sign) # 공개키로 sign을 확인하여 nonce에 대한 서명을 검증
            while cert_chain:
                cert = cert_chain.pop()
                hash_val = SHA256.new(cert.public)
                issuer_pub = ECC.import_key(cert.issuer)
                verifier = DSS.new(issuer_pub, 'fips-186-3')
                verifier.verify(hash_val, cert.sign) # 공개키로 sign을 확인하여 서명을 검증
            try: # cert_chain이 주어졌다면 최상단 issuer는 root
                return cert.issuer == self.root
            except: # cert_chain이 주어지지 않았다면 pub_key로 받은 holder의 공개키가 root
                return pub_key == self.root
        except:
            return False
