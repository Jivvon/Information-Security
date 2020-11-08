import json
from os.path import join, curdir, abspath
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def save(cert):
    cert_path = join('week_10', 'cert.json')
    if abspath(curdir).endswith('week_10'):
        cert_path = 'cert.json'
    with open(cert_path, 'w') as f:
        json.dump(cert, f)


def load():
    cert_path = join('week_10', 'cert.json')
    if abspath(curdir).endswith('week_10'):
        cert_path = 'cert.json'
    with open(cert_path, 'r') as f:
        return json.load(f)


def sign():
    """
    (cert.json) 인증서에 공개키와 서명을 저장

    Sign: sign( Hash ( student_id | is_success | week ) )

    서명은 bytes 값의 .hex()를 이용해 string으로 저장
    공개키는 .export_key(format='PEM')을 이용해 PEM 형태로 저장

    sign_param : student_id + is_success + week
    1. 개인키를 생성하고 이를 이용하여 공개키를 생성한다.
    2. 개인키를 이용하여 서명하기 위한 DSS 객체를 생성한다.
    3. sign_param을 해시화한다.
    4. 2에서 만든 객체에서 3의 결과 해시값을 개인키를 이용하여 서명한다.
    5. 3과 4의 결과를 포함하여 cert.json에 저장한다.
    :return: None
    """
    # TODO:
    cert_data = load()
    sign_param = ''.join([cert_data["student_id"], cert_data["is_success"], str(cert_data["week"])])
    # 1. 키 생성
    private_key = ECC.generate(curve='P-256')
    public = private_key.public_key()
    # 2. 서명
    signer = DSS.new(private_key, 'fips-186-3') # 개인키를 이용하여 서명하기 위한 DSS 객체 생성
    hash_val = SHA256.new(sign_param.encode('utf-8')) # ( student_id | is_success | week )를 hash 적용
    signature = signer.sign(hash_val) # signer의 키(개인키)를 이용하여 hash_val에 서명
    cert_data["public_key"] = public.export_key(format='PEM') # 공개키 저장
    cert_data["sign"] = signature.hex() # 서명 저장
    save(cert_data) # cert.json에 저장


def verify() -> bool:
    """
    (cert.json) 인증서에 저장된 공개키와 서명을 이용해 값을 검증하는 함수

    Sign: sign( Hash ( student_id | is_success | week ) )
    임을 이용해 해시를 생성한 후 서명 검증

    verifier.verify 함수를 이용할 때 true, false가 아닌 exception으로
    검증 여부가 판단되는 점을 주의
    try 문을 이용해 검증 성공 시 true, 실패시 false를 반환

    sign_param : student_id + is_success + week
    1. sign_param을 해시화한다.
    2. 공개키를 가져온다.
    3. 2의 공개키를 이용하여 서명을 검증하기 위한 DSS 객체 생성
    4. 3에서 만든 객체에서 cert.json의 서명을 공개키를 이용하여 검증한다.

    :return: 검증되면 True 아니면 False.
    """
    # TODO:
    cert_data = load()
    sign_param = ''.join([cert_data["student_id"], cert_data["is_success"], str(cert_data["week"])])
    hash_val = SHA256.new(sign_param.encode('utf-8')) # ( student_id | is_success | week )을 이용하여 hash값 생성
    public = ECC.import_key(cert_data['public_key']) # 공개키 가져오기
    try:
        verifier = DSS.new(public, 'fips-186-3') # 공개키를 이용하여 서명을 검증하기 위한 DSS 객체 생성
        verifier.verify(hash_val, bytes.fromhex(cert_data['sign'])) # cert.json에 저장된 공개키로 sign을 확인하여 서명을 검증
        return True
    except:
        return False


if __name__ == '__main__':
    pass
    sign()
    # a = load()
    # print(a)
    #
    # # 키 생성
    # private_key = ECC.generate(curve='P-256')
    # public = private_key.public_key()
    # # 서명
    # signer = DSS.new(private_key, 'fips-186-3')
    # hash_val = SHA256.new('abc'.encode('utf-8'))
    # signature = signer.sign(hash_val)
    # print(signature)
    # # 검증
    # verifier = DSS.new(public, 'fips-186-3')
    # print(type(bytes.fromhex(a['sign'])))
    # verifier.verify(SHA256.new('abc'.encode('utf-8')), bytes.fromhex(a['sign']))
    # # 키 및 서명 저장 관련
    # print(public.export_key(format='PEM'))
    # print(signature.hex())
    # print(bytes.fromhex(signature.hex()))
    # # 키 가져오기
    # public = ECC.import_key(a['public_key'])
