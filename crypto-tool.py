# coding=utf-8
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import os

RSA_key_len = 1024
sentinel_len = 100
MAX_DECRYPT_BLOCK = RSA_key_len / 8  # see PKCS1-v1_5: encrypt
MAX_ENCRYPT_BLOCK = RSA_key_len / 8 - 11  # see PKCS1-v1_5: encrypt
users_file_name = 'users'
email_file_name = 'email'
data_file_name = 'data'


def generate_key_pair():
    private_key = RSA.generate(RSA_key_len)
    private_key_str = private_key.exportKey(format='PEM')
    public_key = private_key.publickey()
    public_key_str = public_key.exportKey(format='PEM')
    return private_key_str, public_key_str


def decrypt_folder(user, private_key_str):
    for dirpath, dirnames, filenames in os.walk(user):
        for filename in filenames:
            cipher_text_block = []
            with open('{0}/{1}'.format(dirpath, filename), 'rb+') as encrypted_file:
                while True:
                    cipherText = encrypted_file.read(MAX_DECRYPT_BLOCK)
                    if cipherText == '':
                        break
                    cipher_text_block.append(cipherText)
                encrypted_file.truncate(0)
                encrypted_file.seek(0)
                private_key = RSA.importKey(private_key_str)
                decipher = PKCS1_v1_5.new(private_key)
                for block in cipher_text_block:
                    sentinel = Random.new().read(sentinel_len)
                    plainText = decipher.decrypt(block, sentinel)
                    encrypted_file.write(plainText)


def get_private_key_str(user, data_file_name):
    private_key_str = ''
    with open(data_file_name) as data_file:
        lines = data_file.readlines()
        for line in lines:
            if user in line:
                break
        index = lines.index(line) + 1
        while '---END' not in lines[index]:
            private_key_str += lines[index]
            index += 1
        private_key_str += lines[index]
        return private_key_str

def admin():
    while True:
        print u'>>> 1.初次使用 2.生成秘钥 3.解密文件'
        cmd = raw_input()
        if cmd == '1':
            print u">>> 请手动创建文件，命名为" + users_file_name + u"，在文件中的每行分别输入用户的姓名："
            print u'>>> 完成后再次执行本程序，选择2'
            exit()

        elif cmd == '2':
            print u'>>> 生成秘钥将更新现有的秘钥数据，是否继续(Y/n)'
            if raw_input() == 'n':
                exit()
            if not os.path.exists(users_file_name):
                print users_file_name + '不存在'
                exit()
            try:
                users_file = open(users_file_name, 'rb')
                email_file = open(email_file_name, 'wb')
                crypto_data = open(data_file_name, 'wb')

                users = users_file.readlines()
                for user in users:
                    private_key_str, public_key_str = generate_key_pair()
                    email_file.write(user + public_key_str + '\n\n')
                    crypto_data.write(user + private_key_str + '\n')
            except Exception, e:
                print e
            finally:
                users_file.close()
                email_file.close()
                crypto_data.close()
            print u'>>> 公钥已经保存在email文件中，请将其发送给对应用户'
            exit()

        elif cmd == '3':
            try:
                users_file = open(users_file_name, 'rb')
                crypto_data = open(data_file_name, 'rb')
                users = users_file.readlines()
                for user in users:
                    user = user.split('\n')
                    user = user[0] if user else None
                    if os.path.exists(user):
                        key_str = get_private_key_str(user, data_file_name)
                        try:
                            decrypt_folder(user, key_str)
                            print '[{0}] done'.format(user)
                        except Exception, e:
                            print '[{0}] {1}'.format(user, e)
            except Exception, e:
                print e
            finally:
                users_file.close()
                crypto_data.close()
            exit()

def user():
    print u'>>> 请将所有文件存放进目录，目录以管理员分配的个人ID命名'
    print u'>>> 请输入要加密的目录名称'
    target_dir = raw_input()
    if not os.path.exists(target_dir):
        print u'>>> 目录不存在'
        exit()
    print u'>>> 请粘贴进管理员分配的公钥'
    public_key_str = ''
    while True:
        cmd = raw_input() + '\n'
        public_key_str += cmd
        if '--END' in cmd:
            break
    print u'>>> 开始加密...'

    os.system('rm -rf {0}.copy'.format(target_dir))
    os.system('cp -rf {0} {0}.copy'.format(target_dir))

    for dirpath, dirnames, filenames in os.walk(target_dir):
        for filename in filenames:
            plain_text_block = []
            with open('{0}/{1}'.format(dirpath, filename), 'rb+') as source_file:
                while True:
                    plain_text = source_file.read(MAX_ENCRYPT_BLOCK)
                    if plain_text == '':
                        break
                    plain_text_block.append(plain_text)
                source_file.truncate(0)
                source_file.seek(0)
                public_key = RSA.importKey(public_key_str)
                cipher = PKCS1_v1_5.new(public_key)
                for block in plain_text_block:
                    cipher_text = cipher.encrypt(block)
                    source_file.write(cipher_text)
    print u'>>> 原目录已经被改名为.copy，请将新生成的加密目录上传'

if __name__ == '__main__':
    print u'>>> 请选择：1. admin  2. user'
    cmd = raw_input()
    if cmd == '1':
        admin()
    elif cmd == '2':
        user()
    else:
        exit()
