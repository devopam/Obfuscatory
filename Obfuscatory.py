import hashlib
import hmac
import platform
import random
import string
import time
import uuid
import pbkdf2


class Obfuscatory(object):
    """
    Utility Class for HMAC based anonymization, pseudo-anonymization etc.

    PyObfuscator provides methods to generate secure keys , hash messages based on various algorithms including
    latest SHA3 support. It helps aid quick integration encapsulating base HMAC module. It uses an alternate approach to
    store and use keys by putting them into a keytab.plist file so that actual exchange of key is never needed.
    """
    _keytab_file_name_: str
    _default_length_: int
    _digest_mod_: str
    _hash_dict_ = {}

    # Public methods are designed for use while internal methods are not to be accessed directly
    def __init__(self, hash_algo_name: str = None):
        """
        Initialize the base constructor
        :param hash_algo_name: Provision to supply a hash algorithm name to override default sha3_512
        """
        self._keytab_file_name_ = "keytab.plist"
        self.load_key_from_file()
        if hash_algo_name is not None and hash_algo_name in hashlib.algorithms_guaranteed:
            self._digest_mod_ = hash_algo_name
        elif hash_algo_name is None:
            print('Using Hash algo sha3_512 default')
            self._digest_mod_ = 'sha3_512'
        else:
            print('Hashing algo ' + hash_algo_name + ' is not supported. Switching to sha3_512 default')
            self._digest_mod_ = 'sha3_512'
        self._default_length_ = 64

    def load_key_from_file(self):
        """
        Loads Hashing keys from a file named keytab.plist which should be accessible to this program ( placed in path )
        :return: None
        """
        try:
            with open(self._keytab_file_name_, 'r') as dict_file:
                for line in dict_file:
                    if line is not None and len(line) > 1:
                        if "=" in line:
                            (k, v) = line.strip().split('=')
                            if k is not None and v is not None and len(k) > 0 and len(v) > 0:
                                self._hash_dict_[k] = v
                            else:
                                raise SyntaxError("Malformed keytab file. Please check " + self._keytab_file_name_)
                        else:
                            raise SyntaxError("Either separator \'=\' is missing or encountered blank line in "
                                              + self._keytab_file_name_)

        except Exception as e:
            exit(e.args[0])

    @staticmethod
    def anonymize(message: str):
        """
        Randomized digest of input message string using a secure , non-traceable algorithm
        :param message: Text that has to be hashed
        :type message: str
        :return: 512 bytes hexified string digest ( hash ) of the input message
        """
        try:
            hash_key: str = ''.join(random.choices(string.hexdigits, k=64))
            msg: str = message + time.asctime(time.gmtime()).strip() + platform.node()
            return None if message is None else hmac.new(hash_key.encode('utf-8'),
                                                         msg.encode('utf-8'), hashlib.sha3_512).hexdigest()
        except Exception as e:
            print(e.args[0])
            return None

    def pseudo_anonymize(self, message: str = None, key_name: str = None):
        """
        Hashed digest of input message for the key name supplied.
        The actual message will be lost, but the hash can be compared at a later point in time to determine a match.
        Care should be taken to remember the Hashing algorithm used in order to determine match at a later moment

        :param message: Input message to be hashed
        :type message: str
        :param key_name: Valid key name , which is expected to be present in keytab.plist file.
        :type key_name: str
        :return: Hexified string hash of the input message ( of variable length depending on the algorithm )
        """
        key: str
        try:
            if key_name is None or message is None:
                return None
            elif key_name not in self._hash_dict_.keys():
                raise AttributeError('Unable to lookup ' + key_name + ' in ' + self._keytab_file_name_)
            else:
                key = str(self._hash_dict_[key_name])
                if key is None or len(key) == 0:
                    raise AttributeError('Unable to retrieve value of ' + key_name + ' from ' + self._keytab_file_name_)
                else:
                    return hmac.new(key.encode('utf-8'), message.encode('utf-8'), self._digest_mod_).hexdigest()
        except Exception as e:
            exit(e.args[0])

    @staticmethod
    def generate_key(passphrase: str = None):
        """
        Generates a strong key of 512 byte size. Leverages pbkdf2 and sha3_512

        Function allows user to provide an optional passphrase as well to aid generation.
        However, it is a stochastic function by design and same passphrase shall not generate same key on repeated call.

        :param passphrase: Optional passphrase to aid generation of strong key
        :type passphrase: str
        :return: Hexified string of 512 bytes length that can be used as a key for future hashes.
        """
        try:
            hash_key: str = ''.join(random.choices(string.hexdigits, k=64))
            passphrase = time.asctime(time.gmtime()).strip() + platform.node() + hex(uuid.getnode()) \
                if passphrase is None else passphrase
            msg: str = pbkdf2.crypt(passphrase, iterations=3)
            return hmac.new(hash_key.encode('utf-8'), msg.encode('utf-8'), hashlib.sha3_512).hexdigest()
        except Exception as e:
            print(e.args[0])
            return None


if __name__ == '__main__':
    obfuscate = Obfuscatory('sha512')
    print('Anonymize           : ' + obfuscate.anonymize("Hello World"))
    print('Pseudo (SHA512) Anon: ' + obfuscate.pseudo_anonymize("Hello World", 'key1'))
    count: int = 5
    while count > 0:
        print('Pass'+str(6-count)+': Key Gen       : ' + obfuscate.generate_key(passphrase='Hello World'))
        print('Pass'+str(6-count)+': KeyGen noargs : ' + obfuscate.generate_key())
        count -= 1
