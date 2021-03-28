#!/usr/bin/env python3

"""
    User management script for the wireguard server
"""
import os
import io
import stat
import shutil
import sys
import platform
import argparse
import hashlib
import crypt
import logging
import secrets
import string
import subprocess
import pathlib

class OperationError(Exception):
    '''raise this when there's an Exception running operations'''

class Settings(object):
    def __init__(self):
        self.arg = self.get_arg()

    def get_arg(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('-c', '--config_path', type=str, default='./config.yaml', required=False, help='Specify config path')
        self.parser.add_argument('-crd', '--credentials_path', type=str, default='./credentials.txt', required=False, help='Specify credentials path')
        self.parser.add_argument('-lg', '--log_path', type=str, default='./mgt_users.log', required=False, help='Specify log path')
        self.parser.add_argument('-bk', '--config_backup', type=str, default='./config.yaml.bk', required=False, help='Specify config backup path')
        self.parser.add_argument('-cbk', '--credentials_backup', type=str, required=False, help='Specify credentials backup path')
        self.parser.add_argument('-v', '--verbose', action='store_true', default=False, required=False, help='Enable verbose output')
        self.parser.add_argument('-f', '--force', action='store_true', default=False, required=False, help='Force a command without checks')
        self.parser.add_argument('-e', '--encrypt', action='store_true', default=False, required=False, help='Encrypt credentials file')
        self.parser.add_argument('-d', '--decrypt', action='store_true', default=False, required=False, help='Decrypt credentials file')
        self.parser.add_argument('-b', '--backup', action='store_true', default=False, required=False, help='Backup configurations and credentials files')
        self.parser.add_argument('-l', '--list_users', action='store_true', default=False, required=False, help='List users')
        self.parser.add_argument('-s', '--show_password', nargs='?', const='', required=False, help='Show user password, if empty shows for all users')
        self.parser.add_argument('-a', '--add_user', type=str, required=False, help='Add user')
        self.parser.add_argument('-r', '--rm_user', action='append', type=str, required=False, help='Remove user, specify multiple times to remove multimple users')
        self.parser.add_argument('-p', '--change_password', type=str, required=False, help='Change user password')
        self.parser.add_argument('-x', '--random_password', action='store_true', default=False, required=False, help='Set random password')
        self.parser.add_argument('-n', '--num_chars_password', type=int, default=24, required=False, help='Specify number of charecters for auto-generated passwords')
        self.parser.add_argument('-t', '--type_password', type=str, choices=(
            'Alpha', 
            'Num',
            'Sym',
            'AlphaNum',
            'AlphaSym',
            'NumSym',
            'AlphaNumSym',
        ), default='AlphaNum', nargs='?', const='AlphaNum', required=False, help='Specify type of password to generate')
    
        args, unknown = self.parser.parse_known_args()

        self.arg = self.parser.parse_args()
        return self.arg

class Basics(Settings):
    def __init__(self):
        Settings.__init__(self)
    
    def continue_input(self, prompt=True):
        yes = False
        while not yes:
            if prompt:
                self.log.info("continue?")
            answer = input("(y/n): ")
            self.log.info(answer)
            if answer.lower() in ["true", "yes", "y"]:
                yes = True
            elif answer.lower() in ["false", "no", "n"]:
                yes = False
                break
            else:
                self.logger.error(f"invalid response, try again: '{answer}'") 
        return yes

    def read_file(self, p):
        if self.valid_file(p, logger=True):
            with open(p) as f:
                lines = f.readlines()
            return lines

    def print_list(self, lst):
        if not lst:
            raise OperationError("invalid list")
        elif len(lst) == 0:
            raise OperationError("empty list")
        for e in lst:
            print(e)

    def is_type_path(self, entry):
        spl = entry.split(os.sep)
        s = pathlib.PurePath(entry).suffix
        if len(spl) > 1:
            return True
        elif s:
            return True
        else:
            return False

    def valid_file(self, path, logger=False):
        try:
            exists = os.path.exists(path)
        except PermissionError:
            self.logger.error(f"permission denied: '{path}'")
            return
        except:
            self.logger.error(f"failed to copy: '{path}'")    
            return    
        if exists:
            if os.path.isfile(path):
                return True
            else:
                if logger: 
                    self.logger.error(f"not a file: '{source}'")
                return False
        else:
            if logger:
                self.logger.error(f"does not exist: '{path}'")
            return False

    def valid_credentials_file(self, path):
        if self.valid_file(path):
            try:
                lines = self.read_file(path)
                valid_lines = list()
                for l in lines:
                    if l.isspace():
                        continue
                    l = l.rstrip('\r\n')
                    l = l.split()
                    if len(l) == 2:
                        valid_lines.append(True)
                    else:
                        return False
                if all(valid_lines):
                    return True
            except ValueError:
                return False
        else:
            return False

class Logging(Basics):
    def __init__(self):
        Basics.__init__(self)
        self.log_level = "DEBUG" if self.arg.verbose else "INFO"
        self.logger = self.setup()
        self.work_dir = pathlib.Path(self.arg.config_path).parent
        self.save()
    
    def setup(self):
        logging.basicConfig(
            format='[%(levelname)s] %(message)s',
            level=logging.INFO,
            stream=sys.stdout)
        self.log = logging.getLogger(__name__)   
        self.log.setLevel(self.log_level)
        return self.log
    
    def color(self):
        coloredlogs.install(fmt='[%(levelname)s] %(message)s', level=self.log_level, logger=self.log)

    def save(self):
        log_file = self.work_dir.joinpath(pathlib.Path(self.arg.log_path))
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        fh = logging.FileHandler(log_file)
        fh.setLevel(self.log_level)
        fh.setFormatter(formatter)
        self.log.addHandler(fh)
        return self.log

class Setup(Logging):
    def __init__(self):
        Logging.__init__(self)
        self.pip = ['pip3', '--version']
    
    def execute(self, cmd):
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        except FileNotFoundError:
            self.logger.error("command not found: '{c}'".format(c=" ".join(cmd)))
    
    def exit_code(self, cmd, logger=None):
        sp = self.execute(cmd)
        if sp == None:
            status = -1
            return status
        else:
            status = sp.wait()
            out, err = sp.communicate()
            self.logger.debug("console: {o}".format(o=out.rstrip('\r\n')))
            self.logger.debug("error: {e}".format(e=err))
            return status
    
    def install(self, required_pkgs):
        if not self.arg.force:
            self.check_linux()
        local_bin = os.path.join(os.getenv("HOME"), ".local/bin")
        def is_installed(requirement):
            import pkg_resources
            try:
                pkg_resources.require(requirement)
            except pkg_resources.ResolutionError:
                return False
            else:
                return True
        def is_local_path_set():
            exists = False
            paths = os.getenv("PATH").split(":")
            for p in paths:
                if p == local_bin:
                    exists = True
            return exists
        if not is_local_path_set():
            os.environ["PATH"] += os.pathsep + local_bin
        for pkg in required_pkgs:
            installed = is_installed(pkg)
            if installed == False:
                if not self.arg.force:
                    self.check_pip()
                p = pkg.split(">=")
                self.logger.info(f"installing: '{p[0]}'")
                if not self.arg.force: 
                    if self.continue_input():
                        subprocess.run(['pip3', 'install', pkg])
                    else:
                        sys.exit()
                else:
                    subprocess.run(['pip3', 'install', pkg])
    
    def check_pip(self):
        exit_code = self.exit_code(self.pip)
        if exit_code == 0:
            self.logger.debug("Pip installation found")
        else:
            self.logger.error("Pip is not installed!")
            sys.exit()

    def check_linux(self):
        sys_arch = platform.system()
        if sys_arch == "Linux":
            self.logger.debug(f"Running on: '{sys_arch}'")
            is_linux = True
            return True
        else:
            self.logger.warning(f"This script has not been tested on '{sys_arch}'")
            if not self.continue_input():
                sys.exit()

class Operations(Logging):
    def __init__(self):
        Logging.__init__(self)
        self.yaml = YAML(typ="rt", pure=True)
        self.yaml.default_flow_style = False
        self.yaml.allow_duplicate_keys = True
        self.yaml.allow_unicode = True
        self.yaml.indent(mapping=2, sequence=2, offset=2)
        self.yaml.width = 1000
        self.config = self.load_config()
        if self.config.get("auth").get("basic").get("users") == None:
            self.config["auth"]["basic"]["users"] = []
        if self.config != None:
            self.hashes = self.config.get("auth").get("basic").get("users")
        else:
            self.logger.error("Invalid configuration")
            sys.exit()
        try:
            self.users = self.get_users()
        except OperationError:
            self.users = []

    def load_config(self):
        if not self.valid_file(self.arg.config_path, logger=False):
            self.logger.info(f"creating config file: '{self.arg.config_path}")
            self.yaml.dump({
                'auth': {
                    'basic': {
                        'users': None,
                    }
                }},
                self.work_dir.joinpath(pathlib.Path(self.arg.config_path)))
        try:
            with open(self.arg.config_path, "r") as f:
                loaded_config = self.yaml.load(f)
        except PermissionError:
            self.logger.error(f"permission denied: '{self.arg.config_path}'")
            return
        except:
            self.logger.error(f"failed to copy: '{self.arg.config_path}'")
            return 
        return loaded_config

    def update_config(self):
        out = pathlib.Path(self.arg.config_path)
        try:
            in_hash = self.get_file_hash(self.arg.config_path, algo="md5")
            self.yaml.dump(self.config, out)
            out_hash = self.get_file_hash(self.arg.config_path, algo="md5")
            if not self.is_hash_same(in_hash, out_hash) and not in_hash == None:
                self.logger.info("Config Updated. You must restart the Wireguard Access Server for changes to take effect")
        except PermissionError:
            self.logger.error(f"permission denied: '{out}'")
            return
        except:
            self.logger.error(f"failed to copy: '{out}'")
            return

    def get_users(self):
        usrs_lst = list()
        if self.hashes:
            for u in self.hashes:
                name = u.split(":")[0]
                usrs_lst.append(name)
            return usrs_lst
        else:
            raise OperationError("No users defined!")

    def copy_file(self, source, target):
        success = False
        if self.valid_file(source):
            try:
                shutil.copy2(source, target)
            except PermissionError:
                self.logger.error(f"permission denied: '{source}'")
                return
            except:
                self.logger.error(f"failed to copy: '{source}'")
                return
            st = os.stat(source)
            if self.is_hash_same(self.get_file_hash(source, algo="md5"), self.get_file_hash(target, algo="md5"), logger=True):
                success = True
                self.logger.debug("backup of '{s}' saved at '{t}' with hash '{h}'".format(s=source, t=target, h=self.get_file_hash(source, algo="md5")))
            else:
                self.logger.error(f"error backing up: '{source}'")
        return success

    def get_file_hash(self, path, algo="blake"):
        if self.valid_file(path):
            try:
                with open(path, "rb") as f:
                    if algo == "blake":
                        file_hash = hashlib.blake2b()
                    elif algo == "md5":
                        file_hash = hashlib.md5()
                    chunk = f.read(8192)
                    while chunk:
                        file_hash.update(chunk)
                        chunk = f.read(8192)
            except PermissionError:
                self.logger.error(f"permission denied: '{path}'")
                return
            except:
                self.logger.error(f"failed to copy: '{path}'")
                return
            file_hash_digest = file_hash.hexdigest()
            return file_hash_digest

    def is_hash_same(self, source_hash, target_file_hash, logger=False):
        if source_hash == target_file_hash:
            self.logger.debug(f"hash match: '{source_hash}'")
            return True
        else:
            if logger: self.logger.warning(f"hash '{source_hash}' does not match '{target_file_hash}'")
            return False

class Crypt(Operations):
    def __init__(self):
        Operations.__init__(self)
        self.cred_pwd = str()
        self.pwd_entered = False
        encrypted_name = "{b}.aes".format(b=os.path.basename(self.arg.credentials_path))
        encrypted_path = os.path.join(os.path.dirname(self.arg.credentials_path), encrypted_name)
        unencrypted_path = "{b}.plain".format(b=os.path.basename(self.arg.credentials_path))
        if self.is_aes(encrypted_path, logger=True):
            self.encrypted_path = encrypted_path
            self.credentials = self.encrypted_path
            self.unencrypted_path = self.arg.credentials_path
            self.backup_source = encrypted_path
        elif not self.is_aes(unencrypted_path, logger=False) and self.valid_file(unencrypted_path, logger=False):
            self.encrypted_path = self.arg.credentials_path
            self.credentials = self.encrypted_path
            self.unencrypted_path = unencrypted_path
            self.backup_source = unencrypted_path
        elif self.is_aes(self.arg.credentials_path, logger=False):
            self.encrypted_path = self.arg.credentials_path
            self.credentials = self.encrypted_path
            self.unencrypted_path = unencrypted_path
            self.backup_source = self.arg.credentials_path
        elif self.valid_file(self.arg.credentials_path, logger=False):
            self.encrypted_path = encrypted_path
            self.credentials = self.arg.credentials_path
            self.unencrypted_path = self.credentials 
            self.backup_source = self.arg.credentials_path
        else:
            self.logger.error(f"credentials file not found, create?")
            if self.continue_input(prompt=False):
                self.encrypted_path = encrypted_path
                self.credentials = self.encrypted_path
                self.unencrypted_path = self.arg.credentials_path
                self.backup_source = encrypted_path
                try:
                    with open(self.unencrypted_path, "w") as f:
                        f.write(str())
                    self.encrypt_file(self.encrypted_path, self.unencrypted_path)               
                except:
                    self.logger.error(f"failed to create credentials file: '{self.unencrypted_path}'")
                    sys.exit()
            else:
                sys.exit()

    def run_backup(self):
        config_default = "{b}.bk".format(b=os.path.basename(self.arg.config_path))
        config_backup_path = self.arg.config_backup if self.arg.config_backup else config_default
        credentials_default = "{b}.bk".format(b=os.path.basename(self.backup_source))
        credentials_backup_path = self.arg.credentials_backup if self.arg.credentials_backup else credentials_default
        if self.valid_file(self.arg.config_path, logger=True):
            conf_copied = self.copy_file(self.arg.config_path, config_backup_path)
            config_hash = self.get_file_hash(self.arg.config_path, algo="md5")
            config_backup_hash = self.get_file_hash(config_backup_path, algo="md5")
            if config_hash == None:
                self.logger.error(f"backup failed: {self.arg.config_path}")
            elif self.is_hash_same(config_hash, config_backup_hash):
                self.logger.info(f"Succesfuly backed up '{self.arg.config_path}' to '{config_backup_path}'")            
            else:
                self.logger.error(f"backup failed: {self.arg.config_path}")
        if self.valid_file(self.backup_source, logger=True):
            cred_copied = self.copy_file(self.backup_source, credentials_backup_path)
            cred_hash = self.get_file_hash(self.backup_source, algo="md5")
            cred_backup_hash = self.get_file_hash(credentials_backup_path, algo="md5")
            if cred_hash == None:
                self.logger.error(f"backup failed: {self.backup_source}")
            elif self.is_hash_same(cred_hash, cred_backup_hash):
                self.logger.info(f"Succesfuly backed up '{self.backup_source}' to '{credentials_backup_path}'")            
            else:
                self.logger.error(f"backup failed: {self.backup_source}")

    def is_aes(self, file_path, logger=False):
        AESBlockSize = 16
        bufferSize = 64 * 1024
        # validate bufferSize
        if bufferSize % AESBlockSize != 0:
            if logger: 
                self.logger.error("Buffer size must be a multiple of AES block size")
            return False
        if self.valid_file(file_path):
            inputLength = os.stat(file_path).st_size
            try:
                fIn = io.open(file_path, "rb")
            except PermissionError:
                self.logger.error(f"permission denied: '{file_path}'")
                return
            except:
                self.logger.error(f"failed to copy: '{file_path}'")
                return            
            fdata = fIn.read(3)
            # check if file is in AES Crypt format (also min length check)
            if (fdata != bytes("AES", "utf8") or inputLength < 136):
                if logger: 
                    self.logger.error(f"File is corrupted or not an AES Crypt: '{file_path}'")
                return False
            # check if file is in AES Crypt format, version 2
            fdata = fIn.read(1)
            if len(fdata) != 1:
                if logger: 
                    self.logger.error(f"File is corrupted: '{file_path}'")
                return False
            if fdata != b"\x02":
                if logger: 
                    self.logger.error(f"Incompatible AES Crypt format, must be version 2: '{file_path}'")
                return False
            # skip reserved byte
            fIn.read(1)
            # skip all the extensions
            while True:
                fdata = fIn.read(2)
                if len(fdata) != 2:
                    if logger:
                        self.logger.error(f"File is corrupted: '{file_path}'")
                    return False
                    break
                if fdata == b"\x00\x00":
                    break
                fIn.read(int.from_bytes(fdata, byteorder="big"))
            # read external iv
            iv1 = fIn.read(16)
            fIn.close()
            if len(iv1) != 16:
                if logger: 
                    self.logger.error(f"File is corrupted: '{file_path}'")
                return False
        else:
            return False
        if logger: 
            self.logger.debug(f"Valid AES file: '{file_path}'")
        return True

    def passprompt(self, prompt, out = sys.stdout):
        out.write(prompt); out.flush()
        password = ""
        while True:
            ch = readchar.readchar()
            if ch == '\r':
                print('')
                break
            # Account for backspacing
            elif ch == '\b' or ch == '\x7f':
                out.write('\b \b')
                password = password[0:len(password)-1]
                out.flush()
            else: 
                password += ch
                out.write('*')
                out.flush()
        return password

    def prompt_credentials(self):
        if not self.pwd_entered:
            self.cred_pwd = self.passprompt("Credentials file password: ")
            self.pwd_entered = True

    def gen_password(self):
        if self.arg.type_password == "Alpha":
            password = ''.join((secrets.choice(string.ascii_letters) for i in range(self.arg.num_chars_password)))
        elif self.arg.type_password == "Num":
            password = ''.join((secrets.choice(string.digits) for i in range(self.arg.num_chars_password)))
        elif self.arg.type_password == "Sym":
            password = ''.join((secrets.choice(string.punctuation) for i in range(self.arg.num_chars_password)))
        elif self.arg.type_password == "AlphaNum":
            password = ''.join((secrets.choice(string.ascii_letters + string.digits) for i in range(self.arg.num_chars_password)))
        elif self.arg.type_password == "AlphaSym":
            password = ''.join((secrets.choice(string.ascii_letters + string.punctuation) for i in range(self.arg.num_chars_password)))
        elif self.arg.type_password == "NumSym":
            password = ''.join((secrets.choice(string.digits + string.punctuation) for i in range(self.arg.num_chars_password)))
        elif self.arg.type_password == "AlphaNumSym":
            password = ''.join((secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(self.arg.num_chars_password)))
        else:
            self.logger.error(f"unknown password type: '{self.arg.type_password}'")
            sys.exit()
        return password

    def gen_pass_hash(self, pwd):
        hashed = bcrypt.using(rounds=14, ident="2y").hash(pwd)
        return hashed

    def verify_pwd(self, pwd, pwd_hash):
        match = False 
        while not match:
            match = bcrypt.verify(pwd, pwd_hash)
            if not match: 
                pwd = self.passprompt("incorrect password, try again: ")
        else:
            match = True
        return match

    def encrypt_file(self, crypt_file, plain_file):
        bufferSize = 64 * 1024
        if self.valid_file(plain_file, logger=True):
            self.logger.debug(f"encrypting: '{plain_file}'")
            self.prompt_credentials()
            try:
                pyAesCrypt.encryptFile(plain_file, crypt_file, self.cred_pwd, bufferSize)
            except ValueError:
                self.logger.error(f"Failed to encrypt: '{plain_file}'")
                return
            if self.valid_file(plain_file):
                self.logger.debug(f"deleting: '{plain_file}'")
                os.remove(plain_file)
            else:
                self.logger.error(f"encryption failed: '{plain_file}'")

    def decrypt_file(self, crypt_file, plain_file):
        bufferSize = 64 * 1024
        if self.is_aes(crypt_file):
            self.logger.debug(f"decrypting: '{crypt_file}'")
            self.prompt_credentials()
            try:
                pyAesCrypt.decryptFile(crypt_file, plain_file, self.cred_pwd, bufferSize)
            except ValueError:
                self.logger.error("Invalid password, or file is corrupted")
                return
            if self.valid_file(crypt_file):
                self.logger.debug(f"deleting: '{crypt_file}'")
                os.remove(crypt_file)
            else:
                self.logger.error(f"decryption failed: '{crypt_file}'")

    def open_encrypted_path(self):
        bufferSize = 64 * 1024
        fDec = io.BytesIO()
        if self.is_aes(self.credentials):
            encFileSize = os.stat(self.credentials).st_size
            self.logger.debug(f"opening: '{self.credentials}'")
            self.prompt_credentials()
            with open(self.credentials, "rb") as fIn:
                try:
                    pyAesCrypt.decryptStream(fIn, fDec, self.cred_pwd, bufferSize, encFileSize)
                except ValueError:
                    self.logger.error(f"failed to decrypt file: '{self.credentials}'")
                    sys.exit()
                content = fDec.getvalue().decode('UTF-8')
                fDec.close()
                lines = [s + ('\n') for s in content.split('\n')]
                for l in lines:
                    if l.isspace(): lines.remove(l)
            return lines
        else:
            sys.exit()

    def write_credentials(self, content, action, pwd=None):
        crypt = False
        if self.is_aes(self.credentials):
            self.decrypt_file(self.encrypted_path, self.unencrypted_path)
            crypt = True
        if action == "append":
            self.logger.debug(f"appending to: '{self.unencrypted_path}'")
            try:
                in_hash = self.get_file_hash(self.unencrypted_path, algo="md5")
                with open(self.unencrypted_path, "a") as f:
                    f.write(content + "\n")
                out_hash = self.get_file_hash(self.unencrypted_path, algo="md5")
                if not self.is_hash_same(in_hash, out_hash) and not in_hash == None:
                    changed = True
                else:
                    changed = False
                if crypt:
                    self.encrypt_file(self.encrypted_path, self.unencrypted_path)
                return changed
            except:
                return False
        elif action == "create":
            self.logger.debug(f"creating: '{self.unencrypted_path}'")
            try:
                in_hash = self.get_file_hash(self.unencrypted_path, algo="md5")
                with open(self.unencrypted_path, "w") as f:
                    for c in content:
                        if c.isspace():
                            continue
                        f.write(c)
                out_hash = self.get_file_hash(self.unencrypted_path, algo="md5")
                if not self.is_hash_same(in_hash, out_hash) and not in_hash == None:
                    changed = True
                else:
                    changed = False
                if crypt:
                    self.encrypt_file(self.encrypted_path, self.unencrypted_path)
                return changed
            except:
                return False
        else:
            self.logger.error(f"invalid action: '{action}'")
            return False

    def remove_credentials(self, usr):
        updated = False
        usr_crd = str()
        crds = list()
        crypt = False
        if self.is_aes(self.credentials):
            self.decrypt_file(self.encrypted_path, self.unencrypted_path)
            crypt = True
        usr_creds = self.read_file(self.unencrypted_path)
        if usr_creds:
            for c in usr_creds:
                if c.isspace():
                    continue
                l = c.rstrip('\r\n')
                u = l.split()[0]
                crds.append(u)
                if u == usr:
                    try:
                        usr_creds.remove(c)
                        written = self.write_credentials(usr_creds, "create")
                        if written:
                            updated = True
                            self.logger.debug(f"credentials removed: '{u}'")
                        else:
                            self.logger.error(f"credentials removal failed: '{u}'")
                        break
                    except ValueError:
                        self.logger.error(f"Failed to remove credentials: '{u}'")
            if not usr in crds:
                self.logger.warning(f"no credentials found for: '{usr}'")
        if crypt:
            self.encrypt_file(self.encrypted_path, self.unencrypted_path)
        return updated

class Commands(Crypt):
    def __init__(self):
        Crypt.__init__(self)
        if self.arg.backup:
            self.run_backup()
        elif self.arg.encrypt:
            self.encrypt_file(self.encrypted_path, self.unencrypted_path)
        elif self.arg.decrypt:
            self.decrypt_file(self.encrypted_path, self.unencrypted_path)
        elif self.arg.show_password:
            self.user_password_show(self.arg.show_password)
        elif self.arg.show_password == '':
            self.user_password_show()
        elif self.arg.add_user:
            if self.valid_credentials_file(self.arg.add_user):
                self.iterate_file(self.arg.add_user, "add")
            elif self.is_type_path(self.arg.add_user):
                self.logger.warning(f"This looks like a path '{self.arg.add_user}', add this user? ")
                if not self.continue_input(): 
                    sys.exit()
                self.user_add(self.arg.add_user, skip_prompt=self.arg.force, logger=True)
            else:
                self.user_add(self.arg.add_user, skip_prompt=self.arg.force, logger=True)
        elif self.arg.rm_user:
            for ru in self.arg.rm_user:
                self.user_remove(ru, skip_prompt=self.arg.force)
        elif self.arg.change_password:
            if self.valid_credentials_file(self.arg.change_password):
                self.iterate_file(self.arg.change_password, "change")
            elif self.is_type_path(self.arg.change_password):
                self.logger.warning(f"This looks like a path '{self.arg.change_password}', change passwords? ")
                if not self.continue_input(): 
                    sys.exit()
                self.user_add(self.arg.add_user, skip_prompt=self.arg.force, logger=True)
            else:
                self.user_password_change(self.arg.change_password)

    def user_exists(self, usr, logger=False):
        if usr in self.users:
            if logger:
                self.logger.debug(f"user exists: '{usr}'")
            return True
        else:
            if logger:
                self.logger.error(f"user does not exist: '{usr}'")
            return False

    def user_password_show(self, usr=None):
        def display(uc):
            num_element_chars = [len(s.split()[0]) for s in uc]
            if len(num_element_chars) != 0:
                max_chars = max(num_element_chars)
            else:
                self.logger.warning("no passwords found")
            for c in uc:
                c = c.rstrip('\r\n')
                if c.isspace() or not c:
                    continue
                u = c.split()[0]
                p = c.split()[1]
                if usr == None:
                    num_spaces = max_chars - len(u) + 2
                    spaces = str().join([" " for s in range(num_spaces)])
                    output = f"{u}{spaces}{p}"
                    print(output)
                elif usr == u:
                    print(p)
        if self.is_aes(self.credentials):
            usr_creds = self.open_encrypted_path()
        elif self.valid_file(self.unencrypted_path):
            usr_creds = self.read_file(self.unencrypted_path)
        else:
            return
        if usr == None:
            display(usr_creds)
        elif self.user_exists(usr, logger=True):      
            display(usr_creds)

    def user_password_change(self, usr, passwd=None):
        if self.user_exists(usr, logger=True):
            if self.arg.force:
                self.user_remove(usr, skip_prompt=True)
                self.user_add(usr, passwd, skip_prompt=True)
            elif self.arg.force and passwd:
                self.user_remove(usr, skip_prompt=True)
                self.user_add(usr, passwd, skip_prompt=True)
            else:
                for u in self.hashes:
                    name = u.split(":")[0]
                    old_hash = u.split(":")[1]
                    if name == usr:
                        old_pwd = self.passprompt(f"Enter previous password for '{usr}': ")
                        if self.verify_pwd(old_pwd, old_hash):
                            self.user_remove(usr, skip_prompt=True)
                            self.user_add(usr, skip_prompt=True)
                            break

    def user_add(self, usr, passwd=None, skip_prompt=False, logger=False):
        if self.user_exists(usr):
            self.logger.error(f"user already exists: '{usr}'")
            return
        if self.arg.random_password or passwd == "<gen>":
            if skip_prompt:
                self.logger.info(f"generating random password for: '{usr}'")
                pwd = self.gen_password()
            else:
                self.logger.info(f"Generate random password for: '{usr}'?")
                if self.continue_input():
                    pwd = self.gen_password()
                    print(pwd)
                else:
                    return 
        elif passwd == "<prompt>":
            pwd = self.passprompt(f"Enter new password for: '{usr}': ")          
        elif passwd:
            pwd = passwd
        else:
            pwd = self.passprompt(f"Enter new password for: '{usr}': ")
        hashed_pwd = self.gen_pass_hash(pwd)
        usr_hash = f"{usr}:{hashed_pwd}"
        usr_auth = f"{usr} {pwd}"
        self.config.get("auth").get("basic").get("users").append(usr_hash)
        self.update_config()
        written = self.write_credentials(usr_auth, "append")
        if written:
            if logger:
                self.logger.info(f"user added: '{usr}'")
        else:
            self.logger.error(f"failed to add user: '{usr}'")
    
    def user_remove(self, usr, skip_prompt=False):
        if not self.user_exists(usr):
            self.logger.error(f"user does not exists: '{usr}'")
            return
        if skip_prompt:
            check = True
        else:
            self.logger.warning(f"remove user '{usr}'?")
            check = self.continue_input(prompt=False)
        if check:
            if self.user_exists(usr, logger=True):
                for h in self.hashes:
                    u = h.split(":")[0]
                    if u == usr:
                        removed = self.remove_credentials(u)
                        if removed:
                            self.logger.debug(f"credentials removed: '{u}'")
                        else:
                            self.logger.error(f"failed to remove credentials: '{u}'")
                        try:
                            self.config.get("auth").get("basic").get("users").remove(h)
                            self.users.remove(u)
                            self.update_config()
                            self.logger.debug(f"user removed: '{u}'")
                        except ValueError:
                            self.logger.error(f"Failed to remove user: '{u}'")                   
                        break
        else:
            return

    def iterate_file(self, path, kind):
        entries = self.read_file(path)
        for e in entries:
            e = e.rstrip('\r\n')
            p = None
            if len(e.split()) == 1:
                u = e.split()[0]
            elif len(e.split()) == 2:
                u = e.split()[0]
                p = e.split()[1]
            else:
                self.logger.error(f"invalid entry: '{e}'")
            if kind == "add":
                self.user_add(u, p, skip_prompt=self.arg.force, logger=True)
            elif kind == "change":
                self.user_password_change(u, p)

def main():
    settings = Settings()
    basics = Basics()
    arg = settings.arg
    logging = Logging()
    logging.color()
    logger = logging.logger 
    op = Operations()

    if arg.list_users:
        try:
            op.print_list(op.get_users())
        except OperationError as err:
            logger.error(err)
            sys.exit()     

    if any([
        arg.backup,
        arg.encrypt,
        arg.decrypt, 
        arg.show_password,
        arg.show_password == '',
        arg.add_user, 
        arg.rm_user, 
        arg.change_password,
    ]):
        cmd = Commands()

if __name__ == "__main__":
    setup = Setup()
    setup.install([
        'coloredlogs>=15.0', 
        'ruyaml>=0.20.0',
        'bcrypt>=3.2.0',
        'passlib>=1.7.4',
        'pyAesCrypt>=5.0.0',
        'readchar>=3.0.4',
    ])

    import coloredlogs
    import pyAesCrypt
    import readchar
    from ruyaml import YAML
    from passlib.hash import bcrypt

    main()