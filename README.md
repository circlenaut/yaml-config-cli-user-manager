# YAML Config Command Line User Manager

This script allows for the management of users within a YAML configuration file formatted like the 'config.yaml' and a corresponding credentials file that stores plaintext passwords.

### Install

- Run 'pip3 install -r requirements.txt' to load required dependencies.
- Run the 'install.sh' script if you'd like to run "mgt_users" system wide.

### Examples

Add a user:

    python3 mgt_users.py -a user1

Change a user's password:

    python3 mgt_users.py -p user1

Remove a user:

    python3 mgt_users.py -r user1

Add multiple users from a file(formated like the multi_test.txt example):

    python3 mgt_users.py -a multi_test.txt

Change passwords of multiple users specified in a file:

    python3 mgt_users.py -p multi_test.txt

Set random passwords of multiple users listed in a file:

    python3 mgt_users.py -x -f multi_test.txt

Remove multiple users:

    python3 mgt_users.py -r user1 -r user2 -r user3 -user4

List users:

    python3 mgt_users.py -l

Show passwords for all users:

    python3 mgt_users.py -s

Show password for a specific user:

    python3 mgt_users.py -s user1

Decrypt credentials file:

    python3 mgt_users.py -d

Encrypt credentials file:

    python3 mgt_users.py -e

Show additional options:

    python3 mgt_users.py -h


### Command line options
    -h, --help            show this help message and exit
    -cfg CONFIG_PATH, --config_path CONFIG_PATH
                        Specify config path
    -crd CREDENTIALS_PATH, --credentials_path CREDENTIALS_PATH
                        Specify credentials path
    -lg LOG_PATH, --log_path LOG_PATH
                        Specify log path
    -bak CONFIG_BACKUP, --config_backup CONFIG_BACKUP
                        Specify config backup path
    -cbk CREDENTIALS_BACKUP, --credentials_backup CREDENTIALS_BACKUP
                        Specify credentials backup path
    -v, --verbose         Enable verbose output
    -f, --force           Force a command without checks
    -e, --encrypt         Encrypt credentials file
    -d, --decrypt         Decrypt credentials file
    -b, --backup          Backup configurations and credentials files
    -l, --list_users      List users
    -s [SHOW_PASSWORD], --show_password [SHOW_PASSWORD]
                        Show user password, if empty shows for all users
    -a ADD_USER, --add_user ADD_USER
                        Add user
    -r RM_USER, --rm_user RM_USER
                        Remove user, specify multiple times to remove
                        multimple users
    -p CHANGE_PASSWORD, --change_password CHANGE_PASSWORD
                        Change user password
    -x, --random_password
                        Set random password
    -n NUM_CHARS_PASSWORD, --num_chars_password NUM_CHARS_PASSWORD
                        Specify number of charecters for auto-generated
                        passwords
    -t [{Alpha,Num,Sym,AlphaNum,AlphaSym,NumSym,AlphaNumSym}], --type_password [{Alpha,Num,Sym,AlphaNum,AlphaSym,NumSym,AlphaNumSym}]
                        Specify type of password to generate