import json, enum
import pyotp, qrcode
import os
import logging

from getpass import getpass
from bcrypt import hashpw, gensalt

#-----------------------Functions----------------------------------------

'''
Offer the option of using OTP instead of password for login to the supplied user
Generates a QR Code that the user can scan into their Authenticator application
to generate the OTP's

To enable OTP suppport, user must scan the QR Code and generate atleast one OTP
Code which is input into the application for verification

The OTP is generated using the password, it can also be using a random seed but
for now the password is considered a better option
'''
def offerotp(user, app_name):
    
    print("Would you like to use OTP instead of password?(Y/N): " ,end='')

    choice= input();
    if choice == 'Y' or choice == 'y':

        print("Please scan below QR Code and enter the otp generated")

#Generate the QR Code and output it onto the command line as ASCII Art
        qr = qrcode.QRCode()
        qr.add_data(pyotp.totp.TOTP(get_otp_key(user)).provisioning_uri(
            user['name'], issuer_name=app_name))
        qr.make()

        qrcode.QRCode.print_ascii(qr)
        
#Verify user input OTP, uses validity window of 1
        if verify_otp(user, getpass()):
            user['otp_enabled'] = True            
        else:
            user['otp_enabled'] = False

        logger.info("User enabled with OTP: {}".format(
                user['otp_enabled'] ))

    return user
    
'''
Perform the main login activity
@create_flag Allows the application to create user and offer OTP function
to existing users

This functions shows basic username and password prompt and compares the
credentials entered to those on file.

This has built in OTP support. If user is OTP enabled, it gets the OTP key
from file and uses it to generate the OTP Server Side comparison

If the create flag is set, it allows the creation of user and enabling OTP
for user 
'''
def login(app_name, payload = None):
    logger.debug("Attempting login. App Name: {}, Command = {}".format(
        app_name, payload))
    status = 0

#Show the login prompt
    print("Username: ",end='')
    username = input ()

    password = getpass("Password: ")
    

#Load the details of the user from file
    user = read_user_file(username)       
    
#If the user is successfully loaded
    if user:
        logger.debug(user)
        '''
Check if the user is enabled for OTP and the application is also run with
OTP Support
        '''       
        if user.get("otp_enabled") and not(no_otp):
            logger.info("User is OTP enabled")
            
#Verify the entered password/code with OTP from key on file
            if verify_otp(user, password):
                status = login_success(user, payload)
            else:
                status= login_failed(user, payload, FAIL_REASONS.INCORRECT_OTP)                
        else:
#If the user is not otp enabled or otp flag is false, check password            
            if hashpw(password.encode('utf-8'), user.get('password').encode('utf-8')).decode("utf-8") == user.get('password'):                
#If the offer otp flag is set, then offer the user the option to upgrade to OTP                
                if options.offer_otp and\
                    not(user.get('otp_enabled')):
                    user= offerotp(user, app_name)
        #Update the user with the choice. In a more sophisticated application this would be done only when something changes
                    def_update_user(user)
#If everything is okay, then login and execute payload                    
                status = login_success(user, payload)
            else:
#report login failed
                status=\
                    login_failed(user, payload, FAIL_REASONS.INCORRECT_PASSWORD)
    #elif create_flag:
    elif options.create:
#If the create flag is set, create the user by asking for repeat password        
        print ("User %s not found. Enter password again to create"% username)
        salt = gensalt()
        if hashpw(password.encode('utf-8'),salt) == hashpw(getpass("Password: ").encode('utf-8')
                              , salt ):
            user= {}
            user['name'] = username
            user['password'] = hashpw(password.encode('utf-8'), gensalt()).decode("utf-8")
            logger.info("User password created")
            user= offerotp(user, app_name)
            def_update_user(user)
            login_success(user, payload)
        else:
            status=\
                login_failed(user, payload, FAIL_REASONS.REPEAT_PASSWORD)
    else:        
        status=\
            login_failed(user, payload, FAIL_REASONS.NO_MATCHING_USER)
    
    return status

#--------------------Helper Methods--------------------------------------
#If everything is okay, then login and execute payload
def login_success(user, payload):    
    logger.info ("Login successfull for user %s" % user)
    return run_application(payload)    

#If login failed, execute payload without user
def login_failed(user, payload, fail_reason):
    logger.info ("Login failed for user {} with reason: {}".format(user, fail_reason))
    if options.run_no_user:
        return run_application(payload)
    return

'''
Currently the password is used as the OTP key but it could be randomly
generated seed
'''
def get_otp_key(user):
    return user['password']

def verify_otp(user, otp, totp = None):
    if not(totp):
        totp = pyotp.totp.TOTP(get_otp_key(user))
    return totp.verify(otp, valid_window = OTP_VALID_WINDOW)

def run_application(args):
    from subprocess import run
    logger.debug("Running application: %s" % args)
    run(args)
    return

def read_user_file(user):
    if not(os.path.isdir(DATA_DIR)):
        raise Exception ("Data directory " + DATA_DIR +" not found")
    
    if os.path.isfile(USERS_FILE):
        with open(USERS_FILE) as infile:
            global all_users
            all_users = json.load(infile)
            user_details= all_users.get(user)
    else:        
        user_details = None
    logger.debug(USERS_FILE)
    return user_details

def def_update_user(user):
    if all_users.get(user['name']):
        del all_users[user['name']]
    all_users[user['name']] = user    
    with open(USERS_FILE, 'w') as outfile:
            json.dump(all_users, outfile)
    

#---------------------Global Variables------------------------------
all_users = {}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

APPLICATION_NAME = "login_cli"
DATA_DIR = 'data/'
USERS_FILE = DATA_DIR + "users.users"
PARAMETERS_FILE = DATA_DIR + "login.txt"

global options


def enum(*args):
    #enums = dict(zip(args, range(len(args))))
    enums = dict(zip(args, args))
    return type('Enum', (), enums)

FAIL_REASONS = enum('NO_MATCHING_USER', 'INCORRECT_PASSWORD',
                    'INCORRECT_OTP', 'REPEAT_PASSWORD')
               
OTP_VALID_WINDOW = 1

#----------------------Main Method ----------------------------------

if __name__ == "__main__":
    
    try:        
        import sys

        from simple_parameters import simple_parameters
        parser = simple_parameters.SimpleParser(PARAMETERS_FILE )
        (options, args) = parser.resolve_parameters(sys.argv)

        logger.debug("Input parameters:{}".format(options))        
        
        if(len(args) > 1):
            payload = args[1:]
        else:
            payload = "python --version"
        status = login(app_name = APPLICATION_NAME,
                   payload = payload)
        sys.exit(status)
    
    except Exception as err:
        import traceback
        traceback.print_exception(*(sys.exc_info()))
        logger.error(err)
        logger.info("Error, lets start again")

        
