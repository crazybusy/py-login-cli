# py-login-cli
Command line login for python applications including suppport for OTP via Authenticator Apps

Dependancies
It uses my own SimpleParameters to evaluate command line parameters, hence it is published alongside.
There is file login.txt in the data directory that contains the parameters this application accepts on the command line. The Users Master file is also housed there.

Usage:
Pass the application you would like to add login to add as parameter on the command line
For e.g.
python login.py test.py

This will add a login prompt before test.py with otp support. Ofcourse the user could directly run test.py. For that you can integrate this script into your python code. 

$ python ./login.py -h
Usage: login.py [options]

Command line login for python applications including suppport for OTP via
Authenticator Apps

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -c, --create       Allows to create the user if it doesnt exist
  -n, --no-otp       login without the otp even if it is enabled. Safe mode,
                     use password
  -o, --offer-otp    Offer the option of using the OTP to the user
  -r, --run-no-user  Run the payload application even if the user is not
                     available
