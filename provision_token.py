"""
provision_token.py

Unconditionally erases a YubiKey's PIV applet following the 'reset'
procedure described on
https://developers.yubico.com/yubico-piv-tool/YubiKey_PIV_introduction.html,
then sets it up with a new keypair (and self-signed certificate) in
accordance with our defined best-practices. In particular, these are:

This script requires yubico-piv-tool:
https://developers.yubico.com/yubico-piv-tool/Releases

* Disable OTP mode

  We find that provisioning all new YubiKeys with OTP mode disabled
  helps cut down on accidental chatter in our team Slack channels,
  among other things :)

  This operation requires the 'ykneomgr' binary to be available,
  and will be skipped if it is not. It is available as part of the
  'libykneomgr' distribution:
  https://developers.yubico.com/libykneomgr/Releases

* Leave the default management key in place

  The management key can't be used to perform any operations that
  could expose a private key or bypass the PIN requirement, and a
  denial-of-service attack is always achievable by providing a bad PIN
  / PUK a sufficient number of times.

  (see https://developers.yubico.com/PIV/Introduction/Admin_access.html)

* Generate a random PIN

  Specifically, an 8-character randomly generated alphanumeric string

* Set PIN retries to 5

  The randomly-generated PIN is sufficiently strong that increasing
  the retry-counter slightly should have no negative security impact

* Block the PUK

  We do not have any intention to escrow a PUK with e.g. our IT
  organization, so it seems to serve no useful purpose.

* Generate a new private key + self-signed certificate in Slot 9a

  The key is generated on-chip, using 2048-bit RSA, and with
  'touch-policy' set to 'always'
"""


import argparse
import csv
from random import SystemRandom
import string
import subprocess
import tempfile

DEFAULT_PIN = '123456'
INVALID_PUK = 'xxxxxxxx'

def get_status_and_output(args):
    print args
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, _ignored = p.communicate()
    status = p.wait()
    print stdout
    return status, stdout

def check_call(args):
    print args
    subprocess.check_call(args)
    print

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '--yubico-piv-tool-path',
        default='/opt/yubico-piv-tool/bin/yubico-piv-tool',
        help=("Path to 'yubico-piv-tool' binary. "
              "(Default: '/opt/yubico-piv-tool/bin/yubico-piv-tool')")
        )
    parser.add_argument(
        '--ykneomgr-path',
        default='/opt/libykneomgr/bin/ykneomgr',
        help=("Path to optional 'ykneomgr' binary. "
              "(Default: '/opt/libykneomgr/bin/ykneomgr'")
        )
    parser.add_argument('--append-csv')
    parser.add_argument('--common-name')
    args = parser.parse_args()

    if not args.common_name:
        args.common_name = raw_input(
            'Enter username for self-signed cert: ')

    # print out status display of the PIV applet's current contents
    # (i.e. what's about to be erased)
    check_call([args.yubico_piv_tool_path, '-a', 'status'])

    if raw_input('THIS WILL ERASE ANY EXISTING PIV CREDENTIALS. '
                 'TYPE "YES" TO CONTINUE: ') != 'YES':
        return

    # attempt to query the serial number, just for record-keeping.
    serial_number = 'UNKNOWN'
    if args.ykneomgr_path:
        print 'Reading serial number...'
        try:
            status, output = get_status_and_output(
                [args.ykneomgr_path, '-s'])
            if status:
                raise Exception()
        except Exception:
            print 'Could not read serial number. Is ykneomgr installed?'
        else:
            serial_number = output.strip()

        # attempt to set the YubiKey to CCID+U2F mode (disable OTP)
        try:
            print 'Disabling OTP mode'
            check_call([args.ykneomgr_path, '-M', '5'])
        except Exception as e:
            print ('Failed to disable OTP mode: {}. '
                   'Is ykneomgr installed?').format(e)

    # block the PIN
    print 'Blocking PIN'
    for i in range(10):
        status, output = get_status_and_output(
            [args.yubico_piv_tool_path, '-a', 'verify-pin', '--pin',
             INVALID_PUK])
        if not status:
            raise RuntimeError('Invalid pin not invalid?')
        if 'pin code blocked' in output.lower():
            break
    else:
        raise RuntimeError('Could not block PIN!')

    print 'Blocking PUK'
    # block the PUK
    for i in range(10):
        status, output = get_status_and_output(
            [args.yubico_piv_tool_path, '-a', 'unblock-pin', '--pin',
             INVALID_PUK, '--new-pin', INVALID_PUK])
        if not status:
            raise RuntimeError('Invalid puk not invalid?')
        if 'puk code is blocked' in output.lower():
            break
    else:
        raise RuntimeError('Could not block PUK!')

    print 'Resetting PIV applet '
    # reset the piv applet
    check_call([args.yubico_piv_tool_path, '-a', 'reset'])

    # set pin retries to 5, puk retries to 1
    print 'Setting PIN retries to 5, PUK retries to 1'
    check_call(
        [args.yubico_piv_tool_path, '-a', 'verify-pin', '--pin', DEFAULT_PIN,
         '-a', 'pin-retries', '--pin-retries', '5', '--puk-retries', '1'])

    # then immediately block the puk
    print 'Blocking PUK'
    status, output = get_status_and_output(
        [args.yubico_piv_tool_path, '-a', 'unblock-pin', '--pin',
         INVALID_PUK, '--new-pin', INVALID_PUK])
    if not status:
        raise RuntimeError('Invalid puk not invalid?')
    if 'puk code is blocked' not in output.lower():
        raise RuntimeError('Could not block PUK')

    # generate a random PIN
    g = SystemRandom()
    new_pin = ''.join(
        g.choice(string.letters + string.digits)
        for x in range(8))
    print 'Setting new PIN: {}'.format(new_pin)
    check_call(
        [args.yubico_piv_tool_path, '-a', 'verify-pin', '--pin', DEFAULT_PIN,
         '-a', 'change-pin', '--new-pin', new_pin])

    # generate key/cert
    # XXX could use stdout/stdin for this rather than tempfiles
    with tempfile.NamedTemporaryFile(suffix='.crt') as certfile, \
            tempfile.NamedTemporaryFile(suffix='.key') as keyfile:
        print 'Generating key in slot 9a'
        check_call([args.yubico_piv_tool_path, '-a', 'generate', '-s', '9a',
                    '-o', keyfile.name, '--touch-policy=always'])

        print 'Self-signing the cert. Touch the token when it flashes!'
        check_call(
            [args.yubico_piv_tool_path, '-a', 'verify-pin', '--pin', new_pin,
             '-a', 'selfsign-certificate', '-s', '9a', '-S',
             '/CN={}/'.format(args.common_name), '-i', keyfile.name, '-o',
             certfile.name])
        print 'Importing cert'
        check_call(
            [args.yubico_piv_tool_path, '-a', 'import-certificate', '-s', '9a',
             '-i', certfile.name])

        print 'Converting to ssh pubkey'
        status, output = get_status_and_output(
            ['/usr/bin/ssh-keygen', '-i', '-m', 'pkcs8', '-f', keyfile.name])
        if status:
            raise RuntimeError('could not convert pubkey!')
        sshkey = output.strip()

    print 'Setting CHUID and CCC'
    check_call([args.yubico_piv_tool_path, '-a', 'set-chuid', '-a', 'set-ccc'])

    print 'Provisioning Complete!'
    print 'SERIAL: ', serial_number
    print 'PIN: ', new_pin
    print 'SSH KEY: {} {}'.format(sshkey, args.common_name)

    if args.append_csv:
        with open(args.append_csv, 'a') as fp:
            writer = csv.writer(fp)
            writer.writerow(
                [args.common_name, serial_number, new_pin, sshkey])

if __name__ == '__main__':
    main()
