import time
import tempfile
import os
import subprocess
import argparse
import struct
import md5
import datetime

from collections import namedtuple
from collections import defaultdict

from multiprocessing import Process
from distutils.spawn import find_executable

try:
    from watchdog.observers import Observer
    from watchdog.events import PatternMatchingEventHandler
except ImportError:
    raise Exception("Watchdog is needed for Gladius: pip install watchdog.")
    exit(0)

verbosity = False
art = True

Cred = namedtuple('Cred', ['domain', 'username', 'password'])

colors = {
    'normal'         : "\x1b[0m",
    'black'          : "\x1b[30m",
    'red'            : "\x1b[31m",
    'green'          : "\x1b[32m",
    'yellow'         : "\x1b[33m",
    'blue'           : "\x1b[34m",
    'purple'         : "\x1b[35m",
    'cyan'           : "\x1b[36m",
    'grey'           : "\x1b[90m",
    'gray'           : "\x1b[90m",
    'bold'           : "\x1b[1m"
}

ntlm_hashes = defaultdict(dict)


################################################################################
# Helper functions
################################################################################

def print_banner():
    with open('banner.txt', 'r') as f:
        data = f.read()

    """
    for line in data.split('\n'):
        if 'Author' in line or 'Present' in line:
            data = data.replace(line, color(line, 'red'))

    for words, c in [('@CoryDuplantis', 'yellow'), 
                     ('Cory Duplantis', 'yellow'), 
                     ('Praetorian', 'yellow')]:
        data = data.replace(words, color(words, c))
    """

    data = data.replace('R', colors['red'])
    data = data.replace('Y', colors['yellow'])
    data = data.replace('B', colors['blue'])

    print(data)

def get_cracked_stats():
    total_hashes = len(ntlm_hashes)

    total_hashes = []
    for hash in ntlm_hashes:
        total_hashes.extend(ntlm_hashes[hash]['users'])
    total_hashes = len(total_hashes)

    cracked_hashes = []
    for hash in ntlm_hashes:
        if ntlm_hashes[hash]['password']:
            cracked_hashes.extend(ntlm_hashes[hash]['users'])
    total_cracked = len(cracked_hashes)
    # total_cracked = len([hash for hash in ntlm_hashes if ntlm_hashes[hash]['password']])
    percentage = "{:.2f}".format(((total_cracked * 1.0) / total_hashes)*100)
    result = "({}/{} {}%)".format(total_cracked, total_hashes, percentage)
    return result

def find_file(filename):
    """Find a particular file on disk"""
    for root, dirs, files in os.walk('/'):
        for file in files:
            if file == filename:
                return os.path.join(root, file)

def get_sword_art():
    with open('gladius.ascii', 'r') as f:
        data = f.read()

    return data

def create_sword(creds, sword_color='red', cred_color='green'):
    sword = color(get_sword_art(), color=sword_color)
    creds = str(creds)
    sword = sword.replace('LEN', '-' * len(creds))
    sword = sword.replace('CRED', colors[cred_color] + creds + colors[sword_color])
    return sword

def color(string, color='', graphic=''):
    """
    Change text color for the Linux terminal.

    Args:
        string (str): String to colorify
        color (str): Color to colorify the string in the following list:
            black, red, green, yellow, blue, purple, cyan, gr[ae]y
        graphic (str): Graphic to append to the beginning of the line
    """


    if not color:
        if string.startswith("[!] "):
            color = 'red'
        elif string.startswith("[+] "):
            color = 'green'
        elif string.startswith("[*] "):
            color = 'blue'
        else:
            color = 'normal'

    if color not in colors:
        print colors['red'] + 'Color not found: {}'.format(color) + colors['normal']
        return

    if color:
        return colors[color] + graphic + string + colors['normal']
    else:
        return string + colors['normal']

def output(string):
    print color(string)

def success(string):
    print color(string, color="green", graphic='[+] ')

def warning(string):
    print color(string, color="yellow", graphic='[*] ')

def error(string):
    print color(string, color="red", graphic='[!] ')

def info(string):
    print color(string, color="blue", graphic='[-] ')

def debug(string):
    print color(string, color="purple", graphic='[.] ')

def verbose(string):
    if verbosity:
        print color(string, color="cyan", graphic='[.] ')

################################################################################
# Watchdog Handler classes
################################################################################

class GladiusHandler(PatternMatchingEventHandler):
    """
    Base Class for Handlers in Gladius

    Attributes:
        output: Directory to write temporary files specific to the handler
        junkpath: Directory to write junk files for intermediate use
    """

    def __init__(self):
        self.cache = []
        self.outpath = os.path.join('engagement', "{}_out".format(self.__class__.__name__.lower()))
        self.junkpath = os.path.join('engagement', "junk")

        if not os.path.exists(self.outpath):
            os.makedirs(self.outpath)

        if not os.path.exists(self.junkpath):
            os.makedirs(self.junkpath)

        super(GladiusHandler, self).__init__()

    def process(self, event):
        pass

    def get_outfile(self, suffix=''):
        return tempfile.NamedTemporaryFile(delete=False, dir=self.outpath, suffix=suffix)

    def get_junkfile(self, suffix=''):
        return tempfile.NamedTemporaryFile(delete=False, dir=self.junkpath, suffix=suffix)

    def get_lines(self, event):
        """Given an event, return the lines of the event file"""
        with open(event.src_path, 'r') as f:
            data = f.read().split('\n')
        return data

    def on_modified(self, event):
        self.on_created(event)

    def on_created(self, event):
        # Ignore events that flag on the directory itself
        if os.path.isdir(event.src_path):
            return

        # In order to prevent duplication between created and modified
        # Check the md5 of the contents of the file
        # If cached file, ignore
        with open(event.src_path, 'r') as f:
            data = f.read()

        md5sum = md5.new(data).hexdigest()
        if md5sum in self.cache:
            return

        self.cache.append(md5sum)
        verbose("New data in {} path".format(self.__class__.__name__))
        self.process(event)


class ResponderHandler(GladiusHandler):
    """
    Watch for new hash files and run hashcat against them
    """

    patterns = ["*NTLM*.txt", "*hashdump*"]

    # Add to this list to add new hashcat crack types
    # NOTE: If the type isn't NTLM, be sure to add a regex pattern to patterns
    types = [
                ('ntlmv1', '5500'),
                ('ntlmv2', '5600'),
                ('hashdump', '1000'),
            ]

    cache = set()

    def accept_eula(self, hashcat):
        """Ensure we sign the EULA so that we don't have spinning hashcats"""

        eula = os.path.join(os.path.dirname(hashcat), 'eula.accepted')
        with open(eula, 'w') as f:
            f.write('1\0\0\0')

    def call_hashcat(self, hash_num, hashes):
        """Run hashcat against a list of hashes"""

        hashcat, ruleset, wordlist = args.hashcat, args.ruleset, args.wordlist

        self.accept_eula(hashcat)

        temp = self.get_junkfile()
        for curr_hash in hashes:
            temp.write(curr_hash + '\n')
        temp.close()

        outfile = self.get_outfile()

        # Spawn hashcat
        command = [hashcat, '-m', hash_num, '-r', ruleset, '-o', outfile.name, temp.name, wordlist]
        warning(' '.join([str(x) for x in command]))
        verbose("Hashcat command: {}".format([str(x) for x in command]))
        res = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def process(self, event):
        data = self.get_lines(event)

        new_hashes = []
        hash_type = 0

        for line in data:
            verbose("Responder: {}".format(line))
            # Ignore blank lines
            if not line:
                continue

            for curr_hash, curr_type in self.types:
                if hash_type == 0:
                    hash_type = curr_type

                if 'hashdump' in event.src_path:
                    # Handle smart_hashdump output
                    hash_type = curr_type
                    if line.count(':') != 3:
                        continue
                    if '$' in line:
                        continue

                    line = line.replace('\x1b[1m\x1b[32m[+]\x1b[0m \t', '')
                    username, _, _, hash = line.split(':')

                    if hash not in new_hashes:
                        new_hashes.append(hash)


                    if hash not in ntlm_hashes:
                        ntlm_hashes[hash]['time'] = datetime.datetime.now()
                        ntlm_hashes[hash]['users'] = []
                        ntlm_hashes[hash]['password'] = ''

                    if username not in ntlm_hashes[hash]['users']:
                        info("New hash to crack: {}:{}".format(username, hash))
                        ntlm_hashes[hash]['users'].append(username)

                elif curr_hash.lower() in event.src_path.lower():
                    hash_type = curr_type
                    info("New hash to crack: {}".format(line))
                    new_hashes.append(line)

        if new_hashes and hash_type != 0:
            self.call_hashcat(hash_type, new_hashes)

class CredsHandler(GladiusHandler):
    """
    Watch for new hash files and run hashcat against them
    """
    patterns = ['*']

    def process(self, event):
        with open(event.src_path, 'r') as f:
            data = f.read().split('\n')

        outfile = self.get_outfile()

        for line in data:
            verbose("Creds: {}".format(line))
            line = line.split(':')
            if len(line) == 2:
                hash, password = line
                if not line[1]:
                    continue
                if ntlm_hashes[hash]['password']:
                    # Already cracked it
                    continue

                cracked_stats = get_cracked_stats()
                usernames = ', '.join(ntlm_hashes[hash]['users'])
                crack_time = datetime.datetime.now() - ntlm_hashes[hash]['time']

                cred = '[{}] {} {} : {}'.format(crack_time, cracked_stats, usernames, password)
                success("New creds: {}".format(cred))
                ntlm_hashes[line[0]]['password'] = password
            else:
                try:
                    cred = '{} {} {}'.format(line[2], line[0], line[-1])
                except IndexError:
                    continue

                if art:
                    print create_sword(cred)
                else:
                    success("New creds: {}".format(cred))


            outfile.write(cred + '\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action="store_true", default=False, help="Increased output verbosity")
    parser.add_argument('--responder-dir', default="/usr/share/responder", help="Directory to watch for Responder output")
    parser.add_argument('--hashcat', default="/usr/share/hashcat/hashcat.bin", help="Path to hashcat binary")
    parser.add_argument('-r', '--ruleset', default="hob064.rule", help="Ruleset to use with hashcat")
    parser.add_argument('-w', '--wordlist', default="/usr/share/wordlists/rockyou.txt", help="Wordlist to use with hashcat")
    parser.add_argument('--no-art', action="store_true", default=False, help="Disable the sword ascii art for displaying credentials and default to only text.")
    args = parser.parse_args()

    for curr_arg in [args.hashcat, args.ruleset, args.wordlist]:
        if not os.path.exists(curr_arg):
            warning("Argument not found: {}. Ensure the file exists.".format(curr_arg))
            exit(1)

    verbosity = args.verbose
    if args.no_art:
        print color('Awe, no swords? Okay, fine..', color='yellow')
        art = False

    print_banner()

    # Add more handlers to this list.
    # (Handler, watch directory)
    handlers = [(ResponderHandler, args.responder_dir),
                (CredsHandler, ResponderHandler().outpath)]

    observer = Observer()
    observers = []

    for handler, path in handlers:
        if not os.path.exists(path):
            os.makedirs(path)

        info("Watching ({}) for files with ({})".format(path, ', '.join(handler.patterns)))
        observer.schedule(handler(), path=path, recursive=False)

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.unschedule_all()
        observer.stop()

    observer.join()
