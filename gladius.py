import time
import tempfile
import os
import subprocess
import argparse
import struct

from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler  
from multiprocessing import Process
from distutils.spawn import find_executable

from ConfigParser import SafeConfigParser

config = SafeConfigParser()
config.read('config.ini')

project_path = config.get("Project", 'project_path')

verbosity = False

################################################################################
# Helper functions
################################################################################

def find_file(filename):
    for root, dirs, files in os.walk('/'):
        for file in files:
            if file == filename:
                return os.path.join(root, file)

def color(string, color='', graphic=''):
    """
    Change text color for the Linux terminal.

    Args:
        string (str): String to colorify
        color (str): Color to colorify the string in the following list:
            black, red, green, yellow, blue, purple, cyan, gr[ae]y
        graphic (str): Graphic to append to the beginning of the line
    """

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

class ResponderHandler(PatternMatchingEventHandler):
    """
    Watch for new hash files and run hashcat against them
    """

    patterns = ["*NTLM*.txt"]
    
    # Add to this list to add new hashcat crack types
    # NOTE: If the type isn't NTLM, be sure to add a regex pattern to patterns
    types = [
                ('ntlmv1', '5500'),
                ('ntlmv2', '5600'),
            ]

    cache = set()

    def call_hashcat(self, hash_num, hashes):
        """Run hashcat against a list of hashes"""
        hashcat = config.get('Responder', 'hashcat')
        ruleset = config.get('Responder', 'ruleset')
        wordlist = config.get('Responder', 'wordlist')

        eula = os.path.join(os.path.dirname(hashcat), 'eula.accepted')

        with open(eula, 'w') as f:
            f.write('1\0\0\0')

        if not os.path.exists(hashcat):
            hashcat = find_file(hashcat)

        if not os.path.exists(ruleset):
            ruleset = find_file(ruleset)

        if not os.path.exists(wordlist):
            wordlist = find_file(wordlist)

        if not hashcat:
            error("Could not find hashcat: {}".format(hashcat))
            return

        if not ruleset:
            error("Could not find ruleset: {}".format(ruleset))
            return

        if not wordlist:
            error("Could not find wordlist: {}".format(wordlist))
            return

        temp = tempfile.NamedTemporaryFile(mode='w', delete=False)
        for curr_hash in hashes:
            temp.write(curr_hash + '\n')

        temp.close()

        out_path = os.path.join(project_path, config.get('Responder', 'outfile_path'))
        if not os.path.exists(out_path):
            os.makedirs(out_path)
        
        outfile = tempfile.NamedTemporaryFile(delete=False, 
                                              prefix=config.get("Responder", 'outfile_prefix'),
                                              dir=out_path,
                                              suffix="out")

        # Spawn hashcat
        command = [hashcat, '-m', hash_num, '-r', ruleset, '-o', outfile.name, temp.name, wordlist]
        warning(' '.join([str(x) for x in command]))
        verbose("Hashcat command: {}".format([str(x) for x in command]))
        res = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def process(self, event):
        with open(event.src_path, 'r') as f:
            data = f.read().split('\n')

        new_hashes = []
        hash_type = 0

        for line in data:
            if line in self.cache:
                verbose("Currently in cache, skipping: {}".format(line))
                continue

            # Ignore blank lines
            if not line:
                continue
            for curr_hash, curr_type in self.types:
                if hash_type == 0:
                    hash_type = curr_type

                if curr_hash.lower() in event.src_path.lower():
                    hash_type = curr_type
                    info("New hash to crack: {}".format(line))
                    new_hashes.append(line)
                    self.cache.add(line)

        if new_hashes and hash_type != 0:
            self.call_hashcat(hash_type, new_hashes)

    def on_modified(self, event):
        verbose("File in responder path modified")
        self.process(event)

    def on_created(self, event):
        verbose("File in responder path created")
        self.process(event)

class CredsHandler(PatternMatchingEventHandler):
    """
    Watch for new hash files and run hashcat against them
    """

    patterns = ["*{}*".format(config.get("Responder", "outfile_prefix"))]
    cache = []

    def process(self, event):
        with open(event.src_path, 'r') as f:
            data = f.read().split('\n')

        cache = []
        if os.path.exists(config.get('Creds', 'outfile_path')):
            with open(config.get('Creds', 'outfile_path'), 'r') as f:
                cache = f.read().split('\n')

        out_path = os.path.join(project_path, config.get('Creds', 'outfile_path'))
        if not os.path.exists(out_path):
            os.makedirs(out_path)

        outfile = tempfile.NamedTemporaryFile(delete=False, 
                                              prefix=config.get("Creds", 'outfile_prefix'),
                                              dir=out_path,
                                              suffix="out")

        # with open(config.get('Creds', 'outfile_path'), 'a') as f:

        for line in data:
            line = line.split(':')
            try:
                cred = '{} {} {}'.format(line[2], line[0], line[-1])
                verbose("Found new cred: {}".format(cred))
                if cred not in cache:
                    success("New creds: {}".format(cred))
                    outfile.write(cred + '\n')
            except IndexError:
                pass

    def on_modified(self, event):
        verbose("File in creds path modified")
        self.process(event)

    def on_created(self, event):
        verbose("File in creds path created")
        self.process(event)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action="store_true", default=False, help="Increased output verbosity")
    args = parser.parse_args()

    verbosity = args.verbose

    handlers = [(ResponderHandler, config.get('Responder', 'watch_path')),
                (CredsHandler, os.path.join(project_path, config.get('Responder', 'outfile_path')))]

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

