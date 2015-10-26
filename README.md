## Responder to Credentials

### Install
```
pip install watchdog
git clone https://git.praetorianlabs.com/thebarbershopper/gladius/blob/master/gladius.py
```

### Configuration
First things first, have to set our configuration:
```
[Responder]
hashcat = /root/tools/hashcat/hashcat-cli64.bin # Path to hashcat binary
wordlist = /root/tools/hashcat/rockyou.txt # Path to wordlist for hashcat
ruleset = /root/tools/hob064.rule # Path to ruleset for hashcat 
log_path = /opt/responder/logs # Path to monitor for new Responder hashes

[Creds]
outfile_path = /root/creds # File to write cracked credentials
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

Check the file in `Creds outfile_path` from the config for your reward.

### Example module

```
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
            line = line.split(':')
            try:
                cred = '{} {} {}'.format(line[2], line[0], line[-1])
                success("New creds: {}".format(cred))
                outfile.write(cred + '\n')
            except IndexError:
                pass
```

Just need a `process` function to handle the new data.


Add yourself to the handlers list
```
handlers = [(ResponderHandler, config.get('Responder', 'watch_path')),
            (CredsHandler, ResponderHandler().outpath),
            (PentestlyHandler, CredsHandler().outpath)]
```
