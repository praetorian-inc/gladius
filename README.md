## Responder to Credentials

### Configuration
First things first, have to set our configuration:
```
[Responder]
hashcat = /root/tools/hashcat/hashcat-cli64.bin # Path to hashcat binary
wordlist = /root/tools/hashcat/rockyou.txt # Path to wordlist for hashcat
ruleset = /root/tools/esymode.rule # Path to ruleset for hashcat 
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
