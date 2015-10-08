## Responder to Credentials

### Configuration
First things first, have to set our configuration:
```
[Responder]
hashcat = /root/tools-old/hashcat/hashcat-cli64.bin # Path to hashcat binary
wordlist = /root/tools-old/hashcat/rockyou.txt # Path to wordlist for hashcat
ruleset = /root/tools-old/esymode.rule # Path to ruleset for hashcat 
log_path = /opt/responder/logs # Path to monitor for new Responder hashes
outfile_path = /tmp/responder # Directory to output hashcat results
outfile_prefix = responder_hashes # Filename prefix for hashcat results

[Creds]
infile_path = /tmp # Directory to monitor for hashcat results
outfile_path = /root/creds # File to write cracked credentials
```

