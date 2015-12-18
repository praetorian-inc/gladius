# Gladius
## Easy mode from Responder to Credentials

[![asciicast](https://asciinema.org/a/77yqou5omy7ubrrqzjkut8sw7.png)](https://asciinema.org/a/77yqou5omy7ubrrqzjkut8sw7)

### Install
```
pip install watchdog
git clone https://www.github.com/praetorianlabs/gladius
```

### Start
```
python gladius.py
```
#### Note: By running Gladius, you agree to the Hashcat EULA.

### Help
```
$ python gladius.py -h
usage: gladius.py [-h] [-v] [--responder-dir RESPONDER_DIR]
                  [--hashcat HASHCAT] [-r RULESET] [-w WORDLIST] [--no-art]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Increased output verbosity
  --responder-dir RESPONDER_DIR
                        Directory to watch for Responder output
  --hashcat HASHCAT     Path to hashcat binary
  -r RULESET, --ruleset RULESET
                        Ruleset to use with hashcat
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist to use with hashcat
  --no-art              Disable the sword ascii art for displaying credentials
                        and default to only text.
```

### Working with secretsdump
Sent results of secretsdump to Gladius for parsing and cracking.
```
for ip in $(cat ips); do secretsdump.py DOMAIN/username:password@$ip > /usr/share/responder/secretsdump_$ip; done
    ```

### Workings

#### Ruleset

The default ruleset is a better best64 ruleset from Julian Dunning ([@hob0man](https://twitter.com/hob0man)) of Praetorian. His presentation on the topic can be found below:

[![Picture to Youtube](https://img.youtube.com/vi/Bw7DSG0svgs/0.jpg)](https://www.youtube.com/watch?v=Bw7DSG0svgs)

#### Responder

Watches responder log for `*NTLM*txt` files. For each file found, parses output, creates a temp file containing the new hashes, and passes this to hashcat with the correct hash type

```
To watch for NTLM hashes from hashdump, simply create a file with NTLM hashes from hashdump and drop a file with `hashdump` in its name in the Responder directory.
Note: Will have to manually examine output in `./engagement/responderhander_out/*` to check for results from `hashdump` cracking.
```

#### Credentials

Watches for output from `hashcat` and exports files with the following format:

```
Domain Username Password
```

### Example module

To extend Gladius:
* Create a new Handler class that inherits from `GladiusHandler`. 
* Add a list of regex matches for your specific file names (or `'*'` if the filename doesn't matter)
* Create a `process()` function to perform actions on all files matching your pattern.

```
class YourHandler(GladiusHandler):

    patterns = ['*']

    def process(self, event):
        data = self.get_lines(event)

        # Perform work on data
```


Add yourself to the handlers list
```
handlers = [
            (ResponderHandler, args.responder,
            (CredsHandler, ResponderHandler().outpath),
            (YourHandler, CredsHandler().outpath),
            (YourHandler, '/tmp'),
           ]
```
