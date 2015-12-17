# Gladius
## Easy mode from Responder to Credentials

[![asciicast](https://asciinema.org/a/0l8hlq0jt6bstvqnfw51c58lo.png)](https://asciinema.org/a/0l8hlq0jt6bstvqnfw51c58lo)

### Install
```
pip install watchdog
git clone https://www.github.com/praetorianlabs/gladius
```

### Start
```
python gladius.py
```

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

### Workings

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
handlers = [(ResponderHandler, args.responder,
            (CredsHandler, ResponderHandler().outpath),
            (PentestlyHandler, CredsHandler().outpath)]
```
