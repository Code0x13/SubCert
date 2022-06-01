# SubCert
Subdomain enumeration by obtaining SSL certificates and checking the CN and SAN fields. This is a work in progress, so may have bugs! 

This tool is for authorised use only where you have been granted permission to test!

# Usage
```
$ git clone https://github.com/Code0x13/SubCert.git
$ cd SubCert
$ python3 subcert.py -h

With a single host: -
$ python3 subcert.py -t example.domain.com

With multiple hosts, create a text file with hosts on each new line, for example: -
$ cat targets.txt
example-1.domain.com
example-2.domain.com
example-3.domain.com

Then run the tool, specifying the file: -
$ python3 subcert.py -f targets.txt
```

