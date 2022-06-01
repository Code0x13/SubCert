# SubCert
Subdomain enumeration by obtaining SSL certificates and checking the CN and SAN fields. This is a work in progress, so may have bugs! 

This tool is for authorised use only where you have been granted permission to test!

# Usage
```
$ git clone https://github.com/Code0x13/SubCert/

get some help
$ python3 subcert.py -h

run the tool against a single target
$ python3 subcert.py -t example.domain.com

run the tool against a text file containing targets on each line
$ python3 subcert.py -f targets.txt

$ cat targets.txt
example-1.domain.com
example-2.domain.com
example-3.domain.com
```

