vt_rep
======

Query VT using private API to look for rare/suspicious files. There are probably many errors in this script as it's kind of fresh :)

The script has some logic based on which it picks up those rare files:
- all files with at least one positive detection
- files submitted only under one file name and less than 10 times
- files submitted under less than 5 names and not signed
- all unknown files to virustotal

Output of the script is saved to vt\_checklist.txt and is in CSV format. You can than load this in Excel and manually
examine all of the submitted files. 

The script does some caching to spare VT queries - cache is kept in db/ subfolder. Clean the cache db (db/ folder) 
periodically to remove the old entries because files on VT could have been re-analyzed in the meantime with more up-to-date
anti-virus signatures. For example, to remove all files that are more than 30 days old:

find db/ -mtime +30 -exec del "{}"

Two versions of the scripts are attached:

```vt_rep_dsk.py``` - to be used with *.dsk files from Hunter collectors. See Hunter docs for usage instructions.

```vt_rep_csv.py``` - to be used with autoruns CSV files and Hashmod output. Just run:
```
autorunsc.exe -a -f -c * /accepteula > autoruns.csv
hashmods
```
Then in the same folder run ```python vt_rep_csv.py``` - should work. Don't forget to put your VT API key into the vt_rep.yaml file.

If you want to whitelist a particular md5 - for example, you might have some custom tools specific to your organization - just create a file <md5_of_whitelisted_file>.vt in the db/ folder with the following content:
```
{
    "whitelisted": 1
}

```

Keep the whitelisted entries in a separate folder too as after each cleaning of the db you will have to move them again into this place.