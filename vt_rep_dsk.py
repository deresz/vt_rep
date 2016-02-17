'''
Created on 25 mai 2015

@author: deresz

VT private key is needed to use this !

will go to VT and see if there are any positive detection
and most importantly will flag rare files based on 
some simple logic (see end of the script)

without VT private key it will not check the rarity
only positive AV will be flagged

This version takes as imput *.dsk files from hunter collector

'''

import requests,json,hashlib,glob,re,sys,time,os,yaml,csv

if len(sys.argv) < 2:
    all_files = glob.glob('*')
else:
    all_files = [f for files in sys.argv[1:] for f in glob.glob(files)]

abspath = os.path.abspath(os.path.dirname(sys.argv[0]))    
f = open(abspath + '/vt_rep.yaml', "r")
params = yaml.load(f)

# pause if an error occured - for example if the VT private quota is reached 
pause = params['pause']
processed = []

if params.has_key('db'):
    db_dir = params['db']
else:
    db_dir = abspath + '/db'

if not os.path.exists(db_dir):
    os.mkdir(db_dir)

def parse_dsk():
    
    keywarning = False

    for dsk in all_files: 
        m = re.match("(.*)\.", dsk)
        if not m: continue
        f = open(dsk, "rb")
        content = f.read()

        md5 = hashlib.md5(content).hexdigest().lower()
        if md5 in processed:
            continue
        processed.append(md5)
        print "Checking %s" % dsk 
        meta = "%s/%s.vt" % (db_dir,md5)
        if os.path.exists(meta):
            cache = True
            print "vt file exists, getting from cache"
            with open(meta) as cachefile:    
                vtrep = json.load(cachefile)
    	    if vtrep.has_key('whitelisted'):
    	        continue	
        else:
            cache = False
            params['resource'] = md5
            # loop until we get a good response
            while(True):
                try:
                    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                    vtrep = response.json()
                    break
                except IOError as strerror:
                    print "I/O error: %s" % strerror
                    print "Pausing %d seconds" % pause
                    time.sleep(pause)
                    continue
                except ValueError as why:
                    print "ValueError: %s" % str(why)
                    print "Pausing %d seconds" % pause
                    time.sleep(pause)
                    continue
                except requests.ConnectionError as why:
                    print "Connection error: %s" % str(why)
                    print "Pausing %d seconds" % pause
                    time.sleep(pause)
                    continue
    
        if True == cache:
            cache_str = 'yes'
        else:
            cache_str = 'no'
    
        if vtrep['response_code'] == 0:
        	chk.write("%s\tunknown\t%s\n" % (md5,cache_str))
        elif vtrep['response_code'] == 1:
            #print vtrep
            if not vtrep.has_key('submission_names'):
                 if keywarning == False:
                     print 'Warning: your API key has no allinfo privileges, prevalence tests will not be executed.'
                 keywarning = True
                 if vtrep['positives'] > 0:
                     chk.write("%s\tpositives: %d\t%s\n" %(md5, vtrep['positives'],cache_str))
     	    elif vtrep['positives'] > 0:
    	         chk.write("%s\tpositives: %d\t%s\n" %(md5, vtrep['positives'], cache_str))
    	    elif len(vtrep['submission_names']) == 1 and vtrep['times_submitted'] < 10:
                 chk.write("%s\tsubmission names: %d\t%s\n" %(md5, len(vtrep['submission_names']),cache_str))
            elif len(vtrep['submission_names']) < 5 and vtrep.has_key('additional_info') and vtrep['additional_info'].has_key('sigcheck'):
                 if vtrep['additional_info']['sigcheck'].has_key("verified"):
                     if vtrep['additional_info']['sigcheck']['verified'] != "Signed":
                         chk.write("%s\tunverified and rare: %s\t%s \n" % (md5, len(vtrep['submission_names']), cache_str))
        else:
            print "WARNING: VirusTotal returned unknown response code"
        if cache == False:
            f = open(meta, "wb")
            f.write(json.dumps(response.json(), indent=4))
            f.close()
        chk.flush()
        #time.sleep(pause)

# main

chk = open("vt_checklist.txt", "w")
chk.write("MD5\treason\tcached\n")

parse_dsk()

chk.close()
