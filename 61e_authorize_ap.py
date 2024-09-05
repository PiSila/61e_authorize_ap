#!/usr/bin/python3

#########################################################
# #!/usr/bin/python3
# Script liest in allen Filialen die im Hostfile gelistet sind die 
# AP's, authorisiert neue AP's und setzt das AP Profil
# Lars Kähler
# 17.07.2024 
#########################################################

import requests, sys
import socket
import json
import os
import argparse
import time
from getpass import getpass
from datetime import datetime

today = datetime.now()
datum = today.strftime('-%d.%m.%Y-%H_%M_%S')


parser = argparse.ArgumentParser(prog='hostlist.txt lesen', epilog='Lars Kähler V000.1')
parser.add_argument("--vkst", "-v", help="Einzelne VKST über die CLI eingeben", action="store_true")
args = parser.parse_args()

## Log, json und hostfile
hostfile = os.path.dirname(__file__) +  "/hostlist.txt"
logfile = os.path.dirname(__file__) + "/ap-log"+ datum +".txt"

# Function api
def api(ip, profile, hostname):
    print("-")
    log.write("-" + "\n")
    URL='https://' + ip
    session = requests.session()
    # SSl Warnung ausschalten
    requests.packages.urllib3.disable_warnings() 

    try:
        # https Login um den Session Token im Cookie zu speichern
        res = session.post(URL + '/logincheck', data='username=' + user + '&secretkey=' + key, verify = False)
        if res.text.find('error') != -1:
            # Found some error in the response, consider login failed
            print(hostname + " - LOGIN fail")
            log.write(hostname + " - LOGIN fail" + "\n")
            sys.exit()
        #else:
            #print("")

        # Im Cookie stehen viele Token, für die Rest API wird nur der CSRF Token benötigt
        for cookie in session.cookies:
            if cookie.name.startswith('ccsrftoken_'):    
                # CSRF Token aus Liste lesen und speichern
                csrftoken = cookie.value[1:-1]
                # print("using crsftoken: %s" % csrftoken)
                # CSRF Token für das nächste https GET im Header speichern
                session.headers.update({'X-CSRFTOKEN': csrftoken})


        # Rest API GET, all AP Daten lesen
        res = session.get(URL + '/api/v2/monitor/wifi/managed_ap/select', verify=False)
        # Wenn AP's angeschlossen sind
        if len(res.json()['results']) > 0:
            for ap_index in range(len(res.json()['results'])):
                try:
                    # AP Seriennummer für das Profil holen
                    ap_ser = res.json()['results'][ap_index]['wtp_id']
 
                    # Wenn der AP im state discovered ist, ist er nicht autorisiert
                    print(hostname + " - " + res.json()['results'][ap_index]['wtp_id'] + " - " + res.json()['results'][ap_index]['state'] + " - " + res.json()['results'][ap_index]['ap_profile'])
                    log.write(hostname + " - " + res.json()['results'][ap_index]['wtp_id'] + " - " + res.json()['results'][ap_index]['state'] + " - " + res.json()['results'][ap_index]['ap_profile'] + "\n")
                    if not res.json()['results'][ap_index]['ap_profile'] == profile:

                        ### Payload AP Profile ###
                        payload_profile =  {
                            'wtp-profile': ''
                            ,
                            'radio-1': {
                            'band': ''
                            },
                            'radio-2': {
                            'band': ''
                            },
                            'radio-3': {
                            'band': ''
                            },
                            'radio-4': {
                            'band': ''
                            }
                        }

                        print(hostname + " - " + res.json()['results'][ap_index]['wtp_id'] + " - falsches Profile"  + " - " + res.json()['results'][ap_index]['ap_profile'])
                        log.write(hostname + " - " + res.json()['results'][ap_index]['wtp_id'] + " - falsches Profile"  + " - " + res.json()['results'][ap_index]['ap_profile'] + "\n")

                        # Payload Profile, Profile Namen eintragen
                        payload_profile['wtp-profile'] = profile
                                                
                        # Payload in JSON convertieren
                        payload_profile = json.dumps(payload_profile)
                        #print(payload_profile)

                        # AP Profile die Serinenummer zuweisen  
                        res_profile = session.put(URL + '/api/v2/cmdb/wireless-controller/wtp/' + ap_ser, data=payload_profile, verify=False)
                        # print(res_profile)

                        print(hostname + " - "  + res.json()['results'][ap_index]['wtp_id'] + " - " + "Status Read: " + res.json()['status'] +  ", Status Profile: " + res_profile.json()['status'])
                        log.write(hostname + " - "  + res.json()['results'][ap_index]['wtp_id'] + " - " + "Status Read: " + res.json()['status'] + ", Status Profile: " + res_profile.json()['status'] + "\n")

                    time.sleep(3)

                    if res.json()['results'][ap_index]['state'] == "discovered":

                        ### Payload AP Authorization ###
                        payload_auth = {
                            'wtpname': '',
                            'admin': ''
                        }

                        print(hostname + " - " + res.json()['results'][ap_index]['wtp_id'] + " - nicht authorisiert"  + " - " + res.json()['results'][ap_index]['ap_profile'])
                        log.write(hostname + " - " + res.json()['results'][ap_index]['wtp_id'] + " - nicht authorisiert"  + " - " + res.json()['results'][ap_index]['ap_profile'] + "\n")

                        # Payload Authorizierung SerNr. eintargen               
                        payload_auth['wtpname'] = res.json()['results'][ap_index]['wtp_id']
                        payload_auth['admin'] = 'enable'
                           
                        # Payload in JSON convertieren
                        payload_auth = json.dumps(payload_auth)
                        #print(payload_auth)

                        # admin = enable autorisiert den AP
                        res_auth = session.post(URL + '/api/v2/monitor/wifi/managed_ap/set_status', data=payload_auth, verify=False)

                        print(hostname + " - "  + res.json()['results'][ap_index]['wtp_id'] + " - " + "Status Read: " + res.json()['status'] + ", Status Auth: " + res_auth.json()['status'])
                        log.write(hostname + " - "  + res.json()['results'][ap_index]['wtp_id'] + " - " + "Status Read: " + res.json()['status'] + ", Status Auth: " + res_auth.json()['status'] + "\n")

                    # Ist das Profle richtig zugeordnet ?


                except Exception as e: 
                    print(e) 	


        # Logout 
        session.post(URL + '/logout', verify = False)
        session.close

    
    except requests.exceptions.ConnectionError as err:        
        return("offline")
   
          
         
    return()

# Start

user = input("Username:")
key = getpass("Password:")

# open Log File
try:
    log = open(logfile, "w") 
except IOError:
    print("Datei nicht gefunden:")    


if args.vkst:
    hostname = input("VKST:")
    profile = input("Profile:")
    ip = None 
    # Hostname DNS Auflösung
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        outstring_api = 'DNS Fehler'
        quit() 


    # IP Adresse OK? API Function starten
    if not ip is None:
        api(ip, profile, hostname)

else:
    # open Host File
    try:
        rollout = open(hostfile, "r")
    except IOError:
        print("Datei nicht gefunden:")    

    
    # Host File zeilenweise lesen 
    for hostnamelist in rollout:
        if not hostnamelist.startswith('#'):

            # Bei mehreren Parametern pro Zeile ; als Trenner
            csv = hostnamelist.split(";")
            hostname = csv[0]
            profile = csv[1]
            profile = profile.rstrip()
                
            ip = None

            # Hostname DNS Auflösung
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
               print('DNS Fehler')
               ip = '0.0.0.0'
    
          
            # IP Adresse OK? API Function starten
            if not ip is None:
                api(ip, profile, hostname)
            
    rollout.close()
log.close()

