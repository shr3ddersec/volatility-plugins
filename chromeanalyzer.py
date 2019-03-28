"""
@author:      dthomas 
@license:     GNU General Public License 2.0 or later
"""

import volatility.plugins.chromehistory as chrome
import datetime
from requests import get
import csv,socket

class chromeanalyzer(chrome.ChromeVisits):

    def __init__(self, config, *args, **kwargs):
        chrome.ChromeVisits.__init__(self, config, *args,  **kwargs)

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Visit ID", "8"), ("URL ID", "6"), ("Visit Time", "26"), ("From Visit", "10"), ("Visit Duration", "13"), ("URL", "80"), ("Title", "80"), ("Visits", "6"), ("Typed", "5"),
         ("Last Visit Time", "26"),("ip","10"),("malicious","10")])

        for data1, data2 in chrome.ChromeVisits.calculate(self):
            if(len(data2)!= 0 and data2 !=None):
                if "www" not in str(data2[0].split('://')[1].split('/')[0]) and "docs" not in str(data2[0].split('://')[1].split('/')[0]):
                    try:
                        ip = socket.gethostbyname("www."+str(data2[0].split('://')[1].split('/')[0]))
                    except:
                        ip = socket.gethostbyname(str(data2[0].split('://')[1].split('/')[0]))
                        pass

                else:
                    try:
                        ip = socket.gethostbyname(str(data2[0].split('://')[1].split('/')[0]))
                    except:
                        pass

                new_url = "https://www.abuseipdb.com/check/"+str(ip)+"/json?key=[putyourkeyhere]&days=60"

                try:
                    response = get(new_url)
                    if(response.status_code==200 and len(response.json())>0):
                        # print "found one malicious ip\t", ip
                        ip_address= ip
                        ip_mal= 'True'
                    elif (response.status_code==200 and len(response.json())==0):
                        # print "not malicious ip\t", ip
                        ip_address= ip
                        ip_mal= 'False'
                    else:
                        # print "no response from webservice"
                        ip_address= ip
                        ip_mal= ''
                except Exception as e:
                    print e
                (visit_id, url_id, visit_time, from_visit, transition, segment_id, is_indexed, visit_duration) = data1
                (url, title, visit_count, typed_count, last_visit_time, hidden, favicon_id) = data2
                # print "ip\t",ip_address
                self.table_row(outfd, visit_id, url_id, str(visit_time), from_visit, visit_duration, url, title,
                visit_count,typed_count, str(last_visit_time),ip_address,str(ip_mal))
