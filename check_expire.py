import socket
import ssl
import datetime
import sys

domain = sys.argv[1]

def ssl_expiry_datetime(hostname):
    ssl_dateformat = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.settimeout(5.0)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_dateformat)

if __name__ == "__main__":
    now = datetime.datetime.now()
    try:
        expire = ssl_expiry_datetime(domain)
        diff = expire - now
        # print ("Domain name: {} Expiry Date: {} Expiry Day: {}".format(domain,expire.strftime("%Y-%m-%d"),diff.days))
        print ("Expiry Date: {} Expiry Day: {}".format(expire.strftime("%Y-%m-%d"),diff.days))
    except Exception as e:
        print (e)
