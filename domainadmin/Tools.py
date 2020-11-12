# import dnspython as dns
import dns.resolver

class Tools():
    def sendVerifyMail(id,verifyhash,mail):
        data = {}
        userid = current_user.id
        apiurl = "http://api:4006/api/v1/domainadmin/profile/sendverify/" + id + "/" + mail + "/" + verifyhash
        response = urllib.request.urlopen(apiurl)
        data = json.loads(response.read())
        return data

    def dnsARecord(domain):
        count=0
        records = {}
        result = dns.resolver.query(domain, 'A')
        for ipval in result:
            count=count+1
            records[count] = ipval.to_text()
        return records

    def dnsCnameRecord(domain):
        result = dns.resolver.query(domain, 'CNAME')
        for cnameval in result:
            print (' cname target address:', cnameval.target)

    def dnsMxRecord(domain):
        result = dns.resolver.query(domain, 'MX')
        for exdata in result:
            print (' MX Record:', exdata.exchange.text())

    def dnsNsRecord(domain):
        result = dns.resolver.query(domain, 'MX')
        for exdata in result:
            print (' NS Record:', exdata.exchange.text())
