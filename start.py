import os
import sys
import socket
import json
import smtplib
import time
from email.mime.text import MIMEText
from email.header import Header
import requests

def log(msg):
    msg = '[{}]{}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), msg)
    print(msg)
    with open(config['log'], 'a', encoding='utf-8') as log_f:
        log_f.write(msg + '\n')

ua = 'Py DDNS for DNSPod/0.0.1(lkmcfjmic@outlook.com)'
headers = {
    'User-Agent': ua,
    'Content-Type': 'application/x-www-form-urlencoded'
}
def access_api(uri, data):
    url = 'https://dnsapi.cn' + uri
    data['login_token'] = config['token']
    data['format'] = 'json'
    data['error_on_empty'] = 'no'
    r = requests.post(url, data=data, headers=headers)
    if not r.ok:
        raise Exception('HTTP request failed on DNSPod API ' + uri)
    r = r.json()
    if r['status']['code'] != '1':
        raise Exception('DNSPod API {} error: {}'.format(uri, json.dumps(r['status'], ensure_ascii=False)))
    return r

def dns_resolve_list(domain):
    return [i[4][0] for i in socket.getaddrinfo(domain, None)]

def internet_ok():
    try:
        requests.get(config['internet_test_url'])
        return True
    except:
        return False

def send_warning_email(error_message):
    email_conf = config['email']
    message = MIMEText(email_conf['content'].replace('<msg>', error_message), 'plain', 'utf-8')
    message['From'] = Header(email_conf['sender_name'], 'utf-8')
    message['To'] = Header(email_conf['receiver_name'], 'utf-8')
    message['Subject'] = Header(email_conf['title'], 'utf-8')
    if email_conf['ssl']:
        with smtplib.SMTP_SSL(email_conf['server'], email_conf['port']) as smtp:
            smtp.login(email_conf['from'], email_conf['token'])
            smtp.sendmail(email_conf['from'], email_conf['to'], message.as_bytes())
    else:
        with smtplib.SMTP(email_conf['server'], email_conf['port']) as smtp:
            smtp.login(email_conf['from'], email_conf['token'])
            smtp.sendmail(email_conf['from'], email_conf['to'], message.as_bytes())

cur_ip = None
def my_ip(remain=10):
    try:
        r = requests.get('http://ip.42.pl/anything')
        if not r.ok:
            raise Exception('HTTP request failed on http://ip.42.pl/anything')
        return r.text
    except:
        if remain > 0:
            return my_ip(remain - 1)
        else:
            raise

records = []
# list of dict with keys: record_id, domain, subdomain, line

def update_record(record, ip):
    log('update record: {}.{}, id={}, line={}, value={}'.format(
        record['subdomain'], record['domain'], record['record_id'], record['line'], ip
    ))
    access_api('/Record.Ddns', {
        'domain': record['domain'],
        'record_id': record['record_id'],
        'sub_domain': record['subdomain'],
        'record_line': record['line'],
        'value': ip
    })

def init():
    global cur_ip, records, config
    cur_ip = my_ip()
    for domain in config['domains']:
        record_list = access_api('/Record.List', {
            'domain': domain['domain'],
            'sub_domain': domain['subdomain'],
            'record_type': 'A'
        })
        record_list = record_list['records']
        for record in record_list:
            cur = {
                'record_id': record['id'],
                'domain': domain['domain'],
                'subdomain': domain['subdomain'],
                'line': record['line']
            }
            records.append(cur)
            if record['value'] != cur_ip:
                update_record(cur, cur_ip)
    log('Initialized.')
    log(json.dumps(records, ensure_ascii=False, indent=4))

def update(ip):
    global records
    for record in records:
        update_record(record, ip)

def loop():
    global cur_ip, config
    try:
        while True:
            time.sleep(config['period'])
            new_ip = my_ip()
            if new_ip != cur_ip:
                log('IP change: {} --> {}'.format(cur_ip, new_ip))
                update(new_ip)
                cur_ip = new_ip
            else:
                log('IP not changed')
    except:
        error_message = str(sys.exc_info()[0]) + str(sys.exc_info()[1])
        log(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + ': ' + error_message)
        if internet_ok():
            log('Internet OK, sending email')
            send_warning_email(error_message)
            sys.exit(1)
        else:
            log('Bad network, retry after {} seconds'.format(config['period']))
            loop()

if __name__ == '__main__':
    with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'config.json'), 'r', encoding='utf-8') as config_f:
        config = json.load(config_f)
    while not internet_ok():
        time.sleep(30)
    init()
    loop()
        
