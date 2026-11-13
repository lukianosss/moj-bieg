#!/usr/bin/env python3
"""Download Garmin Personal API data and encrypt before publishing. Stdlib + cryptography."""
import base64, datetime as dt, hashlib, json, os, secrets, urllib.request, urllib.parse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST='https://personal.connectapi.garmin.com'
KEY=os.environ['GARMIN_API_KEY'].strip()
PASSWORD=os.environ['SYNC_PASSWORD']
if len(PASSWORD)<16: raise SystemExit('SYNC_PASSWORD must have at least 16 characters')

def request(path, method='GET', token=None):
    headers={'Accept':'application/json'}
    headers['Authorization']=('Bearer '+token) if token else ('ApiKey '+KEY)
    req=urllib.request.Request(HOST+path,headers=headers,method=method)
    with urllib.request.urlopen(req,timeout=40) as r:
        return r.read().decode('utf-8').strip()

def get(path,token):
    return json.loads(request(path,token=token))

def num(x):
    try: return float(x) if x is not None else None
    except (ValueError,TypeError): return None

def first(*vals):
    return next((x for x in vals if x is not None),None)

def unpack(x):
    return x.get('data',x) if isinstance(x,dict) else x

def main():
    token=request('/personalapitoken-service/personal-api/personal-api-key/token','POST').strip('"')
    if not token: raise RuntimeError('Garmin did not return an access token')
    today=dt.date.today(); start=today-dt.timedelta(days=13)
    s,e=start.isoformat(),today.isoformat()
    days={(start+dt.timedelta(days=i)).isoformat():{'hrv':None,'sleep':None,'battery':None} for i in range(14)}
    errors=[]
    def safe(name,path):
        try:return unpack(get(path,token))
        except Exception as ex:
            errors.append(name+': '+str(ex));return None
    hrv=safe('hrv',f'/hrv-service/hrv/daily/{s}/{e}')
    if isinstance(hrv,dict):hrv=hrv.get('hrvSummaries',hrv.get('data',[]))
    if isinstance(hrv,list):
        for row in hrv:
            if not isinstance(row,dict):continue
            d=str(row.get('calendarDate',row.get('date','')))[:10]
            item=row.get('hrvSummary') or row
            if d in days and isinstance(item,dict):days[d]['hrv']=first(num(item.get('lastNightAvg')),num(item.get('weeklyAvg')))
    sleep=safe('sleep',f'/sleep-service/sleep/dailySleepSummariesByDate?startDate={s}&endDate={e}')
    if isinstance(sleep,dict):sleep=sleep.get('dailySleepSummaries',sleep.get('data',[]))
    if isinstance(sleep,list):
        for row in sleep:
            if not isinstance(row,dict):continue
            item=row.get('dailySleepDTO') or row
            if not isinstance(item,dict):continue
            d=str(first(item.get('calendarDate'),row.get('calendarDate'),row.get('date')) or '')[:10]
            seconds=first(num(item.get('sleepTimeSeconds')),num(item.get('totalSleepSeconds')))
            if seconds is None:
                vals=[num(item.get(k)) for k in ('deepSleepSeconds','lightSleepSeconds','remSleepSeconds')]
                if any(v is not None for v in vals):seconds=sum(v or 0 for v in vals)
            if d in days and seconds is not None:days[d]['sleep']=round(seconds/3600,2)
    battery=safe('battery',f'/wellness-service/wellness/bodyBattery/reports/daily?startDate={s}&endDate={e}')
    if isinstance(battery,dict):battery=battery.get('data',battery.get('reports',[]))
    if isinstance(battery,list):
        for row in battery:
            if not isinstance(row,dict):continue
            d=str(row.get('calendarDate',row.get('date','')))[:10]
            if d not in days:continue
            value=first(num(row.get('bodyBatteryMostRecentValue')),num(row.get('bodyBatteryHighestValue')),num(row.get('bodyBatteryValue')),num(row.get('value')))
            if value is not None:days[d]['battery']=value
    payload={'updated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'days':days}
    salt=secrets.token_bytes(16);nonce=secrets.token_bytes(12)
    aeskey=hashlib.pbkdf2_hmac('sha256',PASSWORD.encode(),salt,310000,dklen=32)
    encrypted=AESGCM(aeskey).encrypt(nonce,json.dumps(payload,separators=(',',':')).encode(),None)
    b64=lambda b:base64.b64encode(b).decode('ascii')
    with open('garmin-data.enc.json','w') as f:json.dump({'v':1,'alg':'AES-256-GCM','salt':b64(salt),'iv':b64(nonce),'data':b64(encrypted)},f)
    print('Encrypted Garmin data created. Nonfatal API errors:',errors)
    if not any(any(v is not None for v in day.values()) for day in days.values()):
        raise RuntimeError('No health values returned; refusing to publish empty data. Check API response structure.')
if __name__=='__main__':main()
