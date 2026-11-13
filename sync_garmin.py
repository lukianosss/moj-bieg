#!/usr/bin/env python3
"""Download Garmin Personal API health data and encrypt before publishing."""
import base64
import datetime as dt
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = 'https://personal.connectapi.garmin.com'
KEY = os.environ['GARMIN_API_KEY'].strip()
PASSWORD = os.environ['SYNC_PASSWORD']
if len(PASSWORD) < 16:
    raise SystemExit('SYNC_PASSWORD must have at least 16 characters')


def request(path, method='GET', token=None):
    # Token exchange can return text/plain rather than application/json.
    headers = {'Accept': 'application/json' if token else 'text/plain, */*'}
    headers['Authorization'] = ('Bearer ' + token) if token else ('ApiKey ' + KEY)
    req = urllib.request.Request(HOST + path, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            return response.read().decode('utf-8').strip()
    except urllib.error.HTTPError as exc:
        # Never log response bodies or auth headers; they might contain secrets.
        raise RuntimeError(f'Garmin HTTP {exc.code} while requesting {path.split("?")[0]}') from None


def get(path, token):
    return json.loads(request(path, token=token))


def num(x):
    try:
        return float(x) if x is not None else None
    except (ValueError, TypeError):
        return None


def first(*vals):
    return next((x for x in vals if x is not None), None)


def unpack(x):
    return x.get('data', x) if isinstance(x, dict) else x


def main():
    token = request('/personalapitoken-service/personal-api/personal-api-key/token', 'POST').strip('"')
    if not token:
        raise RuntimeError('Garmin did not return an access token')
    today = dt.date.today()
    start = today - dt.timedelta(days=13)
    s, e = start.isoformat(), today.isoformat()
    days = {(start + dt.timedelta(days=i)).isoformat(): {'hrv': None, 'sleep': None, 'battery': None} for i in range(14)}
    errors = []

    def safe(name, path):
        try:
            return unpack(get(path, token))
        except Exception as ex:
            errors.append(name + ': ' + str(ex))
            return None

    hrv = safe('hrv', f'/hrv-service/hrv/daily/{s}/{e}')
    if isinstance(hrv, dict):
        hrv = hrv.get('hrvSummaries', hrv.get('data', []))
    if isinstance(hrv, list):
        for row in hrv:
            if not isinstance(row, dict):
                continue
            d = str(row.get('calendarDate', row.get('date', '')))[:10]
            item = row.get('hrvSummary') or row
            if d in days and isinstance(item, dict):
                days[d]['hrv'] = first(num(item.get('lastNightAvg')), num(item.get('weeklyAvg')))

    sleep = safe('sleep', f'/sleep-service/sleep/dailySleepSummariesByDate?startDate={s}&endDate={e}')
    if isinstance(sleep, dict):
        sleep = sleep.get('dailySleepSummaries', sleep.get('data', []))
    if isinstance(sleep, list):
        for row in sleep:
            if not isinstance(row, dict):
                continue
            item = row.get('dailySleepDTO') or row
            if not isinstance(item, dict):
                continue
            d = str(first(item.get('calendarDate'), row.get('calendarDate'), row.get('date')) or '')[:10]
            seconds = first(num(item.get('sleepTimeSeconds')), num(item.get('totalSleepSeconds')))
            if seconds is None:
                vals = [num(item.get(k)) for k in ('deepSleepSeconds', 'lightSleepSeconds', 'remSleepSeconds')]
                if any(v is not None for v in vals):
                    seconds = sum(v or 0 for v in vals)
            if d in days and seconds is not None:
                days[d]['sleep'] = round(seconds / 3600, 2)

    battery = safe('battery', f'/wellness-service/wellness/bodyBattery/reports/daily?startDate={s}&endDate={e}')
    if isinstance(battery, dict):
        battery = battery.get('data', battery.get('reports', []))
    if isinstance(battery, list):
        for row in battery:
            if not isinstance(row, dict):
                continue
            d = str(row.get('calendarDate', row.get('date', '')))[:10]
            if d not in days:
                continue
            value = first(num(row.get('bodyBatteryMostRecentValue')), num(row.get('bodyBatteryHighestValue')), num(row.get('bodyBatteryValue')), num(row.get('value')))
            if value is not None:
                days[d]['battery'] = value

    # Activity list: returns activity summaries, distances in metres, duration in seconds.
    activities = []
    raw_activities = safe('activities', '/activitylist-service/activities/search/activities?start=0&limit=30')
    if isinstance(raw_activities, dict):
        raw_activities = raw_activities.get('activities', raw_activities.get('data', []))
    if isinstance(raw_activities, list):
        for row in raw_activities:
            if not isinstance(row, dict):
                continue
            kind = row.get('activityType') or {}
            kind = (kind.get('typeKey') or kind.get('typeId') or '') if isinstance(kind, dict) else str(kind)
            # Running activities only; exclude cycling/walking and other sports.
            if 'run' not in str(kind).lower():
                continue
            activity_id = row.get('activityId')
            date = row.get('startTimeGMT') or row.get('startTimeLocal')
            distance = num(row.get('distance'))
            duration = num(row.get('movingDuration')) or num(row.get('duration'))
            if not all([activity_id, date, distance, duration]):
                continue
            activities.append({'id': str(activity_id), 'date': str(date).replace(' ', 'T') + ('Z' if str(date).endswith('GMT') or row.get('startTimeGMT') else ''),
                               'distance': round(distance / 1000, 4), 'duration': duration,
                               'hr': num(row.get('averageHR')), 'name': str(row.get('activityName') or 'Bieg Garmin')[:120]})

    payload = {'updated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'days': days, 'activities': activities}
    if not any(any(v is not None for v in day.values()) for day in days.values()):
        raise RuntimeError('No health values returned; refusing to publish empty data. API errors: ' + '; '.join(errors))

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    aeskey = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), salt, 310000, dklen=32)
    encrypted = AESGCM(aeskey).encrypt(nonce, json.dumps(payload, separators=(',', ':')).encode(), None)
    b64 = lambda b: base64.b64encode(b).decode('ascii')
    with open('garmin-data.enc.json', 'w') as f:
        json.dump({'v': 1, 'alg': 'AES-256-GCM', 'salt': b64(salt), 'iv': b64(nonce), 'data': b64(encrypted)}, f)
    print('Encrypted Garmin data created. Nonfatal API errors:', errors)


if __name__ == '__main__':
    main()
