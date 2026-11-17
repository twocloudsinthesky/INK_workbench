#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
import base64
import getpass
import sys
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from contextlib import closing

os.umask(0o077)
ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('WORKBENCH_DATA_DIR',ROOT)) / 'workbench.sqlite3'
DB.parent.mkdir(parents=True,exist_ok=True)
PORT = int(os.environ.get('MOSHUI_PORT', '8765'))
HOST = os.environ.get('MOSHUI_HOST', '127.0.0.1')
SESSIONS = {}
REQUIRE_INVITES = True

def connect():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    return db

with closing(connect()) as db:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS config (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY, member TEXT NOT NULL, kind TEXT NOT NULL,
            ids TEXT NOT NULL, proof TEXT, status TEXT NOT NULL DEFAULT '待审核',
            created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL,
            ids TEXT NOT NULL, status TEXT NOT NULL DEFAULT '待接单',
            created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, seen INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS invites (member TEXT PRIMARY KEY, code TEXT NOT NULL);
        INSERT OR IGNORE INTO config VALUES ('rows','[]'), ('revision','0');
    """)
    if 'volume_ml' not in {r['name'] for r in db.execute('PRAGMA table_info(transfers)')}:
        db.execute('ALTER TABLE transfers ADD COLUMN volume_ml REAL')
    if 'expected' not in {r['name'] for r in db.execute('PRAGMA table_info(requests)')}:
        db.execute('ALTER TABLE requests ADD COLUMN expected INTEGER')
    if not db.execute("SELECT 1 FROM config WHERE name='password'").fetchone():
        password=os.environ.get('WORKBENCH_ADMIN_PASSWORD')
        code=os.environ.get('WORKBENCH_GROUP_CODE')
        if sys.stdin.isatty():
            password=password or getpass.getpass('设置管理员密码（至少 12 字符）：')
            code=code or getpass.getpass('设置群访问码（至少 8 字符）：')
        if not password or len(password)<12 or not code or len(code)<8 or password==code:
            raise SystemExit('首次启动需要设置不同的管理员密码（至少 12 字符）和群访问码（至少 8 字符）。')
        salt=secrets.token_hex(16)
        digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600000).hex()
        db.executemany('INSERT INTO config VALUES (?,?)',[('salt',salt),('password',digest),('group_access_code',code)])
    db.commit()

def row_volume(row):
    return row.get('volumeMl',(row.get('ml') or 0)*row['qty'])

def billing_holder(row,holders):
    return row.get('billingHolder',holders.get(row['id'],row['member']))

def normalize_default_containers(rows, holders):
    groups = {}
    for row in rows:
        if row.get('billingSource'):
            continue
        key = (row['group'], row['member'], billing_holder(row,holders))
        groups.setdefault(key, []).append(row)
    for records in groups.values():
        automatic = []
        for row in records:
            counts = row.get('containers') or {}
            active = {k:v for k,v in counts.items() if v}
            expected = {k:1 for k, flag in (('tube','defaultTube'),('glass','defaultGlass')) if row.get(flag)}
            if expected and active == expected:
                automatic.append(row)
        if not automatic or any(row.get('wantsBottle') for row in records):
            continue
        if any(row not in automatic and (row.get('containers') is not None or row.get('fee')) for row in records):
            continue
        volume = sum(row.get('billingVolume',row_volume(row)) for row in records)
        if volume not in (10,15) and not (0<volume<10):
            continue
        use_glass = volume in (10,15)
        use_tube = volume!=10
        automatic[0]['containers'] = {kind:1 for kind,used in (('glass',use_glass),('tube',use_tube)) if used}
        automatic[0]['defaultGlass'] = use_glass
        automatic[0]['defaultTube'] = use_tube
        for row in automatic[1:]:
            row.pop('containers',None)
            row.pop('defaultGlass',None)
            row.pop('defaultTube',None)

def charges(rows, holders=None):
    holders = holders or {}
    costs, defaults = {}, {}
    for row in rows:
        group, member, row_id = row['group'], row['member'], row['id']
        counts = row.get('containers')
        cost = 30*counts.get('tube',0)+70*counts.get('glass',0) if counts is not None else row.get('fee',0)
        costs[row_id] = cost
        if not ((row.get('defaultTube') and cost==30) or (row.get('defaultGlass') and cost==70) or (row.get('defaultGlass') and row.get('defaultTube') and cost==100)):
            continue
        key = (group,member,billing_holder(row,holders))
        previous = defaults.get(key)
        if previous is None or cost>costs[previous]:
            if previous is not None:
                costs[previous] = 0
            defaults[key] = row_id
        else:
            costs[row_id] = 0
    pools, payers, fees = {}, {}, costs.copy()
    for row in rows:
        group, member = row['group'], row['member']
        pools[group] = pools.get(group,0) + costs[row['id']]
        if row.get('wantsBottle'):
            payers.setdefault(group,{}).setdefault(member,row['id'])
    for row in rows:
        if row['group'] in payers:
            fees.pop(row['id'],None)
    for group, members in payers.items():
        share, remainder = divmod(pools[group],len(members))
        for index, row_id in enumerate(members.values()):
            fees[row_id] = share + (index < remainder)
    return fees

def amount(row, fees):
    return row.get('manualAmount',row.get('qty',0)*row.get('price',0)+fees.get(row['id'],0))

def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000).hex()

def get_config(db, name):
    result = db.execute('SELECT value FROM config WHERE name=?', (name,)).fetchone()
    return result[0] if result else None

class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message

class Handler(BaseHTTPRequestHandler):
    def reply(self, data, status=200, cookie=None, content='application/json; charset=utf-8'):
        payload = json.dumps(data, ensure_ascii=False).encode() if content.startswith('application/json') else data
        self.send_response(status)
        self.send_header('Content-Type', content)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        if cookie is not None:
            self.send_header('Set-Cookie', 'moshui='+cookie+'; Path=/; HttpOnly; SameSite=Strict'+('; Secure' if self.headers.get('X-Forwarded-Proto')=='https' else '')+('; Max-Age=0' if not cookie else ''))
        self.end_headers()
        self.wfile.write(payload)

    def session(self):
        from http.cookies import SimpleCookie
        cookie = SimpleCookie(self.headers.get('Cookie','')).get('moshui')
        token = cookie.value if cookie else ''
        return token, SESSIONS.get(token, ('',''))

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)

    def handle_request(self, write):
        try:
            path = urlsplit(self.path).path
            token, (role, member) = self.session()
            data = {}
            if write:
                host = self.headers.get('Host', '')
                origin = self.headers.get('Origin', '')
                if origin and origin not in ('http://'+host,'https://'+host):
                    raise APIError(403,'请求来源无效。')
                if self.headers.get('Content-Type','').split(';')[0] != 'application/json':
                    raise APIError(415,'请求格式无效。')
                size = int(self.headers.get('Content-Length',0))
                if size < 1 or size > 4_500_000:
                    raise APIError(413,'请求过大或为空。')
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise APIError(400,'请求格式无效。')
            if not write and path in ('/','/admin','/member'):
                if path=='/admin' and role!='admin':
                    self.send_response(303)
                    self.send_header('Location','/#admin')
                    self.end_headers()
                    return
                page = 'admin.html' if path=='/admin' else '入口.html'
                return self.reply((ROOT/page).read_bytes(),content='text/html; charset=utf-8')
            with closing(connect()) as db:
                if write:
                    db.execute('BEGIN IMMEDIATE')
                result, cookie = self.route(db,path,write,data,token,role,member)
                db.commit()
            self.reply(result,cookie=cookie)
        except APIError as e:
            self.reply({'error':e.message},e.status)
        except (ValueError, TypeError, KeyError, AttributeError):
            self.reply({'error':'请求格式无效。'},400)

    def route(self,db,path,write,data,token,role,member):
        salt = get_config(db,'salt')
        if path=='/api/branding':
            branding=json.loads(get_config(db,'branding') or '{"name":"拼谷工作台","avatar":""}')
            if write:
                if role!='admin':
                    raise APIError(403,'请先登录管理端。')
                name=data.get('name','').strip()
                avatar=data.get('avatar','')
                if not 1<=len(name)<=24 or len(avatar)>400000:
                    raise APIError(400,'团名须为 1～24 字符，头像文件须小于 280 KB。')
                if avatar:
                    prefix,_,encoded=avatar.partition(',')
                    signatures={'data:image/png;base64':b'\x89PNG\r\n\x1a\n','data:image/jpeg;base64':b'\xff\xd8\xff'}
                    try:
                        valid=prefix in signatures and base64.b64decode(encoded,validate=True).startswith(signatures[prefix])
                    except ValueError:
                        valid=False
                    if not valid:
                        raise APIError(400,'请选择 PNG 或 JPG 头像。')
                branding={'name':name,'avatar':avatar}
                db.execute("INSERT OR REPLACE INTO config VALUES (?,?)",('branding',json.dumps(branding,ensure_ascii=False)))
            return branding,None
        if path=='/api/session' and not write:
            return {'role':role,'member':member,'inviteRequired':REQUIRE_INVITES},None
        if path=='/api/login' and write:
            password=data.get('secret','')
            if not isinstance(password,str) or len(password)>256:
                raise APIError(400,'登录信息无效。')
            kind=data.get('role')
            name=''
            if kind=='admin':
                if not hmac.compare_digest(password_hash(password,salt),get_config(db,'password')):
                    raise APIError(401,'管理员密码错误。')
            elif kind=='member':
                name=password.strip()
                orders=json.loads(get_config(db,'rows'))
                real_orders=[r for r in orders if not r.get('demo')]
                if not any(r['member']==name for r in real_orders):
                    raise APIError(401,'查不到这个昵称，请先导入排表，再输入表里的完整昵称。')
                if REQUIRE_INVITES:
                    supplied=data.get('invite','')
                    code=get_config(db,'group_access_code')
                    if not isinstance(supplied,str) or not code or not hmac.compare_digest(supplied.strip().encode(),code.encode()):
                        raise APIError(401,'昵称或群访问码有误。')
            else:
                raise APIError(400,'入口无效。')
            SESSIONS.pop(token,None)
            new=secrets.token_urlsafe(32)
            SESSIONS[new]=(kind,name)
            return {'role':kind},new
        if path=='/api/logout' and write:
            SESSIONS.pop(token,None)
            return {},''
        if path.startswith('/api/admin/') and role!='admin':
            raise APIError(403,'请先登录管理端。')
        if path.startswith('/api/member/') and role!='member':
            raise APIError(403,'请从团员入口输入昵称。')
        rows=json.loads(get_config(db,'rows'))
        by_id={r['id']:r for r in rows}
        for row in rows:
            if row.get('billingSource') in by_id:
                row['paid']=by_id[row['billingSource']]['paid']
        holders=self.holders(db)
        normalize_default_containers(rows,holders)
        fees=charges(rows,holders)
        schedules=json.loads(get_config(db,'schedules') or '{}')
        cancelled=set(json.loads(get_config(db,'cancelled_inks') or '[]'))
        for row in rows:
            row['cancelled']=row['group'] in cancelled
        if path=='/api/admin/cancel-ink' and write:
            group=data.get('group')
            cancel=data.get('cancelled')
            if type(cancel) is not bool or not any(r['group']==group for r in rows):
                raise APIError(400,'请选择有效的墨水。')
            cancelled.add(group) if cancel else cancelled.discard(group)
            db.execute("INSERT OR REPLACE INTO config VALUES (?,?)",('cancelled_inks',json.dumps(sorted(cancelled),ensure_ascii=False)))
            db.execute("UPDATE config SET value=CAST(value AS INTEGER)+1 WHERE name='revision'")
            return {},None
        if path=='/api/admin/schedules':
            if write:
                group=data.get('group')
                dates=data.get('dates')
                keys={'opened','deadline','ready'}
                if not any(r['group']==group for r in rows) or not isinstance(dates,dict) or set(dates) not in (keys,keys|{'shipping'}):
                    raise APIError(400,'请选择已导入的墨水并填写时间。')
                for value in dates.values():
                    if not isinstance(value,str) or (value and datetime.strptime(value,'%Y-%m-%dT%H:%M').isoformat(timespec='minutes')!=value):
                        raise APIError(400,'时间格式无效。')
                if dates['opened'] and dates['deadline'] and dates['deadline']<dates['opened']:
                    raise APIError(400,'交肾截止时间须在成团时间之后。')
                if dates['ready'] and dates.get('shipping') and dates['shipping']<dates['ready']:
                    raise APIError(400,'预计发货时间须在可排发时间之后。')
                note=data.get('note',schedules.get(group,{}).get('note',''))
                if not isinstance(note,str) or len(note)>500:
                    raise APIError(400,'墨水备注最多 500 个字符。')
                schedules[group]={**({'shipping':schedules.get(group,{}).get('shipping','')}),**dates,**({'note':note.strip()} if note.strip() else {})}
                db.execute("INSERT OR REPLACE INTO config VALUES ('schedules',?)",(json.dumps(schedules,ensure_ascii=False),))
            return {'schedules':schedules},None
        if path=='/api/admin/batch' and write:
            action=data.get('action')
            scope=data.get('scope')
            by_ink=data.get('byInk') is True or action=='arrived'
            if action not in ('paid','queued','arrived') or not isinstance(scope,str) or not scope:
                raise APIError(400,'请选择操作和对象。')
            pending={i for t in self.transfers(db) if t['status']=='待接单' for i in t['ids']} if action=='queued' else set()
            targets=[]
            skipped=0
            for row in rows:
                name=row['group'] if by_ink else holders.get(row['id'],row['member']) if action=='queued' else row['member']
                if name!=scope or row.get('demo') or row.get('cancelled'):
                    continue
                if action=='queued':
                    eligible=row['paid'] and row['arrived'] and not row['ship'] and row['id'] not in pending
                else:
                    eligible=not row[action]
                if eligible:
                    targets.append(row)
                else:
                    skipped+=1
            ids=sorted(row['id'] for row in targets)
            revision=int(get_config(db,'revision'))
            preview={'ids':ids,'revision':revision,'skipped':skipped,'amount':sum(amount(row,fees) for row in targets)}
            if 'ids' not in data:
                return preview,None
            if not ids or data['ids']!=ids or data.get('revision')!=revision:
                raise APIError(409,'明细已变化，请重新预览后确认。')
            arrived_at=datetime.now(timezone.utc).isoformat(timespec='seconds')
            for row in targets:
                if action=='arrived':
                    row['arrivedAt']=arrived_at
                if action=='queued':
                    row['ship']=1
                else:
                    row[action]=True
            db.execute("UPDATE config SET value=? WHERE name='rows'",(json.dumps(rows,ensure_ascii=False),))
            db.execute("UPDATE config SET value=? WHERE name='revision'",(str(revision+1),))
            return {'count':len(ids)},None
        if path=='/api/admin/delete-rows' and write:
            revision=int(get_config(db,'revision'))
            ids=data.get('ids')
            if not isinstance(ids,list) or not ids or any(not isinstance(i,str) for i in ids):
                raise APIError(400,'请勾选要删除的明细。')
            selected=set(ids)
            if data.get('revision')!=revision or not selected.issubset({r['id'] for r in rows}):
                raise APIError(409,'明细已变化，请刷新后重新勾选。')
            if any(r.get('billingSource') in selected for r in rows) or any(selected.intersection(t['ids']) and t['status'] in ('待接单','已接单') for t in self.transfers(db)):
                raise APIError(409,'所选明细有相关转单，请先处理转单。')
            if any(selected.intersection(r['ids']) and r['status']=='待审核' for r in self.requests(db)):
                raise APIError(409,'所选明细有待审核申请，请先处理。')
            remaining=[r for r in rows if r['id'] not in selected]
            db.execute("UPDATE config SET value=? WHERE name='rows'",(json.dumps(remaining,ensure_ascii=False),))
            db.execute("UPDATE config SET value=? WHERE name='revision'",(str(revision+1),))
            return {'count':len(selected),'rows':remaining,'revision':revision+1},None
        if path=='/api/admin/reprice' and write:
            group=data.get('group')
            cents=data.get('cents')
            capacity=data.get('capacity')
            if type(cents) is not int or not 0<=cents<=999999999 or type(capacity) not in (int,float) or not 0<capacity<=1000000:
                raise APIError(400,'请输入有效的整瓶价格和容量。')
            from decimal import Decimal, ROUND_HALF_UP
            revision=int(get_config(db,'revision'))
            targets=[r for r in rows if r['group']==group and not r.get('billingSource') and r.get('ml',0)>0]
            if not targets:
                raise APIError(400,'该墨水没有可改价的分装明细。')
            rate=Decimal(cents)/Decimal(str(capacity))
            changes=[(r,int((rate*Decimal(str(r['ml']))).quantize(Decimal('1'),rounding=ROUND_HALF_UP))) for r in targets if 'manualAmount' not in r]
            if not changes:
                raise APIError(400,'该墨水的应收均为手动金额。')
            summary={'revision':revision,'count':len(changes),'manual':len(targets)-len(changes),
                     'old':sum(amount(r,fees) for r,_ in changes),
                     'new':sum(r['qty']*price+fees.get(r['id'],0) for r,price in changes),
                     'paidDelta':sum(r['qty']*(r['price']-price) for r,price in changes if r['paid'])}
            if 'revision' not in data:
                return summary,None
            if data['revision']!=revision:
                raise APIError(409,'明细已变化，请重新预览。')
            for row,price in changes:
                row['price']=price
                row['bottlePricing']={'cents':cents,'capacity':capacity}
            db.execute("UPDATE config SET value=? WHERE name='rows'",(json.dumps(rows,ensure_ascii=False),))
            db.execute("UPDATE config SET value=? WHERE name='revision'",(str(revision+1),))
            return summary,None
        if path=='/api/admin/rows':
            revision=int(get_config(db,'revision'))
            excluded=json.loads(get_config(db,'excluded_members') or '[]')
            if not write:
                return {'rows':rows,'revision':revision,'excluded':excluded},None
            if data.get('revision')!=revision:
                raise APIError(409,'记录已被其他管理员更新。请刷新后重试。')
            updates=data['rows']
            if isinstance(updates,list):
                updates=[r for r in updates if not isinstance(r,dict) or not r.get('demo')]
            if not isinstance(updates,list) or any(not isinstance(r,dict) or not isinstance(r.get('group'),str) or not isinstance(r.get('member'),str) or not isinstance(r.get('id'),str) for r in updates):
                raise APIError(400,'记录格式无效。')
            if any('volumeMl' in r and (type(r['volumeMl']) not in (int,float) or not 0<r['volumeMl']<=1000000 or round(r['volumeMl'],3)!=r['volumeMl']) for r in updates):
                raise APIError(400,'毫升数须大于 0 且最多三位小数。')
            if any('manualAmount' in r and (type(r['manualAmount']) is not int or not 0<=r['manualAmount']<=999999999) for r in updates):
                raise APIError(400,'手动应收金额无效。')
            if len({r['id'] for r in updates})!=len(updates):
                raise APIError(400,'记录有重复。')
            change=data.get('membership')
            if change is not None:
                pair=[change.get('group'),change.get('member')]
                if not all(isinstance(v,str) and v for v in pair):
                    raise APIError(400,'请选择墨水和团员。')
                matches=lambda r: [r['group'],r['member']]==pair
                if change.get('remove'):
                    removed=[r for r in rows if matches(r)]
                    if not removed or any(matches(r) for r in updates):
                        raise APIError(409,'团员明细已变化。')
                    ids={r['id'] for r in removed}
                    if any(r.get('billingSource') in ids for r in rows) or any(ids.intersection(t['ids']) and t['status'] in ('待接单','已接单') for t in self.transfers(db)):
                        raise APIError(409,'该团员有相关转单，请先处理转单。')
                    if any(ids.intersection(r['ids']) and r['status']=='待审核' for r in self.requests(db)):
                        raise APIError(409,'该团员有待审核申请，请先处理。')
                    if pair not in excluded:
                        excluded.append(pair)
                elif pair in excluded:
                    excluded.remove(pair)
                db.execute("INSERT OR REPLACE INTO config VALUES ('excluded_members',?)",(json.dumps(excluded,ensure_ascii=False),))
            previous={row['id']:row for row in rows}
            arrived_at=datetime.now(timezone.utc).isoformat(timespec='seconds')
            for row in updates:
                old=previous.get(row['id'])
                if not row.get('arrived'):
                    row.pop('arrivedAt',None)
                elif old is not None and not old.get('arrived'):
                    row['arrivedAt']=arrived_at
                elif old and old.get('arrivedAt'):
                    row['arrivedAt']=old['arrivedAt']
            if data.get('imported') is True:
                previous_groups={row['group'] for row in rows}
                created_groups={row['group'] for row in updates}-previous_groups
                if created_groups:
                    now=datetime.now(timezone(timedelta(hours=8))).replace(tzinfo=None)
                    for group in created_groups:
                        dates=schedules.setdefault(group,{})
                        if not dates.get('opened'):
                            dates['opened']=now.isoformat(timespec='minutes')
                        if not dates.get('deadline'):
                            formed=datetime.fromisoformat(dates['opened'])
                            dates['deadline']=(formed+timedelta(days=3)).isoformat(timespec='minutes')
                    db.execute("INSERT OR REPLACE INTO config VALUES ('schedules',?)",(json.dumps(schedules,ensure_ascii=False),))
            normalize_default_containers(updates,holders)
            db.execute("UPDATE config SET value=? WHERE name='rows'",(json.dumps(updates,ensure_ascii=False),))
            db.execute("UPDATE config SET value=? WHERE name='revision'",(str(revision+1),))
            return {'revision':revision+1,'excluded':excluded,'rows':updates,'schedules':schedules},None
        if path in ('/api/admin/transfers','/api/member/transfers'):
            if write:
                raise APIError(405,'此入口仅供查询。')
            transfers=self.transfers(db)
            visible=transfers if role=='admin' else [t for t in transfers if member in (t['sender'],t['recipient'])]
            by_id={r['id']:r for r in rows}
            for transfer in visible:
                transfer['items']=[{k:by_id[i].get(k) for k in ('group','item','qty')} for i in transfer['ids'] if i in by_id]
            return {'transfers':visible},None
        if path=='/api/admin/transfer-seen' and write:
            db.execute("UPDATE transfers SET seen=1 WHERE id=? AND status='已接单'",(data['id'],))
            return {},None
        if path=='/api/member/transfer' and write:
            recipient=data.get('recipient','').strip()
            ids=data.get('ids')
            if not recipient or recipient==member or not any(r['member']==recipient and not r.get('demo') for r in rows):
                raise APIError(400,'请输入另一位已登记团员的完整昵称。')
            if not isinstance(ids,list) or not ids or any(not isinstance(i,str) for i in ids) or len(ids)!=len(set(ids)):
                raise APIError(400,'请选择要转出的明细。')
            self.check_transfer(db,rows,member,ids)
            volume=data.get('volumeMl')
            if volume is not None and (len(ids)!=1 or type(volume) not in (int,float) or not 0<volume<=row_volume(by_id[ids[0]]) or round(volume,3)!=volume):
                raise APIError(400,'转让毫升数须大于 0、最多三位小数，且不能超过所选明细的剩余量。')
            if any(t['status']=='待接单' and set(ids).intersection(t['ids']) for t in self.transfers(db)):
                raise APIError(409,'部分明细已有待确认的转单。')
            db.execute('INSERT INTO transfers(sender,recipient,ids,volume_ml) VALUES (?,?,?,?)',(member,recipient,json.dumps(ids),volume))
            return {},None
        if path=='/api/member/transfer-response' and write:
            transfer=db.execute('SELECT * FROM transfers WHERE id=?',(data['id'],)).fetchone()
            action=data.get('action')
            if not transfer or transfer['status']!='待接单':
                raise APIError(409,'转单已处理或不存在。')
            if not ((action=='cancel' and transfer['sender']==member) or (action in ('accept','reject') and transfer['recipient']==member)):
                raise APIError(403,'你无权处理这条转单。')
            if action=='accept':
                self.check_transfer(db,rows,transfer['sender'],json.loads(transfer['ids']))
                ids=json.loads(transfer['ids'])
                for row_id in ids:
                    original=by_id[row_id]
                    original.setdefault('billingHolder',holders.get(row_id,original['member']))
                volume=transfer['volume_ml']
                if volume is not None:
                    original=by_id[ids[0]]
                    available=row_volume(original)
                    if volume>available:
                        raise APIError(409,'剩余毫升数已变化，请重新发起转单。')
                    if volume<available:
                        original.setdefault('billingVolume',available)
                        original['volumeMl']=round(available-volume,3)
                        part={k:original[k] for k in ('group','member','paid','arrived','arrivedAt','handoff') if k in original}
                        part.update(id='transfer-'+str(transfer['id']),item=f'{volume:g} ml',qty=1,ml=volume,price=0,
                                    billingSource=original.get('billingSource',original['id']),ship=0,tracking='')
                        rows.append(part)
                        db.execute('UPDATE transfers SET ids=? WHERE id=?',(json.dumps([part['id']]),transfer['id']))
                revision=int(get_config(db,'revision'))+1
                db.execute("UPDATE config SET value=? WHERE name='rows'",(json.dumps(rows,ensure_ascii=False),))
                db.execute("UPDATE config SET value=? WHERE name='revision'",(str(revision),))
            db.execute('UPDATE transfers SET status=? WHERE id=?',({'cancel':'已撤回','accept':'已接单','reject':'已拒绝'}[action],transfer['id']))
            return {},None
        if path=='/api/admin/pending-count' and not write:
            count=db.execute("SELECT COUNT(*) FROM requests WHERE kind='proof' AND status='待审核'").fetchone()[0]
            return {'count':count},None
        if path=='/api/admin/requests' and not write:
            return {'requests':self.requests(db)},None
        if path=='/api/admin/review' and write:
            record=db.execute('SELECT * FROM requests WHERE id=?',(data['id'],)).fetchone()
            if not record or record['status']!='待审核':
                raise APIError(409,'这条申请已处理或不存在。')
            action=data.get('action')
            if action not in ('approve','reject'):
                raise APIError(400,'审核操作无效。')
            if action=='approve':
                ids=set(json.loads(record['ids']))
                targets=[r for r in rows if r['id'] in ids and (holders.get(r['id'],r['member']) if record['kind']=='ship' else r['member'])==record['member'] and not r.get('demo')]
                if not targets or len(targets)!=len(ids) or any(not self.eligible(r,record['kind']) for r in targets):
                    raise APIError(409,'所选明细状态已变化，请核对后处理。')
                if record['kind']=='proof' and record['expected'] is not None and sum(amount(row,fees) for row in targets)!=record['expected']:
                    raise APIError(409,'应收金额已变化。请核对后退回申请，让团员按新金额重新提交。')
                for r in targets:
                    if record['kind']=='proof':
                        r['paid']=True
                    else:
                        r['ship']=1
                revision=int(get_config(db,'revision'))+1
                db.execute("UPDATE config SET value=? WHERE name='rows'",(json.dumps(rows,ensure_ascii=False),))
                db.execute("UPDATE config SET value=? WHERE name='revision'",(str(revision),))
            db.execute('UPDATE requests SET status=? WHERE id=?',('已通过' if action=='approve' else '已退回',record['id']))
            return {},None
        if path=='/api/member/rows' and not write:
            own=[]
            for r in rows:
                holder=holders.get(r['id'],r['member'])
                if not r.get('demo') and (member==holder or (member==r['member'] and not r.get('billingSource'))):
                    own.append({**r,'chargedFee':fees.get(r['id'],0),'ownedVolumeMl':row_volume(r) if holder==member else 0,'fulfillmentMember':holder,'canProof':r['member']==member and not r.get('billingSource'),'canShip':holder==member})
            dates={g:schedules[g] for g in {r['group'] for r in own} if g in schedules}
            return {'rows':own,'requests':self.requests(db,member),'schedules':dates},None
        if path=='/api/member/request' and write:
            kind=data.get('kind')
            ids=data.get('ids')
            if kind=='proof':
                raise APIError(403,'工作台已关闭团员付款确认，请按群公告交肾。')
            if kind!='ship' or not isinstance(ids,list) or not ids or any(not isinstance(i,str) for i in ids) or len(ids)!=len(set(ids)):
                raise APIError(400,'请选择要提交的明细。')
            targets=[r for r in rows if r['id'] in ids and (holders.get(r['id'],r['member']) if kind=='ship' else r['member'])==member and not r.get('demo') and (kind=='ship' or not r.get('billingSource'))]
            if len(targets)!=len(ids) or any(not self.eligible(r,kind) for r in targets):
                raise APIError(409,'部分明细不符合条件，请刷新后重选。')
            if kind=='ship' and any(t['status']=='待接单' and set(ids).intersection(t['ids']) for t in self.transfers(db)):
                raise APIError(409,'待确认的转单须先处理，再申请发货。')
            if any(r['kind']==kind and r['status']=='待审核' and set(r['ids']).intersection(ids) for r in self.requests(db,member)):
                raise APIError(409,'部分明细已有待审核申请。')
            expected=sum(amount(row,fees) for row in targets) if kind=='proof' else None
            db.execute('INSERT INTO requests(member,kind,ids,expected) VALUES (?,?,?,?)',(member,kind,json.dumps(ids),expected))
            return {},None
        raise APIError(404,'页面或操作不存在。')

    @staticmethod
    def transfers(db):
        return [{**dict(r),'ids':json.loads(r['ids'])} for r in db.execute('SELECT * FROM transfers ORDER BY id DESC')]

    @classmethod
    def holders(cls,db):
        holders={}
        for transfer in reversed(cls.transfers(db)):
            if transfer['status']=='已接单':
                holders.update(dict.fromkeys(transfer['ids'],transfer['recipient']))
        return holders

    @classmethod
    def check_transfer(cls,db,rows,member,ids):
        holders=cls.holders(db)
        targets=[r for r in rows if r['id'] in ids and holders.get(r['id'],r['member'])==member and not r.get('demo')]
        if len(targets)!=len(ids) or any(r['ship'] or r.get('cancelled') for r in targets):
            raise APIError(409,'只能转出自己持有且未排发的明细。')
        if any(r['kind']=='ship' and r['status']=='待审核' and set(ids).intersection(r['ids']) for r in cls.requests(db,member)):
            raise APIError(409,'待审核的排发明细暂不能转出。')

    @staticmethod
    def requests(db,member=None):
        fields='id,member,kind,ids,status,created,expected'
        records=db.execute('SELECT '+fields+' FROM requests ORDER BY id DESC') if member is None else db.execute('SELECT '+fields+' FROM requests WHERE member=? ORDER BY id DESC',(member,))
        return [{**dict(r),'ids':json.loads(r['ids'])} for r in records]

    @staticmethod
    def eligible(row,kind):
        if row.get('cancelled'):
            return False
        return not row.get('paid') if kind=='proof' else row.get('paid') and row.get('arrived') and not row.get('ship')

if __name__=='__main__':
    import sys
    with ThreadingHTTPServer((HOST,PORT),Handler) as server:
        url=f'http://{HOST}:{PORT}/'
        print(f'拼谷工作台：{url}',flush=True)
        if '--open' in sys.argv:
            import webbrowser
            webbrowser.open(url)
        server.serve_forever()
