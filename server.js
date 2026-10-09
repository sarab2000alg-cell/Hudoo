// هدوء: خادم مستقل بدون أي مكتبات. التشغيل: node server.js
const http=require('http'),https=require('https'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
const PORT=process.env.PORT||3000,MPASS=process.env.MANAGER_PASSWORD||'1234',APASS=process.env.ADMIN_PASSWORD||'',SUBJ=process.env.VAPID_SUBJECT||'mailto:admin@example.com';
const FILE=process.env.DATA_FILE||path.join(__dirname,'data.json');
let D={profile:{name:'المدير'},status:{v:'free',end:'',who:''},gate:'',emps:{},reqs:[],files:{},tokens:{},subs:{},join:undefined,vapid:null};
try{D=Object.assign(D,JSON.parse(fs.readFileSync(FILE,'utf8')))}catch(e){}
if(D.join===undefined)D.join=process.env.JOIN_CODE||'';
if(!D.vapid){const k=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),j=k.publicKey.export({format:'jwk'});D.vapid={pub:Buffer.concat([Buffer.from([4]),Buffer.from(j.x,'base64url'),Buffer.from(j.y,'base64url')]).toString('base64url'),priv:k.privateKey.export({type:'pkcs8',format:'pem'})};fs.writeFileSync(FILE,JSON.stringify(D))}
let t0;function persist(){clearTimeout(t0);t0=setTimeout(()=>fs.writeFile(FILE,JSON.stringify(D),()=>{}),300)}
const hash=t=>crypto.createHash('sha256').update('hudoo:'+t).digest('hex');
const rid=n=>crypto.randomBytes(n).toString('hex');
const CR={1:3,2:2,3:1},IMP=['عادي','مهم','عاجل','طوارئ'],SV=['meet','with','emerg','free'];
const clients=new Set(),tries={};
const b64u=x=>Buffer.from(x).toString('base64url'),hmac=(k,d)=>crypto.createHmac('sha256',k).update(d).digest();
function eq(a,b){const x=Buffer.from(s(a,100)),y=Buffer.from(b||'');return y.length>0&&x.length===y.length&&crypto.timingSafeEqual(x,y)}
function vapidAuth(endpoint){const h=b64u(JSON.stringify({typ:'JWT',alg:'ES256'})),c=b64u(JSON.stringify({aud:new URL(endpoint).origin,exp:Math.floor(Date.now()/1000)+43200,sub:SUBJ})),d=h+'.'+c;
 return 'vapid t='+d+'.'+crypto.sign('sha256',Buffer.from(d),{key:D.vapid.priv,dsaEncoding:'ieee-p1363'}).toString('base64url')+', k='+D.vapid.pub}
function encrypt(payload,sub){
 const ua=Buffer.from(sub.keys.p256dh,'base64url'),auth=Buffer.from(sub.keys.auth,'base64url');
 const e=crypto.createECDH('prime256v1');e.generateKeys();const asPub=e.getPublicKey(),secret=e.computeSecret(ua);
 const ikm=hmac(hmac(auth,secret),Buffer.concat([Buffer.from('WebPush: info\0'),ua,asPub,Buffer.from([1])]));
 const salt=crypto.randomBytes(16),prk=hmac(salt,ikm);
 const cek=hmac(prk,Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'),Buffer.from([1])])).slice(0,16),nonce=hmac(prk,Buffer.concat([Buffer.from('Content-Encoding: nonce\0'),Buffer.from([1])])).slice(0,12);
 const ci=crypto.createCipheriv('aes-128-gcm',cek,nonce),ct=Buffer.concat([ci.update(Buffer.concat([Buffer.from(payload),Buffer.from([2])])),ci.final(),ci.getAuthTag()]);
 const rs=Buffer.alloc(4);rs.writeUInt32BE(4096);return Buffer.concat([salt,rs,Buffer.from([asPub.length]),asPub,ct])}
function sendPush(tok,obj){const sub=D.subs[tok];if(!sub)return;let body;try{body=encrypt(JSON.stringify(obj),sub)}catch(e){return}
 try{const u=new URL(sub.endpoint);const r=https.request({method:'POST',hostname:u.hostname,port:u.port||443,path:u.pathname+u.search,headers:{'Content-Encoding':'aes128gcm','Content-Type':'application/octet-stream','Content-Length':body.length,TTL:'86400',Urgency:'high',Authorization:vapidAuth(sub.endpoint)}},res=>{res.resume();if(res.statusCode===404||res.statusCode===410){delete D.subs[tok];persist()}});r.on('error',()=>{});r.setTimeout(10000,()=>r.destroy());r.end(body)}catch(e){}}
function notify(filter,obj){Object.keys(D.subs).forEach(k=>{const t=D.tokens[k];if(t&&filter(t))sendPush(k,obj)})}
function fmtT(t){if(!t)return '';const p=t.split(':');let h=+p[0];const ap=h>=12?'م':'ص';h=h%12||12;return h+':'+p[1]+' '+ap}
function stText(){const x=D.status;let t={meet:'في اجتماع',with:'مشغول حالياً',emerg:'للطارئ فقط',free:'متاح'}[x.v];if(x.v==='with'&&x.who)t+=' مع '+x.who;if((x.v==='meet'||x.v==='with')&&x.end)t+=' حتى '+fmtT(x.end);return t}
let crcT;function crc32(b){if(!crcT){crcT=[];for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;crcT[n]=c>>>0}}let c=0xFFFFFFFF;for(const x of b)c=crcT[(c^x)&255]^(c>>>8);return (c^0xFFFFFFFF)>>>0}
function chunk(t,d){const l=Buffer.alloc(4);l.writeUInt32BE(d.length);const td=Buffer.concat([Buffer.from(t),d]),c=Buffer.alloc(4);c.writeUInt32BE(crc32(td));return Buffer.concat([l,td,c])}
const icons={};function png(n){if(icons[n])return icons[n];const raw=Buffer.alloc(n*(n*4+1));
 for(let y=0;y<n;y++){raw[y*(n*4+1)]=0;for(let x=0;x<n;x++){const dx=(x+.5)/n-.5,dy=(y+.5)/n-.5,r=Math.hypot(dx,dy);let c=[11,22,36];
  if(r>.28&&r<.32)c=[201,162,75];else if(r<=.28&&Math.abs(dx)<.09&&dy>-.17&&dy<.17)c=(Math.hypot(dx-.045,dy)<.02)?[11,22,36]:[201,162,75];
  const o=y*(n*4+1)+1+x*4;raw[o]=c[0];raw[o+1]=c[1];raw[o+2]=c[2];raw[o+3]=255}}
 const ih=Buffer.alloc(13);ih.writeUInt32BE(n,0);ih.writeUInt32BE(n,4);ih[8]=8;ih[9]=6;
 return icons[n]=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',ih),chunk('IDAT',zlib.deflateSync(raw)),chunk('IEND',Buffer.alloc(0))])}
const SW=`self.addEventListener('push',e=>{let d={};try{d=e.data.json()}catch(x){}e.waitUntil(self.registration.showNotification(d.title||'هدوء',{body:d.body||'',tag:d.tag||'hudoo',icon:'/icon-192.png',badge:'/icon-192.png',dir:'rtl',lang:'ar'}))});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const c of l){if('focus' in c)return c.focus()}return clients.openWindow('/')}))});`;
const MAN=JSON.stringify({name:'هدوء',short_name:'هدوء',start_url:'/',scope:'/',display:'standalone',background_color:'#0B1624',theme_color:'#0B1624',lang:'ar',dir:'rtl',icons:[{src:'/icon-192.png',sizes:'192x192',type:'image/png',purpose:'any maskable'},{src:'/icon-512.png',sizes:'512x512',type:'image/png',purpose:'any maskable'}]});
function weekStart(){const d=new Date();d.setHours(0,0,0,0);d.setDate(d.getDate()-d.getDay());return d.getTime()}
function view(t){
 const base={role:t.role,profile:D.profile,status:D.status,hasGate:!!D.gate};
 if(t.role==='mgr')return Object.assign(base,{emps:D.emps,reqs:D.reqs,join:D.join});
 if(t.role==='adm')return Object.assign(base,{emps:D.emps,join:D.join});
 const e=D.emps[t.id];if(!e)return null;
 return Object.assign(base,{me:Object.assign({id:t.id},e),items:D.reqs.filter(r=>r.eid===t.id)});
}
function push(){clients.forEach(c=>{const v=view(c.t);if(v)c.res.write('data: '+JSON.stringify(v)+'\n\n')});persist()}
function auth(req,url){const k=req.headers['x-token']||url.searchParams.get('token');return k&&D.tokens[k]?{k,t:D.tokens[k]}:null}
function body(req){return new Promise((ok,no)=>{let b='',n=0;req.on('data',c=>{n+=c.length;if(n>3e6){no();req.destroy();return}b+=c});req.on('end',()=>{try{ok(JSON.parse(b||'{}'))}catch(e){no()}})})}
function js(res,code,o){res.writeHead(code,{'content-type':'application/json'});res.end(JSON.stringify(o))}
const s=(x,n)=>String(x==null?'':x).slice(0,n);
const srv=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://x');
 if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'content-type':'text/html; charset=utf-8'});return res.end(fs.readFileSync(path.join(__dirname,'index.html')))}
 const P=url.pathname;
 if(P==='/sw.js'){res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','service-worker-allowed':'/'});return res.end(SW)}
 if(P==='/manifest.json'){res.writeHead(200,{'content-type':'application/manifest+json; charset=utf-8'});return res.end(MAN)}
 const im={'/icon-192.png':192,'/icon-512.png':512,'/apple-touch-icon.png':180};
 if(im[P]){res.writeHead(200,{'content-type':'image/png','cache-control':'public, max-age=86400'});return res.end(png(im[P]))}
 if(!P.startsWith('/api/')){res.writeHead(404);return res.end()}
 const ep=url.pathname.slice(5),ip=req.socket.remoteAddress;
 try{
  if(ep==='login'||ep==='join'){
   const k=ip+ep;tries[k]=(tries[k]||[]).filter(x=>Date.now()-x<6e4);if(tries[k].length>=15)return js(res,429,{error:'many'});tries[k].push(Date.now());
   const b=await body(req);
   if(ep==='login'){const role=eq(b.password,MPASS)?'mgr':eq(b.password,APASS)?'adm':'';if(!role)return js(res,403,{error:'pass'});const tok=rid(24);D.tokens[tok]={role};persist();return js(res,200,{token:tok})}
   if(D.join&&s(b.code,100)!==D.join)return js(res,403,{error:'code'});
   const name=s(b.name,40).trim();if(!name)return js(res,400,{error:'name'});
   const id=rid(5),tok=rid(24);D.emps[id]={name,grade:3,phone:''};D.tokens[tok]={role:'emp',id};push();return js(res,200,{token:tok});
  }
  if(ep==='vapid')return js(res,200,{key:D.vapid.pub});
  const a=auth(req,url);if(!a)return js(res,401,{error:'auth'});
  if(ep==='stream'){res.writeHead(200,{'content-type':'text/event-stream','cache-control':'no-cache',connection:'keep-alive'});const c={res,t:a.t};clients.add(c);const v=view(a.t);if(!v){res.end();clients.delete(c);return}res.write('data: '+JSON.stringify(v)+'\n\n');const ping=setInterval(()=>res.write(': ping\n\n'),25000);req.on('close',()=>{clearInterval(ping);clients.delete(c)});return}
  if(ep==='state'){const v=view(a.t);return v?js(res,200,v):js(res,401,{error:'auth'})}
  if(ep.startsWith('file/')){if(a.t.role!=='mgr')return js(res,403,{});const f=D.files[ep.slice(5)];return f?js(res,200,f):js(res,404,{})}
  if(req.method!=='POST')return js(res,405,{});
  const b=await body(req);
  if(ep==='request'){
   if(a.t.role!=='emp')return js(res,403,{error:'role'});
   const text=s(b.text,300).trim(),imp=IMP.includes(b.imp)?b.imp:'عادي';if(!text)return js(res,400,{});
   const e=D.emps[a.t.id];
   if(imp==='طوارئ'){const n=D.reqs.filter(r=>r.eid===a.t.id&&r.imp==='طوارئ'&&r.ts>=weekStart()).length;if(n>=CR[e.grade||3])return js(res,200,{error:'credit'})}
   let vip=false;if(b.code){if(!D.gate||hash(s(b.code,100))!==D.gate)return js(res,200,{error:'code'});vip=true}
   const id='r'+rid(5);let file=null;
   if(b.file&&b.file.b64&&b.file.b64.length<2.8e6){D.files[id]={name:s(b.file.name,80),type:s(b.file.type,60),b64:b.file.b64};file={name:s(b.file.name,80)}}
   D.reqs.unshift({id,eid:a.t.id,text,imp,vip,ts:Date.now(),res:'',file});D.reqs=D.reqs.slice(0,500);push();notify(t=>t.role==='mgr',{title:imp==='طوارئ'?'طلب طارئ':vip?'طلب برمز خاص':'طلب جديد',body:e.name+': '+text.slice(0,80),tag:'req'});return js(res,200,{ok:1});
  }
  if(ep==='subscribe'){const sb=b.sub;if(!sb||typeof sb.endpoint!=='string'||!sb.endpoint.startsWith('https://')||!sb.keys||!sb.keys.p256dh||!sb.keys.auth)return js(res,400,{});D.subs[a.k]={endpoint:sb.endpoint,keys:{p256dh:s(sb.keys.p256dh,200),auth:s(sb.keys.auth,100)}};persist();return js(res,200,{ok:1})}
  if(a.t.role==='emp')return js(res,403,{error:'role'});
  if(ep==='gate'){D.gate=b.code?hash(s(b.code,100)):'';push();return js(res,200,{ok:1})}
  if(ep==='roster'){const e=D.emps[b.eid];if(!e)return js(res,404,{});if(b.grade)e.grade=[1,2,3].includes(+b.grade)?+b.grade:3;if('phone' in b)e.phone=s(b.phone,20);push();return js(res,200,{ok:1})}
  if(ep==='delemp'){delete D.emps[b.eid];D.reqs=D.reqs.filter(r=>r.eid!==b.eid);Object.keys(D.tokens).forEach(k=>{if(D.tokens[k].id===b.eid){delete D.tokens[k];delete D.subs[k]}});clients.forEach(c=>{if(c.t.id===b.eid){c.res.end();clients.delete(c)}});push();return js(res,200,{ok:1})}
  if(ep==='joincode'){D.join=s(b.code,40).trim();push();return js(res,200,{ok:1})}
  if(a.t.role!=='mgr')return js(res,403,{error:'role'});
  if(ep==='status'){const old=JSON.stringify(D.status);D.status={v:SV.includes(b.v)?b.v:'free',end:s(b.end,5),who:s(b.who,40)};push();if(old!==JSON.stringify(D.status))notify(t=>t.role==='emp',{title:D.profile.name,body:stText(),tag:'status'});return js(res,200,{ok:1})}
  if(ep==='profile'){D.profile={name:s(b.name,40).trim()||'المدير'};push();return js(res,200,{ok:1})}
  if(ep==='reply'){const r=D.reqs.find(x=>x.id===b.id);if(r){r.res=s(b.v,30);notify(t=>t.id===r.eid,{title:D.profile.name,body:'ردّ على طلبك: '+r.res,tag:'reply'})}push();return js(res,200,{ok:1})}
  js(res,404,{});
 }catch(e){try{js(res,400,{error:'bad'})}catch(x){}}
});
if(require.main===module)srv.listen(PORT,()=>console.log('هدوء يعمل على المنفذ '+PORT+(MPASS==='1234'?' (تنبيه: غيّر MANAGER_PASSWORD)':'')));

module.exports={encrypt,vapidAuth,D};
