'use strict';
// TalkX nightly encrypted database backup + restore helper (Windows PC host).
// DATABASE_URL and generated keys are read from / written to C:/TalkX/secrets at runtime.
// They must never reach command lines, argv, logs, or error messages.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawn}=require('node:child_process');

const FORMAT='talkx-nightly-backup/1',ALGORITHM='aes-256-gcm',KEY_BYTES=32,IV_BYTES=12,AUTH_TAG_BYTES=16,RETENTION_DAYS=14;
const rootDir=()=>process.env.TALKX_HOME||'C:/TalkX';

// --- pure helpers (covered by test/nightly-backup.test.js) ---
function parseBackendEnv(text){const out={};for(const line of String(text||'').split(/\r?\n/)){const t=line.trim();if(!t||t.startsWith('#'))continue;const i=t.indexOf('=');if(i<=0)continue;const k=t.slice(0,i).trim();let v=t.slice(i+1).trim();if(v.length>1&&((v.startsWith('"')&&v.endsWith('"'))||(v.startsWith("'")&&v.endsWith("'"))))v=v.slice(1,-1);if(k)out[k]=v;}return out;}
// The WHATWG URL parser keeps percent-escapes inside userinfo, so libpq would receive
// 'p%40ss%23word' instead of the real secret. Decode user, password and database name.
// Malformed escapes are kept verbatim instead of throwing on a backup run.
function decodeComponent(value){const s=String(value??'');if(!s)return '';try{return decodeURIComponent(s);}catch{return s;}}
function parseDatabaseUrl(url){const u=new URL(String(url));if(u.protocol!=='postgresql:'&&u.protocol!=='postgres:')throw new Error('DATABASE_URL is not a PostgreSQL connection string');const params={};for(const [k,v] of u.searchParams)params[k]=v;const database=decodeComponent(u.pathname).replace(/^\/+/,'').replace(/\/+$/,'');if(!database)throw new Error('DATABASE_URL has no database name');return{host:u.hostname,port:u.port||'5432',user:decodeComponent(u.username),password:decodeComponent(u.password),database,params};}
function libpqEnv(conn){const env={PGHOST:conn.host,PGPORT:conn.port,PGUSER:conn.user,PGPASSWORD:conn.password,PGDATABASE:conn.database};const map={sslmode:'PGSSLMODE',sslrootcert:'PGSSLROOTCERT',sslnegotiation:'PGSSLNEGOTIATION',channel_binding:'PGCHANNELBINDING',connect_timeout:'PGCONNECT_TIMEOUT',application_name:'PGAPPNAME',options:'PGOPTIONS'};for(const [k,v] of Object.entries(conn.params||{}))if(map[k]&&v!=='')env[map[k]]=v;return env;}
function redact(text,secrets){let out=String(text??'');for(const s of secrets||[])if(s)out=out.split(String(s)).join('***');return out;}
// Accepts a 32-byte buffer, a 32-byte raw file, or base64/hex text (base64 of 32 bytes is 44 chars).
function decodeKey(raw){let buf=Buffer.isBuffer(raw)?raw:Buffer.from(String(raw??''),'utf8');if(buf.length!==KEY_BYTES){const t=buf.toString('utf8').trim();buf=/^[0-9a-fA-F]{64}$/.test(t)?Buffer.from(t,'hex'):Buffer.from(t,'base64');}if(buf.length!==KEY_BYTES)throw new Error('Backup key must be exactly 32 bytes (base64 or hex).');return buf;}
function encryptDump(dump,key){const keyBuf=decodeKey(key);const iv=crypto.randomBytes(IV_BYTES);const cipher=crypto.createCipheriv(ALGORITHM,keyBuf,iv);const body=Buffer.concat([cipher.update(dump),cipher.final()]);return{version:1,format:FORMAT,algorithm:ALGORITHM,keyBytes:KEY_BYTES,createdAt:new Date().toISOString(),sha256:crypto.createHash('sha256').update(dump).digest('hex'),bytes:dump.length,iv:iv.toString('base64'),authTag:cipher.getAuthTag().toString('base64'),data:body.toString('base64')};}
function decryptDump(envelope,key){if(!envelope||envelope.format!==FORMAT||envelope.algorithm!==ALGORITHM)throw new Error('Unsupported or foreign backup envelope.');const decipher=crypto.createDecipheriv(ALGORITHM,decodeKey(key),Buffer.from(envelope.iv,'base64'),{authTagLength:AUTH_TAG_BYTES});decipher.setAuthTag(Buffer.from(envelope.authTag,'base64'));return Buffer.concat([decipher.update(Buffer.from(envelope.data,'base64')),decipher.final()]);}
function selectExpiredBackups(entries,nowMs,retentionDays=RETENTION_DAYS){const cutoff=nowMs-retentionDays*24*60*60*1000;return entries.filter(e=>typeof e?.mtimeMs==='number'&&e.mtimeMs<cutoff).map(e=>e.name);}
function keyNameForBackup(fileName){const m=/^talkx-db-(.+)\.dump\.aes\.json$/.exec(path.basename(String(fileName||'')));return m?`backup-${m[1]}.key`:null;}
// --- runtime (depends on the C:/TalkX layout) ---
function findTool(binEnv,exe){const cands=[];if(process.env[binEnv])cands.push(process.env[binEnv]);cands.push(path.join(rootDir(),'bin',exe));for(const p of cands){try{fs.accessSync(p);return p;}catch{}}return path.basename(exe);}
function activeReleaseDir(){const sha=fs.readFileSync(path.join(rootDir(),'active-release.txt'),'utf8').trim();if(!/^[a-f0-9]{40}$/.test(sha))throw new Error('Invalid active release pointer.');return path.join(rootDir(),'releases',sha);}
function loadBackendEnv(file){try{return require(path.join(activeReleaseDir(),'node_modules','dotenv')).parse(fs.readFileSync(file,'utf8'));}catch{return parseBackendEnv(fs.readFileSync(file,'utf8'));}}
function run(exe,args,env,secrets){return new Promise((resolve,reject)=>{const p=spawn(exe,args,{env,windowsHide:true});let err='';p.stderr.on('data',b=>{err+=b;});p.stdout.on('data',()=>{});p.once('error',reject);p.once('exit',code=>code===0?resolve():reject(new Error(redact(path.basename(exe)+' failed (exit '+code+') '+err.slice(-1500),secrets))));});}
function prune(nightly,secretsDir){const now=Date.now();const entries=fs.readdirSync(nightly).filter(n=>n.endsWith('.dump.aes.json')).map(n=>({name:n,mtimeMs:fs.statSync(path.join(nightly,n)).mtimeMs}));for(const name of selectExpiredBackups(entries,now)){try{fs.unlinkSync(path.join(nightly,name));}catch{}const key=keyNameForBackup(name);if(key){try{fs.unlinkSync(path.join(secretsDir,key));}catch{}}console.log(JSON.stringify({step:'retention',deleted:name}));}}
async function backup(){const r=rootDir();const url=loadBackendEnv(path.join(r,'secrets','backend.env')).DATABASE_URL;if(!url)throw new Error('DATABASE_URL missing in backend.env.');
 // The decoded secret and its percent-encoded form must never survive in tool output.
 const conn=parseDatabaseUrl(url);const secrets=[url,conn.password,encodeURIComponent(conn.password)].filter(Boolean);const pgEnv={...process.env,...libpqEnv(conn)};
 const stamp=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d+Z$/,'Z');const base='talkx-db-'+stamp;
 const nightly=path.join(r,'backups','nightly');fs.mkdirSync(nightly,{recursive:true});fs.mkdirSync(path.join(r,'secrets'),{recursive:true});
 const dumpBin=findTool('PG_DUMP_BIN','pg_dump.exe'),restoreBin=findTool('PG_RESTORE_BIN','pg_restore.exe');
 const tmp=path.join(nightly,'.tmp-'+base+'.dump');let verified;
 try{
  console.log(JSON.stringify({step:'pg_dump',start:new Date().toISOString()}));
  await run(dumpBin,['--format=custom','--file='+tmp],pgEnv,secrets);
  const {verifyBackup}=require(path.join(activeReleaseDir(),'scripts','verify-backup.js'));
  verified=await verifyBackup({filePath:tmp,restoreBin});
  console.log(JSON.stringify({step:'verify',bytes:verified.bytes,sha256:verified.sha256,archiveEntries:verified.archiveEntries}));
  const key=crypto.randomBytes(KEY_BYTES);const envelope=encryptDump(fs.readFileSync(tmp),key);
  envelope.archiveEntries=verified.archiveEntries;
  const keyFile=path.join(r,'secrets','backup-'+stamp+'.key');fs.writeFileSync(keyFile,key.toString('base64')+'\n');
  const archive=path.join(nightly,base+'.dump.aes.json');fs.writeFileSync(archive,JSON.stringify(envelope));
  console.log(JSON.stringify({status:'success',file:archive,keyFile,bytes:envelope.bytes,sha256:envelope.sha256,archiveEntries:envelope.archiveEntries,time:new Date().toISOString()}));
 }finally{try{fs.unlinkSync(tmp);}catch{}}
 prune(nightly,path.join(r,'secrets'));
}
function parseFlags(argv){const f={};for(let i=0;i<argv.length;i++)if(argv[i].startsWith('--')){const v=argv[i+1];if(v===undefined||v.startsWith('--'))f[argv[i].slice(2)]=true;else{f[argv[i].slice(2)]=v;i++;}}return f;}
async function main(){const flags=parseFlags(process.argv.slice(2));
 if(flags.decrypt){for(const k of ['archive','key','out'])if(!flags[k])throw new Error('--decrypt needs --archive <file>, --key <file>, --out <file>.');
  const envelope=JSON.parse(fs.readFileSync(flags.archive,'utf8'));
  const dump=decryptDump(envelope,fs.readFileSync(flags.key));
  fs.mkdirSync(path.dirname(path.resolve(flags.out)),{recursive:true});fs.writeFileSync(flags.out,dump);
  console.log(JSON.stringify({status:'decrypted',file:path.resolve(flags.out),bytes:dump.length,sha256:envelope.sha256,next:'verify with npm run backup:verify, then restore into an isolated target only'}));return;}
 await backup();}
if(require.main===module){main().catch(e=>{console.error(JSON.stringify({status:'failed',error:e&&e.message,time:new Date().toISOString()}));process.exitCode=1;});}
module.exports={FORMAT,ALGORITHM,RETENTION_DAYS,parseBackendEnv,parseDatabaseUrl,libpqEnv,redact,decodeKey,encryptDump,decryptDump,selectExpiredBackups,keyNameForBackup};