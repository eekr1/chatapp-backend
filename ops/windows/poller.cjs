'use strict';
const fs=require('node:fs'),path=require('node:path');
const {spawn}=require('node:child_process');
const root='C:/TalkX', state=root+'/deploy', repo='eekr1/chatapp-backend';
const headers={'User-Agent':'TalkX-PC-Deploy','Accept':'application/vnd.github+json'};
const tokenPath=root+'/secrets/github-readonly.token';
let busy=false,token;
function readTokenFile(p){try{return fs.readFileSync(p,'utf8').trim()||null;}catch{return null;}}
function getToken(){if(token===undefined)token=readTokenFile(tokenPath);return token;}
// Pure helpers: build GitHub API headers and git process env from an optional token.
// The token only travels in HTTP headers or process env (GIT_CONFIG_*), never in argv or logs.
// A missing, empty or whitespace-only token means "anonymous": no Authorization header and
// no git credentials are produced. The token is never read from disk here.
function normalizeToken(token){return typeof token==='string'?token.trim():'';}
function buildAuthHeaders(base,token){const h={...base};const t=normalizeToken(token);if(t)h.Authorization='Bearer '+t;return h;}
function buildGitAuthEnv(token){const t=normalizeToken(token);if(!t)return{};const basic=Buffer.from('x-access-token:'+t,'utf8').toString('base64');return{GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:'http.extraHeader',GIT_CONFIG_VALUE_0:'Authorization: Basic '+basic};}
function selectSuccessfulRun(runs, head, notBefore){return runs?.find(r=>r.head_sha===head&&r.head_branch==='sale-release'&&r.event==='push'&&r.conclusion==='success'&&r.head_repository?.full_name===repo&&Date.parse(r.created_at)>=notBefore);}
// Pure: decide whether a /health/ready response is acceptable for the *previous* release
// when a newer migration has already been applied to the database.
// Returns {ok, reason}.
function interpretReadiness(httpStatus, body){
 if(httpStatus>=200&&httpStatus<300)return{ok:true,reason:'ready'};
 const db=body?.database||body?.checks?.database;
 if(db&&db.code==='MIGRATION_NOT_CURRENT'&&typeof db.migrationHead==='string'&&typeof db.expectedMigrationHead==='string'&&db.migrationHead>db.expectedMigrationHead){
  return{ok:true,reason:'migration_ahead'};
 }
 return{ok:false,reason:db?.code||'not_ready'};
}
// Pure: decide what to do with an existing candidate directory.
// Returns {action:'resume'|'abort', reason}.
function classifyCandidate(dirExists, hasFailed, headMatches){
 if(!dirExists)return{action:'fresh',reason:'no_candidate'};
 if(hasFailed)return{action:'abort',reason:'candidate_failed_flag'};
 if(!headMatches)return{action:'abort',reason:'head_mismatch'};
 return{action:'resume',reason:'resuming_candidate'};
}
async function api(route){const r=await fetch('https://api.github.com/repos/'+repo+route,{headers:buildAuthHeaders(headers,getToken()),signal:AbortSignal.timeout(15000)});if(!r.ok)throw new Error('GitHub HTTP '+r.status);return r.json();}
function run(exe,args,cwd,env=process.env){return new Promise((resolve,reject)=>{const p=spawn(exe,args,{cwd,env,windowsHide:true,stdio:'ignore'});p.once('error',reject);p.once('exit',c=>c===0?resolve():reject(new Error(path.basename(exe)+' failed')));});}
async function ready(sha,{migrationTolerant}={}){for(let n=0;n<20;n++){try{const r=await fetch('http://127.0.0.1:3000/health/ready',{signal:AbortSignal.timeout(4000)});const d=await r.json();if(r.ok&&d.commitSha===sha)return;if(migrationTolerant&&d.commitSha===sha){const verdict=interpretReadiness(r.status,d);if(verdict.ok){try{const lr=await fetch('http://127.0.0.1:3000/health/live',{signal:AbortSignal.timeout(4000)});if(lr.ok)return;}catch{}}}}catch{}await new Promise(r=>setTimeout(r,1500));}throw new Error('Readiness failed');}
async function stopped(){for(let n=0;n<30;n++){const p=spawn('C:/Windows/System32/sc.exe',['query','TalkXBackend'],{windowsHide:true});let out='';p.stdout.on('data',b=>out+=b);await new Promise(r=>p.once('exit',r));if(out.includes('STOPPED'))return;await new Promise(r=>setTimeout(r,500));}throw new Error('Stop timeout');}
async function tick(){if(busy||!fs.existsSync(state+'/enabled'))return;busy=true;let previous, switched=false, sha;
 try{
  const branch=await api('/branches/sale-release');
  const runs=await api('/actions/workflows/quality.yml/runs?branch=sale-release&event=push&status=success&per_page=5');
  const notBefore=Date.parse(JSON.parse(fs.readFileSync(state+'/enabled','utf8')).notBefore);
  if(!Number.isFinite(notBefore))throw new Error('Invalid deploy activation time');
  const runInfo=selectSuccessfulRun(runs.workflow_runs,branch.commit.sha,notBefore);
  if(!runInfo)return;
  sha=runInfo.head_sha;if(!/^[a-f0-9]{40}$/.test(sha))throw new Error('Invalid SHA');
  previous=fs.readFileSync(root+'/active-release.txt','utf8').trim();if(previous===sha)return;
  if(!/^[a-f0-9]{40}$/.test(previous))throw new Error('Invalid rollback SHA');
  await ready(previous,{migrationTolerant:true});
  const cwd=root+'/releases/'+sha;
  // Classify existing candidate directory.
  const candidateExists=fs.existsSync(cwd);
  const candidateFailed=candidateExists&&fs.existsSync(path.join(cwd,'.candidate-failed'));
  const candidateHeadOk=candidateExists&&(()=>{try{const h=require('node:child_process').execFileSync('C:/Program Files/Git/cmd/git.exe',['rev-parse','HEAD'],{cwd,encoding:'utf8',windowsHide:true}).trim();return h===sha;}catch{return false;}})();
  const decision=classifyCandidate(candidateExists,candidateFailed,candidateHeadOk);
  if(decision.action==='abort')throw new Error('Candidate blocked: '+decision.reason);
  if(decision.action==='fresh'){
  await run('C:/Program Files/Git/cmd/git.exe',['clone','--no-checkout','https://github.com/'+repo+'.git',cwd],state,{...process.env,...buildGitAuthEnv(getToken())});
  await run('C:/Program Files/Git/cmd/git.exe',['checkout','--detach',sha],cwd);
  await run('C:/Program Files/nodejs/node.exe',['C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js','ci','--omit=dev'],cwd);
  }
  // Run forward-only migrations before preflight checks.
  await run(process.execPath,[root+'/ops/migrate-candidate.cjs',cwd],state);
  // Candidate must accept the database schema after migration.
  await run(process.execPath,[root+'/ops/preflight.cjs',cwd],state);
  await run('C:/Windows/System32/sc.exe',['stop','TalkXBackend'],state);
  await stopped();
  switched=true;fs.writeFileSync(root+'/active-release.txt',sha);
  await run('C:/Windows/System32/sc.exe',['start','TalkXBackend'],state);await ready(sha);
  await run(process.execPath,[cwd+'/ops/windows/smoke.cjs','https://api.talkx.chat'],state);
  fs.writeFileSync(state+'/last-result.json',JSON.stringify({sha,previous,status:'healthy',time:new Date().toISOString()}));
  console.log('Deployment healthy',sha);
 }catch(e){
  if(switched){try{await run('C:/Windows/System32/sc.exe',['stop','TalkXBackend'],state);await stopped();fs.writeFileSync(root+'/active-release.txt',previous);await run('C:/Windows/System32/sc.exe',['start','TalkXBackend'],state);await ready(previous,{migrationTolerant:true});}catch{console.error('Rollback needs operator attention');}}
  // Mark failed candidate so the next tick skips it instead of blocking on "already exists".
  if(sha){const failPath=root+'/releases/'+sha;try{if(fs.existsSync(failPath)&&!fs.existsSync(path.join(failPath,'.candidate-failed'))){fs.writeFileSync(path.join(failPath,'.candidate-failed'),e.message||'unknown error');}}catch{}}
  console.error('Deploy stopped:',e.message);
 }finally{busy=false;}
}
if(require.main===module){tick();setInterval(tick,120000);}
module.exports={selectSuccessfulRun,buildAuthHeaders,buildGitAuthEnv,readTokenFile,interpretReadiness,classifyCandidate};
