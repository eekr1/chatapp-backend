'use strict';
const fs=require('node:fs'),path=require('node:path');
const {spawn}=require('node:child_process');
const root='C:/TalkX', state=root+'/deploy', repo='eekr1/chatapp-backend';
const headers={'User-Agent':'TalkX-PC-Deploy','Accept':'application/vnd.github+json'};
let busy=false;
function selectSuccessfulRun(runs, head, notBefore){return runs?.find(r=>r.head_sha===head&&r.head_branch==='sale-release'&&r.event==='push'&&r.conclusion==='success'&&r.head_repository?.full_name===repo&&Date.parse(r.created_at)>=notBefore);}
async function api(route){const r=await fetch('https://api.github.com/repos/'+repo+route,{headers,signal:AbortSignal.timeout(15000)});if(!r.ok)throw new Error('GitHub HTTP '+r.status);return r.json();}
function run(exe,args,cwd,env=process.env){return new Promise((resolve,reject)=>{const p=spawn(exe,args,{cwd,env,windowsHide:true,stdio:'ignore'});p.once('error',reject);p.once('exit',c=>c===0?resolve():reject(new Error(path.basename(exe)+' failed')));});}
async function ready(sha){for(let n=0;n<20;n++){try{const r=await fetch('http://127.0.0.1:3000/health/ready',{signal:AbortSignal.timeout(4000)});const d=await r.json();if(r.ok&&d.commitSha===sha)return;}catch{}await new Promise(r=>setTimeout(r,1500));}throw new Error('Readiness failed');}
async function stopped(){for(let n=0;n<30;n++){const p=spawn('C:/Windows/System32/sc.exe',['query','TalkXBackend'],{windowsHide:true});let out='';p.stdout.on('data',b=>out+=b);await new Promise(r=>p.once('exit',r));if(out.includes('STOPPED'))return;await new Promise(r=>setTimeout(r,500));}throw new Error('Stop timeout');}
async function tick(){if(busy||!fs.existsSync(state+'/enabled'))return;busy=true;let previous, switched=false;
 try{
  const branch=await api('/branches/sale-release');
  const runs=await api('/actions/workflows/quality.yml/runs?branch=sale-release&event=push&status=success&per_page=5');
  const notBefore=Date.parse(JSON.parse(fs.readFileSync(state+'/enabled','utf8')).notBefore);
  if(!Number.isFinite(notBefore))throw new Error('Invalid deploy activation time');
  const runInfo=selectSuccessfulRun(runs.workflow_runs,branch.commit.sha,notBefore);
  if(!runInfo)return;
  const sha=runInfo.head_sha;if(!/^[a-f0-9]{40}$/.test(sha))throw new Error('Invalid SHA');
  previous=fs.readFileSync(root+'/active-release.txt','utf8').trim();if(previous===sha)return;
  if(!/^[a-f0-9]{40}$/.test(previous))throw new Error('Invalid rollback SHA');
  await ready(previous);
  const cwd=root+'/releases/'+sha;
  // Failed candidates are retained. Retry requires operator inspection.
  if(fs.existsSync(cwd))throw new Error('Candidate already exists; inspect it');
  await run('C:/Program Files/Git/cmd/git.exe',['clone','--no-checkout','https://github.com/'+repo+'.git',cwd],state);
  await run('C:/Program Files/Git/cmd/git.exe',['checkout','--detach',sha],cwd);
  await run('C:/Program Files/nodejs/node.exe',['C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js','ci','--omit=dev'],cwd);
  // Candidate must accept the existing database schema before any stop/switch.
  await run(process.execPath,[root+'/ops/preflight.cjs',cwd],state);
  await run('C:/Windows/System32/sc.exe',['stop','TalkXBackend'],state);
  await stopped();
  switched=true;fs.writeFileSync(root+'/active-release.txt',sha);
  await run('C:/Windows/System32/sc.exe',['start','TalkXBackend'],state);await ready(sha);
  await run(process.execPath,[cwd+'/ops/windows/smoke.cjs','https://api.talkx.chat'],state);
  fs.writeFileSync(state+'/last-result.json',JSON.stringify({sha,previous,status:'healthy',time:new Date().toISOString()}));
  console.log('Deployment healthy',sha);
 }catch(e){
  if(switched){try{await run('C:/Windows/System32/sc.exe',['stop','TalkXBackend'],state);await stopped();fs.writeFileSync(root+'/active-release.txt',previous);await run('C:/Windows/System32/sc.exe',['start','TalkXBackend'],state);await ready(previous);}catch{console.error('Rollback needs operator attention');}}
  console.error('Deploy stopped:',e.message);
 }finally{busy=false;}
}
if(require.main===module){tick();setInterval(tick,120000);}
module.exports={selectSuccessfulRun};
