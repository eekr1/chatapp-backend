'use strict';
const fs=require('node:fs'),path=require('node:path');
const cwd=process.argv[2];
if(!/^C:[\\/]TalkX[\\/]releases[\\/][a-f0-9]{40}$/i.test(cwd||''))throw new Error('Invalid release directory');
Object.assign(process.env,require(path.join(cwd,'node_modules/dotenv')).parse(fs.readFileSync('C:/TalkX/secrets/backend.env')));
const db=require(path.join(cwd,'db.js'));
(async()=>{try{const state=await db.getDatabaseReadiness();if(!state.ok)process.exitCode=1;}finally{await db.closeDatabase();}})().catch(()=>{process.exitCode=1;});
