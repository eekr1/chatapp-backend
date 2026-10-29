const test = require('node:test');
const assert = require('node:assert/strict');
const { publicMatchIdentity, resolveSearchIdentity } = require('../utils/matchIdentity');
const { createSearchLifecycle } = require('../utils/searchLifecycle');
const { createPendingMatchRecord } = require('../utils/pendingMatch');
const { rebindTransientParticipant, resolveTransientSnapshot } = require('../utils/transientRecovery');
const { validateWsEvent } = require('../utils/wave01Security');
const { listConversations, markConversationMessageRead } = require('../utils/mobileReadModels');
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;

test('new anonymous identity omits persistent profile fields while legacy clients keep their previous labels', () => {
    const identity = { identityMode:'anon', nickname:'Real name', username:'private_username', publicProfile:{ displayName:'Real profile', username:'private_username', avatar:'/avatars/avatar-3.svg' } };
    assert.deepEqual(publicMatchIdentity(identity), { peerIdentityMode:'anon', peerNickname:'Anonymous', peerUsername:null, peerAvatar:null });
    assert.equal(publicMatchIdentity({ nickname:'Existing', username:'existing' }).peerUsername, 'existing');
});

test('profile matching reads the authenticated profile and rejects remote/script avatar sources', async () => {
    assert.equal(publicMatchIdentity({ identityMode:'profile' }).peerNickname,'TalkX');
    let params;
    const pool = { query:async (_sql, values) => { params=values; return { rows:[{ username:'karanx', display_name:'Karan', avatar_url:'https://untrusted.test/avatar.svg' }] }; } };
    const identity = await resolveSearchIdentity({ pool, userId:id(1), mode:'profile', legacyNickname:'Forged' });
    assert.deepEqual(params,[id(1),'active']);
    assert.equal(publicMatchIdentity(identity).peerNickname,'Karan');
    assert.equal(publicMatchIdentity(identity).peerAvatar,'/avatars/avatar-1.svg');
    await assert.rejects(resolveSearchIdentity({ pool:{query:async()=>({rows:[]})},userId:id(2),mode:'profile' }),/PROFILE_UNAVAILABLE/);
});

test('profile identity stays pinned through duplicate joins, requeue, scope replacement and socket recovery', () => {
    const lifecycle = createSearchLifecycle({setTimer:()=>1,clearTimer(){}});
    const profile = { displayName:'Karan', username:'karanx', avatar:'/avatars/avatar-1.svg' };
    const first=lifecycle.begin({userId:id(1),connectionId:'a',searchId:id(10),commandId:id(11),scopeContext:{identityMode:'profile',publicProfile:profile}});
    profile.displayName='Mutated outside';
    assert.equal(first.record.publicProfile.displayName,'Karan');
    assert.equal(lifecycle.begin({userId:id(1),connectionId:'a',searchId:id(10),commandId:id(11),scopeContext:{identityMode:'anon'}}).record.identityMode,'profile');
    assert.equal(lifecycle.requeue({connectionId:'a'}).record.identityMode,'profile');
    lifecycle.rebind({userId:id(1),previousConnectionId:'a',connectionId:'a2'});
    const next=lifecycle.replace({userId:id(1),connectionId:'a2',fromSearchId:id(10),searchId:id(12),commandId:id(13),scopeContext:{effectiveScope:'COUNTRY',country:{code:'TR'}}});
    assert.equal(next.record.identityMode,'profile');
    assert.equal(next.record.publicProfile.displayName,'Karan');
});

test('two participants recover a profile offer and an anonymous offer without cross-mode disclosure', () => {
    const participants=[{clientId:'a',identityMode:'anon',nickname:'Hidden',username:'secret'},{clientId:'b',identityMode:'profile',publicProfile:{displayName:'Bora',username:'borax',avatar:'/avatars/avatar-2.svg'}}];
    const pending=createPendingMatchRecord({id:id(1),participants,offeredAt:1,autoAcceptAt:100,timeoutMs:99});
    const pendingMatches=new Map([[id(1),pending]]), userPendingMatchMap=new Map([['a',id(1)],['b',id(1)]]);
    const input={waitingQueue:[],pendingMatches,userPendingMatchMap,rooms:new Map(),userRoomMap:new Map(),activeClients:new Map()};
    rebindTransientParticipant({...input,previousConnectionId:'a',connectionId:'a2',ws:{}});
    const toA=resolveTransientSnapshot({...input,connectionId:'a2'}),toB=resolveTransientSnapshot({...input,connectionId:'b'});
    assert.equal(toA.peerPublicLabel,'Bora'); assert.equal(toA.peerAvatar,'/avatars/avatar-2.svg');
    assert.equal(toB.peerPublicLabel,'Anonymous'); assert.equal(toB.peerAvatar,null); assert.equal(toB.peerUsername,undefined);
    assert.equal(toA.identityMode,'anon');assert.equal(toB.identityMode,'profile');
});

test('socket contract accepts only the two identity modes and never accepts a caller-supplied profile', () => {
    const command={type:'joinQueue',protocolVersion:1,searchId:id(1),commandId:id(2),identityMode:'profile'};
    assert.equal(validateWsEvent(command).ok,true);
    assert.equal(validateWsEvent({...command,identityMode:'admin'}).ok,false);
    assert.equal(validateWsEvent({...command,publicProfile:{displayName:'Forged'}}).ok,false);
});

test('inbox cursor uses timestamp and user identity, is account bound, bounded, escaped and rejects malformed input', async () => {
    const rows=[{user_id:id(3),last_message_at:'2026-10-29T12:00:00Z'},{user_id:id(2),last_message_at:'2026-10-29T12:00:00Z'}];let captured;
    const pool={query:async(sql,params)=>{captured={sql,params};return{rows};}};
    const first=await listConversations(pool,id(1),{limit:1,query:'a_%'});
    assert.equal(first.conversations.length,1);assert.ok(first.nextCursor);assert.equal(captured.params[0],id(1));assert.equal(captured.params[3],'a\\_\\%');
    await listConversations(pool,id(1),{before:first.nextCursor});assert.equal(captured.params[4],id(3));
    assert.match(captured.sql,/FROM blocks/);assert.match(captured.sql,/LEFT\(lm.text, 180\)/);assert.match(captured.sql,/THEN NULL/);
    await assert.rejects(listConversations(pool,id(1),{before:'bad cursor'}),/Invalid cursor/);
});

test('fractional inbox limits produce integer SQL bounds and valid pagination cursors', async () => {
    let params;
    const pool={query:async(_sql, values)=>{params=values;return{rows:[1,2].map(n=>({user_id:id(n),last_message_at:'2026-10-29T12:00:00Z'}))};}};
    const result=await listConversations(pool,id(9),{limit:1.5});
    assert.equal(params[2],2);
    assert.equal(result.conversations.length,1);
    assert.equal(result.hasMore,true);
    assert.equal(JSON.parse(Buffer.from(result.nextCursor,'base64url')).id,id(1));
});

test('live read acknowledgement is scoped to the recipient, peer and exact message and is idempotent', async () => {
    let captured;
    const pool={query:async(sql,params)=>{captured={sql,params};return {rows:[{id:id(3)}]};}};
    assert.equal(await markConversationMessageRead(pool,id(1),id(2),id(3)),true);
    assert.deepEqual(captured.params,[id(1),id(2),id(3)]);
    assert.match(captured.sql,/m\.id = \$3 AND m\.sender_id = \$2/);
    assert.match(captured.sql,/f\.status = 'accepted'/);
    assert.match(captured.sql,/FROM blocks/);
    assert.equal(await markConversationMessageRead({query:async()=>({rows:[]})},id(1),id(2),id(3)),false);
});
