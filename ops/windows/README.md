# Windows migration preparation

The backend remains on Render until cutover is verified. Do not start two production matching instances.

`Install.ps1 -SecretSource <Render-export-path>` installs a stopped/manual LocalService service and immutable committed source. Production credentials stay outside Git. `launch.cjs` binds localhost and trusts Cloudflare client IP only for a loopback peer.

Before starting: current encrypted backup and isolated restore rehearsal, matching production migration checksums, working named Tunnel, DNS inventory, and an agreed old-client route are required. This preparation does not create Tunnel credentials, change DNS, schedule automatic deploys, or stop Render.

After cutover, `Deploy.ps1 -Commit <prepared-sha> -ExternalUrl https://api.talkx.chat` switches prepared releases and rolls back on local readiness/CORS/WS or external smoke failure. It does not roll back database schemas. Before using for upgrades, verify migration compatibility and prepare previous release.

`TalkXDeploy` is a LocalService poller. Every two minutes it checks the current `sale-release` head and a successful GitHub-hosted push CI run for that exact SHA, newer than its activation timestamp. It checks out that commit, installs locked production dependencies, verifies database readiness without migrations, switches the stopped service, and checks local readiness plus external HTTPS/CORS/WS. Failed candidates remain for operator inspection. No self-hosted Actions runner is registered on the personal PC.

The poller requires an already healthy current backend and cannot perform the initial cutover. Credentials remain in `C:\TalkX\secrets`; its writable locations are releases, deploy state, logs, and the active-release pointer. Its service control permission applies only to TalkXBackend. Upgrades requiring migrations are stopped by candidate preflight.

Production endpoint: `https://api.talkx.chat` (WebSocket `wss://api.talkx.chat`). Frontend stays on Render. Push to `sale-release` after local checks; successful GitHub CI makes the exact branch head eligible for the PC poller. A PC shutdown takes the backend offline; Windows service automatic start resumes it after boot. Do not resume the old Render matching backend concurrently.
