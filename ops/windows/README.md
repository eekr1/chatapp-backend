# Windows migration preparation

The backend remains on Render until cutover is verified. Do not start two production matching instances.

`Install.ps1 -SecretSource <Render-export-path>` installs a stopped/manual LocalService service and immutable committed source. Production credentials stay outside Git. `launch.cjs` binds localhost and trusts Cloudflare client IP only for a loopback peer.

Before starting: current encrypted backup and isolated restore rehearsal, matching production migration checksums, working named Tunnel, DNS inventory, and an agreed old-client route are required. This preparation does not create Tunnel credentials, change DNS, schedule automatic deploys, or stop Render.

After cutover, `Deploy.ps1 -Commit <prepared-sha> -ExternalUrl https://api.talkx.chat` switches prepared releases and rolls back on local readiness/CORS/WS or external smoke failure. It does not roll back database schemas. Before using for upgrades, verify migration compatibility and prepare previous release.

The approved future push workflow is GitHub-hosted CI followed by a restricted artifact poller. No self-hosted Actions runner is registered on the personal PC. Automatic deployment is not yet installed.
