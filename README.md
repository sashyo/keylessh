<div align="center">
  <img src="client/public/favicon.svg" width="96" height="96" alt="KeyleSSH logo" />
  <h1>KeyleSSH</h1>
  <p>Secure web SSH console with OIDC authentication. SSH encryption happens entirely in the browser; private keys never leave the client.</p>
</div>

## Features

- Browser-side SSH via `@microsoft/dev-tunnels-ssh` + `xterm.js`
- OIDC login with TideCloak (JWT-validated API + WS bridge) — https://tide.org
- Admin UX: servers, users, roles, approvals, sessions, logs
- Optional external `tcp-bridge/` for scalable WS↔TCP forwarding

## Documentation

- Architecture: `docs/ARCHITECTURE.md`
- Deployment (incl. Azure Container Apps for `tcp-bridge/`): `docs/DEPLOYMENT.md`
- Developer guide / contributing: `docs/DEVELOPERS.md`

## Quickstart (Local Dev)

```bash
npm install
npm run dev
```

App: `http://localhost:3000`

## Scripts

- `npm run dev` - start server + Vite dev integration
- `npm run build` - build client + bundle server
- `npm start` - run production build from `dist/`
- `npm run check` - TypeScript typecheck

## Configuration

### Environment variables

```env
PORT=3000

# Optional external TCP bridge (for scaling)
BRIDGE_URL=ws://localhost:8080
BRIDGE_SECRET=change-me-in-production

# SQLite (file path)
DATABASE_URL=./data/keylessh.db
```

### TideCloak configuration

- Browser adapter config: `client/src/tidecloakAdapter.json`
- Server JWT verification config (JWKS): `data/tidecloak.json`

## Key Dependencies

- Authentication: `@tidecloak/react` (wraps/uses `@tidecloak/js`)
- Terminal: `@xterm/xterm`
- Browser SSH: `@microsoft/dev-tunnels-ssh` and `@microsoft/dev-tunnels-ssh-keys`
- API state: `@tanstack/react-query`
- Server: `express`, `ws`
- Storage: `better-sqlite3`, `drizzle-orm`

## Contributing

See `docs/DEVELOPERS.md`.

## License

MIT
