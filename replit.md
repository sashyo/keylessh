# KeyleSSH - Web SSH Console

A multi-user Web SSH console application with OIDC authentication via Tidecloak. This frontend connects to a KeyleSSH backend for secure SSH terminal access.

## Project Overview

KeyleSSH provides:
- **OIDC Authentication**: Secure login via TideCloak using @tidecloak/react SDK
- **Multi-Server Access**: Connect to multiple SSH servers with role-based permissions
- **Terminal Console**: Full xterm.js terminal with copy/paste, resize handling, and connection management
- **Admin Dashboard**: Server management, user permissions, and session monitoring

## Tech Stack

- **Frontend**: React + TypeScript + Vite
- **Styling**: TailwindCSS with dark-first terminal theme
- **Routing**: Wouter
- **State**: TanStack Query
- **Terminal**: xterm.js with fit and web-links addons
- **Backend**: Express.js with WebSocket support
- **UI Components**: Shadcn/ui

## Environment Variables

Configure these in `.env` or Replit Secrets:

```env
# API Configuration
VITE_API_BASE_URL=           # Backend API base URL (leave empty for same-origin)
VITE_WS_BASE_URL=            # WebSocket base URL (leave empty for same-origin)

# TideCloak Configuration (using @tidecloak/react SDK)
VITE_TIDECLOAK_URL=          # TideCloak server URL (e.g., https://auth.example.com)
VITE_TIDECLOAK_REALM=        # TideCloak realm name
VITE_TIDECLOAK_CLIENT_ID=    # TideCloak client ID (public client)

# Mock Mode
VITE_USE_MOCK=true           # Set to "true" for demo/development mode (auto-enabled when TIDECLOAK_URL is not set)
```

## Running the Application

The app runs on port 5000 (required for Replit):

```bash
npm run dev
```

## Project Structure

```
├── client/src/
│   ├── components/
│   │   ├── layout/          # App layout with sidebar
│   │   └── ui/              # Shadcn UI components
│   ├── contexts/
│   │   └── AuthContext.tsx  # OIDC authentication context
│   ├── lib/
│   │   ├── api.ts           # API client layer
│   │   └── queryClient.ts   # TanStack Query setup
│   └── pages/
│       ├── Login.tsx        # Login page
│       ├── Dashboard.tsx    # User dashboard
│       ├── Console.tsx      # SSH terminal page
│       ├── AdminDashboard.tsx
│       ├── AdminServers.tsx
│       ├── AdminUsers.tsx
│       └── AdminSessions.tsx
├── server/
│   ├── routes.ts            # API endpoints + WebSocket
│   └── storage.ts           # In-memory data store with mock data
└── shared/
    └── schema.ts            # TypeScript types and schemas
```

## Routes

- `/login` - Authentication page
- `/app` - User dashboard (protected)
- `/app/console/:serverId` - SSH terminal (protected)
- `/admin` - Admin dashboard (admin only)
- `/admin/servers` - Server management
- `/admin/users` - User management
- `/admin/sessions` - Session monitoring

## API Endpoints

### User Endpoints
- `GET /api/servers` - List accessible servers
- `GET /api/servers/:id` - Get server details
- `GET /api/sessions` - List user's sessions
- `POST /api/sessions` - Create new session
- `DELETE /api/sessions/:id` - End session

### Admin Endpoints
- `GET /api/admin/servers` - List all servers
- `POST /api/admin/servers` - Create server
- `PATCH /api/admin/servers/:id` - Update server
- `DELETE /api/admin/servers/:id` - Delete server
- `GET /api/admin/users` - List all users
- `PATCH /api/admin/users/:id` - Update user
- `GET /api/admin/sessions` - List all sessions

### WebSocket
- `WS /ws?session={sessionId}&token={accessToken}` - Terminal stream

## Mock Mode

When `VITE_USE_MOCK=true`, the app uses:
- Mock authentication (click login to authenticate as demo admin)
- Simulated terminal with basic commands (help, ls, whoami, date, etc.)
- Pre-populated mock data for servers, users, and sessions

## Connecting to KeyleSSH Backend

To connect to a real KeyleSSH backend:

1. Set `VITE_USE_MOCK=false`
2. Configure OIDC variables for your Tidecloak instance
3. Set `VITE_API_BASE_URL` if backend is on different origin
4. The WebSocket endpoint should proxy to KeyleSSH's SSH gateway

## User Preferences

- **Theme**: Dark mode by default (terminal-centric)
- **Fonts**: Inter for UI, JetBrains Mono for terminal/code
- **Sidebar**: Collapsible navigation with role-based sections
