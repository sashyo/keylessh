# Multi-Tenancy Implementation Guide

This document describes the multi-tenancy architecture for KeyleSSH, enabling multiple organizations to share a single deployment with data isolation.

## Architecture Overview

KeyleSSH supports two tiers of organizations:

### Free Tier (Freemium)
- **Shared TideCloak Realm**: All free tier organizations share a single TideCloak realm (`keylesshmulti`)
- **Attribute-based Isolation**: Users have `organization_id` and `org_role` attributes
- **Limits**: Up to 5 SSH servers, 10 users per organization
- **No dedicated realm admin**: Org-admins manage users through KeyleSSH API (proxied via master admin)

### Paid Tier (Enterprise)
- **Dedicated TideCloak Realm**: Each organization gets their own isolated realm
- **Full Isolation**: Complete separation of users, roles, and data
- **Unlimited**: No server or user limits
- **Realm Admin**: Organization admin has `tide-realm-admin` role in their realm

## TideCloak Configuration

### Required Protocol Mappers

For the shared realm (`keylesshmulti`), add these mappers to the `keylessh` client:

#### 1. organization_id Mapper
- **Location**: Clients → keylessh → Client scopes → keylessh-dedicated → Add mapper → By configuration → User Attribute
- **Settings**:
  - Name: `organization_id`
  - User Attribute: `organization_id`
  - Token Claim Name: `organization_id`
  - Claim JSON Type: `String`
  - Add to ID token: ON
  - Add to access token: ON
  - Add to userinfo: ON

#### 2. org_role Mapper
- **Location**: Same as above
- **Settings**:
  - Name: `org_role`
  - User Attribute: `org_role`
  - Token Claim Name: `org_role`
  - Claim JSON Type: `String`
  - Add to ID token: ON
  - Add to access token: ON
  - Add to userinfo: ON

### User Attributes

Freemium users have these attributes set:
- `organization_id`: UUID of their organization
- `org_role`: One of `"org-admin"`, `"user"`, or `"global-admin"`

## Environment Variables

### Required for Provisioning

```bash
# TideCloak master realm admin credentials (for provisioning)
KC_USER=admin
KC_PASSWORD=your-admin-password

# Optional: Service account credentials (currently has issues with Tide-enabled realms)
KC_MASTER_CLIENT_ID=keylessh-provisioner-master
KC_MASTER_CLIENT_SECRET=your-client-secret
```

### Multi-Tenancy Feature Flag

```bash
# Enable multi-tenancy mode (extracts org from JWT)
# When false, all data belongs to DEFAULT_ORG_ID
ENABLE_MULTI_TENANT=true
```

## Onboarding Flow

### 1. User Visits /onboarding

The onboarding page guides new organizations through setup:

1. **Welcome Step**: Introduction to KeyleSSH
2. **Tier Selection**: Choose Free or Enterprise tier
3. **Organization Details**: Name, slug, admin info
4. **Admin Details**: First name, last name, email
5. **Terms & Confirmation**: Accept terms
6. **Success**: Display Tide account linking URL

### 2. Backend Provisioning (Free Tier)

When a free tier organization is created:

```
POST /api/onboarding
{
  "tier": "free",
  "organizationName": "Acme Corp",
  "organizationSlug": "acme",
  "adminEmail": "admin@acme.com",
  "adminFirstName": "John",
  "adminLastName": "Doe"
}
```

The backend:
1. Creates organization record in local database
2. Gets master admin token from TideCloak
3. Creates user in shared realm with attributes:
   - `organization_id`: Generated UUID
   - `org_role`: `"org-admin"`
4. Generates Tide account linking URL
5. Returns invite link to frontend

### 3. User Completes Tide Linking

The admin clicks the invite link which:
1. Opens TideCloak's Tide account linking flow
2. User creates/links their Tide account
3. User gets `vuid` and `tideUserKey` attributes
4. **Important**: Admin must approve the user change-set in TideCloak

### 4. User Logs In

After Tide linking is complete and change-set is approved:
1. User visits KeyleSSH login page
2. Clicks "Sign in with Tidecloak"
3. Authenticates via Tide
4. JWT token includes `organization_id` and `org_role` claims
5. Frontend shows admin UI based on `org_role`

## API Endpoints

### Org-Scoped User Management

These endpoints allow org-admins to manage users without TideCloak realm permissions:

```
GET    /api/org/users              - List users in organization
POST   /api/org/users              - Create user in organization
PUT    /api/org/users/:id          - Update user
PUT    /api/org/users/:id/enabled  - Enable/disable user
DELETE /api/org/users/:id          - Delete user
GET    /api/org/users/:id/tide-link - Get Tide linking URL
```

All endpoints:
- Require authentication with `org-admin` or `global-admin` role
- Use master admin credentials to interact with TideCloak
- Filter/validate by caller's `organization_id`

### Traditional Admin Endpoints

These require `tide-realm-admin` role (for paid tier or global admins):

```
GET    /api/admin/users     - List all users (TideCloak realm)
POST   /api/admin/users     - Update user roles
PUT    /api/admin/users     - Update user profile
DELETE /api/admin/users     - Delete user
POST   /api/admin/users/add - Create user
```

## Frontend Auth Flow

### AuthContext.tsx

Extracts claims from JWT:
```typescript
organizationId: tidecloak.getValueFromIdToken("organization_id") || "default"
orgRole: tidecloak.getValueFromIdToken("org_role") || (isAdmin ? "org-admin" : "user")
```

### Admin Access Check

In `App.tsx` and `AppLayout.tsx`:
```typescript
const isAdmin = hasRole("admin") || orgRole === "org-admin" || orgRole === "global-admin";
```

This allows admin access for:
- Users with `tide-realm-admin` role (legacy/paid tier)
- Users with `org_role: "org-admin"` attribute (freemium)
- Users with `org_role: "global-admin"` attribute (super admin)

## Data Isolation

### Database Schema

All tenant-scoped tables include `organization_id` column:
- `servers`
- `sessions`
- `bridges`
- `recordings`
- `file_operations`
- `subscriptions`
- `billing_history`

### Storage Layer

All storage methods accept `organizationId` parameter:
```typescript
storage.getServers(orgId)
storage.createServer(orgId, data)
bridgeStorage.getBridges(orgId)
// etc.
```

### Route Layer

Routes extract org from authenticated user:
```typescript
const orgId = getOrgId(req); // Returns req.user.organizationId
```

## Troubleshooting

### User Can't Login (500 Error)

**Cause**: User change-set not approved in TideCloak

**Solution**:
1. Go to TideCloak admin → keylesshmulti realm
2. Check for pending change-sets
3. Approve and commit the user change-set

### Admin Menu Not Showing

**Cause**: Missing protocol mappers or AppLayout not checking orgRole

**Solution**:
1. Verify `organization_id` and `org_role` mappers exist on client
2. Verify mappers have "Add to ID token" and "Add to access token" enabled
3. Check browser console: `JSON.parse(atob(localStorage.getItem('access_token').split('.')[1]))`
4. Verify `org_role` claim is present in token

### Provisioning Fails (401/500)

**Cause**: Missing or invalid admin credentials

**Solution**:
1. Verify `KC_USER` and `KC_PASSWORD` are set in `.env`
2. Check credentials are valid for TideCloak master realm
3. Check server logs for detailed error message

### User Attributes in Wrong Place

**Issue**: `firstName`/`lastName` appearing as attributes instead of user fields

**Note**: This is a TideCloak quirk. The provisioning code correctly sets them as user fields, but TideCloak may display them in attributes. The actual user profile fields should be correct.

## Security Considerations

1. **Master Admin Credentials**: Store securely, use environment variables
2. **Org Isolation**: All API endpoints validate `organization_id` from JWT
3. **Role Checks**: Backend validates `org_role` before allowing admin operations
4. **Self-Deletion Prevention**: Users cannot delete their own account via API

## Future Enhancements

1. **Service Account Auth**: Currently falls back to password grant due to TideCloak issues with service accounts in Tide-enabled realms
2. **Org Switcher**: Allow users to belong to multiple organizations
3. **Org Settings Page**: Self-service org management
4. **Automated Change-Set Approval**: Streamline user provisioning
