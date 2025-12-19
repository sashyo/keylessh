// Keycloak Types

// TideCloak Change Set Types
export interface ChangeSetRequest {
  changeSetId: string;
  changeSetType: string;
  actionType: string;
}

export interface ChangeSetRequestResponse {
  message: string;
  uri: string;
  changeSetRequests: string;
  requiresApprovalPopup: string;
  expiry: string;
  customDomainUri?: string;
}

export interface AccessApproval {
  id: string;
  timestamp: string;
  username: string;
  role: string;
  clientId: string;
  commitReady: boolean;
  decisionMade: boolean;
  rejectionFound: boolean;
  retrievalInfo: ChangeSetRequest;
  data: any;
}

export interface ClientRepresentation {
  id?: string;
  clientId?: string;
  name?: string;
  description?: string;
  type?: string;
  rootUrl?: string;
  adminUrl?: string;
  baseUrl?: string;
  surrogateAuthRequired?: boolean;
  enabled?: boolean;
  alwaysDisplayInConsole?: boolean;
  clientAuthenticatorType?: string;
  secret?: string;
  registrationAccessToken?: string;
  defaultRoles?: string[];
  redirectUris?: string[];
  webOrigins?: string[];
  notBefore?: number;
  bearerOnly?: boolean;
  consentRequired?: boolean;
  standardFlowEnabled?: boolean;
  implicitFlowEnabled?: boolean;
  directAccessGrantsEnabled?: boolean;
  serviceAccountsEnabled?: boolean;
  authorizationServicesEnabled?: boolean;
  directGrantsOnly?: boolean;
  publicClient?: boolean;
  frontchannelLogout?: boolean;
  protocol?: string;
  attributes?: Record<string, string>;
  authenticationFlowBindingOverrides?: Record<string, string>;
  fullScopeAllowed?: boolean;
  nodeReRegistrationTimeout?: number;
  registeredNodes?: Record<string, number>;
  protocolMappers?: any[];
  clientTemplate?: string;
  useTemplateConfig?: boolean;
  useTemplateScope?: boolean;
  useTemplateMappers?: boolean;
  defaultClientScopes?: string[];
  optionalClientScopes?: string[];
  authorizationSettings?: any;
  access?: Record<string, boolean>;
  origin?: string;
}

export interface RoleRepresentation {
  id?: string;
  name?: string;
  description?: string;
  scopeParamRequired?: boolean;
  composite?: boolean;
  composites?: Composites;
  clientRole?: boolean;
  containerId?: string;
  attributes?: Record<string, string[]>;
}

export interface Composites {
  realm?: RoleRepresentation[];
  client?: Record<string, RoleRepresentation[]>;
  application?: Record<string, RoleRepresentation[]>;
}

export interface ComponentRepresentation {
  id?: string;
  name?: string;
  providerId?: string;
  providerType?: string;
  parentId?: string;
  subType?: string;
  config?: Record<string, any[]>;
}

export interface UserRepresentation {
  id?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  emailVerified?: boolean;
  attributes?: { [key: string]: string[] };
  userProfileMetadata?: UserProfileMetadata;
  self?: string;
  origin?: string;
  createdTimestamp?: number;
  enabled?: boolean;
  totp?: boolean;
  federationLink?: string;
  serviceAccountClientId?: string;
  credentials?: CredentialRepresentation[];
  disableableCredentialTypes?: string[];
  requiredActions?: string[];
  federatedIdentities?: FederatedIdentityRepresentation[];
  realmRoles?: string[];
  clientRoles?: { [key: string]: string[] };
  clientConsents?: UserConsentRepresentation[];
  notBefore?: number;
  applicationRoles?: { [key: string]: string[] };
  socialLinks?: SocialLinkRepresentation[];
  groups?: string[];
  access?: { [key: string]: boolean };
}

export interface UserProfileMetadata {
  attributes?: UserProfileAttributeMetadata[];
  groups?: UserProfileAttributeGroupMetadata[];
}

export interface UserProfileAttributeGroupMetadata {
  name?: string;
  displayHeader?: string;
  displayDescription?: string;
  annotations?: { [key: string]: any };
}

export interface UserProfileAttributeMetadata {
  name?: string;
  displayName?: string;
  required?: boolean;
  readOnly?: boolean;
  annotations?: { [key: string]: any };
  validators?: { [key: string]: any };
  group?: string;
  multivalued?: boolean;
}

export interface CredentialRepresentation {
  id?: string;
  type?: string;
  userLabel?: string;
  createdDate?: number;
  secretData?: string;
  credentialData?: string;
  priority?: number;
  value?: string;
  temporary?: boolean;
  device?: string;
  hashedSaltedValue?: string;
  salt?: string;
  hashIterations?: number;
  counter?: number;
  algorithm?: string;
  digits?: number;
  period?: number;
  config?: { [key: string]: any };
}

export interface FederatedIdentityRepresentation {
  identityProvider?: string;
  userId?: string;
  userName?: string;
}

export interface SocialLinkRepresentation {
  socialProvider?: string;
  socialUserId?: string;
  socialUsername?: string;
}

export interface UserConsentRepresentation {
  clientId?: string;
  grantedClientScopes?: string[];
  createdDate?: number;
  lastUpdatedDate?: number;
  grantedRealmRoles?: string[];
}

export interface MappingsRepresentation {
  realmMappings?: RoleRepresentation[];
  clientMappings?: { [key: string]: ClientMappingsRepresentation };
}

export interface ClientMappingsRepresentation {
  id?: string;
  client?: string;
  mappings?: RoleRepresentation[];
}
