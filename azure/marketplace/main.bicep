// KeyleSSH Azure Marketplace Deployment Template
// Deploys: Container Apps (keylessh + tcp-bridge), Storage Account, File Shares

@description('Name prefix for all resources')
param namePrefix string = 'keylessh'

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('KeyleSSH container image')
param keylesshImage string = 'tideorg/keylessh:latest'

@description('TCP Bridge container image')
param bridgeImage string = 'tideorg/keylessh-bridge:latest'

@description('TideCloak configuration JSON (base64 encoded)')
@secure()
param tidecloakConfigB64 string

@description('Stripe Secret Key (optional - for SaaS billing)')
@secure()
param stripeSecretKey string = ''

@description('Stripe Webhook Secret (optional)')
@secure()
param stripeWebhookSecret string = ''

@description('Container Apps Environment SKU')
@allowed(['Consumption', 'Premium'])
param environmentSku string = 'Consumption'

@description('KeyleSSH CPU allocation')
param keylesshCpu string = '0.5'

@description('KeyleSSH Memory allocation')
param keylesshMemory string = '1Gi'

@description('TCP Bridge CPU allocation')
param bridgeCpu string = '0.25'

@description('TCP Bridge Memory allocation')
param bridgeMemory string = '0.5Gi'

@description('Minimum replicas for KeyleSSH')
param keylesshMinReplicas int = 1

@description('Maximum replicas for KeyleSSH')
param keylesshMaxReplicas int = 3

@description('Minimum replicas for TCP Bridge (0 = scale to zero)')
param bridgeMinReplicas int = 0

@description('Maximum replicas for TCP Bridge')
param bridgeMaxReplicas int = 100

// Variables
var uniqueSuffix = uniqueString(resourceGroup().id)
var storageAccountName = toLower('${namePrefix}${uniqueSuffix}')
var containerEnvName = '${namePrefix}-env'
var keylesshAppName = '${namePrefix}-app'
var bridgeAppName = '${namePrefix}-bridge'
var fileShareName = 'keylessh-data'
var logAnalyticsName = '${namePrefix}-logs'

// Log Analytics Workspace (required for Container Apps)
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// Storage Account for persistent data
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}

// File Services
resource fileServices 'Microsoft.Storage/storageAccounts/fileServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
}

// File Share for KeyleSSH data (SQLite DB + config)
resource fileShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-01-01' = {
  parent: fileServices
  name: fileShareName
  properties: {
    shareQuota: 5 // 5 GB
  }
}

// Container Apps Environment
resource containerEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: containerEnvName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    workloadProfiles: environmentSku == 'Premium' ? [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ] : []
  }
}

// Storage mount for Container Apps Environment
resource storageMount 'Microsoft.App/managedEnvironments/storages@2023-05-01' = {
  parent: containerEnv
  name: 'keylessh-storage'
  properties: {
    azureFile: {
      accountName: storageAccount.name
      accountKey: storageAccount.listKeys().keys[0].value
      shareName: fileShareName
      accessMode: 'ReadWrite'
    }
  }
}

// TCP Bridge Container App
resource bridgeApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: bridgeAppName
  location: location
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      secrets: [
        {
          name: 'tidecloak-config'
          value: tidecloakConfigB64
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'tcp-bridge'
          image: bridgeImage
          resources: {
            cpu: json(bridgeCpu)
            memory: bridgeMemory
          }
          env: [
            {
              name: 'TIDECLOAK_CONFIG_B64'
              secretRef: 'tidecloak-config'
            }
            {
              name: 'PORT'
              value: '8080'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 5
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 3
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: bridgeMinReplicas
        maxReplicas: bridgeMaxReplicas
        rules: [
          {
            name: 'http-connections'
            http: {
              metadata: {
                concurrentRequests: '10'
              }
            }
          }
        ]
      }
    }
  }
}

// Conditionally build secrets array (empty strings not allowed)
var baseSecrets = [
  {
    name: 'tidecloak-config'
    value: tidecloakConfigB64
  }
]
var stripeSecrets = empty(stripeSecretKey) ? [] : [
  {
    name: 'stripe-secret-key'
    value: stripeSecretKey
  }
  {
    name: 'stripe-webhook-secret'
    value: stripeWebhookSecret
  }
]
var allSecrets = concat(baseSecrets, stripeSecrets)

// Conditionally build env vars
var baseEnvVars = [
  {
    name: 'NODE_ENV'
    value: 'production'
  }
  {
    name: 'PORT'
    value: '3000'
  }
  {
    name: 'DATABASE_URL'
    value: '/app/data/keylessh.db'
  }
  {
    name: 'BRIDGE_URL'
    value: 'wss://${bridgeApp.properties.configuration.ingress.fqdn}'
  }
  {
    name: 'TIDECLOAK_CONFIG_B64'
    secretRef: 'tidecloak-config'
  }
]
var stripeEnvVars = empty(stripeSecretKey) ? [] : [
  {
    name: 'STRIPE_SECRET_KEY'
    secretRef: 'stripe-secret-key'
  }
  {
    name: 'STRIPE_WEBHOOK_SECRET'
    secretRef: 'stripe-webhook-secret'
  }
]
var allEnvVars = concat(baseEnvVars, stripeEnvVars)

// KeyleSSH Main Container App
resource keylesshApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: keylesshAppName
  location: location
  dependsOn: [
    storageMount
  ]
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 3000
        transport: 'http'
        allowInsecure: false
      }
      secrets: allSecrets
    }
    template: {
      containers: [
        {
          name: 'keylessh'
          image: keylesshImage
          resources: {
            cpu: json(keylesshCpu)
            memory: keylesshMemory
          }
          env: allEnvVars
          volumeMounts: [
            {
              volumeName: 'data-volume'
              mountPath: '/app/data'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 3000
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 3000
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'data-volume'
          storageName: 'keylessh-storage'
          storageType: 'AzureFile'
        }
      ]
      scale: {
        minReplicas: keylesshMinReplicas
        maxReplicas: keylesshMaxReplicas
        rules: [
          {
            name: 'http-requests'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// Outputs
output keylesshUrl string = 'https://${keylesshApp.properties.configuration.ingress.fqdn}'
output bridgeUrl string = 'wss://${bridgeApp.properties.configuration.ingress.fqdn}'
output storageAccountName string = storageAccount.name
output fileShareName string = fileShareName
output resourceGroupName string = resourceGroup().name
