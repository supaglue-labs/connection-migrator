import { Connection, ScheduleNotFoundError, Client as TemporalClient, WorkflowNotFoundError } from '@temporalio/client';
import axios from 'axios';
import crypto from 'crypto';
import { Client } from 'pg';

/**
 * Fill these in
 */
// Enter the application id for the application you are migrating from in your self-hosted K8s Supaglue instance
const fromApplicationId = '...';

// Run this command to get the secret you are using in your self-hosted K8s Supaglue instance to encrypt/decrypt connection credentials
// echo $(kubectl -n supaglue get secret -o json supaglue-secret | jq '.data."db-encryption-secret"' -r | base64 -d)
const secret = '...';

// Run this command to get the password you are using in your self-hosted K8s Supaglue instance to connect to Postgres
// echo $(kubectl get secrets supaglue-postgresql -n supaglue -o jsonpath='{.data.password}' | base64 -d)
const pgPassword = '...';

// Enter the api key for the new Application you created in Supaglue Cloud. We will migrate connections to the corresponding Application.
const apiKey = '...';

/**
 * Do not touch anything beyond this
 */
// temporal
const temporalHost = 'localhost';
const temporalPort = 7233;

// postgres
const pgHost = 'localhost';
const pgPort = 5432; // 5432
const pgDatabase = 'supaglue'; // docker: postgres
const pgSchema = 'public'; // docker: api
const pgUser = 'supaglue'; // docker: postgres
// const pgPassword = 'supaglue'; // (on docker)


const apiUrl = 'https://api.supaglue.io';

type ConnectionWithCustomer = {
  id: string;
  provider_name: string;
  credentials: string;

  full_customer_id: string;
  customer_name: string;
  customer_email: string;

  sync_id: string;
};

async function pauseTemporalSync(syncId: string): Promise<void> {
  const client = new TemporalClient({
    namespace: 'default',
    connection: Connection.lazy({
      address: `${temporalHost}:${temporalPort}`,
    })
  });

  // Get schedule for syncId
  const scheduleId = `run-sync-${syncId}`;
  const handle = client.schedule.getHandle(scheduleId);

  // Pause schedule
  try {
    await handle.pause('Migrating to Supaglue Cloud');
    console.log(`Paused schedule ${scheduleId}`);
  } catch (err) {
    if (err instanceof ScheduleNotFoundError) {
      console.error('Schedule not found when deleting. Ignoring for idempotency...');
    } else {
      throw err;
    }
  }

  // Kill any running workflows associated with this schedule
  const description = await handle.describe();
  const workflowIds = description.info.runningActions.map((action) => action.workflow.workflowId);
  const workflowHandles = workflowIds.map((workflowId) => client.workflow.getHandle(workflowId));
  for (const workflowHandle of workflowHandles) {
    try {
      await workflowHandle.terminate('Migrating to Supaglue Cloud');
      console.log(`Terminated workflow ${workflowHandle.workflowId}`);
    } catch (err) {
      if (err instanceof WorkflowNotFoundError) {
        console.error('Workflow not found when deleting. Ignoring for idempotency...');
      } else {
        throw err;
      }
    }
  }
}

/**
 * Do not modify
 */
async function listConnections(): Promise<ConnectionWithCustomer[]> {
  const client = new Client({
    host: pgHost,
    port: pgPort,
    database: pgDatabase,
    user: pgUser,
    password: pgPassword,
  });
  await client.connect();

  const res = await client.query(`select s.id as sync_id, c.customer_id as full_customer_id, cc.name as customer_name, cc.email as customer_email, c.id, c.provider_name, encode(c.credentials, 'hex') as credentials from ${pgSchema}.connections c join ${pgSchema}.customers cc on c.customer_id = cc.id join ${pgSchema}.integrations i on c.integration_id = i.id join ${pgSchema}.applications a on i.application_id = a.id join ${pgSchema}.syncs s on c.id = s.connection_id where a.id = '${fromApplicationId}' order by c.created_at asc`);
  const rows = res.rows;

  await client.end();
  
  return rows;
}

const algorithm = 'aes-256-cbc';
const saltLength = 16;
const ivLength = 16;

async function getKey(secret: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(secret, salt, 100000, 32, 'sha512', (err, key) => {
      if (err) {
        return reject(err);
      }

      resolve(key);
    });
  });
}

async function decrypt(buffer: Buffer): Promise<Credentials> {
  const salt = buffer.subarray(0, saltLength);
  const iv = buffer.subarray(saltLength, saltLength + ivLength);
  const encryptedData = buffer.subarray(saltLength + ivLength);
  if (!secret) {
    throw new Error('Cannot decrypt without a secret');
  }
  const key = await getKey(secret, salt);

  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
  const decryptedString = Buffer.concat([decipher.update(encryptedData), decipher.final()]).toString();
  return JSON.parse(decryptedString);
}

type Credentials = {
  refreshToken: string;
  instanceUrl?: string;
};

type Integration = {
  id: string;
  provider_name: 'hubspot' | 'salesforce';
};

async function listIntegrations(): Promise<Integration[]> {
  const response = await axios.get(`${apiUrl}/mgmt/v1/integrations`, {
    headers: {
      'x-api-key': apiKey,
    },
  });

  return response.data;
}

async function getIntegrationIdForProviderName(providerName: string): Promise<string> {
  const integrations = await listIntegrations();
  const integration = integrations.find((integration) => integration.provider_name === providerName);
  if (!integration) {
    throw new Error(`${providerName} integration not found on Supaglue Cloud. Please create one first.`);
  }
  return integration.id;
}

type ConnectionCreateParams = {
  integration_id: string;
  credentials: {
    type: 'oauth2';
    refresh_token: string;
    refreshToken: string;
    instance_url?: string;
  }
};

async function createConnection(customerId: string, params: ConnectionCreateParams): Promise<void> {
  await axios.post(`${apiUrl}/mgmt/v1/customers/${encodeURIComponent(customerId)}/connections`, params, {
    headers: {
      'x-api-key': apiKey,
      'Content-Type': 'application/json',
    },
  });
}

async function getConnectionById(connectionId: string): Promise<ConnectionWithCustomer> {
  const connections = await listConnections();
  const connection = connections.find((connection) => connection.id === connectionId);
  if (!connection) {
    throw new Error('Connection not found');
  }
  return connection;
}

type Customer = { customer_id: string; name: string; email: string };

async function createCustomer(params: Customer): Promise<void> {
  await axios.put(`${apiUrl}/mgmt/v1/customers`, params, {
    headers: {
      'x-api-key': apiKey,
      'Content-Type': 'application/json',
    },
  });
}

async function getConnectionCountForCustomerIdOnCloud(customerId: string): Promise<number> {
  const response = await axios.get(`${apiUrl}/mgmt/v1/customers/${encodeURIComponent(customerId)}/connections`, {
    headers: {
      'x-api-key': apiKey,
    },
  });

  return response.data.length;
}

async function migrateAll(): Promise<void> {
  const connections = await listConnections();
  for (const connection of connections) {
    await migrateSingle(connection.id);
  }
}

async function migrateMultiple(connectionIds: string[]): Promise<void> {
  for (const connectionId of connectionIds) {
    await migrateSingle(connectionId);
  }
}

async function migrateSingle(connectionId: string): Promise<void> {
  console.log(`---------- Migrating connection ${connectionId} ----------`);
  const connection = await getConnectionById(connectionId);
  const customerId = connection.full_customer_id.split(':')[1];
  console.log(`Connection belongs to customer ${customerId}`);

  if (connection.provider_name !== 'hubspot' && connection.provider_name !== 'salesforce') {
    throw new Error(`Connection type not supported: ${connection.provider_name}`);
  }

  console.log('Fetching corresponding integration from Cloud...');
  const integrationId = await getIntegrationIdForProviderName(connection.provider_name);
  console.log('Found hubspot integration in Cloud!');

  console.log(`Upserting customer ${customerId} on Cloud...`);
  const customer = {
    customer_id: customerId,
    name: connection.customer_name,
    email: connection.customer_email,
  };
  await createCustomer(customer);
  console.log('Customer upserted!');

  console.log('Decrypting credentials...');
  const decrypted = await decrypt(Buffer.from(connection.credentials, 'hex'));
  console.log('Decrypted credentials!');

  console.log(`Pausing Temporal sync ${connection.sync_id}...`);
  await pauseTemporalSync(connection.sync_id);
  console.log('Temporal sync paused!');

  console.log('Checking if connection already exists on Cloud...');
  const numConnectionsOnCloud = await getConnectionCountForCustomerIdOnCloud(customerId);
  if (numConnectionsOnCloud > 0) {
    console.log('Connection already exists on Cloud!');
    console.log();
    return;
  }

  console.log('Creating connection on Cloud...');
  const params = {
    integration_id: integrationId,
    credentials: {
      type: 'oauth2' as const,
      refresh_token: decrypted.refreshToken,
      refreshToken: decrypted.refreshToken,
      instance_url: decrypted.instanceUrl
    },
  };
  await createConnection(customerId, params);
  console.log('Connection created on Cloud!');
  console.log();
}

// Begin
const args = process.argv.slice(2);

if (args[0] === 'list-connections') {
  (async () => {
    const connections = await listConnections();
    for (const connection of connections) {
      console.log(`id: ${connection.id}, provider_name: ${connection.provider_name}, customer_id: ${connection.full_customer_id}`);
    }
  })();
// } else if (args[0] === 'migrate-all') {
//   (async () => {
//     await migrateAll();
//   })();
} else if (args[0] === 'migrate') {
  if (!args[1]) {
    console.error('Please provide at least one connection id');
    process.exit(1);
  }
  const connectionIds = args.slice(1);
  (async () => {
    await migrateMultiple(connectionIds);
    // await migrateSingle(args[1]);
  })();
}
