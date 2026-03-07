// Mongo inicial
if (!db.getCollectionNames().includes('tenant')) { db.createCollection('tenant'); }
db.tenant.createIndex({ slug: 1 }, { unique: true });

if (!db.getCollectionNames().includes('client')) { db.createCollection('client'); }
db.client.createIndex({ client_id: 1 }, { unique: true });
db.client.createIndex({ tenant_id: 1 });

if (!db.getCollectionNames().includes('client_version')) { db.createCollection('client_version'); }
db.client_version.createIndex({ client_id: 1, status: 1 });

if (!db.getCollectionNames().includes('app_user')) { db.createCollection('app_user'); }
db.app_user.createIndex({ tenant_id: 1, email: 1 }, { unique: true });

if (!db.getCollectionNames().includes('identity')) { db.createCollection('identity'); }
db.identity.createIndex({ user_id: 1 });
db.identity.createIndex({ provider: 1, provider_user_id: 1 });
