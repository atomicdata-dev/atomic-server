use reflector_rs::AtomicStorage;
use syncables::{Ontology, Record, Storage, StorageError};

/// Separate each signed-in user's source data, including APIs whose namespace
/// is the account-relative `primary`. Ontology terms remain shared definitions.
pub struct AgentStorage {
    pub inner: AtomicStorage<atomic_lib::Db>,
    pub prefix: String,
}
impl AgentStorage {
    pub fn namespace(&self, namespace: &str) -> String {
        format!("{}/{namespace}", self.prefix)
    }
}
#[async_trait::async_trait]
impl Storage for AgentStorage {
    async fn put(&self, record: &Record) -> Result<(), StorageError> {
        let mut record = record.clone();
        record.namespace = self.namespace(&record.namespace);
        let result = self.inner.put(&record).await;
        // Let the import deadline run during large batches of local writes.
        tokio::task::yield_now().await;
        result
    }
    async fn get(
        &self,
        ns: &str,
        resource: &str,
        id: &str,
    ) -> Result<Option<Record>, StorageError> {
        let mut record = self.inner.get(&self.namespace(ns), resource, id).await?;
        if let Some(record) = &mut record {
            record.namespace = ns.into();
        }
        Ok(record)
    }
    async fn list(&self, ns: &str, resource: &str) -> Result<Vec<Record>, StorageError> {
        let mut records = self.inner.list(&self.namespace(ns), resource).await?;
        for record in &mut records {
            record.namespace = ns.into();
        }
        Ok(records)
    }
    async fn delete(&self, ns: &str, resource: &str, id: &str) -> Result<(), StorageError> {
        self.inner.delete(&self.namespace(ns), resource, id).await
    }
    async fn put_ontology(&self, ontology: &Ontology) -> Result<(), StorageError> {
        self.inner.put_ontology(ontology).await
    }
}
