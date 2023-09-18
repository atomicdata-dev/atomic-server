use std::{fmt, fs, io::Write, path::PathBuf, time::Duration};

use actix_multipart::Field;
use futures::StreamExt;
use opendal::{services::S3, Operator};

use crate::{appstate::AppState, config::Config, errors::AtomicServerResult};

#[derive(Clone, Debug, PartialEq)]
pub enum FileStore {
    S3(S3Config),
    FS(FSConfig),
}

#[derive(Clone, Debug, PartialEq)]
pub struct S3Config {
    pub bucket: String,
    pub path: String,
    pub endpoint: Option<String>,
    pub region: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FSConfig {
    pub path: PathBuf,
}

impl FileStore {
    const S3_PREFIX: &'static str = "s3:";
    const FS_PREFIX: &'static str = "fs:";

    pub fn init_fs_from_config(config: &Config) -> FileStore {
        FileStore::FS(FSConfig {
            path: config.uploads_path.clone(),
        })
    }

    pub fn init_from_config(config: &Config, fs_file_store: FileStore) -> FileStore {
        let opts = &config.opts;
        if let Some(bucket) = &opts.s3_bucket {
            let config = S3Config {
                bucket: bucket.clone(),
                endpoint: opts.s3_endpoint.clone(),
                region: opts.s3_region.clone(),
                path: opts.s3_path.clone().unwrap_or("uploads".to_string()),
            };
            FileStore::S3(config)
        } else {
            fs_file_store
        }
    }

    pub fn get_subject_file_store<'a>(appstate: &'a AppState, subject: &str) -> &'a FileStore {
        if subject.contains(Self::S3_PREFIX) {
            &appstate.file_store
        } else {
            &appstate.fs_file_store
        }
    }

    pub fn get_fs_file_path(&self, file_id: &str) -> AtomicServerResult<PathBuf> {
        if let FileStore::FS(config) = self {
            let fs_file_id = file_id.strip_prefix(Self::FS_PREFIX).unwrap_or(file_id);
            let mut file_path = config.path.clone();
            file_path.push(fs_file_id.to_string());
            Ok(file_path)
        } else {
            Err("Wrong FileStore passed to get_fs_file_path".into())
        }
    }

    pub fn prefix(&self) -> &str {
        match self {
            Self::S3(_) => Self::S3_PREFIX,
            Self::FS(_) => Self::FS_PREFIX,
        }
    }

    pub fn encoded(&self) -> String {
        urlencoding::encode(self.prefix()).into_owned()
    }

    pub async fn upload_file(&self, file_id: &str, field: Field) -> AtomicServerResult<i64> {
        match self {
            FileStore::S3(_) => s3_upload(self, &file_id, field).await,
            FileStore::FS(config) => fs_upload(self, &config, &file_id, field).await,
        }
    }
}

impl fmt::Display for FileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix())
    }
}

async fn fs_upload(
    file_store: &FileStore,
    config: &FSConfig,
    file_id: &str,
    mut field: Field,
) -> AtomicServerResult<i64> {
    std::fs::create_dir_all(config.path.clone())?;

    let mut file = fs::File::create(file_store.get_fs_file_path(file_id)?)?;

    let byte_count: i64 = file
        .metadata()?
        .len()
        .try_into()
        .map_err(|_e| "Too large")?;

    // Field in turn is stream of *Bytes* object
    while let Some(chunk) = field.next().await {
        let data = chunk.map_err(|e| format!("Error while reading multipart data. {}", e))?;
        // TODO: Update a SHA256 hash here for checksum
        file.write_all(&data)?;
    }

    Ok(byte_count)
}

async fn s3_upload(
    file_store: &FileStore,
    file_id: &str,
    mut field: Field,
) -> AtomicServerResult<i64> {
    let mut builder = S3::default();

    if let FileStore::S3(config) = file_store {
        builder.bucket(&config.bucket);
        builder.root(&config.path);
        config.region.as_ref().map(|r| builder.region(&r));
        config.endpoint.as_ref().map(|e| builder.endpoint(&e));
    } else {
        return Err("Uploading to S3 but no S3 config provided".into());
    }

    let op: Operator = Operator::new(builder)?.finish();
    let mut w = op.writer(file_id).await?;
    let mut len = 0;
    while let Some(chunk) = field.next().await {
        let data = chunk.map_err(|e| format!("Error while reading multipart data. {}", e))?;
        len = len + data.len();
        w.write(data).await?;
    }

    let byte_length: i64 = len.try_into().map_err(|_e| "Too large")?;
    w.close().await?;
    Ok(byte_length)
}

pub async fn get_s3_signed_url(
    file_store: &FileStore,
    duration: Duration,
    file_id: &str,
) -> AtomicServerResult<String> {
    let mut builder = S3::default();

    if let FileStore::S3(config) = file_store {
        builder.bucket(&config.bucket);
        builder.root(&config.path);
        config.region.as_ref().map(|r| builder.region(&r));
        config.endpoint.as_ref().map(|e| builder.endpoint(&e));
    } else {
        return Err("Downloading from S3 but no S3 config provided".into());
    }

    let op: Operator = Operator::new(builder)?.finish();

    let uri = op.presign_read(file_id, duration).await?.uri().to_string();

    Ok(uri)
}
