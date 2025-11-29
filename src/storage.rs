use anyhow::{Context, Result};
use heed::{Database, EnvOpenOptions};
use heed::types::*;
use lmdb_blob_store::LmdbBlobStore;
use hashtree::{
    TreeBuilder, TreeReader, StreamBuilder, BuilderConfig,
    sha256, to_hex, from_hex, Hash, TreeNode, DirEntry as HashTreeDirEntry,
};
use hashtree::store::Store;
use sha2::{Sha256, Digest}; // Used in tests
use std::path::Path;
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;
use futures::executor::block_on as sync_block_on;

pub struct NostaStore {
    env: heed::Env,
    /// Set of pinned hashes (hex strings, prevents garbage collection)
    pins: Database<Str, Unit>,
    /// Maps SHA256 hex → root hash hex (for blossom compatibility)
    sha256_index: Database<Str, Str>,
    /// Maps SHA256 hex → pubkey (blob ownership for blossom)
    blob_owners: Database<Str, Str>,
    /// Maps pubkey → blob metadata JSON (for blossom list)
    pubkey_blobs: Database<Str, Bytes>,
    /// Raw blob storage (sha256-addressed) - implements hashtree Store trait
    blobs: Arc<LmdbBlobStore>,
}

impl NostaStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(10 * 1024 * 1024 * 1024) // 10GB
                .max_dbs(5)
                .open(path)?
        };

        let mut wtxn = env.write_txn()?;
        let pins = env.create_database(&mut wtxn, Some("pins"))?;
        let sha256_index = env.create_database(&mut wtxn, Some("sha256_index"))?;
        let blob_owners = env.create_database(&mut wtxn, Some("blob_owners"))?;
        let pubkey_blobs = env.create_database(&mut wtxn, Some("pubkey_blobs"))?;
        wtxn.commit()?;

        // Create blob store in subdirectory
        let blobs = Arc::new(LmdbBlobStore::new(path.join("blobs"))
            .map_err(|e| anyhow::anyhow!("Failed to create blob store: {}", e))?);

        Ok(Self {
            env,
            pins,
            sha256_index,
            blob_owners,
            pubkey_blobs,
            blobs,
        })
    }

    /// Get access to the underlying blob store.
    pub fn blob_store(&self) -> &LmdbBlobStore {
        &self.blobs
    }

    /// Get the blob store as Arc for async operations.
    pub fn blob_store_arc(&self) -> Arc<LmdbBlobStore> {
        Arc::clone(&self.blobs)
    }

    /// Upload a file and return its hash (hex)
    pub fn upload_file<P: AsRef<Path>>(&self, file_path: P) -> Result<String> {
        let file_path = file_path.as_ref();
        let file_content = std::fs::read(file_path)?;

        // Compute SHA256 hash of file content for blossom compatibility
        let content_sha256 = sha256(&file_content);
        let sha256_hex = to_hex(&content_sha256);

        // Use hashtree to store the file (handles chunking if needed)
        let store = Arc::clone(&self.blobs);
        let builder = TreeBuilder::new(BuilderConfig::new(store));

        let result = sync_block_on(async {
            builder.put_file(&file_content).await
        }).context("Failed to store file")?;

        let root_hex = to_hex(&result.hash);

        let mut wtxn = self.env.write_txn()?;

        // Store SHA256 → root hash mapping for blossom compatibility
        self.sha256_index.put(&mut wtxn, &sha256_hex, &root_hex)?;

        // Auto-pin on upload
        self.pins.put(&mut wtxn, &root_hex, &())?;

        wtxn.commit()?;

        Ok(root_hex)
    }

    /// Upload a file from a stream with progress callbacks
    pub fn upload_file_stream<R: Read, F>(
        &self,
        mut reader: R,
        _file_name: impl Into<String>,
        mut callback: F,
    ) -> Result<String>
    where
        F: FnMut(&str),
    {
        // Read all data first to compute SHA256 and stream to hashtree
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        // Compute SHA256 hash of file content
        let content_sha256 = sha256(&data);
        let sha256_hex = to_hex(&content_sha256);

        // Use hashtree StreamBuilder for streaming upload
        let store = Arc::clone(&self.blobs);
        let config = BuilderConfig::new(store);

        let (root_hash, _size) = sync_block_on(async {
            let mut stream = StreamBuilder::new(config);

            // Stream data in chunks
            let chunk_size = 256 * 1024; // 256KB chunks
            for chunk in data.chunks(chunk_size) {
                stream.append(chunk).await?;

                // Get intermediate root for progress callback
                if let Ok(Some(intermediate_hash)) = stream.current_root().await {
                    callback(&to_hex(&intermediate_hash));
                }
            }

            stream.finalize().await
        }).context("Failed to store file stream")?;

        let root_hex = to_hex(&root_hash);

        let mut wtxn = self.env.write_txn()?;

        // Store SHA256 → root hash mapping for blossom compatibility
        self.sha256_index.put(&mut wtxn, &sha256_hex, &root_hex)?;

        // Auto-pin on upload
        self.pins.put(&mut wtxn, &root_hex, &())?;

        wtxn.commit()?;

        Ok(root_hex)
    }

    /// Upload a directory and return its root hash (hex)
    pub fn upload_dir<P: AsRef<Path>>(&self, dir_path: P) -> Result<String> {
        let dir_path = dir_path.as_ref();

        let store = Arc::clone(&self.blobs);
        let builder = TreeBuilder::new(BuilderConfig::new(store));

        let root_hash = sync_block_on(async {
            self.upload_dir_recursive(&builder, dir_path).await
        }).context("Failed to upload directory")?;

        let root_hex = to_hex(&root_hash);

        let mut wtxn = self.env.write_txn()?;
        self.pins.put(&mut wtxn, &root_hex, &())?;
        wtxn.commit()?;

        Ok(root_hex)
    }

    async fn upload_dir_recursive<S: Store>(&self, builder: &TreeBuilder<S>, path: &Path) -> Result<Hash> {
        let mut entries = Vec::new();

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let name = entry.file_name().to_string_lossy().to_string();

            if file_type.is_file() {
                let content = std::fs::read(entry.path())?;
                let result = builder.put_file(&content).await
                    .map_err(|e| anyhow::anyhow!("Failed to upload file {}: {}", name, e))?;
                entries.push(HashTreeDirEntry::new(name, result.hash).with_size(result.size));
            } else if file_type.is_dir() {
                let hash = Box::pin(self.upload_dir_recursive(builder, &entry.path())).await?;
                entries.push(HashTreeDirEntry::new(name, hash));
            }
        }

        builder.put_directory(entries, None).await
            .map_err(|e| anyhow::anyhow!("Failed to create directory node: {}", e))
    }

    /// Get tree node by hash (hex)
    pub fn get_tree_node(&self, hash_hex: &str) -> Result<Option<TreeNode>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = Arc::clone(&self.blobs);
        let reader = TreeReader::new(store);

        sync_block_on(async {
            reader.get_tree_node(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to get tree node: {}", e))
        })
    }

    /// Look up root hash by SHA256 hash (blossom compatibility)
    pub fn get_cid_by_sha256(&self, sha256_hex: &str) -> Result<Option<String>> {
        let rtxn = self.env.read_txn()?;
        Ok(self.sha256_index.get(&rtxn, sha256_hex)?.map(|s| s.to_string()))
    }

    /// Store a raw blob, returns SHA256 hash as hex.
    pub fn put_blob(&self, data: &[u8]) -> Result<String> {
        let hash = sha256(data);
        self.blobs.put_sync(hash, data)
            .map_err(|e| anyhow::anyhow!("Failed to store blob: {}", e))?;
        Ok(to_hex(&hash))
    }

    /// Get a raw blob by SHA256 hex hash.
    pub fn get_blob(&self, sha256_hex: &str) -> Result<Option<Vec<u8>>> {
        let hash = from_hex(sha256_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
        self.blobs.get_sync(&hash)
            .map_err(|e| anyhow::anyhow!("Failed to get blob: {}", e))
    }

    /// Check if a blob exists by SHA256 hex hash.
    pub fn blob_exists(&self, sha256_hex: &str) -> Result<bool> {
        let hash = from_hex(sha256_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
        self.blobs.exists(&hash)
            .map_err(|e| anyhow::anyhow!("Failed to check blob: {}", e))
    }

    // === Blossom ownership tracking ===

    /// Set the owner (pubkey) of a blob for Blossom protocol
    pub fn set_blob_owner(&self, sha256_hex: &str, pubkey: &str) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut wtxn = self.env.write_txn()?;

        // Store sha256 -> pubkey mapping
        self.blob_owners.put(&mut wtxn, sha256_hex, pubkey)?;

        // Get existing blobs for this pubkey
        let mut blobs: Vec<BlobMetadata> = self
            .pubkey_blobs
            .get(&wtxn, pubkey)?
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();

        // Check if blob already exists for this pubkey
        if !blobs.iter().any(|b| b.sha256 == sha256_hex) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Get size from root hash lookup
            let size = self
                .get_cid_by_sha256(sha256_hex)?
                .and_then(|cid| self.get_file_chunk_metadata(&cid).ok().flatten())
                .map(|m| m.total_size)
                .unwrap_or(0);

            blobs.push(BlobMetadata {
                sha256: sha256_hex.to_string(),
                size,
                mime_type: "application/octet-stream".to_string(),
                uploaded: now,
            });

            let blobs_json = serde_json::to_vec(&blobs)?;
            self.pubkey_blobs.put(&mut wtxn, pubkey, &blobs_json)?;
        }

        wtxn.commit()?;
        Ok(())
    }

    /// Get the owner (pubkey) of a blob
    pub fn get_blob_owner(&self, sha256_hex: &str) -> Result<Option<String>> {
        let rtxn = self.env.read_txn()?;
        Ok(self.blob_owners.get(&rtxn, sha256_hex)?.map(|s| s.to_string()))
    }

    /// Delete a blossom blob and remove ownership tracking
    pub fn delete_blossom_blob(&self, sha256_hex: &str) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;

        // Get owner first
        let owner = self.blob_owners.get(&wtxn, sha256_hex)?.map(|s| s.to_string());

        // Delete from sha256_index
        let root_hex = self.sha256_index.get(&wtxn, sha256_hex)?.map(|s| s.to_string());
        if let Some(ref root_hex) = root_hex {
            // Unpin
            self.pins.delete(&mut wtxn, root_hex)?;
        }
        self.sha256_index.delete(&mut wtxn, sha256_hex)?;

        // Delete ownership
        self.blob_owners.delete(&mut wtxn, sha256_hex)?;

        // Remove from pubkey's blob list
        if let Some(ref pubkey) = owner {
            if let Some(blobs_bytes) = self.pubkey_blobs.get(&wtxn, pubkey)? {
                if let Ok(mut blobs) = serde_json::from_slice::<Vec<BlobMetadata>>(blobs_bytes) {
                    blobs.retain(|b| b.sha256 != sha256_hex);
                    let blobs_json = serde_json::to_vec(&blobs)?;
                    self.pubkey_blobs.put(&mut wtxn, pubkey, &blobs_json)?;
                }
            }
        }

        // Delete raw blob (by content hash)
        let hash = from_hex(sha256_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
        let _ = self.blobs.delete_sync(&hash);

        wtxn.commit()?;
        Ok(root_hex.is_some())
    }

    /// List all blobs owned by a pubkey (for Blossom /list endpoint)
    pub fn list_blobs_by_pubkey(&self, pubkey: &str) -> Result<Vec<crate::server::blossom::BlobDescriptor>> {
        let rtxn = self.env.read_txn()?;

        let blobs: Vec<BlobMetadata> = self
            .pubkey_blobs
            .get(&rtxn, pubkey)?
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();

        Ok(blobs
            .into_iter()
            .map(|b| crate::server::blossom::BlobDescriptor {
                url: format!("/{}", b.sha256),
                sha256: b.sha256,
                size: b.size,
                mime_type: b.mime_type,
                uploaded: b.uploaded,
            })
            .collect())
    }

    /// Get a single chunk/blob by hash (hex)
    pub fn get_chunk(&self, chunk_hex: &str) -> Result<Option<Vec<u8>>> {
        let hash = from_hex(chunk_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;
        self.blobs.get_sync(&hash)
            .map_err(|e| anyhow::anyhow!("Failed to get chunk: {}", e))
    }

    /// Get file content by hash (hex)
    pub fn get_file(&self, hash_hex: &str) -> Result<Option<Vec<u8>>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = Arc::clone(&self.blobs);
        let reader = TreeReader::new(store);

        sync_block_on(async {
            reader.read_file(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))
        })
    }

    /// Get chunk metadata for a file (chunk list, sizes, total size)
    pub fn get_file_chunk_metadata(&self, hash_hex: &str) -> Result<Option<FileChunkMetadata>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = Arc::clone(&self.blobs);
        let reader = TreeReader::new(store.clone());

        sync_block_on(async {
            // Get total size
            let total_size = reader.get_size(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to get size: {}", e))?;

            // Check if it's a tree (chunked) or blob
            let is_tree = reader.is_tree(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to check tree: {}", e))?;

            if !is_tree {
                // Single blob, not chunked
                return Ok(Some(FileChunkMetadata {
                    total_size,
                    chunk_cids: vec![],
                    chunk_sizes: vec![],
                    is_chunked: false,
                }));
            }

            // Get tree node to extract chunk info
            let node = match reader.get_tree_node(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to get tree node: {}", e))? {
                Some(n) => n,
                None => return Ok(None),
            };

            // Check if it's a directory (has named links)
            let is_directory = reader.is_directory(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to check directory: {}", e))?;

            if is_directory {
                return Ok(None); // Not a file
            }

            // Extract chunk info from links
            let chunk_cids: Vec<String> = node.links.iter().map(|l| to_hex(&l.hash)).collect();
            let chunk_sizes: Vec<u64> = node.links.iter().map(|l| l.size.unwrap_or(0)).collect();

            Ok(Some(FileChunkMetadata {
                total_size,
                chunk_cids,
                chunk_sizes,
                is_chunked: !node.links.is_empty(),
            }))
        })
    }

    /// Get byte range from file
    pub fn get_file_range(&self, hash_hex: &str, start: u64, end: Option<u64>) -> Result<Option<(Vec<u8>, u64)>> {
        let metadata = match self.get_file_chunk_metadata(hash_hex)? {
            Some(m) => m,
            None => return Ok(None),
        };

        if metadata.total_size == 0 {
            return Ok(Some((Vec::new(), 0)));
        }

        if start >= metadata.total_size {
            return Ok(None);
        }

        let end = end.unwrap_or(metadata.total_size - 1).min(metadata.total_size - 1);

        // For non-chunked files, load entire file
        if !metadata.is_chunked {
            let content = self.get_file(hash_hex)?.unwrap_or_default();
            let range_content = if start < content.len() as u64 {
                content[start as usize..=(end as usize).min(content.len() - 1)].to_vec()
            } else {
                Vec::new()
            };
            return Ok(Some((range_content, metadata.total_size)));
        }

        // For chunked files, load only needed chunks
        let mut result = Vec::new();
        let mut current_offset = 0u64;

        for (i, chunk_cid) in metadata.chunk_cids.iter().enumerate() {
            let chunk_size = metadata.chunk_sizes[i];
            let chunk_end = current_offset + chunk_size - 1;

            // Check if this chunk overlaps with requested range
            if chunk_end >= start && current_offset <= end {
                let chunk_content = match self.get_chunk(chunk_cid)? {
                    Some(content) => content,
                    None => {
                        return Err(anyhow::anyhow!("Chunk {} not found", chunk_cid));
                    }
                };

                let chunk_read_start = if current_offset >= start {
                    0
                } else {
                    (start - current_offset) as usize
                };

                let chunk_read_end = if chunk_end <= end {
                    chunk_size as usize - 1
                } else {
                    (end - current_offset) as usize
                };

                result.extend_from_slice(&chunk_content[chunk_read_start..=chunk_read_end]);
            }

            current_offset += chunk_size;

            if current_offset > end {
                break;
            }
        }

        Ok(Some((result, metadata.total_size)))
    }

    /// Stream file range as chunks
    pub fn stream_file_range_chunks(
        &self,
        hash_hex: &str,
        start: u64,
        end: u64,
    ) -> Result<Option<FileRangeChunks<'_>>> {
        let metadata = match self.get_file_chunk_metadata(hash_hex)? {
            Some(m) => m,
            None => return Ok(None),
        };

        if metadata.total_size == 0 || start >= metadata.total_size {
            return Ok(None);
        }

        let end = end.min(metadata.total_size - 1);

        Ok(Some(FileRangeChunks {
            store: self,
            metadata,
            start,
            end,
            current_chunk_idx: 0,
            current_offset: 0,
        }))
    }

    /// Stream file range as chunks using Arc for async/Send contexts
    pub fn stream_file_range_chunks_owned(
        self: Arc<Self>,
        hash_hex: &str,
        start: u64,
        end: u64,
    ) -> Result<Option<FileRangeChunksOwned>> {
        let metadata = match self.get_file_chunk_metadata(hash_hex)? {
            Some(m) => m,
            None => return Ok(None),
        };

        if metadata.total_size == 0 || start >= metadata.total_size {
            return Ok(None);
        }

        let end = end.min(metadata.total_size - 1);

        Ok(Some(FileRangeChunksOwned {
            store: self,
            metadata,
            start,
            end,
            current_chunk_idx: 0,
            current_offset: 0,
        }))
    }

    /// Get directory structure by hash (hex)
    pub fn get_directory_listing(&self, hash_hex: &str) -> Result<Option<DirectoryListing>> {
        let hash = from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let store = Arc::clone(&self.blobs);
        let reader = TreeReader::new(store);

        sync_block_on(async {
            // Check if it's a directory
            let is_dir = reader.is_directory(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to check directory: {}", e))?;

            if !is_dir {
                return Ok(None);
            }

            // Get directory entries
            let tree_entries = reader.list_directory(&hash).await
                .map_err(|e| anyhow::anyhow!("Failed to list directory: {}", e))?;

            let entries: Vec<DirEntry> = tree_entries.into_iter().map(|e| DirEntry {
                name: e.name,
                cid: to_hex(&e.hash),
                is_directory: e.is_tree,
                size: e.size.unwrap_or(0),
            }).collect();

            Ok(Some(DirectoryListing {
                dir_name: String::new(), // hashtree doesn't store directory name
                entries,
            }))
        })
    }

    /// Pin a hash (prevent garbage collection)
    pub fn pin(&self, hash_hex: &str) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.pins.put(&mut wtxn, hash_hex, &())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Unpin a hash (allow garbage collection)
    pub fn unpin(&self, hash_hex: &str) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.pins.delete(&mut wtxn, hash_hex)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Check if hash is pinned
    pub fn is_pinned(&self, hash_hex: &str) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        Ok(self.pins.get(&rtxn, hash_hex)?.is_some())
    }

    /// List all pinned hashes
    pub fn list_pins(&self) -> Result<Vec<String>> {
        let rtxn = self.env.read_txn()?;
        let mut pins = Vec::new();

        for item in self.pins.iter(&rtxn)? {
            let (hash_hex, _) = item?;
            pins.push(hash_hex.to_string());
        }

        Ok(pins)
    }

    /// List all pinned hashes with names
    pub fn list_pins_with_names(&self) -> Result<Vec<PinnedItem>> {
        let rtxn = self.env.read_txn()?;
        let store = Arc::clone(&self.blobs);
        let reader = TreeReader::new(store);
        let mut pins = Vec::new();

        for item in self.pins.iter(&rtxn)? {
            let (hash_hex, _) = item?;
            let hash_hex_str = hash_hex.to_string();

            // Try to determine if it's a directory
            let is_directory = if let Ok(hash) = from_hex(&hash_hex_str) {
                sync_block_on(async {
                    reader.is_directory(&hash).await.unwrap_or(false)
                })
            } else {
                false
            };

            pins.push(PinnedItem {
                cid: hash_hex_str,
                name: "Unknown".to_string(), // hashtree doesn't store names
                is_directory,
            });
        }

        Ok(pins)
    }

    /// List all stored hashes
    pub fn list_cids(&self) -> Result<Vec<String>> {
        let hashes = self.blobs.list()
            .map_err(|e| anyhow::anyhow!("Failed to list hashes: {}", e))?;
        Ok(hashes.iter().map(to_hex).collect())
    }

    /// Get storage statistics
    pub fn get_storage_stats(&self) -> Result<StorageStats> {
        let rtxn = self.env.read_txn()?;
        let total_pins = self.pins.len(&rtxn)? as usize;

        let stats = self.blobs.stats()
            .map_err(|e| anyhow::anyhow!("Failed to get stats: {}", e))?;

        Ok(StorageStats {
            total_dags: stats.count,
            pinned_dags: total_pins,
            total_bytes: stats.total_bytes,
        })
    }

    /// Garbage collect unpinned content
    pub fn gc(&self) -> Result<GcStats> {
        let rtxn = self.env.read_txn()?;

        // Get all pinned hashes
        let pinned: HashSet<String> = self.pins.iter(&rtxn)?
            .filter_map(|item| item.ok())
            .map(|(hash_hex, _)| hash_hex.to_string())
            .collect();

        drop(rtxn);

        // Get all stored hashes
        let all_hashes = self.blobs.list()
            .map_err(|e| anyhow::anyhow!("Failed to list hashes: {}", e))?;

        // Delete unpinned hashes
        let mut deleted = 0;
        let mut freed_bytes = 0u64;

        for hash in all_hashes {
            let hash_hex = to_hex(&hash);
            if !pinned.contains(&hash_hex) {
                if let Ok(Some(data)) = self.blobs.get_sync(&hash) {
                    freed_bytes += data.len() as u64;
                    let _ = self.blobs.delete_sync(&hash);
                    deleted += 1;
                }
            }
        }

        Ok(GcStats {
            deleted_dags: deleted,
            freed_bytes,
        })
    }
}

#[derive(Debug)]
pub struct StorageStats {
    pub total_dags: usize,
    pub pinned_dags: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct FileChunkMetadata {
    pub total_size: u64,
    pub chunk_cids: Vec<String>,
    pub chunk_sizes: Vec<u64>,
    pub is_chunked: bool,
}

/// Iterator that yields chunks on demand for streaming
pub struct FileRangeChunks<'a> {
    store: &'a NostaStore,
    metadata: FileChunkMetadata,
    start: u64,
    end: u64,
    current_chunk_idx: usize,
    current_offset: u64,
}

impl<'a> Iterator for FileRangeChunks<'a> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.metadata.is_chunked || self.current_chunk_idx >= self.metadata.chunk_cids.len() {
            return None;
        }

        if self.current_offset > self.end {
            return None;
        }

        let chunk_cid = &self.metadata.chunk_cids[self.current_chunk_idx];
        let chunk_size = self.metadata.chunk_sizes[self.current_chunk_idx];
        let chunk_end = self.current_offset + chunk_size - 1;

        self.current_chunk_idx += 1;

        if chunk_end < self.start || self.current_offset > self.end {
            self.current_offset += chunk_size;
            return self.next();
        }

        let chunk_content = match self.store.get_chunk(chunk_cid) {
            Ok(Some(content)) => content,
            Ok(None) => {
                return Some(Err(anyhow::anyhow!("Chunk {} not found", chunk_cid)));
            }
            Err(e) => {
                return Some(Err(e));
            }
        };

        let chunk_read_start = if self.current_offset >= self.start {
            0
        } else {
            (self.start - self.current_offset) as usize
        };

        let chunk_read_end = if chunk_end <= self.end {
            chunk_size as usize - 1
        } else {
            (self.end - self.current_offset) as usize
        };

        let result = chunk_content[chunk_read_start..=chunk_read_end].to_vec();
        self.current_offset += chunk_size;

        Some(Ok(result))
    }
}

/// Owned iterator for async streaming
pub struct FileRangeChunksOwned {
    store: Arc<NostaStore>,
    metadata: FileChunkMetadata,
    start: u64,
    end: u64,
    current_chunk_idx: usize,
    current_offset: u64,
}

impl Iterator for FileRangeChunksOwned {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.metadata.is_chunked || self.current_chunk_idx >= self.metadata.chunk_cids.len() {
            return None;
        }

        if self.current_offset > self.end {
            return None;
        }

        let chunk_cid = &self.metadata.chunk_cids[self.current_chunk_idx];
        let chunk_size = self.metadata.chunk_sizes[self.current_chunk_idx];
        let chunk_end = self.current_offset + chunk_size - 1;

        self.current_chunk_idx += 1;

        if chunk_end < self.start || self.current_offset > self.end {
            self.current_offset += chunk_size;
            return self.next();
        }

        let chunk_content = match self.store.get_chunk(chunk_cid) {
            Ok(Some(content)) => content,
            Ok(None) => {
                return Some(Err(anyhow::anyhow!("Chunk {} not found", chunk_cid)));
            }
            Err(e) => {
                return Some(Err(e));
            }
        };

        let chunk_read_start = if self.current_offset >= self.start {
            0
        } else {
            (self.start - self.current_offset) as usize
        };

        let chunk_read_end = if chunk_end <= self.end {
            chunk_size as usize - 1
        } else {
            (self.end - self.current_offset) as usize
        };

        let result = chunk_content[chunk_read_start..=chunk_read_end].to_vec();
        self.current_offset += chunk_size;

        Some(Ok(result))
    }
}

#[derive(Debug)]
pub struct GcStats {
    pub deleted_dags: usize,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub cid: String,
    pub is_directory: bool,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct DirectoryListing {
    pub dir_name: String,
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, Clone)]
pub struct PinnedItem {
    pub cid: String,
    pub name: String,
    pub is_directory: bool,
}

/// Blob metadata for Blossom protocol
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobMetadata {
    pub sha256: String,
    pub size: u64,
    pub mime_type: String,
    pub uploaded: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_create_store() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        let cids = store.list_cids()?;
        assert_eq!(cids.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_and_get_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Create a test file
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Hello, Nosta!")?;

        // Upload the file
        let cid = store.upload_file(&test_file)?;
        assert!(!cid.is_empty());

        // Get the file back by CID
        let content = store.get_file(&cid)?;
        assert!(content.is_some());
        assert_eq!(content.unwrap(), b"Hello, Nosta!");

        // Check it's auto-pinned
        assert!(store.is_pinned(&cid)?);

        Ok(())
    }

    #[tokio::test]
    async fn test_deduplication() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Create a test file
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Deduplicate me!")?;

        // Upload same file multiple times
        let cid1 = store.upload_file(&test_file)?;
        let cid2 = store.upload_file(&test_file)?;
        let cid3 = store.upload_file(&test_file)?;

        // All should have same CID
        assert_eq!(cid1, cid2);
        assert_eq!(cid2, cid3);

        Ok(())
    }

    #[tokio::test]
    async fn test_pinning() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Pin me!")?;

        // Upload and pin
        let cid = store.upload_file(&test_file)?;
        assert!(store.is_pinned(&cid)?);

        // Unpin
        store.unpin(&cid)?;
        assert!(!store.is_pinned(&cid)?);

        // Re-pin
        store.pin(&cid)?;
        assert!(store.is_pinned(&cid)?);

        Ok(())
    }

    #[tokio::test]
    async fn test_garbage_collection() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Create two different files
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        std::fs::write(&file1, b"Keep me!")?;
        std::fs::write(&file2, b"Delete me!")?;

        // Upload both
        let cid1 = store.upload_file(&file1)?;
        let cid2 = store.upload_file(&file2)?;

        // Unpin second file
        store.unpin(&cid2)?;

        // Run GC
        let gc_stats = store.gc()?;
        assert!(gc_stats.deleted_dags >= 1);
        assert!(gc_stats.freed_bytes > 0);

        // First file should still be accessible
        assert!(store.get_file(&cid1)?.is_some());

        // Second file should be gone
        assert!(store.get_file(&cid2)?.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_bitcoin_pdf() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        let bitcoin_pdf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/bitcoin.pdf");

        if !bitcoin_pdf.exists() {
            return Ok(()); // Skip if file doesn't exist
        }

        // Upload the file
        let cid = store.upload_file(&bitcoin_pdf)?;
        assert!(!cid.is_empty());

        // Verify we can retrieve it by CID
        let content = store.get_file(&cid)?;
        assert!(content.is_some());

        // Verify the content matches
        let original = std::fs::read(&bitcoin_pdf)?;
        assert_eq!(content.unwrap(), original);

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Create a test directory structure
        let test_dir = temp_dir.path().join("testdir");
        std::fs::create_dir(&test_dir)?;
        std::fs::write(test_dir.join("file1.txt"), b"File 1")?;
        std::fs::write(test_dir.join("file2.txt"), b"File 2")?;

        let subdir = test_dir.join("subdir");
        std::fs::create_dir(&subdir)?;
        std::fs::write(subdir.join("file3.txt"), b"File 3")?;

        // Upload the directory
        let cid = store.upload_dir(&test_dir)?;
        assert!(!cid.is_empty());

        // Get directory listing
        let listing = store.get_directory_listing(&cid)?;
        assert!(listing.is_some());

        let listing = listing.unwrap();
        assert!(listing.entries.len() > 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_streaming_large_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Generate 30MB file
        let size = 30 * 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // Calculate expected content hash
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let expected_hash = hasher.finalize().to_vec();

        let cursor = std::io::Cursor::new(data.clone());

        // Track intermediate CIDs
        let mut intermediate_cids = Vec::new();
        let cid = store.upload_file_stream(cursor, "large.bin", |intermediate_cid| {
            intermediate_cids.push(intermediate_cid.to_string());
        })?;

        assert!(!cid.is_empty());
        assert!(intermediate_cids.len() > 1, "Should have multiple intermediate CIDs");

        // Verify it's NOT detected as directory
        let listing = store.get_directory_listing(&cid)?;
        assert!(listing.is_none(), "Chunked file should not be treated as directory");

        // Verify retrieval
        let content = store.get_file(&cid)?;
        assert!(content.is_some());
        let retrieved = content.unwrap();
        assert_eq!(retrieved.len(), size);

        // Verify content hash matches
        let mut hasher = Sha256::new();
        hasher.update(&retrieved);
        let actual_hash = hasher.finalize().to_vec();
        assert_eq!(actual_hash, expected_hash, "Content hash mismatch");

        Ok(())
    }

    #[tokio::test]
    async fn test_on_demand_chunk_loading() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Create a large file that will be chunked (10MB, ~40 chunks at 256KB)
        let size = 10 * 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let cursor = std::io::Cursor::new(data.clone());
        let cid = store.upload_file_stream(cursor, "large.bin", |_| {})?;

        // Get metadata to verify chunking
        let metadata = store.get_file_chunk_metadata(&cid)?;
        assert!(metadata.is_some());
        let metadata = metadata.unwrap();
        assert!(metadata.is_chunked, "File should be chunked");
        assert!(metadata.chunk_cids.len() >= 5, "Should have multiple chunks");

        // Request only first 1KB - should only need first chunk
        let (range_content, total_size) = store.get_file_range(&cid, 0, Some(1023))?.unwrap();
        assert_eq!(range_content.len(), 1024);
        assert_eq!(&range_content[..], &data[0..1024]);
        assert_eq!(total_size, size as u64);

        // Request middle range that crosses chunk boundary
        let mid = 2 * 1024 * 1024; // 2MB in
        let (range_content, _) = store.get_file_range(&cid, mid as u64, Some((mid + 2047) as u64))?.unwrap();
        assert_eq!(range_content.len(), 2048);
        assert_eq!(&range_content[..], &data[mid..(mid + 2048)]);

        // Test streaming iterator
        let chunks = store.stream_file_range_chunks(&cid, 0, 1023)?.unwrap();
        let mut collected = Vec::new();
        for chunk in chunks {
            let chunk_data = chunk?;
            collected.extend_from_slice(&chunk_data);
        }
        assert_eq!(collected.len(), 1024);
        assert_eq!(&collected[..], &data[0..1024]);

        Ok(())
    }

    #[tokio::test]
    async fn test_chunk_iterator() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Create a 15MB file for multiple chunks
        let size = 15 * 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let cursor = std::io::Cursor::new(data.clone());
        let cid = store.upload_file_stream(cursor, "huge.bin", |_| {})?;

        // Stream a 100MB range (will be clamped to file size)
        let range_end = size as u64 - 1;
        let chunks_iter = store.stream_file_range_chunks(&cid, 0, range_end)?.unwrap();

        let mut total_bytes = 0;
        let mut chunk_count = 0;
        for chunk_result in chunks_iter {
            let chunk_data = chunk_result?;
            total_bytes += chunk_data.len();
            chunk_count += 1;
        }

        assert_eq!(total_bytes, size, "Should yield all bytes");
        assert!(chunk_count > 1, "Should have multiple chunks");

        Ok(())
    }

    #[tokio::test]
    async fn test_blob_store() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = NostaStore::new(temp_dir.path().join("db"))?;

        // Store a blob
        let data = b"raw blob data";
        let hash = store.put_blob(data)?;

        // Verify hash is 64 hex chars (sha256)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Retrieve it
        assert!(store.blob_exists(&hash)?);
        let retrieved = store.get_blob(&hash)?;
        assert_eq!(retrieved, Some(data.to_vec()));

        // Non-existent blob
        let fake = "0".repeat(64);
        assert!(!store.blob_exists(&fake)?);
        assert_eq!(store.get_blob(&fake)?, None);

        Ok(())
    }
}
