use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub use hasher::{Hasher, HasherError, HashingFunction};
pub use store::{InStoreCounter, InStoreTable, InStoreTableError, Store, StoreError, SubKey};

use crate::{
    formatting::{format_peaks, format_proof, PeaksFormattingOptions},
    helpers::{
        array_deduplicate, element_index_to_leaf_index, find_peaks, find_siblings, get_peak_info,
        leaf_count_to_append_no_merges, leaf_count_to_peaks_count, mmr_size_to_leaf_count,
        AppendResult, Proof, ProofOptions, TreeMetadataKeys,
    },
};

use super::{FormattingError, PeaksOptions, TreeMetadataKeysError};

/// An error that can occur when using an MMR
#[derive(Error, Debug)]
pub enum MMRError {
    #[error("Store error: {0}")]
    Store(#[from] StoreError),
    #[error("Hasher error: {0}")]
    Hasher(#[from] HasherError),
    #[error("Cannot do with non-empty MMR. Please provide an empty store or change the MMR id.")]
    NonEmptyMMR,
    #[error("Invalid element count")]
    InvalidElementCount,
    #[error("Invalid element index")]
    InvalidElementIndex,
    #[error("Invalid peaks count")]
    InvalidPeaksCount,
    #[error("InStoreTable error: {0}")]
    InStoreTable(#[from] InStoreTableError),
    #[error("TreeMetadataKeys error: {0}")]
    TreeMetadataKeys(#[from] TreeMetadataKeysError),
    #[error("Formatting error: {0}")]
    Formatting(#[from] FormattingError),
    #[error("No hash found for index {0}")]
    NoHashFoundForIndex(usize),
}

#[derive(Debug)]
pub struct MMR {
    pub store: Arc<dyn Store>,
    pub hasher: Arc<dyn Hasher>,
    pub mmr_id: String,
    pub leaves_count: InStoreCounter,
    pub elements_count: InStoreCounter,
    pub hashes: InStoreTable,
    pub root_hash: InStoreTable,
    #[cfg(feature = "stacked_mmr")]
    pub sub_mmrs: SizesToMMRs,
}

#[derive(Debug, Clone)]
pub struct MmrMetadata {
    pub mmr_id: String,
    pub store: Arc<dyn Store>,
    pub hasher: HashingFunction,
}

/// A tuple of the size at which the MMR is stacked and the MMR itself.
#[cfg(feature = "stacked_mmr")]
pub type SizesToMMRs = Vec<(usize, MmrMetadata)>;

impl MMR {
    pub fn new(store: Arc<dyn Store>, hasher: Arc<dyn Hasher>, mmr_id: Option<String>) -> Self {
        let mmr_id = mmr_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let (leaves_count, elements_count, root_hash, hashes) =
            MMR::get_stores(&mmr_id, store.clone());

        Self {
            leaves_count,
            elements_count,
            hashes,
            root_hash,
            store,
            hasher,
            mmr_id,
            #[cfg(feature = "stacked_mmr")]
            sub_mmrs: Vec::new(),
        }
    }

    pub async fn create_with_genesis(
        store: Arc<dyn Store>,
        hasher: Arc<dyn Hasher>,
        mmr_id: Option<String>,
    ) -> Result<Self, MMRError> {
        let mut mmr = MMR::new(store, hasher, mmr_id);
        let elements_count: usize = mmr.elements_count.get().await?;
        if elements_count != 0 {
            return Err(MMRError::NonEmptyMMR);
        }
        let genesis = mmr.hasher.get_genesis()?;
        mmr.append(genesis).await?;
        Ok(mmr)
    }

    pub fn get_metadata(&self) -> MmrMetadata {
        MmrMetadata {
            mmr_id: self.mmr_id.clone(),
            store: self.store.clone(),
            hasher: self.hasher.get_name(),
        }
    }

    pub fn get_store_keys(mmr_id: &str) -> (String, String, String, String) {
        (
            format!("{}:{}", mmr_id, TreeMetadataKeys::LeafCount),
            format!("{}:{}", mmr_id, TreeMetadataKeys::ElementCount),
            format!("{}:{}", mmr_id, TreeMetadataKeys::RootHash),
            format!("{}:{}:", mmr_id, TreeMetadataKeys::Hashes),
        )
    }

    pub fn decode_store_key(
        store_key: &str,
    ) -> Result<(String, TreeMetadataKeys, SubKey), MMRError> {
        let mut parts = store_key.split(':');
        let mmr_id = parts.next().unwrap().to_string();
        let key = TreeMetadataKeys::from_str(parts.next().unwrap())?;
        let sub_key = match parts.next() {
            Some(sub_key) => SubKey::String(sub_key.to_string()),
            None => SubKey::None,
        };

        Ok((mmr_id, key, sub_key))
    }

    pub fn encode_store_key(mmr_id: &str, key: TreeMetadataKeys, sub_key: SubKey) -> String {
        let store_key = format!("{}:{}", mmr_id, key);
        match sub_key {
            SubKey::None => store_key,
            _ => format!("{}:{}", store_key, sub_key),
        }
    }

    pub fn get_stores(
        mmr_id: &str,
        store_rc: Arc<dyn Store>,
    ) -> (InStoreCounter, InStoreCounter, InStoreTable, InStoreTable) {
        let (leaves_count_key, elements_count_key, root_hash_key, hashes_key) =
            MMR::get_store_keys(mmr_id);

        (
            InStoreCounter::new(store_rc.clone(), leaves_count_key),
            InStoreCounter::new(store_rc.clone(), elements_count_key),
            InStoreTable::new(store_rc.clone(), root_hash_key),
            InStoreTable::new(store_rc.clone(), hashes_key),
        )
    }

    pub async fn append(&mut self, value: String) -> Result<AppendResult, MMRError> {
        self.hasher.is_element_size_valid(&value)?;

        let elements_count = self.elements_count.get().await?;

        let mut peaks = self
            .retrieve_peaks_hashes(find_peaks(elements_count), None)
            .await?;

        let mut last_element_idx = self.elements_count.increment().await?;
        let leaf_element_index = last_element_idx;

        // Store the hash in the database
        self.hashes
            .set(&value, SubKey::Usize(last_element_idx))
            .await?;

        peaks.push(value);

        let no_merges = leaf_count_to_append_no_merges(self.leaves_count.get().await?);
        for _ in 0..no_merges {
            last_element_idx += 1;

            let right_hash = match peaks.pop() {
                Some(hash) => hash,
                None => return Err(MMRError::NoHashFoundForIndex(last_element_idx)),
            };
            let left_hash = match peaks.pop() {
                Some(hash) => hash,
                None => return Err(MMRError::NoHashFoundForIndex(last_element_idx)),
            };

            let parent_hash = self.hasher.hash(vec![left_hash, right_hash])?;
            self.hashes
                .set(&parent_hash, SubKey::Usize(last_element_idx))
                .await?;

            peaks.push(parent_hash);
        }

        self.elements_count.set(last_element_idx).await?;
        let leaves = self.leaves_count.increment().await?;

        let bag = self.bag_the_peaks(None).await?;

        let root_hash = self.calculate_root_hash(&bag, last_element_idx).expect("Calculate root hash failed");
        self.root_hash.set(&root_hash, SubKey::None).await?;

        Ok(AppendResult {
            leaves_count: leaves,
            elements_count: last_element_idx,
            element_index: leaf_element_index,
            root_hash,
        })
    }

    pub async fn get_proof(
        &self,
        element_index: usize,
        options: Option<ProofOptions>,
    ) -> Result<Proof, MMRError> {
        if element_index == 0 {
            return Err(MMRError::InvalidElementIndex);
        }

        let options = options.unwrap_or_default();
        let tree_size = match options.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        if element_index > tree_size {
            return Err(MMRError::InvalidElementIndex);
        }

        let peaks = find_peaks(tree_size);

        let siblings = find_siblings(element_index, tree_size)?;

        let formatting_opts = options
            .formatting_opts
            .as_ref()
            .map(|opts| opts.peaks.clone());
        let peaks_hashes = self.retrieve_peaks_hashes(peaks, formatting_opts).await?;

        let siblings_hashes = self
            .hashes
            .get_many(
                siblings
                    .clone()
                    .into_iter()
                    .map(SubKey::Usize)
                    .collect::<Vec<SubKey>>(),
            )
            .await?;

        let mut siblings_hashes_vec: Vec<String> = siblings
            .iter()
            .filter_map(|&idx| siblings_hashes.get(&idx.to_string()).cloned())
            .collect();

        if let Some(formatting_opts) = options.formatting_opts.as_ref() {
            siblings_hashes_vec = format_proof(siblings_hashes_vec, formatting_opts.proof.clone())?;
        }

        let element_hash = self
            .hashes
            .get(SubKey::Usize(element_index))
            .await?
            .ok_or(MMRError::NoHashFoundForIndex(element_index))?;

        Ok(Proof {
            element_index,
            element_hash,
            siblings_hashes: siblings_hashes_vec,
            peaks_hashes,
            elements_count: tree_size,
        })
    }

    pub async fn get_proofs(
        &self,
        elements_indexes: Vec<usize>,
        options: Option<ProofOptions>,
    ) -> Result<Vec<Proof>, MMRError> {
        let options = options.unwrap_or_default();
        let tree_size = match options.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        for &element_index in &elements_indexes {
            if element_index == 0 {
                return Err(MMRError::InvalidElementIndex);
            }
            if element_index > tree_size {
                return Err(MMRError::InvalidElementIndex);
            }
        }

        let peaks = find_peaks(tree_size);
        let peaks_hashes = self.retrieve_peaks_hashes(peaks, None).await?;

        let mut siblings_per_element = HashMap::new();
        for &element_id in &elements_indexes {
            siblings_per_element.insert(element_id, find_siblings(element_id, tree_size)?);
        }
        let sibling_hashes_to_get = array_deduplicate(
            siblings_per_element
                .values()
                .flat_map(|x| x.iter().cloned())
                .collect(),
        )
        .into_iter()
        .map(SubKey::Usize)
        .collect();
        let all_siblings_hashes = self.hashes.get_many(sibling_hashes_to_get).await?;

        let elements_ids_str: Vec<SubKey> =
            elements_indexes.iter().map(|&x| SubKey::Usize(x)).collect();
        let element_hashes = self.hashes.get_many(elements_ids_str).await?;

        let mut proofs: Vec<Proof> = Vec::new();
        for &element_id in &elements_indexes {
            let siblings = siblings_per_element.get(&element_id).unwrap();
            let mut siblings_hashes: Vec<String> = siblings
                .iter()
                .map(|s| all_siblings_hashes.get(&s.to_string()).unwrap().clone()) // Note the conversion here
                .collect();

            if let Some(formatting_opts) = &options.formatting_opts {
                siblings_hashes = format_proof(siblings_hashes, formatting_opts.proof.clone())?
            }

            proofs.push(Proof {
                element_index: element_id,
                element_hash: element_hashes.get(&element_id.to_string()).unwrap().clone(),
                siblings_hashes,
                peaks_hashes: peaks_hashes.clone(),
                elements_count: tree_size,
            });
        }

        Ok(proofs)
    }

    pub async fn verify_proof(
        &self,
        mut proof: Proof,
        element_value: String,
        options: Option<ProofOptions>,
    ) -> Result<bool, MMRError> {
        let options = options.unwrap_or_default();
        let tree_size = match options.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        let leaf_count = mmr_size_to_leaf_count(tree_size);
        let peaks_count = leaf_count_to_peaks_count(leaf_count);

        if peaks_count as usize != proof.peaks_hashes.len() {
            return Err(MMRError::InvalidPeaksCount);
        }

        if let Some(formatting_opts) = options.formatting_opts {
            let proof_format_null_value = &formatting_opts.proof.null_value;
            let peaks_format_null_value = &formatting_opts.peaks.null_value;

            let proof_null_values_count = proof
                .siblings_hashes
                .iter()
                .filter(|&s| s == proof_format_null_value)
                .count();
            proof
                .siblings_hashes
                .truncate(proof.siblings_hashes.len() - proof_null_values_count);

            let peaks_null_values_count = proof
                .peaks_hashes
                .iter()
                .filter(|&s| s == peaks_format_null_value)
                .count();
            proof
                .peaks_hashes
                .truncate(proof.peaks_hashes.len() - peaks_null_values_count);
        }
        let element_index = proof.element_index;

        if element_index == 0 {
            return Err(MMRError::InvalidElementIndex);
        }

        if element_index > tree_size {
            return Err(MMRError::InvalidElementIndex);
        }

        let (peak_index, peak_height) = get_peak_info(tree_size, element_index);
        if proof.siblings_hashes.len() != peak_height {
            return Ok(false);
        }

        let mut hash = element_value.clone();
        let mut leaf_index = element_index_to_leaf_index(element_index)?;

        for proof_hash in proof.siblings_hashes.iter() {
            let is_right = leaf_index % 2 == 1;
            leaf_index /= 2;

            hash = self.hasher.hash(if is_right {
                vec![proof_hash.clone(), hash.clone()]
            } else {
                vec![hash.clone(), proof_hash.clone()]
            })?;
        }

        let peak_hashes = self
            .retrieve_peaks_hashes(find_peaks(tree_size), None)
            .await?;

        Ok(peak_hashes[peak_index] == hash)
    }

    pub async fn get_peaks(&self, option: PeaksOptions) -> Result<Vec<String>, MMRError> {
        let tree_size = match option.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        let peaks_idxs = find_peaks(tree_size);
        let peaks = self.retrieve_peaks_hashes(peaks_idxs, None).await?;
        if (option.formatting_opts).is_some() {
            match format_peaks(peaks, &option.formatting_opts.unwrap()) {
                Ok(peaks) => Ok(peaks),
                Err(e) => Err(MMRError::Formatting(e)),
            }
        } else {
            Ok(peaks)
        }
    }

    pub async fn retrieve_peaks_hashes(
        &self,
        peak_idxs: Vec<usize>,
        formatting_opts: Option<PeaksFormattingOptions>,
    ) -> Result<Vec<String>, MMRError> {
        let hashes_result = self
            .hashes
            .get_many(peak_idxs.clone().into_iter().map(SubKey::Usize).collect())
            .await?;
        // Assuming hashes_result is a HashMap<String, String>
        let hashes: Vec<String> = peak_idxs
            .iter()
            .filter_map(|&idx| hashes_result.get(&idx.to_string()).cloned())
            .collect();

        match formatting_opts {
            Some(opts) => match format_peaks(hashes, &opts) {
                Ok(peaks) => Ok(peaks),
                Err(e) => Err(MMRError::Formatting(e)),
            },
            None => Ok(hashes),
        }
    }

    pub async fn bag_the_peaks(&self, elements_count: Option<usize>) -> Result<String, MMRError> {
        let tree_size = match elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        let peaks_idxs = find_peaks(tree_size);

        let peaks_hashes = self.retrieve_peaks_hashes(peaks_idxs.clone(), None).await?;

        match peaks_idxs.len() {
            0 => Ok("0x0".to_string()),
            1 => Ok(peaks_hashes[0].clone()),
            _ => {
                let mut peaks_hashes: VecDeque<String> = peaks_hashes.into();
                let last = peaks_hashes.pop_back().unwrap();
                let second_last = peaks_hashes.pop_back().unwrap();
                let root0 = self.hasher.hash(vec![second_last.clone(), last.clone()])?;

                let final_root = peaks_hashes.into_iter().rev().fold(root0, |prev, cur| {
                    self.hasher.hash(vec![cur.clone(), prev.clone()]).unwrap()
                });

                Ok(final_root)
            }
        }
    }

    pub fn calculate_root_hash(
        &self,
        bag: &str,
        elements_count: usize,
    ) -> Result<String, MMRError> {
        match self
            .hasher
            .hash(vec![elements_count.to_string(), bag.to_string()])
        {
            Ok(root_hash) => Ok(root_hash),
            Err(e) => Err(MMRError::Hasher(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hasher::stark_poseidon::StarkPoseidonHasher;
    use std::sync::Arc;
    use store::memory::InMemoryStore;
    use tokio;

    #[tokio::test]
    async fn test_guest_mmr_initialization() -> Result<(), MMRError> {
        let store = Arc::new(InMemoryStore::default());
        let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
        let initial_peaks = vec!["0xabc".to_string(), "0xdef".to_string()];
        let elements_count = 3;
        let leaves_count = 2;
        let mmr_id = Some("test_mmr".to_string());
        let mmr = MMR::new(store.clone(), hasher.clone(), mmr_id);

        // Manually set initial peaks
        let peak_positions = find_peaks(elements_count);
        for (peak, pos) in initial_peaks.iter().zip(&peak_positions) {
            mmr.hashes
                .set(peak, SubKey::Usize(*pos))
                .await
                .expect("Failed to set peak hash");
        }

        mmr.elements_count.set(elements_count).await?;
        mmr.leaves_count.set(leaves_count).await?;

        // Check elements and leaves count
        assert_eq!(mmr.elements_count.get().await?, elements_count);
        assert_eq!(mmr.leaves_count.get().await?, leaves_count);

        // Check initial peaks are stored correctly
        for (peak, pos) in initial_peaks.iter().zip(peak_positions) {
            let stored_peak = mmr
                .hashes
                .get(SubKey::Usize(pos))
                .await?
                .expect("Peak not found");
            assert_eq!(&stored_peak, peak);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_guest_mmr_append() -> Result<(), MMRError> {
        // Initialize an empty MMR
        let store = Arc::new(InMemoryStore::default());
        let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
        let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

        // Append a value
        let value = "0x123".to_string();
        let append_result = mmr.append(value.clone()).await.expect("Append failed");

        // Check counts
        assert_eq!(mmr.elements_count.get().await?, 1);
        assert_eq!(mmr.leaves_count.get().await?, 1);

        // Check the new element is stored
        let stored_value = mmr
            .hashes
            .get(SubKey::Usize(1))
            .await?
            .expect("Value not found");
        assert_eq!(stored_value, value);

        // Verify append result
        assert_eq!(append_result.leaves_count, 1);
        assert_eq!(append_result.elements_count, 1);
        assert_eq!(append_result.element_index, 1);

        // Verify root hash
        let expected_bag = mmr.bag_the_peaks(None).await.expect("Bag the peaks failed");
        let expected_root_hash = mmr
            .calculate_root_hash(&expected_bag, mmr.elements_count.get().await?)
            .expect("Calculate root hash failed");
        assert_eq!(append_result.root_hash, expected_root_hash);

        Ok(())
    }

    #[tokio::test]
    async fn test_guest_mmr_get_peaks() -> Result<(), MMRError> {
        // Initialize MMR and append elements
        let store = Arc::new(InMemoryStore::default());
        let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
        let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

        mmr.append("0x6c17009d66e34c1d6b7e4d73fd5a105243feb10c7cae9598d60b0fa97d08868".to_string())
            .await
            .expect("Append failed");
        mmr.append("0x4998b07fef69c1b1658fcb44d44fa5bb0ca62c835b26fe763ca14b61a6595da".to_string())
            .await
            .expect("Append failed");
        mmr.append("0x7337cf1262bf9eeaecffe02776fa1cc9fd35c6fc49303a2b5f39d96a7b46afa".to_string())
            .await
            .expect("Append failed");
        mmr.append("0x16fa2f065f204a16db293c9adf370da4e08eea45874692dfa00123b21bbfe81".to_string())
            .await
            .expect("Append failed");

        // Get peaks
        let peaks_options = PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        };
        let peaks = mmr
            .get_peaks(peaks_options)
            .await
            .expect("Get peaks failed");
        // Expected peaks
        let elements_count = mmr.elements_count.get().await?;
        let peaks_indices = find_peaks(elements_count);
        let expected_peaks = mmr
            .retrieve_peaks_hashes(peaks_indices, None)
            .await
            .expect("Retrieve peaks hashes failed");

        assert_eq!(peaks, expected_peaks);

        Ok(())
    }

    #[tokio::test]
    async fn test_guest_mmr_bag_the_peaks() -> Result<(), MMRError> {
        // Initialize MMR and append elements
        let store = Arc::new(InMemoryStore::default());
        let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
        let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

        mmr.append("0x6c17009d66e34c1d6b7e4d73fd5a105243feb10c7cae9598d60b0fa97d08868".to_string())
            .await
            .expect("Append failed");
        mmr.append("0x4998b07fef69c1b1658fcb44d44fa5bb0ca62c835b26fe763ca14b61a6595da".to_string())
            .await
            .expect("Append failed");
        mmr.append("0x7337cf1262bf9eeaecffe02776fa1cc9fd35c6fc49303a2b5f39d96a7b46afa".to_string())
            .await
            .expect("Append failed");
        mmr.append("0x16fa2f065f204a16db293c9adf370da4e08eea45874692dfa00123b21bbfe81".to_string())
            .await
            .expect("Append failed");

        // Bag the peaks
        let bag = mmr.bag_the_peaks(None).await.expect("Bag the peaks failed");

        // Calculate root hash
        let elements_count = mmr.elements_count.get().await?;
        let root_hash = mmr.calculate_root_hash(&bag, elements_count).expect("Calculate root hash failed");

        // Verify root hash is not empty
        assert!(!root_hash.is_empty());

        Ok(())
    }

    #[test]
    fn test_format_peaks() {
        let peaks = vec!["0x1".to_string(), "0x2".to_string()];
        let formatting_opts = PeaksFormattingOptions {
            output_size: 4,
            null_value: "0x0".to_string(),
        };

        let formatted_peaks =
            format_peaks(peaks.clone(), &formatting_opts).expect("Format peaks failed");

        let expected_peaks = vec![
            "0x1".to_string(),
            "0x2".to_string(),
            "0x0".to_string(),
            "0x0".to_string(),
        ];

        assert_eq!(formatted_peaks, expected_peaks);
    }

    #[test]
    fn test_format_peaks_error() {
        let peaks = vec!["0x1".to_string(), "0x2".to_string(), "0x3".to_string()];
        let formatting_opts = PeaksFormattingOptions {
            output_size: 2,
            null_value: "0x0".to_string(),
        };

        let result = format_peaks(peaks, &formatting_opts);

        assert!(matches!(result, Err(FormattingError::PeaksOutputSizeError)));
    }
}
