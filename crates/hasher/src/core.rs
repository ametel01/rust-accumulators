use starknet::core::types::FromStrError;
use std::{
    fmt::{self, Debug},
    str::FromStr,
};
use strum_macros::EnumIter;
use thiserror::Error;

/// Hasher error
#[derive(Error, Debug)]
pub enum HasherError {
    #[error("Invalid hashing function")]
    InvalidHashingFunction,
    #[error(
        "Element size {element_size} is too big for hashing function with block size {block_size_bits}"
    )]
    InvalidElementSize {
        element_size: usize,
        block_size_bits: usize,
    },
    #[error("Invalid elements length for hashing function")]
    InvalidElementsLength,
    #[error("Fail to decode hex")]
    HexDecodeError(#[from] hex::FromHexError),
    #[error("Fail to convert to felt")]
    FeltConversionError(#[from] FromStrError),
}

/// A trait for hash functions
pub trait Hasher: Send + Sync + Debug {
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError>;
    fn is_element_size_valid(&self, element: &str) -> Result<bool, HasherError>;
    fn hash_single(&self, data: &str) -> Result<String, HasherError>;
    fn get_genesis(&self) -> Result<String, HasherError>;
    fn get_name(&self) -> HashingFunction;
    fn get_block_size_bits(&self) -> usize;
}

/// Hashing functions types supported by the hasher
#[derive(EnumIter, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum HashingFunction {
    Keccak256,
    Poseidon,
    Pedersen,
}

impl FromStr for HashingFunction {
    type Err = HasherError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "keccak" => Ok(HashingFunction::Keccak256),
            "poseidon" => Ok(HashingFunction::Poseidon),
            "pedersen" => Ok(HashingFunction::Pedersen),
            _ => Err(HasherError::InvalidHashingFunction),
        }
    }
}

impl fmt::Display for HashingFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HashingFunction::Keccak256 => "keccak",
            HashingFunction::Poseidon => "poseidon",
            HashingFunction::Pedersen => "pedersen",
        };
        write!(f, "{}", name)
    }
}

/// Returns the byte size of a hex string
pub fn byte_size(hex: &str) -> usize {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex.len() / 2
}
