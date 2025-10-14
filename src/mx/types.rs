#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

impl MxRecord {
    pub fn new(preference: u16, exchange: impl Into<String>) -> Self {
        Self {
            preference,
            exchange: exchange.into(),
        }
    }
}

#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MxStatus {
    Records(Vec<MxRecord>),
    NoRecords,
}

impl MxStatus {
    pub fn records(&self) -> &[MxRecord] {
        match self {
            Self::Records(records) => records.as_slice(),
            Self::NoRecords => &[],
        }
    }
}
