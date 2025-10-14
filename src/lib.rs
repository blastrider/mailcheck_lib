#![forbid(unsafe_code)]
//! mailcheck_lib — validation format e-mail (MVP)

pub mod validator;
pub use validator::{
    EmailError,
    NormalizedEmail, // << nouveau
    SpecCharacters,
    SpecClass,
    SpecFinding,
    SpecOptions,
    SpecSegment,
    ValidationMode,
    ValidationReport,
    normalize_email, // << nouveau
    normalize_email_with_spec,
    validate_email,
    validate_email_with_spec,
};

#[cfg(feature = "with-mx")]
pub mod mx;
#[cfg(feature = "with-mx")]
pub use mx::{Error as MxError, MxRecord, MxStatus, check_mx};

#[cfg(feature = "with-auth-records")]
pub mod auth;
#[cfg(feature = "with-auth-records")]
pub use auth::{
    AuthError, AuthLookupOptions, AuthStatus, DkimIssue, DkimPolicyStatus, DkimSelectorStatus,
    DkimStatus, DkimWeakness, DmarcIssue, DmarcPolicy, DmarcStatus, DmarcWeakness, SpfIssue,
    SpfQualifier, SpfStatus, check_auth_records, check_auth_records_with_options,
};
