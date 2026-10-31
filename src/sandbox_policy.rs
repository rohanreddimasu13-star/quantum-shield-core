//! Shared network policy for all Software Shield sandbox backends.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum SandboxNetworkMode {
    /// Require network namespace isolation. Never fall back to host networking.
    #[default]
    Isolated,

    /// Explicitly permit the host network.
    Shared,

    /// Prefer isolation; fall back only for recognized capability restrictions.
    Automatic,
}

impl SandboxNetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Shared => "shared",
            Self::Automatic => "automatic",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxNetworkReport {
    pub requested_mode: SandboxNetworkMode,
    pub effective_mode: SandboxNetworkMode,
    pub fallback_reason: Option<String>,
}

#[allow(dead_code)]
impl SandboxNetworkReport {
    pub fn new(
        requested_mode: SandboxNetworkMode,
        effective_mode: SandboxNetworkMode,
        fallback_reason: Option<String>,
    ) -> Self {
        Self {
            requested_mode,
            effective_mode,
            fallback_reason,
        }
    }
}

/// Resolve the new option and legacy flag into one unambiguous policy.
#[allow(dead_code)]
pub fn resolve_network_mode(
    requested: Option<SandboxNetworkMode>,
    legacy_share_network: bool,
) -> anyhow::Result<SandboxNetworkMode> {
    if legacy_share_network && requested.is_some() {
        anyhow::bail!(
            "--share-network cannot be combined with --network-mode; use --network-mode shared"
        );
    }

    if legacy_share_network {
        Ok(SandboxNetworkMode::Shared)
    } else {
        Ok(requested.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_isolated() {
        assert_eq!(
            resolve_network_mode(None, false).unwrap(),
            SandboxNetworkMode::Isolated
        );
    }

    #[test]
    fn legacy_flag_means_shared() {
        assert_eq!(
            resolve_network_mode(None, true).unwrap(),
            SandboxNetworkMode::Shared
        );
    }

    #[test]
    fn accepts_each_explicit_mode() {
        for mode in [
            SandboxNetworkMode::Isolated,
            SandboxNetworkMode::Shared,
            SandboxNetworkMode::Automatic,
        ] {
            assert_eq!(resolve_network_mode(Some(mode), false).unwrap(), mode);
        }
    }

    #[test]
    fn rejects_legacy_and_new_options_together() {
        assert!(resolve_network_mode(Some(SandboxNetworkMode::Isolated), true).is_err());
        assert!(resolve_network_mode(Some(SandboxNetworkMode::Shared), true).is_err());
        assert!(resolve_network_mode(Some(SandboxNetworkMode::Automatic), true).is_err());
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    #[test]
    fn network_report_serializes_requested_and_effective_modes() {
        let report = SandboxNetworkReport::new(
            SandboxNetworkMode::Automatic,
            SandboxNetworkMode::Shared,
            Some("unprivileged user namespaces unavailable".to_owned()),
        );
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["requested_mode"], "automatic");
        assert_eq!(value["effective_mode"], "shared");
        assert!(value["fallback_reason"]
            .as_str()
            .unwrap()
            .contains("namespaces"));
    }
}
