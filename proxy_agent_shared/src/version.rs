// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::error::{Error, ParseVersionErrorType};
use crate::result::Result;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub build: Option<u32>,
    pub revision: Option<u32>,
}

impl Version {
    pub fn from_major_minor(major: u32, minor: u32) -> Self {
        Version::from_major_minor_build_revision(major, minor, None, None)
    }

    pub fn from_major_minor_build(major: u32, minor: u32, build: Option<u32>) -> Self {
        Version::from_major_minor_build_revision(major, minor, build, None)
    }

    pub fn from_major_minor_build_revision(
        major: u32,
        minor: u32,
        build: Option<u32>,
        revision: Option<u32>,
    ) -> Self {
        Version {
            major,
            minor,
            build,
            revision,
        }
    }

    pub fn from_string(version_string: String) -> Result<Version> {
        let version_parts = version_string.split('.').collect::<Vec<&str>>();
        if version_parts.len() < 2 || version_parts.len() > 4 {
            return Err(Error::ParseVersion(ParseVersionErrorType::InvalidString(
                version_string,
            )));
        }

        let major = version_parts[0].parse::<u32>().map_err(|_| {
            Error::ParseVersion(ParseVersionErrorType::MajorBuild(
                version_string.to_string(),
            ))
        })?;

        let minor = version_parts[1].parse::<u32>().map_err(|_| {
            Error::ParseVersion(ParseVersionErrorType::MinorBuild(
                version_string.to_string(),
            ))
        })?;

        if version_parts.len() == 2 {
            return Ok(Version::from_major_minor(major, minor));
        }

        let mut build = None;
        let mut revision = None;
        if version_parts.len() > 2 {
            match version_parts[2].parse::<u32>() {
                Ok(u) => build = Some(u),
                Err(_) => build = None,
            };
            if version_parts.len() > 3 {
                match version_parts[3].parse::<u32>() {
                    Ok(u) => revision = Some(u),
                    Err(_) => revision = None,
                };
            }
        }

        Ok(Version::from_major_minor_build_revision(
            major, minor, build, revision,
        ))
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut ver = format!("{}.{}", self.major, self.minor);

        if let Some(b) = self.build {
            ver = format!("{}.{}", ver, b);

            if let Some(r) = self.revision {
                ver = format!("{}.{}", ver, r);
            }
        }

        write!(f, "{}", ver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_from_string() {
        let version = Version::from_string("1.0".to_string()).unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 0);
        assert_eq!(version.build, None);
        assert_eq!(version.revision, None);

        let version = Version::from_string("1.0.0".to_string()).unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 0);
        assert_eq!(version.build, Some(0));
        assert_eq!(version.revision, None);

        let version = Version::from_string("0".to_string());
        assert!(version.is_err());
    }
}
