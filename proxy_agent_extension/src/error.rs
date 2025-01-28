// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(windows)]
    #[error(transparent)]
    WindowsService(#[from] windows_service::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
