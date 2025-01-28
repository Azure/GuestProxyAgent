// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
