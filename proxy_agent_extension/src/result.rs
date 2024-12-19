// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::error::Error;

pub type Result<T> = core::result::Result<T, Error>;
