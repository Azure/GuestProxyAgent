// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

/// Global state variables for the extension service.
#[derive(Clone, Default)]
pub struct ServiceState {
    state_map: HashMap<String, (String, u32)>,
}

impl ServiceState {
    /// Update the service state entry with the given key and value.
    /// If the state value is the same as the previous value, increment the count.
    /// If the count reaches the maximum value, update the state value and reset the count.
    /// Return true if the state value is updated, false otherwise.
    /// # Arguments
    /// * `service_state` - The service state to update.
    /// * `state_key` - The key of the state entry.
    /// * `state_value` - The value of the state entry.
    /// * `max_count` - The maximum count before reset the state value count.
    /// # Returns
    /// * `bool` - True if the state value is updated or state value count reset, false otherwise.
    pub fn update_service_state_entry(
        &mut self,
        state_key: &str,
        state_value: &str,
        max_count: u32,
    ) -> bool {
        match self.state_map.get_mut(state_key) {
            Some(entry) => {
                let value = entry.0.to_string();
                let count = entry.1;
                // State value changed or max count reached
                if value != state_value || count >= max_count {
                    // Update the state value and reset the count to 1
                    self.state_map
                        .insert(state_key.to_string(), (state_value.to_string(), 1));
                    true
                } else {
                    self.state_map
                        .insert(state_key.to_string(), (state_value.to_string(), count + 1));
                    false
                }
            }
            None => {
                self.state_map
                    .insert(state_key.to_string(), (state_value.to_string(), 1));
                true
            }
        }
    }
}
