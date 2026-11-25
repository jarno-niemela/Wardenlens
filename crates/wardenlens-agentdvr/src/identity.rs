//! Camera ids. An id is an opaque, non-sensitive reference (ADR 0006 section 1, core
//! `CameraId`): it is never derived from the camera name, host or any other value of the file.
//!
//! The id is `agentdvr-<n>` where `n` is `AgentDVR`'s own numeric `id` attribute, when the entry
//! has one that no earlier imported camera used; otherwise `agentdvr-pos-<p>` with `p` the
//! zero-based position of the `camera` element. The two forms cannot collide with each other,
//! positions are unique, and the numeric form is unique by construction, so ids are unique
//! without any search. Both are stable across runs. The numeric form also survives re-exports
//! that reorder the file; the position form does not, and is only the fallback.

use std::collections::BTreeSet;

use wardenlens_core::camera::{CameraError, CameraId};

/// Hands out ids in document order.
#[derive(Default)]
pub(crate) struct IdAllocator {
    numeric_used: BTreeSet<u32>,
}

impl IdAllocator {
    /// The id of the camera at `position` with `AgentDVR` id `agent_id`.
    pub(crate) fn allocate(
        &mut self,
        position: usize,
        agent_id: Option<u32>,
    ) -> Result<CameraId, CameraError> {
        match agent_id {
            Some(n) if self.numeric_used.insert(n) => CameraId::new(&format!("agentdvr-{n}")),
            _ => CameraId::new(&format!("agentdvr-pos-{position}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_longest_ids_are_valid() {
        let mut a = IdAllocator::default();
        let id = a
            .allocate(crate::MAX_CAMERAS, Some(u32::MAX))
            .expect("numeric");
        assert_eq!(id.as_str(), "agentdvr-4294967295");
        let id = a
            .allocate(crate::MAX_CAMERAS, Some(u32::MAX))
            .expect("fallback");
        assert!(id.as_str().len() <= wardenlens_core::camera::MAX_CAMERA_ID_LEN);
    }

    #[test]
    fn numeric_ids_are_used_once_then_fall_back_to_the_position() {
        let mut a = IdAllocator::default();
        let ids: Vec<String> = [(0, Some(7)), (1, Some(7)), (2, None), (3, Some(0))]
            .into_iter()
            .map(|(p, n)| a.allocate(p, n).expect("id").to_string())
            .collect();
        assert_eq!(
            ids,
            [
                "agentdvr-7",
                "agentdvr-pos-1",
                "agentdvr-pos-2",
                "agentdvr-0"
            ]
        );
    }
}
