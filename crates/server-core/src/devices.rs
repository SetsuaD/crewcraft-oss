//! Each user's enrolled devices, identified by the SHA-256 fingerprint of the device's client certificate. A revoked
//! fingerprint is banned for good: it can never be enrolled again, by anyone. Task T127.

use std::collections::HashMap;

/// Live (not revoked) devices one user may have.
pub const MAX_DEVICES: usize = 10;
/// Longest device name, in chars after trimming.
pub const MAX_NAME_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// 1 for the first device enrolled on the server, then 2, 3, ...; never reused.
    pub id: u64,
    pub user: String,
    /// The trimmed name.
    pub name: String,
    pub fingerprint: [u8; 32],
    pub enrolled_ms: u64,
    pub last_seen_ms: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// The trimmed name is empty, longer than `MAX_NAME_CHARS`, or has a control character (`char::is_control`).
    BadName,
    /// The fingerprint belongs to a revoked device.
    Revoked,
    /// The fingerprint belongs to a live device (of any user).
    FingerprintInUse,
    /// The user already has `MAX_DEVICES` live devices.
    TooMany,
    NoSuchDevice,
    /// The device belongs to another user.
    NotYours,
}

#[derive(Debug)]
pub struct Devices {
    next_id: u64,
    devices: Vec<Device>,
    by_fingerprint: HashMap<[u8; 32], usize>,
}

impl Default for Devices {
    fn default() -> Self {
        Self::new()
    }
}

impl Devices {
    pub fn new() -> Self {
        Self { next_id: 1, devices: Vec::new(), by_fingerprint: HashMap::new() }
    }

    /// Enroll a device for `user` at `now_ms` (its `enrolled_ms` and `last_seen_ms`). Checks, in order: `BadName`,
    /// `Revoked`, `FingerprintInUse`, `TooMany`. Returns the new id.
    pub fn enroll(&mut self, user: &str, name: &str, fingerprint: [u8; 32], now_ms: u64) -> Result<u64, DeviceError> {
        self.check_enroll(user, name, &fingerprint)?;
        let trimmed = name.trim();
        let id = self.next_id;
        self.next_id += 1;
        let device =
            Device { id, user: user.to_string(), name: trimmed.to_string(), fingerprint, enrolled_ms: now_ms, last_seen_ms: now_ms, revoked: false };
        let idx = self.devices.len();
        self.devices.push(device);
        self.by_fingerprint.insert(fingerprint, idx);
        Ok(id)
    }

    /// The id the next enrolled device will get (ids are never reused, and revoked devices keep theirs).
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    /// What `enroll` would refuse, in the same order, without changing anything; `Ok` is the id `enroll` would assign.
    /// The account store validates with this before it journals an activation.
    pub fn check_enroll(&self, user: &str, name: &str, fingerprint: &[u8; 32]) -> Result<u64, DeviceError> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.chars().count() > MAX_NAME_CHARS || trimmed.chars().any(|c| c.is_control()) {
            return Err(DeviceError::BadName);
        }
        if let Some(&idx) = self.by_fingerprint.get(fingerprint) {
            if self.devices[idx].revoked {
                return Err(DeviceError::Revoked);
            }
            return Err(DeviceError::FingerprintInUse);
        }
        let live_count = self.devices.iter().filter(|d| d.user == user && !d.revoked).count();
        if live_count >= MAX_DEVICES {
            return Err(DeviceError::TooMany);
        }
        Ok(self.next_id)
    }

    /// A connection presented this certificate fingerprint: the live device it belongs to, after setting its
    /// `last_seen_ms` to `now_ms` (never moved back: an earlier `now_ms` leaves it). `Revoked` for a revoked device,
    /// `NoSuchDevice` for an unknown fingerprint.
    pub fn authenticate(&mut self, fingerprint: &[u8; 32], now_ms: u64) -> Result<Device, DeviceError> {
        let idx = *self.by_fingerprint.get(fingerprint).ok_or(DeviceError::NoSuchDevice)?;
        if self.devices[idx].revoked {
            return Err(DeviceError::Revoked);
        }
        if now_ms > self.devices[idx].last_seen_ms {
            self.devices[idx].last_seen_ms = now_ms;
        }
        Ok(self.devices[idx].clone())
    }

    /// `user` revokes their own device `id`. Checks, in order: `NoSuchDevice`, `NotYours`. `Ok(true)` when it was live,
    /// `Ok(false)` when it was already revoked.
    pub fn revoke(&mut self, user: &str, id: u64) -> Result<bool, DeviceError> {
        if id == 0 || id as usize > self.devices.len() {
            return Err(DeviceError::NoSuchDevice);
        }
        let idx = id as usize - 1;
        if self.devices[idx].user != user {
            return Err(DeviceError::NotYours);
        }
        if self.devices[idx].revoked {
            return Ok(false);
        }
        self.devices[idx].revoked = true;
        Ok(true)
    }

    /// An administrator revokes every live device of `user`; returns how many.
    pub fn revoke_all(&mut self, user: &str) -> usize {
        let mut count = 0;
        for device in self.devices.iter_mut() {
            if device.user == user && !device.revoked {
                device.revoked = true;
                count += 1;
            }
        }
        count
    }

    /// The user's devices, live and revoked, by id.
    pub fn list(&self, user: &str) -> Vec<Device> {
        self.devices.iter().filter(|d| d.user == user).cloned().collect()
    }
}
