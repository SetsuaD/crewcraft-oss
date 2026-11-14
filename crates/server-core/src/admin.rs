//! Administrative actions that leave an audit trail. Each successful action appends exactly one entry to the audit log
//! (`audit`, T125); a refused action, or one that changes nothing, appends none. Composed from `server` (T122), `devices`
//! (T127) and `audit` (T125). Task T137.

use crate::audit::{AuditError, AuditLog, MAX_FIELD};
use crate::devices::{DeviceError, Devices};
use crate::room::Role;
use crate::server::{Server, ServerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminError {
    Server(ServerError),
    Device(DeviceError),
    /// The audit entry could not be written, so the action was not taken.
    Audit(AuditError),
}

pub struct Admin {
    server: Server,
    devices: Devices,
    audit: AuditLog,
}

impl Default for Admin {
    fn default() -> Self {
        Self::new()
    }
}

/// The audit `action` text for each action, exactly (single spaces, roles in lowercase: guest, member, admin, owner):
/// - `room.create <slug>`
/// - `member.add <slug> <user> <role>`
/// - `member.remove <slug> <user>`
/// - `device.revoke <user> <id>`
/// - `device.revoke_all <user> <count>`
///
/// `action_text` joins `parts` with single spaces (for example `["member.add", "general", "bob", "member"]`), then cuts
/// text longer than `MAX_FIELD` bytes to its longest prefix of at most `MAX_FIELD` bytes that ends on a char boundary.
pub fn action_text(parts: &[&str]) -> String {
    let joined = parts.join(" ");
    if joined.len() <= MAX_FIELD {
        return joined;
    }
    let mut i = MAX_FIELD;
    while i > 0 && !joined.is_char_boundary(i) {
        i -= 1;
    }
    joined[..i].to_string()
}

impl Admin {
    /// No rooms, no devices, an empty audit log.
    pub fn new() -> Self {
        Self { server: Server::new(), devices: Devices::new(), audit: AuditLog::new() }
    }

    fn check_audit_pre(&self, actor: &str, now_ms: u64) -> Result<(), AdminError> {
        if actor.is_empty() || actor.len() > MAX_FIELD {
            return Err(AdminError::Audit(AuditError::FieldLength));
        }
        if self.audit.entries().last().is_some_and(|last| now_ms < last.at_ms) {
            return Err(AdminError::Audit(AuditError::ClockBackwards));
        }
        Ok(())
    }

    /// `Server::create_room` with `actor` as the owner. Audit: `room.create <slug>`. Returns the slug.
    pub fn create_room(&mut self, actor: &str, name: &str, now_ms: u64) -> Result<String, AdminError> {
        self.check_audit_pre(actor, now_ms)?;
        let slug = self.server.create_room(actor, name).map_err(AdminError::Server)?;
        let action = action_text(&["room.create", &slug]);
        self.audit.append(actor, &action, now_ms).map_err(AdminError::Audit)?;
        Ok(slug)
    }

    /// `Server::add_member`. Audit: `member.add <slug> <user> <role>`. Returns the event's cursor.
    pub fn add_member(&mut self, actor: &str, slug: &str, user: &str, role: Role, now_ms: u64) -> Result<u64, AdminError> {
        self.check_audit_pre(actor, now_ms)?;
        let cursor = self.server.add_member(slug, actor, user, role).map_err(AdminError::Server)?;
        let role_str = match role {
            Role::Guest => "guest",
            Role::Member => "member",
            Role::Admin => "admin",
            Role::Owner => "owner",
        };
        let action = action_text(&["member.add", slug, user, role_str]);
        self.audit.append(actor, &action, now_ms).map_err(AdminError::Audit)?;
        Ok(cursor)
    }

    /// `Server::remove_member`. Audit: `member.remove <slug> <user>`. Returns the event's cursor.
    pub fn remove_member(&mut self, actor: &str, slug: &str, user: &str, now_ms: u64) -> Result<u64, AdminError> {
        self.check_audit_pre(actor, now_ms)?;
        let cursor = self.server.remove_member(slug, actor, user).map_err(AdminError::Server)?;
        let action = action_text(&["member.remove", slug, user]);
        self.audit.append(actor, &action, now_ms).map_err(AdminError::Audit)?;
        Ok(cursor)
    }

    /// Revoke `user`'s device `id` on their behalf (as `Devices::revoke(user, id)`). Audit: `device.revoke <user> <id>`,
    /// only when it was live (`Ok(true)`); an already revoked device (`Ok(false)`) appends nothing.
    pub fn revoke_device(&mut self, actor: &str, user: &str, id: u64, now_ms: u64) -> Result<bool, AdminError> {
        self.check_audit_pre(actor, now_ms)?;
        let was_live = self.devices.revoke(user, id).map_err(AdminError::Device)?;
        if was_live {
            let action = action_text(&["device.revoke", user, &id.to_string()]);
            self.audit.append(actor, &action, now_ms).map_err(AdminError::Audit)?;
        }
        Ok(was_live)
    }

    /// `Devices::revoke_all(user)`. Audit: `device.revoke_all <user> <count>`, only when the count is above 0. Returns
    /// the count.
    pub fn revoke_all(&mut self, actor: &str, user: &str, now_ms: u64) -> Result<usize, AdminError> {
        self.check_audit_pre(actor, now_ms)?;
        let count = self.devices.revoke_all(user);
        if count > 0 {
            let action = action_text(&["device.revoke_all", user, &count.to_string()]);
            self.audit.append(actor, &action, now_ms).map_err(AdminError::Audit)?;
        }
        Ok(count)
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    /// For enrollment and sign-in (no audit entry).
    pub fn devices_mut(&mut self) -> &mut Devices {
        &mut self.devices
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
}
