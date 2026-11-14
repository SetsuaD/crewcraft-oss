//! Room membership and what each role may do. Task T111.

use std::collections::BTreeMap;

/// Roles in increasing power: `Guest < Member < Admin < Owner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Guest,
    Member,
    Admin,
    Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomError {
    /// The actor, or the user acted on, is not in the room.
    NotMember,
    Forbidden,
    AlreadyMember,
    /// The room would be left without an Owner.
    LastOwner,
}

pub struct Room {
    members: BTreeMap<String, Role>,
}

impl Room {
    /// A new room whose only member is `owner`, as Owner.
    pub fn new(owner: &str) -> Self {
        let mut members = BTreeMap::new();
        members.insert(owner.to_string(), Role::Owner);
        Self { members }
    }

    pub fn role(&self, user: &str) -> Option<Role> {
        self.members.get(user).copied()
    }

    /// `actor` adds `user` with `role`. Checks, in order: actor not a member is `NotMember`; user already in is
    /// `AlreadyMember`; then the actor must be an Admin or Owner and may only grant a role below its own (an Owner may
    /// also grant Owner), else `Forbidden`.
    pub fn add(&mut self, actor: &str, user: &str, role: Role) -> Result<(), RoomError> {
        let actor_role = *self.members.get(actor).ok_or(RoomError::NotMember)?;
        if self.members.contains_key(user) {
            return Err(RoomError::AlreadyMember);
        }
        if actor_role < Role::Admin {
            return Err(RoomError::Forbidden);
        }
        if actor_role != Role::Owner && role >= actor_role {
            return Err(RoomError::Forbidden);
        }
        self.members.insert(user.to_string(), role);
        Ok(())
    }

    /// `actor` removes `user`. Checks, in order: either one not a member is `NotMember`. Anyone may remove themselves
    /// (leave). Otherwise the actor must be an Admin or Owner and outrank the user (an Owner may remove another Owner),
    /// else `Forbidden`. Removing the room's only Owner is `LastOwner`, whoever asks.
    pub fn remove(&mut self, actor: &str, user: &str) -> Result<(), RoomError> {
        let actor_role = *self.members.get(actor).ok_or(RoomError::NotMember)?;
        let user_role = *self.members.get(user).ok_or(RoomError::NotMember)?;

        if actor == user {
            if user_role == Role::Owner && self.owner_count() == 1 {
                return Err(RoomError::LastOwner);
            }
            self.members.remove(user);
            return Ok(());
        }

        if actor_role < Role::Admin {
            return Err(RoomError::Forbidden);
        }
        if actor_role == Role::Owner {
            self.members.remove(user);
            return Ok(());
        }
        if user_role >= actor_role {
            return Err(RoomError::Forbidden);
        }
        self.members.remove(user);
        Ok(())
    }

    /// `actor` changes `user`'s role. Checks, in order: either one not a member is `NotMember`; the actor must be an
    /// Admin or Owner; an Admin must outrank both the user's current role and the new one (an Owner may set any role),
    /// else `Forbidden`; demoting the room's only Owner is `LastOwner`.
    pub fn set_role(&mut self, actor: &str, user: &str, role: Role) -> Result<(), RoomError> {
        let actor_role = *self.members.get(actor).ok_or(RoomError::NotMember)?;
        let user_role = *self.members.get(user).ok_or(RoomError::NotMember)?;

        if actor_role < Role::Admin {
            return Err(RoomError::Forbidden);
        }

        if actor_role == Role::Admin && (user_role >= actor_role || role >= actor_role) {
            return Err(RoomError::Forbidden);
        }

        if user_role == Role::Owner && role < Role::Owner && self.owner_count() == 1 {
            return Err(RoomError::LastOwner);
        }

        self.members.insert(user.to_string(), role);
        Ok(())
    }

    fn owner_count(&self) -> usize {
        self.members.values().filter(|r| **r == Role::Owner).count()
    }

    /// Members and above may post; Guests may only read; non-members may do neither.
    pub fn can_post(&self, user: &str) -> bool {
        self.role(user).is_some_and(|r| r >= Role::Member)
    }

    /// Every member and role, sorted by name.
    pub fn members(&self) -> Vec<(String, Role)> {
        self.members.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}
