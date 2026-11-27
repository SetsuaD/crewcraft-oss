//! Transport adapters for the CrewCraft server binary.

pub mod audit_file;
// The control socket is a Unix socket (T238); on Windows, invite, room and add-member run with the server stopped.
#[cfg(unix)]
pub mod control;
pub mod device_session;
pub mod export_teams;
pub mod external_signin;
pub mod guest_lab;
pub mod identity_config;
pub mod import_bundle;
pub mod import_teams;
pub mod issuer_custody;
pub mod lab_admin;
pub mod lab_bootstrap;
pub mod lab_installation;
pub mod lab_runtime;
pub mod lab_server;
pub mod lab_state;
pub mod listener;
pub mod media_link;
pub mod server_install;
pub mod server_name;
pub mod stored_device_auth;
