//! The desktop app: the window (`crewcraft-desktop-ui`) wired to enrollment, the saved device and the connection
//! worker. Task T309.
//!
//! Owns: the app's lifecycle (enroll, authenticator setup, sign in, chat, sign out, connection lost), where the
//! enrolled device is saved, and how worker and enrollment events become window updates. Called by: `main.rs`, which
//! runs `DesktopApp` in an eframe window, and `crewcraft-android`, which runs it on Android (T401). Calls: `enrollment`, `device_store`, `worker`, and a `Join` that turns an
//! invitation link into a server endpoint and an enrollment code (`join_from_link`; tests pass their own). Task T311
//! moved joining off the window's thread. Task T313 seals the saved device with the key store (`key_vault`; tests
//! pass an in-memory one), unless the person has opted out with `PLAIN_RECORD_SETTING`. Task T403 adds phones: with
//! a hardware key store (`Controller::start_with_hardware_keys`) each enrollment makes its device key inside that
//! store and the record only names it. Task T314 applies the appearance (`load_appearance`): a theme, light or dark,
//! and the organization's name in the title bar.
//!
//! Everything that does not need a window is in `Controller`, so it is tested without one.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crewcraft_desktop_ui::appearance::Appearance;
use crewcraft_desktop_ui::{Action, Update, Window};
use crewcraft_enroll::{EnrollmentCode, InvitationLink};
use zeroize::Zeroizing;

use crate::bootstrap_transport::MAX_CONFIRMATION_WINDOW;
use crate::device::{DeviceError, StoredDevice};
use crate::device_store::{DeviceStore, StoreError};
use crate::enroll_client::{BrowserProblem, ERR_EXTERNAL_REFUSED};
use crate::enrollment::{Enrollment, EnrollmentEvent, KeySource};
use crate::hardware_key::{HardwareKeys, new_alias};
use crate::key_vault::{OpenVault, SystemVault};
use crate::lab_client::LabError;
use crate::server_endpoint::ServerEndpoint;
use crate::signed_in::{Credentials, valid_email};
use crate::ticket_file::TicketFile;
use crate::worker::{Browser, Event, Worker, WorkerConfig};

/// The one saved server profile of the first beta. Several servers come later.
pub const PROFILE: &str = "default";

/// A file in the data folder whose presence opts out of the key store: the enrollment is then kept in a plain file
/// protected only by its permissions (docs/SECURITY-DESIGN.md section 2). Only for a computer with no key store; the
/// person creates it by hand, and nothing in CrewCraft ever does.
pub const PLAIN_RECORD_SETTING: &str = "plain-device-record";

/// The appearance settings file in the data folder (crewcraft-desktop-ui `appearance::parse_settings`): the theme,
/// light or dark, and the organization's name. Optional; written by the person or an organization's installer.
pub const APPEARANCE_FILE: &str = "appearance.toml";

/// A theme addon in the data folder (REQUIREMENTS 2.19), checked like any addon (format, contrast, not a built-in
/// id) before it may be chosen in `APPEARANCE_FILE`. Until servers hand addons to clients (M4), this is how an
/// organization's theme reaches a desktop.
pub const THEME_ADDON_FILE: &str = "theme-addon.toml";

/// The appearance from the data folder `dir` (`APPEARANCE_FILE`, `THEME_ADDON_FILE`), and anything refused, in words
/// for the person. A missing folder or file is not a problem: the defaults apply.
pub fn load_appearance(dir: Option<&Path>) -> (Appearance, Vec<String>) {
    let read = |name: &str, max: usize| -> Result<Option<Vec<u8>>, String> {
        let Some(dir) = dir else { return Ok(None) };
        let path = dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Err(_) => Ok(None),
            Ok(meta) if !meta.is_file() => Err(format!("{name} is not a regular file, so it was not used.")),
            Ok(meta) if meta.len() > max as u64 => Err(format!("{name} is larger than {max} bytes, so it was not used.")),
            Ok(_) => std::fs::read(&path).map(Some).map_err(|error| format!("{name} could not be read ({error}).")),
        }
    };
    let mut problems = Vec::new();
    let settings = match read(APPEARANCE_FILE, crewcraft_desktop_ui::appearance::MAX_SETTINGS_BYTES) {
        Ok(bytes) => bytes,
        Err(problem) => {
            problems.push(problem);
            None
        }
    };
    let addon = match read(THEME_ADDON_FILE, crewcraft_desktop_ui::appearance::MAX_ADDON_BYTES) {
        Ok(bytes) => bytes,
        Err(problem) => {
            problems.push(problem);
            None
        }
    };
    let settings_text = match settings.map(String::from_utf8) {
        Some(Ok(text)) => Some(text),
        Some(Err(_)) => {
            problems.push(format!("{APPEARANCE_FILE} is not UTF-8 text, so it was not used."));
            None
        }
        None => None,
    };
    let (appearance, more) = Appearance::resolve(settings_text.as_deref(), addon.as_deref());
    problems.extend(more);
    (appearance, problems)
}

/// Whether the person has opted out of the key store for the data folder `dir` (`PLAIN_RECORD_SETTING`).
pub fn plain_record_chosen(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(PLAIN_RECORD_SETTING)).is_ok_and(|metadata| metadata.is_file())
}

/// The device store for the data folder `dir`: sealed with the key store, or plain if the person opted out. The
/// error is shown to the person as written.
fn open_store(dir: &Path, open_vault: OpenVault<'_>) -> Result<DeviceStore, String> {
    if plain_record_chosen(dir) {
        return DeviceStore::open(dir).map_err(store_problem);
    }
    let vault = match open_vault() {
        Ok(vault) => vault,
        Err(_) => {
            // Make the (owner-only) folder the message names, so the person can opt out there. Nothing is saved in it.
            let _ = DeviceStore::open(dir);
            return Err(no_key_store(dir));
        }
    };
    DeviceStore::open_sealed(dir, vault).map_err(store_problem)
}

/// The file in the data folder that remembers the email last used to sign in (not a secret; it fills the form).
pub const LAST_EMAIL_FILE: &str = "last-email";
const MAX_EMAIL_FILE: u64 = 512;

/// The email last used to sign in, if one was saved in `dir`.
pub fn read_last_email(dir: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(dir.join(LAST_EMAIL_FILE)).ok()?.take(MAX_EMAIL_FILE).read_to_string(&mut text).ok()?;
    let email = text.trim();
    (!email.is_empty() && email.len() < MAX_EMAIL_FILE as usize && !email.chars().any(char::is_control)).then(|| email.to_owned())
}

/// Remember `email` in `dir` for the next start. Best effort: a failure only means the form starts empty.
pub fn write_last_email(dir: &std::path::Path, email: &str) {
    let path = dir.join(LAST_EMAIL_FILE);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if let Ok(mut file) = options.open(path) {
        use std::io::Write;
        let _ = file.write_all(email.as_bytes());
    }
}

/// Turns an invitation link into the endpoint to enroll at and the invitation code. It may connect to the server
/// (to fetch its root certificate against the link's fingerprint). The error is shown to the person as written.
pub type Join = Box<dyn Fn(&str) -> Result<(ServerEndpoint, EnrollmentCode), String> + Send>;

/// Called after any event is queued for the app, to wake the window. Must not block.
pub type Wake = Arc<dyn Fn() + Send + Sync>;

/// How long joining from a link may take to reach the server and fetch its root certificate.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(15);

/// The `Join` the app uses: parse the invitation link, fetch the server's root certificate over TLS and accept it
/// only if it matches the link's fingerprint (`ServerEndpoint::from_invitation`), and hand back the invitation code.
pub fn join_from_link(timeout: Duration) -> Join {
    Box::new(move |text: &str| {
        let link = InvitationLink::parse(text.trim())
            .map_err(|_| "That is not a CrewCraft invitation link. Copy the whole link your administrator sent.".to_owned())?;
        let endpoint = ServerEndpoint::from_invitation(&link, timeout).map_err(|error| match error {
            LabError::Trust => "The server did not prove it is the one in the invitation, so CrewCraft did not connect.".to_owned(),
            LabError::Address => "The server address in the invitation is not valid.".to_owned(),
            _ => "The server in the invitation could not be reached. Check the network and try again.".to_owned(),
        })?;
        Ok((endpoint, link.code().clone()))
    })
}

/// The window update for a link the app was opened with (task T405: an Android intent; later, the desktop's link
/// handlers): `InvitationLink` for a well-formed CrewCraft invitation link, `None` for anything else, which is
/// dropped without a word, so a stray link cannot put text in the form.
pub fn opened_with_link(text: &str) -> Option<Update> {
    let text = text.trim();
    InvitationLink::parse(text).ok().map(|_| Update::InvitationLink(Zeroizing::new(text.to_owned())))
}

type Started = Result<(Enrollment, Receiver<EnrollmentEvent>), String>;

/// Where the enrolled device is kept: the platform's per-user data folder plus `CrewCraft`. `None` when the
/// environment names no home folder.
pub fn data_dir() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        var("APPDATA").map(|dir| dir.join("CrewCraft"))
    } else if cfg!(target_os = "ios") {
        crate::ios::data_dir(var("HOME"))
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|home| home.join("Library").join("Application Support").join("CrewCraft"))
    } else {
        var("XDG_DATA_HOME").or_else(|| var("HOME").map(|home| home.join(".local").join("share"))).map(|dir| dir.join("crewcraft"))
    }
}

/// The name this device is enrolled under, as the server's device list shows it.
pub fn device_name() -> String {
    let os = match std::env::consts::OS {
        "windows" => "Windows",
        "macos" => "macOS",
        "linux" => "Linux",
        "android" => return "CrewCraft on Android".to_owned(),
        "ios" => return "CrewCraft on iOS".to_owned(),
        other => other,
    };
    format!("CrewCraft desktop on {os}")
}

/// The app without its window: it takes the window's actions and gives back window updates.
pub struct Controller {
    store: Option<DeviceStore>,
    /// The data folder, for the remembered email.
    dir: Option<PathBuf>,
    /// Runs on a short-lived thread for each enrollment, so reaching the server never blocks the window.
    join: Arc<Mutex<Join>>,
    joining: Option<Receiver<Started>>,
    wake: Wake,
    config: WorkerConfig,
    enrollment: Option<(Enrollment, Receiver<EnrollmentEvent>)>,
    worker: Option<(Worker, Receiver<Event>)>,
    /// The hardware key store new device keys are made in; `None` on the desktop (software keys, sealed records).
    hardware: Option<Arc<dyn HardwareKeys>>,
    /// Opens an organization's sign-in page (tasks T611h, T611i): the system browser, or a test's or a phone's own.
    browser: Browser,
}

impl Controller {
    /// Open the device store in `dir`, sealed with the operating system's key store (`SystemVault`), and start from
    /// what it holds: the saved device (sign-in) or none (enroll).
    pub fn start(dir: Option<PathBuf>, join: Join, wake: Wake, config: WorkerConfig) -> (Self, Vec<Update>) {
        Self::start_with_vault(dir, SystemVault::opener(), join, wake, config)
    }

    /// `start` with the key store `open_vault` opens (tests pass an in-memory one). It is not opened when there is no
    /// data folder or the person has opted out of the key store (`PLAIN_RECORD_SETTING`). When it cannot be opened, or
    /// does not answer, the app says so and still starts; it never falls back to a plain file on its own.
    pub fn start_with_vault(dir: Option<PathBuf>, open_vault: OpenVault<'_>, join: Join, wake: Wake, config: WorkerConfig) -> (Self, Vec<Update>) {
        Self::start_with_store(dir, |dir| open_store(dir, open_vault), None, join, wake, config)
    }

    /// Start a phone app whose device keys live in the hardware key store `keys` (the Android Keystore; tests pass
    /// `hardware_key::MemoryKeys`). The record in `dir` names the key and holds no secret (`DeviceStore::open_hardware`).
    pub fn start_with_hardware_keys(
        dir: Option<PathBuf>,
        keys: Arc<dyn HardwareKeys>,
        join: Join,
        wake: Wake,
        config: WorkerConfig,
    ) -> (Self, Vec<Update>) {
        let store_keys = keys.clone();
        Self::start_with_store(dir, move |dir| DeviceStore::open_hardware(dir, store_keys).map_err(store_problem), Some(keys), join, wake, config)
    }

    fn start_with_store(
        dir: Option<PathBuf>,
        open: impl FnOnce(&Path) -> Result<DeviceStore, String>,
        hardware: Option<Arc<dyn HardwareKeys>>,
        join: Join,
        wake: Wake,
        config: WorkerConfig,
    ) -> (Self, Vec<Update>) {
        let mut updates = Vec::new();
        let store = match dir.as_deref().map(open) {
            Some(Ok(store)) => Some(store),
            Some(Err(problem)) => {
                updates.push(Update::Failed(problem));
                None
            }
            None => {
                updates.push(Update::Failed("This computer has no user data folder, so CrewCraft cannot save its enrollment.".to_owned()));
                None
            }
        };
        let remembered = store.as_ref().and(dir.as_deref()).and_then(read_last_email);
        let browser: Browser = Arc::new(crate::loopback::open_browser);
        let mut controller =
            Self { store, dir, join: Arc::new(Mutex::new(join)), joining: None, wake, config, enrollment: None, worker: None, hardware, browser };
        let saved = controller.store.as_ref().map(|store| store.load(PROFILE));
        match saved {
            Some(Ok(device)) => {
                updates.extend(controller.use_device(&device));
                updates.extend(remembered.map(Update::LastEmail));
            }
            Some(Err(StoreError::NotFound)) | None => {
                updates.insert(0, Update::NeedsEnrollment);
                // Say before anyone enrolls that the enrollment could not be kept. The store stays open: the key
                // store may be unlocked by the time enrollment finishes, and a failed save is reported then.
                if let (Some(store), Some(dir)) = (&controller.store, controller.dir.as_deref())
                    && store.check_key_store(PROFILE) == Err(StoreError::KeyStoreUnavailable)
                {
                    updates.push(Update::Failed(no_key_store(dir)));
                }
            }
            Some(Err(error)) => {
                updates.push(Update::NeedsEnrollment);
                updates.push(Update::Failed(store_problem(error)));
            }
        }
        (controller, updates)
    }

    /// Open organization sign-in pages with `browser` from now on (tests; a phone's own browser call). Applies to
    /// enrollments started after this call, and to the connection of a device enrolled after it.
    pub fn set_browser(&mut self, browser: Browser) {
        self.browser = browser;
    }

    /// Join from `link` on a short-lived thread, then start the enrollment `start` makes from the endpoint and code.
    fn join_then(
        &mut self,
        link: Zeroizing<String>,
        start: impl FnOnce(ServerEndpoint, EnrollmentCode, Wake) -> Started + Send + 'static,
    ) -> Vec<Update> {
        let (sender, receiver) = mpsc::channel();
        let (join, wake) = (self.join.clone(), self.wake.clone());
        let spawned = thread::Builder::new().name("crewcraft-join".into()).spawn(move || {
            let joined = join.lock().map_err(|_| "Enrollment could not start.".to_owned()).and_then(|join| (*join)(link.as_str()));
            let started = joined.and_then(|(endpoint, code)| start(endpoint, code, wake.clone()));
            if sender.send(started).is_ok() {
                wake();
            }
        });
        match spawned {
            Ok(_) => {
                self.joining = Some(receiver);
                Vec::new()
            }
            Err(_) => vec![Update::NeedsEnrollment, Update::Failed("Enrollment could not start.".to_owned())],
        }
    }

    fn key_source(&self) -> KeySource {
        match &self.hardware {
            Some(keys) => KeySource::Hardware { keys: keys.clone(), alias: new_alias(PROFILE) },
            None => KeySource::Software,
        }
    }

    /// Act on one window action.
    pub fn act(&mut self, action: Action) -> Vec<Update> {
        match action {
            Action::EnrollExternal { link } => {
                let (key, browser) = (self.key_source(), self.browser.clone());
                self.join_then(link, move |endpoint, code, wake| {
                    Enrollment::start_external(endpoint, code, &device_name(), key, browser, move || wake())
                        .map_err(|_| "Enrollment could not start.".to_owned())
                })
            }
            Action::Enroll { link, password } => {
                let key = self.key_source();
                self.join_then(link, move |endpoint, code, wake| {
                    Enrollment::start_with_key(endpoint, code, &device_name(), &password, MAX_CONFIRMATION_WINDOW, key, move || wake())
                        .map_err(|_| "Enrollment could not start.".to_owned())
                })
            }
            Action::ConfirmAuthenticator { code } => match &self.enrollment {
                Some((enrollment, _)) if enrollment.confirm(code.trim()) => Vec::new(),
                Some(_) => vec![Update::Failed("Type the six-digit code your authenticator shows now.".to_owned())],
                None => vec![Update::NeedsEnrollment],
            },
            Action::SignIn { email, password, code } => {
                let Some(credentials) = Credentials::new(&email, &password, code.trim()) else {
                    return vec![Update::Failed("Check the email address, the password and the six-digit code.".to_owned())];
                };
                match &self.worker {
                    Some((worker, _)) if worker.sign_in(credentials) => Vec::new(),
                    _ => vec![Update::Failed("The connection to the server has stopped. Restart CrewCraft.".to_owned())],
                }
            }
            Action::SignInExternal { email } => {
                let email = email.trim();
                if !valid_email(email) {
                    return vec![Update::Failed("Type the email address this device is enrolled for.".to_owned())];
                }
                match &self.worker {
                    Some((worker, _)) if worker.sign_in_external(email) => Vec::new(),
                    _ => vec![Update::Failed("The connection to the server has stopped. Restart CrewCraft.".to_owned())],
                }
            }
            Action::CancelSignIn => {
                if let Some((worker, _)) = &self.worker {
                    worker.cancel_sign_in();
                }
                if let Some((enrollment, _)) = &self.enrollment {
                    enrollment.cancel();
                }
                Vec::new()
            }
            Action::Room(command) => match &self.worker {
                Some((worker, _)) if worker.send(command) => Vec::new(),
                _ => vec![Update::SignedOut],
            },
            Action::SignOut => {
                if let Some((worker, _)) = &self.worker {
                    worker.sign_out();
                }
                vec![Update::SignedOut]
            }
        }
    }

    /// Everything the enrollment and the worker reported since the last call.
    pub fn poll(&mut self) -> Vec<Update> {
        let mut updates = Vec::new();
        if let Some(joining) = &self.joining {
            match joining.try_recv() {
                Ok(Ok(started)) => {
                    self.enrollment = Some(started);
                    self.joining = None;
                }
                Ok(Err(problem)) => {
                    updates.push(Update::NeedsEnrollment);
                    updates.push(Update::Failed(problem));
                    self.joining = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    updates.push(Update::NeedsEnrollment);
                    updates.push(Update::Failed("Enrollment could not start.".to_owned()));
                    self.joining = None;
                }
            }
        }
        let mut enrolled = None;
        if let Some((_, events)) = &self.enrollment {
            loop {
                match events.try_recv() {
                    Ok(EnrollmentEvent::AuthenticatorSetup(setup)) => {
                        updates.push(Update::AuthenticatorSetup { otpauth_uri: setup.otpauth_uri().to_owned() });
                    }
                    Ok(EnrollmentEvent::WaitingForBrowser) => updates.push(Update::WaitingForBrowser),
                    Ok(EnrollmentEvent::Enrolled(device)) => {
                        enrolled = Some(device);
                        break;
                    }
                    Ok(EnrollmentEvent::Failed(error)) => {
                        updates.push(Update::NeedsEnrollment);
                        updates.push(Update::Failed(enrollment_problem(error)));
                        self.enrollment = None;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        updates.push(Update::NeedsEnrollment);
                        self.enrollment = None;
                        break;
                    }
                }
            }
        }
        if let Some(device) = enrolled {
            self.enrollment = None;
            if let Some(store) = &self.store
                && let Err(error) = store.save(PROFILE, &device)
            {
                updates.push(Update::Failed(store_problem(error)));
            }
            // A new enrollment is a new device: a resume ticket from the old one would only be refused.
            if let Some(dir) = self.dir.as_deref() {
                crate::worker::TicketKeeper::clear(&TicketFile::new(dir));
            }
            updates.extend(self.use_device(&device));
        }
        if let Some((_, events)) = &self.worker {
            loop {
                match events.try_recv() {
                    Ok(event) => {
                        if let (Event::SignedIn { email, .. }, Some(dir)) = (&event, self.dir.as_deref()) {
                            write_last_email(dir, email);
                        }
                        updates.extend(worker_update(event));
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        updates.push(Update::SignedOut);
                        updates.push(Update::Failed("The connection to the server has stopped. Restart CrewCraft.".to_owned()));
                        self.worker = None;
                        break;
                    }
                }
            }
        }
        updates
    }

    /// Start the worker for an enrolled device and show its sign-in screen.
    fn use_device(&mut self, device: &StoredDevice) -> Vec<Update> {
        let server = device.endpoint().address().to_owned();
        let identity = match device.identity() {
            Ok(identity) => identity,
            Err(error) => return vec![Update::NeedsEnrollment, Update::Failed(enrollment_problem(error))],
        };
        let wake = self.wake.clone();
        // The resume ticket (T240) is kept next to the saved device, so a restart can reopen the session without a
        // code; with nowhere to keep the device, it is kept in memory only.
        let started = match (&self.store, self.dir.as_deref()) {
            (Some(_), Some(dir)) => Worker::start_with_browser(
                device.endpoint().clone(),
                identity,
                self.config,
                Box::new(TicketFile::new(dir)),
                self.browser.clone(),
                move || wake(),
            ),
            _ => Worker::start(device.endpoint().clone(), identity, self.config, move || wake()),
        };
        match started {
            Ok(worker) => {
                self.worker = Some(worker);
                vec![Update::Enrolled { server }]
            }
            Err(_) => vec![Update::Enrolled { server }, Update::Failed("CrewCraft could not start its connection.".to_owned())],
        }
    }
}

/// The window update for one worker event, if any.
pub fn worker_update(event: Event) -> Vec<Update> {
    match event {
        Event::Connected | Event::Posted { .. } | Event::Changed { .. } => Vec::new(),
        Event::Uploaded { room, file, name, size } => vec![Update::Uploaded { room, file: crewcraft_desktop_ui::FileChip { file, name, size } }],
        Event::Attachments { room, files } => vec![Update::Attachments {
            room,
            files: files
                .into_iter()
                .map(|(cursor, files)| {
                    (
                        cursor,
                        files.into_iter().map(|file| crewcraft_desktop_ui::FileChip { file: file.file, name: file.name, size: file.size }).collect(),
                    )
                })
                .collect(),
        }],
        Event::Saved { path } => vec![Update::Failed(format!("Saved to {}", path.display()))],
        Event::Threads { room, parents } => vec![Update::Threads { room, parents }],
        Event::Reactions { room, reactions } => vec![Update::Reactions { room, reactions }],
        Event::Archive { room, times } => vec![Update::Archive { room, times }],
        Event::Calls { room, open, lines } => vec![Update::Calls { room, open, lines }],
        Event::Files { files } => vec![Update::Files { files }],
        Event::InCall { room, call } => vec![Update::InCall { room, call: Some(call), reason: None }],
        Event::LeftCall { room, reason } => vec![Update::InCall { room, call: None, reason }],
        Event::CallSecurity { room, call, kid, from } => vec![Update::CallSecurity { room, call, kid, from }],
        Event::SearchResults { query, hits } => vec![Update::SearchResults {
            query,
            results: hits
                .into_iter()
                .map(|hit| crewcraft_desktop_ui::SearchResult { room: hit.room, cursor: hit.cursor, author: hit.author, snippet: hit.snippet })
                .collect(),
        }],
        Event::SignedIn { email, rooms } => vec![Update::SignedIn { email, rooms }],
        Event::WaitingForBrowser => vec![Update::WaitingForBrowser],
        Event::Room { room, shown } => vec![Update::Snapshot { room, shown }],
        Event::Unread { room, count } => vec![Update::Unread { room, unread: count }],
        Event::PostFailed { room, problem, .. } => vec![Update::Failed(format!("A message to {room} was not sent: {problem}"))],
        Event::Failed(problem) => vec![Update::Failed(problem.to_string())],
        Event::Disconnected => vec![Update::SignedOut, Update::Failed("The connection was lost. Sign in again with a new code.".to_owned())],
        Event::SessionEnded => vec![Update::SignedOut, Update::Failed("Your session has ended. Sign in again with a new code.".to_owned())],
    }
}

/// What to tell the person when enrollment fails.
pub fn enrollment_problem(error: DeviceError) -> String {
    use crate::bootstrap_transport::BootstrapTransportError as Transport;
    use crate::enroll_client::EnrollmentError as Exchange;
    match error {
        DeviceError::Bootstrap(Transport::Endpoint(_) | Transport::Connection(_)) => {
            "The server could not be reached, or it did not prove it is the server in the invitation.".to_owned()
        }
        DeviceError::Bootstrap(Transport::ConfirmationWindow) | DeviceError::Enrollment(Exchange::PromptCancelled) => {
            "Enrollment took too long. Ask for a new invitation if this one has expired.".to_owned()
        }
        // The two answers of an enrollment through the provider come before the general refusals (task T611i).
        DeviceError::Enrollment(Exchange::WrongPath) => {
            "This server enrolls the other way: with your organization's sign-in, or with a password. Use the other button.".to_owned()
        }
        DeviceError::Enrollment(Exchange::ConfirmRefused(ERR_EXTERNAL_REFUSED)) => {
            "Your organization's sign-in did not match this invitation, or you do not have access to this chat. Ask your \
             administrator."
                .to_owned()
        }
        DeviceError::Enrollment(Exchange::SetupRefused(_)) => {
            "The server refused the invitation. It may have expired or already been used.".to_owned()
        }
        DeviceError::Enrollment(Exchange::ConfirmRefused(_)) => {
            "The server refused that authenticator code. Start again with the invitation.".to_owned()
        }
        DeviceError::Enrollment(Exchange::Browser(problem)) => match problem {
            BrowserProblem::Cancelled => "Enrollment cancelled.".to_owned(),
            BrowserProblem::TimedOut => "The sign-in in the browser was not finished in time. Try again.".to_owned(),
            BrowserProblem::ProviderRefused => "The sign-in page did not sign you in. Try again.".to_owned(),
            BrowserProblem::Browser | BrowserProblem::NoRedirect => "The browser could not be used for the sign-in.".to_owned(),
        },
        DeviceError::Enrollment(Exchange::ConfirmationUnknown(_)) => {
            "The connection dropped while the server confirmed the code. Ask your administrator whether this device was enrolled.".to_owned()
        }
        _ => "Enrollment failed. Ask your administrator for a new invitation.".to_owned(),
    }
}

/// What to tell the person when the saved enrollment cannot be read or written.
pub fn store_problem(error: StoreError) -> String {
    match error {
        StoreError::Permissions => "The saved enrollment's folder or file can be read by other users, so CrewCraft will not use it.".to_owned(),
        StoreError::Corrupt | StoreError::TooLarge => "The saved enrollment is damaged. Enroll this device again.".to_owned(),
        StoreError::NotFound => "No enrollment is saved on this computer.".to_owned(),
        StoreError::KeyStoreUnavailable => "CrewCraft could not reach this computer's key store, which holds the key to its saved \
                                            enrollment. Unlock or start the key store, then restart CrewCraft."
            .to_owned(),
        StoreError::KeyMissing => "The key to the saved enrollment is not in this computer's key store (it was removed, or the \
                                   files came from another computer or user). Enroll this device again."
            .to_owned(),
        StoreError::Sealed => format!(
            "The saved enrollment is sealed with a key from the key store, but CrewCraft is set to keep it in a plain file \
             ({PLAIN_RECORD_SETTING}). Remove that setting, or enroll this device again."
        ),
        StoreError::KeyKind => "The saved enrollment was made for a different kind of key store. Enroll this device again.".to_owned(),
        StoreError::InvalidName | StoreError::Io(_) => "CrewCraft could not read or write its saved enrollment.".to_owned(),
    }
}

/// What to tell the person when the data folder `dir` has no key store to seal the enrollment with.
pub fn no_key_store(dir: &Path) -> String {
    if cfg!(target_os = "android") {
        // The device key lives in the Android Keystore (T403); without it there is nowhere safe to make one.
        return "CrewCraft could not reach this phone's key store (the Android Keystore), so it cannot make a device key or keep \
                an enrollment. Restart the phone and try again."
            .to_owned();
    }
    if cfg!(target_os = "ios") {
        // The device key lives in the Secure Enclave and the app's Keychain (T422).
        return "CrewCraft could not reach this iPhone's Keychain, so it cannot make a device key or keep an enrollment. Restart \
                the iPhone and try again."
            .to_owned();
    }
    format!(
        "This computer has no key store CrewCraft can use (on Linux, a Secret Service such as GNOME Keyring or KWallet), so it \
         cannot keep its enrollment sealed and will not save it. Start or unlock the key store, then restart CrewCraft. To keep \
         the enrollment in a file protected only by its permissions instead, create an empty file named {PLAIN_RECORD_SETTING} \
         in {}.",
        dir.display()
    )
}

/// The eframe app: the window plus the controller.
pub struct DesktopApp {
    window: Window,
    controller: Controller,
}

impl DesktopApp {
    /// Fill the enrollment form with the invitation link the app was opened with (`opened_with_link`). False if the
    /// text is not an invitation link.
    pub fn open_link(&mut self, text: &str) -> bool {
        match opened_with_link(text) {
            Some(update) => {
                self.window.apply(update);
                true
            }
            None => false,
        }
    }

    /// The app with its enrollment in the platform's data folder (`data_dir`).
    pub fn new(context: &eframe::egui::Context, join: Join) -> Self {
        Self::with_data_dir(context, join, data_dir())
    }

    /// The app with its enrollment in `dir`: on Android, a folder in the app's private storage (T401).
    pub fn with_data_dir(context: &eframe::egui::Context, join: Join, dir: Option<PathBuf>) -> Self {
        let look = load_appearance(dir.as_deref());
        Self::with_controller(context, look, |wake| Controller::start(dir, join, wake, WorkerConfig::default()))
    }

    /// The app with its enrollment in `dir` and its device key in the hardware key store `keys` (the Android
    /// Keystore, T403).
    pub fn with_hardware_keys(context: &eframe::egui::Context, join: Join, dir: Option<PathBuf>, keys: Arc<dyn HardwareKeys>) -> Self {
        let look = load_appearance(dir.as_deref());
        Self::with_controller(context, look, |wake| Controller::start_with_hardware_keys(dir, keys, join, wake, WorkerConfig::default()))
    }

    fn with_controller(
        context: &eframe::egui::Context,
        (appearance, problems): (Appearance, Vec<String>),
        start: impl FnOnce(Wake) -> (Controller, Vec<Update>),
    ) -> Self {
        context.set_fonts(crewcraft_desktop_ui::fonts());
        appearance.install(context);
        let repaint = context.clone();
        let wake: Wake = Arc::new(move || repaint.request_repaint());
        let (controller, updates) = start(wake);
        let mut window = Window::new();
        window.set_title(appearance.title());
        if let Some(colors) = appearance.bubble_colors() {
            window.set_bubble_colors(colors);
        }
        for update in updates {
            window.apply(update);
        }
        // After the start-up updates, which may change the screen and so clear the notice.
        if !problems.is_empty() {
            window.apply(Update::Failed(problems.join(" ")));
        }
        Self { window, controller }
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        for update in self.controller.poll() {
            self.window.apply(update);
        }
        self.window.ui(ui);
        for action in self.window.take_actions() {
            for update in self.controller.act(action) {
                self.window.apply(update);
            }
        }
    }
}
