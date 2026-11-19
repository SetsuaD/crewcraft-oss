//! The desktop app: the window (`crewcraft-desktop-ui`) wired to enrollment, the saved device and the connection
//! worker. Task T309.
//!
//! Owns: the app's lifecycle (enroll, authenticator setup, sign in, chat, sign out, connection lost), where the
//! enrolled device is saved, and how worker and enrollment events become window updates. Called by: `main.rs`, which
//! runs `DesktopApp` in an eframe window. Calls: `enrollment`, `device_store`, `worker`, and a `Join` that turns an
//! invitation link into a server endpoint and an enrollment code (`join_from_link`; tests pass their own). Task T311
//! moved joining off the window's thread.
//!
//! Everything that does not need a window is in `Controller`, so it is tested without one.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crewcraft_desktop_ui::{Action, Update, Window};
use crewcraft_enroll::{EnrollmentCode, InvitationLink};

use crate::device::{DeviceError, StoredDevice};
use crate::device_store::{DeviceStore, StoreError};
use crate::enrollment::{Enrollment, EnrollmentEvent};
use crate::lab_client::LabError;
use crate::server_endpoint::ServerEndpoint;
use crate::signed_in::Credentials;
use crate::worker::{Event, Worker, WorkerConfig};

/// The one saved server profile of the first beta. Several servers come later.
pub const PROFILE: &str = "default";

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

type Started = Result<(Enrollment, Receiver<EnrollmentEvent>), String>;

/// Where the enrolled device is kept: the platform's per-user data folder plus `CrewCraft`. `None` when the
/// environment names no home folder.
pub fn data_dir() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        var("APPDATA").map(|dir| dir.join("CrewCraft"))
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
        other => other,
    };
    format!("CrewCraft desktop on {os}")
}

/// The app without its window: it takes the window's actions and gives back window updates.
pub struct Controller {
    store: Option<DeviceStore>,
    /// Runs on a short-lived thread for each enrollment, so reaching the server never blocks the window.
    join: Arc<Mutex<Join>>,
    joining: Option<Receiver<Started>>,
    wake: Wake,
    config: WorkerConfig,
    enrollment: Option<(Enrollment, Receiver<EnrollmentEvent>)>,
    worker: Option<(Worker, Receiver<Event>)>,
}

impl Controller {
    /// Open the device store in `dir` and start from what it holds: the saved device (sign-in) or none (enroll).
    pub fn start(dir: Option<PathBuf>, join: Join, wake: Wake, config: WorkerConfig) -> (Self, Vec<Update>) {
        let mut updates = Vec::new();
        let store = match dir.as_deref().map(DeviceStore::open) {
            Some(Ok(store)) => Some(store),
            Some(Err(error)) => {
                updates.push(Update::Failed(store_problem(error)));
                None
            }
            None => {
                updates.push(Update::Failed("This computer has no user data folder, so CrewCraft cannot save its enrollment.".to_owned()));
                None
            }
        };
        let mut controller = Self { store, join: Arc::new(Mutex::new(join)), joining: None, wake, config, enrollment: None, worker: None };
        let saved = controller.store.as_ref().map(|store| store.load(PROFILE));
        match saved {
            Some(Ok(device)) => updates.extend(controller.use_device(&device)),
            Some(Err(StoreError::NotFound)) | None => updates.insert(0, Update::NeedsEnrollment),
            Some(Err(error)) => {
                updates.push(Update::NeedsEnrollment);
                updates.push(Update::Failed(store_problem(error)));
            }
        }
        (controller, updates)
    }

    /// Act on one window action.
    pub fn act(&mut self, action: Action) -> Vec<Update> {
        match action {
            Action::Enroll { link, password } => {
                let (sender, receiver) = mpsc::channel();
                let (join, wake) = (self.join.clone(), self.wake.clone());
                let spawned = thread::Builder::new().name("crewcraft-join".into()).spawn(move || {
                    let joined = join.lock().map_err(|_| "Enrollment could not start.".to_owned()).and_then(|join| (*join)(link.as_str()));
                    let started = joined.and_then(|(endpoint, code)| {
                        let notify = wake.clone();
                        Enrollment::start(endpoint, code, &device_name(), &password, move || notify())
                            .map_err(|_| "Enrollment could not start.".to_owned())
                    });
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
            updates.extend(self.use_device(&device));
        }
        if let Some((_, events)) = &self.worker {
            loop {
                match events.try_recv() {
                    Ok(event) => updates.extend(worker_update(event)),
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
        match Worker::start(device.endpoint().clone(), identity, self.config, move || wake()) {
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
        Event::Connected | Event::Posted { .. } => Vec::new(),
        Event::SignedIn { email, rooms } => vec![Update::SignedIn { email, rooms }],
        Event::Room { room, shown } => vec![Update::Snapshot { room, shown }],
        Event::Unread { room, count } => vec![Update::Unread { room, unread: count }],
        Event::PostFailed { room, problem, .. } => vec![Update::Failed(format!("A message to {room} was not sent: {problem}"))],
        Event::Failed(problem) => vec![Update::Failed(problem.to_string())],
        Event::Disconnected => vec![Update::SignedOut, Update::Failed("The connection was lost. Sign in again with a new code.".to_owned())],
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
        DeviceError::Enrollment(Exchange::SetupRefused(_)) => {
            "The server refused the invitation. It may have expired or already been used.".to_owned()
        }
        DeviceError::Enrollment(Exchange::ConfirmRefused(_)) => {
            "The server refused that authenticator code. Start again with the invitation.".to_owned()
        }
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
        StoreError::InvalidName | StoreError::Io(_) => "CrewCraft could not read or write its saved enrollment.".to_owned(),
    }
}

/// The eframe app: the window plus the controller.
pub struct DesktopApp {
    window: Window,
    controller: Controller,
}

impl DesktopApp {
    pub fn new(context: &eframe::egui::Context, join: Join) -> Self {
        context.set_fonts(crewcraft_desktop_ui::fonts());
        let repaint = context.clone();
        let wake: Wake = Arc::new(move || repaint.request_repaint());
        let (controller, updates) = Controller::start(data_dir(), join, wake, WorkerConfig::default());
        let mut window = Window::new();
        for update in updates {
            window.apply(update);
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
