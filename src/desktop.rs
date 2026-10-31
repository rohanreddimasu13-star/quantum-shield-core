//! Quantum Shield's native setup wizard.
//!
//! The wizard prepares TLS-edge deployments and runs the read-only website,
//! application, and repository audit commands. Storage/app-payload encryption
//! remains explicitly incomplete until a matching adapter is implemented.

#[path = "sandbox_policy.rs"]
mod sandbox_policy;

#[path = "config.rs"]
mod config;

use eframe::egui::{self, Color32, RichText};
use sandbox_policy::SandboxNetworkMode;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Website,
    SoftwareApi,
}

impl TargetKind {
    fn label(self) -> &'static str {
        match self {
            Self::Website => "Website",
            Self::SoftwareApi => "Software / API",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Website => "Protect browser-to-site traffic and plan data safeguards.",
            Self::SoftwareApi => {
                "Protect API/client traffic and plan safeguards for application data."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditMode {
    Website,
    Application,
    Repository,
}

impl AuditMode {
    fn label(self) -> &'static str {
        match self {
            Self::Website => "Website",
            Self::Application => "Application",
            Self::Repository => "Repository",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Website => "website-audit",
            Self::Application => "app-audit",
            Self::Repository => "repo-scan",
        }
    }

    fn target_hint(self) -> &'static str {
        match self {
            Self::Website => "https://your-domain.example",
            Self::Application => "/path/to/application",
            Self::Repository => "/path/to/git/repository",
        }
    }
}

struct AuditEvent {
    success: bool,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentKind {
    SelfHosted,
    DockerCompose,
}

impl DeploymentKind {
    fn label(self) -> &'static str {
        match self {
            Self::SelfHosted => "Self-hosted Linux server",
            Self::DockerCompose => "Docker Compose private network",
        }
    }
}

#[derive(Default)]
struct ResultState {
    output_dir: Option<PathBuf>,
    error: Option<String>,
}

struct DeployEvent {
    success: bool,
    message: String,
}

struct DesktopApp {
    target: TargetKind,
    deployment: DeploymentKind,
    domain: String,
    upstream: String,
    layer_at_rest: bool,
    layer_application: bool,
    compose_file: String,
    cert_path: String,
    key_path: String,
    use_acme: bool,
    acme_email: String,
    acme_production: bool,
    acknowledge_acme_production: bool,
    local_test: bool,
    acknowledge_public_listener: bool,
    deploy_running: bool,
    deploy_message: Option<DeployEvent>,
    deploy_tx: Sender<DeployEvent>,
    deploy_rx: Receiver<DeployEvent>,
    audit_mode: AuditMode,
    audit_target: String,
    audit_output: String,
    audit_json: bool,
    audit_running: bool,
    audit_message: Option<AuditEvent>,
    audit_tx: Sender<AuditEvent>,
    audit_rx: Receiver<AuditEvent>,
    proof_running: bool,
    proof_message: Option<AuditEvent>,
    proof_tx: Sender<AuditEvent>,
    proof_rx: Receiver<AuditEvent>,
    sandbox_executable: String,
    sandbox_app_dir: String,
    sandbox_writable_dir: String,
    sandbox_args: String,
    sandbox_network_mode: SandboxNetworkMode,
    sandbox_running: bool,
    sandbox_message: Option<AuditEvent>,
    sandbox_tx: Sender<AuditEvent>,
    sandbox_rx: Receiver<AuditEvent>,
    data_key_id: String,
    data_input: String,
    data_output: String,
    data_kind: String,
    data_running: bool,
    data_message: Option<AuditEvent>,
    data_tx: Sender<AuditEvent>,
    data_rx: Receiver<AuditEvent>,
    ui_context: egui::Context,
    result: ResultState,
}

impl Default for DesktopApp {
    fn default() -> Self {
        let (deploy_tx, deploy_rx) = mpsc::channel();
        let (audit_tx, audit_rx) = mpsc::channel();
        let (proof_tx, proof_rx) = mpsc::channel();
        let (sandbox_tx, sandbox_rx) = mpsc::channel();
        let (data_tx, data_rx) = mpsc::channel();
        Self {
            target: TargetKind::Website,
            deployment: DeploymentKind::SelfHosted,
            domain: String::new(),
            upstream: "http://127.0.0.1:3000".to_owned(),
            // Layer 2 is a user requirement, not a claim that this adapter has
            // already encrypted application storage. The UI reports that status.
            layer_at_rest: true,
            layer_application: false,
            compose_file: "compose.yaml".to_owned(),
            cert_path: String::new(),
            key_path: String::new(),
            use_acme: false,
            acme_email: String::new(),
            acme_production: false,
            acknowledge_acme_production: false,
            local_test: true,
            acknowledge_public_listener: false,
            deploy_running: false,
            deploy_message: None,
            deploy_tx,
            deploy_rx,
            audit_mode: AuditMode::Repository,
            audit_target: String::new(),
            audit_output: "quantum-shield-report.json".to_owned(),
            audit_json: true,
            audit_running: false,
            audit_message: None,
            audit_tx,
            audit_rx,
            proof_running: false,
            proof_message: None,
            proof_tx,
            proof_rx,
            sandbox_executable: String::new(),
            sandbox_app_dir: String::new(),
            sandbox_writable_dir: String::new(),
            sandbox_args: String::new(),
            sandbox_network_mode: SandboxNetworkMode::Isolated,
            sandbox_running: false,
            sandbox_message: None,
            sandbox_tx,
            sandbox_rx,
            data_key_id: "primary".to_owned(),
            data_input: String::new(),
            data_output: String::new(),
            data_kind: "repository".to_owned(),
            data_running: false,
            data_message: None,
            data_tx,
            data_rx,
            ui_context: egui::Context::default(),
            result: ResultState::default(),
        }
    }
}

impl DesktopApp {
    fn start_domain_proof_command(&mut self, subcommand: &'static str) {
        if self.proof_running {
            return;
        }
        let domain = self.domain.trim().to_owned();
        if domain.is_empty() {
            self.proof_message = Some(AuditEvent {
                success: false,
                message: "Enter a public hostname first.".to_owned(),
            });
            return;
        }
        let qsctl = match locate_qsctl() {
            Ok(path) => path,
            Err(error) => {
                self.proof_message = Some(AuditEvent {
                    success: false,
                    message: error,
                });
                return;
            }
        };
        self.proof_running = true;
        self.proof_message = None;
        let tx = self.proof_tx.clone();
        thread::spawn(move || {
            let event = match Command::new(qsctl).arg(subcommand).arg(&domain).output() {
                Ok(output) => {
                    let mut message = String::new();
                    if !output.stdout.is_empty() {
                        message.push_str(&String::from_utf8_lossy(&output.stdout));
                    }
                    if !output.stderr.is_empty() {
                        if !message.is_empty() {
                            message.push('\n');
                        }
                        message.push_str(&String::from_utf8_lossy(&output.stderr));
                    }
                    AuditEvent {
                        success: output.status.success(),
                        message: truncate_for_ui(message.trim(), 9000),
                    }
                }
                Err(error) => AuditEvent {
                    success: false,
                    message: format!("could not run qsctl: {error}"),
                },
            };
            let _ = tx.send(event);
        });
    }

    fn start_data_command(&mut self, args: Vec<OsString>) {
        if self.data_running {
            return;
        }
        let qsctl = match locate_qsctl() {
            Ok(path) => path,
            Err(error) => {
                self.data_message = Some(AuditEvent {
                    success: false,
                    message: error,
                });
                return;
            }
        };
        let tx = self.data_tx.clone();
        let ctx = self.ui_context.clone();
        self.data_running = true;
        self.data_message = None;
        thread::spawn(move || {
            let event = match Command::new(&qsctl).args(&args).output() {
                Ok(output) => {
                    let mut message = String::from_utf8_lossy(&output.stdout).into_owned();
                    if !output.stderr.is_empty() {
                        if !message.is_empty() {
                            message.push('\n');
                        }
                        message.push_str(&String::from_utf8_lossy(&output.stderr));
                    }
                    AuditEvent {
                        success: output.status.success(),
                        message: truncate_for_ui(message.trim(), 9000),
                    }
                }
                Err(error) => AuditEvent {
                    success: false,
                    message: format!("Could not launch {}: {error}", qsctl.display()),
                },
            };
            let _ = tx.send(event);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for DesktopApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.deploy_rx.try_recv() {
            self.deploy_running = false;
            self.deploy_message = Some(event);
        }
        while let Ok(event) = self.audit_rx.try_recv() {
            self.audit_running = false;
            self.audit_message = Some(event);
        }
        while let Ok(event) = self.proof_rx.try_recv() {
            self.proof_running = false;
            self.proof_message = Some(event);
        }
        while let Ok(event) = self.sandbox_rx.try_recv() {
            self.sandbox_running = false;
            self.sandbox_message = Some(event);
        }
        while let Ok(event) = self.data_rx.try_recv() {
            self.data_running = false;
            self.data_message = Some(event);
        }
        if self.deploy_running
            || self.audit_running
            || self.sandbox_running
            || self.proof_running
            || self.data_running
        {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.ui_context = ui.ctx().clone();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("◈ QUANTUM SHIELD")
                    .size(19.0)
                    .strong()
                    .color(Color32::from_rgb(125, 190, 255)),
            );
            ui.add_space(12.0);
            ui.label(
                RichText::new("ONE-CLICK SETUP WIZARD")
                    .small()
                    .color(Color32::from_rgb(160, 170, 190)),
            );
        });
        ui.label(
            RichText::new("SUPPORTED LIVE ADAPTER: DOCKER COMPOSE + TLS / AUTOMATIC ACME")
                .small()
                .color(Color32::from_rgb(232, 190, 100)),
        );
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(8.0);
            ui.heading(RichText::new("What do you want to protect?").size(27.0).strong());
            ui.label("Choose your target and request two or more protection layers. Quantum Shield reports each layer separately and never marks an unimplemented layer as active.");
            ui.add_space(14.0);

            ui.horizontal(|ui| {
                target_card(ui, &mut self.target, TargetKind::Website);
                ui.add_space(8.0);
                target_card(ui, &mut self.target, TargetKind::SoftwareApi);
            });
            ui.add_space(16.0);

            ui.group(|ui| {
                ui.heading("Your site or application");
                ui.label("Public hostname / API domain");
                ui.add(egui::TextEdit::singleline(&mut self.domain)
                    .hint_text("app.yourdomain.com")
                    .desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    let enabled = !self.proof_running && !self.domain.trim().is_empty();
                    if ui.add_enabled(enabled, egui::Button::new("Generate DNS ownership proof")).clicked() {
                        self.start_domain_proof_command("domain-challenge");
                    }
                    if ui.add_enabled(enabled, egui::Button::new("Verify DNS proof")).clicked() {
                        self.start_domain_proof_command("domain-verify");
                    }
                });
                if self.proof_running {
                    ui.horizontal(|ui| { ui.spinner(); ui.label("Checking DNS ownership..."); });
                }
                if let Some(event) = &self.proof_message {
                    let color = if event.success { Color32::from_rgb(112, 218, 155) } else { Color32::from_rgb(240, 135, 110) };
                    ui.label(RichText::new(&event.message).color(color));
                }
                ui.label(RichText::new("Ownership proof only verifies DNS control. It does not authorize deployment; public deployment still requires a separate approval.").small().color(Color32::from_rgb(230, 190, 105)));
                ui.add_space(8.0);
                ui.label("Existing application address (upstream)");
                ui.add(egui::TextEdit::singleline(&mut self.upstream)
                    .hint_text("http://127.0.0.1:3000 or http://web:3000")
                    .desired_width(f32::INFINITY));
                ui.add_space(8.0);
                ui.label("Where is it hosted?");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.deployment, DeploymentKind::SelfHosted, "Self-hosted Linux");
                    ui.selectable_value(&mut self.deployment, DeploymentKind::DockerCompose, "Docker Compose");
                });
                if self.deployment == DeploymentKind::DockerCompose {
                    ui.label(RichText::new("Use the app's service name (for example http://web:3000) on the same private Docker network.").small().color(Color32::from_rgb(230, 190, 105)));
                    ui.add_space(10.0);
                    ui.label("Existing Docker Compose file path");
                    ui.add(egui::TextEdit::singleline(&mut self.compose_file)
                        .hint_text("/srv/my-site/compose.yaml")
                        .desired_width(f32::INFINITY));
                    ui.checkbox(&mut self.use_acme, "Automatically obtain and renew certificates with Let's Encrypt (ACME)");
                    if self.use_acme {
                        self.local_test = false;
                        ui.label("ACME account contact email");
                        ui.add(egui::TextEdit::singleline(&mut self.acme_email)
                            .hint_text("admin@yourdomain.com")
                            .desired_width(f32::INFINITY));
                        ui.checkbox(&mut self.acme_production, "Use production certificates (creates real certificate orders)");
                        if self.acme_production {
                            ui.checkbox(&mut self.acknowledge_acme_production, "I explicitly approve production ACME issuance; I have first validated this domain with staging.");
                        } else {
                            self.acknowledge_acme_production = false;
                            ui.label(RichText::new("Staging is the default; staging certificates are not trusted by browsers. Domain DNS and public TCP/80 and TCP/443 must reach this server.").small().color(Color32::from_rgb(112, 218, 155)));
                        }
                    } else {
                        ui.label("TLS certificate chain (trusted for public mode; self-signed allowed only in local-test mode)");
                        ui.add(egui::TextEdit::singleline(&mut self.cert_path)
                            .hint_text("/etc/letsencrypt/live/app.yourdomain.com/fullchain.pem")
                            .desired_width(f32::INFINITY));
                        ui.label("Matching PEM private key (owner-only permissions)");
                        ui.add(egui::TextEdit::singleline(&mut self.key_path)
                            .hint_text("/etc/letsencrypt/live/app.yourdomain.com/privkey.pem")
                            .desired_width(f32::INFINITY));
                        ui.checkbox(&mut self.local_test, "Local test mode: bind only to 127.0.0.1 on a Docker-assigned port (self-signed certificate allowed for this local health check)");
                    }
                    if self.local_test {
                        self.acknowledge_public_listener = false;
                        ui.label(RichText::new("Safe test mode: no public port is exposed. Certificate trust is bypassed only for the loopback health check; do not use this result as production validation.").small().color(Color32::from_rgb(112, 218, 155)));
                    } else {
                        let exposure_text = if self.use_acme {
                            "I approve exposing host TCP ports 80 and 443 for ACME HTTP-01 and HTTPS."
                        } else {
                            "I approve exposing this service on host TCP port 443."
                        };
                        ui.checkbox(&mut self.acknowledge_public_listener, exposure_text);
                        let public_text = if self.use_acme {
                            "ACME uses persistent account/certificate cache and renews while the service runs. Check DNS A/AAAA, firewall/NAT and TCP/80+443 before applying. Production issuance requires a second acknowledgement."
                        } else {
                            "Public mode requires a valid trusted certificate and free host ports. The adapter preserves your original Compose file and removes only its own proxy if HTTPS health checks fail."
                        };
                        ui.label(RichText::new(public_text).small().color(Color32::from_rgb(230, 190, 105)));
                    }
                }
            });

            ui.add_space(16.0);
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.heading("Choose encryption layers");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let count = 1 + (self.layer_at_rest as usize) + (self.layer_application as usize);
                        let label = format!("{count} layer{} selected", if count == 1 { "" } else { "s" });
                        ui.label(RichText::new(label).strong().color(if count >= 2 { Color32::from_rgb(112, 218, 155) } else { Color32::from_rgb(240, 135, 110) }));
                    });
                });

                ui.horizontal(|ui| {
                    ui.label(RichText::new("LAYER 1 · REQUIRED").strong().color(Color32::from_rgb(125, 190, 255)));
                    ui.label(RichText::new("Encrypted network traffic").strong());
                });
                ui.label("HTTPS / TLS 1.2–1.3 with supported cipher suites (including AES-GCM and ChaCha20-Poly1305 where negotiated). Hybrid X25519MLKEM768 key exchange is preferred where both peers support it; check server logs for the actual suite and group.");
                ui.add_space(10.0);

                ui.checkbox(&mut self.layer_at_rest, "Layer 2 — Stored-data encryption");
                ui.label("Encrypt eligible disks, databases and backups. This wizard records the requirement; it does not yet configure storage or database encryption.");
                ui.add_space(8.0);

                ui.checkbox(&mut self.layer_application, "Layer 3 — Application-level / payload encryption");
                ui.label("Requires application-specific code and a key-management design. A proxy cannot safely add this to arbitrary software automatically.");
            });

            ui.add_space(12.0);
            ui.group(|ui| {
                ui.label(RichText::new("What is operational today").strong());
                ui.label("Website module: TLS edge / ACME certificate lifecycle, plus passive HTTPS and security-header review. Application and repository modules: bounded, read-only source/configuration checks with JSON reports. Git history and cargo-audit available via CLI.");
                ui.label(RichText::new("Important: these scanners do not auto-fix files, run target code, or prove absence of vulnerabilities. This adapter does NOT encrypt arbitrary stored application data or application payloads.").small().color(Color32::from_rgb(230, 190, 105)));
                ui.label(RichText::new("Live TLS apply remains limited to one app service on a private, project-managed Docker Compose network. ACME needs public DNS and reachable TCP/80+443. Other hosting/provider integrations are not universal.").small().color(Color32::from_rgb(230, 190, 105)));
            });

            ui.add_space(12.0);
            ui.group(|ui| {
                ui.heading("Data Protection — keys, files and snapshots");
                ui.label("AES-256-GCM file encryption and encrypted repository/application snapshots. Source files and folders are retained; outputs must be new paths.");
                ui.horizontal(|ui| {
                    ui.label("Key ID");
                    ui.add(egui::TextEdit::singleline(&mut self.data_key_id).desired_width(180.0));
                    if ui.add_enabled(!self.data_running && !self.data_key_id.trim().is_empty(), egui::Button::new("Generate key")).clicked() {
                        self.start_data_command(vec!["key-generate".into(), "--id".into(), self.data_key_id.trim().into()]);
                    }
                    if ui.add_enabled(!self.data_running, egui::Button::new("List keys")).clicked() {
                        self.start_data_command(vec!["key-list".into()]);
                    }
                });
                ui.label("Input file or directory");
                ui.add(egui::TextEdit::singleline(&mut self.data_input).desired_width(f32::INFINITY));
                ui.label("New output path (must not already exist)");
                ui.add(egui::TextEdit::singleline(&mut self.data_output).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.data_running && !self.data_key_id.trim().is_empty() && !self.data_input.trim().is_empty() && !self.data_output.trim().is_empty(), egui::Button::new("Encrypt file")).clicked() {
                        self.start_data_command(vec!["encrypt-file".into(), "--key-id".into(), self.data_key_id.trim().into(), "--input".into(), self.data_input.trim().into(), "--output".into(), self.data_output.trim().into()]);
                    }
                    if ui.add_enabled(!self.data_running && !self.data_key_id.trim().is_empty() && !self.data_input.trim().is_empty() && !self.data_output.trim().is_empty(), egui::Button::new("Decrypt file")).clicked() {
                        self.start_data_command(vec!["decrypt-file".into(), "--key-id".into(), self.data_key_id.trim().into(), "--input".into(), self.data_input.trim().into(), "--output".into(), self.data_output.trim().into()]);
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Snapshot type");
                    ui.selectable_value(&mut self.data_kind, "repository".to_owned(), "Repository");
                    ui.selectable_value(&mut self.data_kind, "application".to_owned(), "Application");
                    if ui.add_enabled(!self.data_running && !self.data_key_id.trim().is_empty() && !self.data_input.trim().is_empty() && !self.data_output.trim().is_empty(), egui::Button::new("Create encrypted snapshot")).clicked() {
                        self.start_data_command(vec!["protect".into(), "--kind".into(), self.data_kind.clone().into(), "--path".into(), self.data_input.trim().into(), "--key-id".into(), self.data_key_id.trim().into(), "--output".into(), self.data_output.trim().into()]);
                    }
                });
                if self.data_running {
                    ui.horizontal(|ui| { ui.spinner(); ui.label("Running data-protection operation…"); });
                }
                if let Some(event) = &self.data_message {
                    let color = if event.success { Color32::from_rgb(112, 218, 155) } else { Color32::from_rgb(255, 125, 115) };
                    ui.label(RichText::new(if event.success { "Data-protection command completed" } else { "Data-protection command failed" }).strong().color(color));
                    ui.label(event.message.as_str());
                }
                ui.label(RichText::new("Limitations: snapshot protection is point-in-time archive encryption, not live directory encryption. Native OS disk encryption and cloud-provider encryption are not implemented.").small().color(Color32::from_rgb(230, 190, 105)));
            });

            ui.add_space(12.0);
            ui.group(|ui| {
                ui.heading("Run a security module");
                ui.label("Read-only audit commands. Website checks use curl and send a HEAD request; application/repository checks inspect source and configuration without executing it.");
                ui.horizontal(|ui| {
                    for mode in [AuditMode::Website, AuditMode::Application, AuditMode::Repository] {
                        ui.selectable_value(&mut self.audit_mode, mode, mode.label());
                    }
                });
                ui.label(match self.audit_mode {
                    AuditMode::Website => "Website URL (no query parameters, fragments, or embedded credentials)",
                    AuditMode::Application => "Local application source/deployment directory",
                    AuditMode::Repository => "Local Git working-tree directory (use CLI for Git history/cargo-audit)",
                });
                ui.add(egui::TextEdit::singleline(&mut self.audit_target)
                    .hint_text(self.audit_mode.target_hint())
                    .desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    ui.label("Report output path");
                    ui.add(egui::TextEdit::singleline(&mut self.audit_output)
                        .hint_text("quantum-shield-report.json")
                        .desired_width(f32::INFINITY));
                });
                ui.checkbox(&mut self.audit_json, "Write JSON report");
                let can_audit = !self.audit_target.trim().is_empty() && !self.audit_running;
                if ui.add_enabled(can_audit, egui::Button::new("Run read-only audit →")).clicked() {
                    self.audit_message = None;
                    match locate_qsctl() {
                        Ok(qsctl) => {
                            let mode = self.audit_mode;
                            let target = self.audit_target.trim().to_owned();
                            let output_path = self.audit_output.trim().to_owned();
                            let json = self.audit_json;
                            let tx = self.audit_tx.clone();
                            self.audit_running = true;
                            let ctx = ui.ctx().clone();
                            thread::spawn(move || {
                                let mut command = Command::new(&qsctl);
                                command.arg(mode.command()).arg(&target);
                                if json {
                                    command.arg("--json");
                                }
                                if !output_path.is_empty() {
                                    command.arg("--output").arg(&output_path);
                                }
                                let event = match command.output() {
                                    Ok(output) => {
                                        let mut message = String::new();
                                        if !output.stdout.is_empty() {
                                            message.push_str(&String::from_utf8_lossy(&output.stdout));
                                        }
                                        if !output.stderr.is_empty() {
                                            if !message.is_empty() { message.push('\n'); }
                                            message.push_str(&String::from_utf8_lossy(&output.stderr));
                                        }
                                        AuditEvent {
                                            success: output.status.success(),
                                            message: truncate_for_ui(message.trim(), 9000),
                                        }
                                    }
                                    Err(error) => AuditEvent {
                                        success: false,
                                        message: format!("Could not launch qsctl at {}: {error}", qsctl.display()),
                                    },
                                };
                                let _ = tx.send(event);
                                ctx.request_repaint();
                            });
                        }
                        Err(error) => self.audit_message = Some(AuditEvent { success: false, message: error }),
                    }
                }
                if self.audit_running {
                    ui.horizontal(|ui| { ui.spinner(); ui.label("Running bounded read-only security checks…"); });
                }
                if let Some(event) = &self.audit_message {
                    let color = if event.success { Color32::from_rgb(112, 218, 155) } else { Color32::from_rgb(255, 125, 115) };
                    ui.label(RichText::new(if event.success { "Audit completed" } else { "Audit could not complete" }).strong().color(color));
                    if !event.message.is_empty() {
                        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                            ui.label(event.message.as_str());
                        });
                    }
                }
            });

            ui.add_space(14.0);
            ui.group(|ui| {
                ui.heading("Software Shield — baseline sandbox");
                ui.label(if cfg!(target_os = "linux") {
                    "Linux: Bubblewrap + seccomp. Requires bwrap; network is disabled by default."
                } else if cfg!(target_os = "macos") {
                    "macOS: Seatbelt via sandbox-exec. Deprecated and potentially unavailable; fails closed if missing."
                } else if cfg!(target_os = "windows") {
                    "Windows: Windows Sandbox. Requires the optional feature on a supported Windows edition."
                } else {
                    "Software Shield sandbox is unsupported on this operating system."
                });
                ui.label("Executable path (absolute or relative to this working directory)");
                ui.add(egui::TextEdit::singleline(&mut self.sandbox_executable)
                    .hint_text("/usr/bin/printf or /path/to/app/tool")
                    .desired_width(f32::INFINITY));
                ui.label("Clean application directory (read-only; must contain executable, no .git metadata or secrets)");
                ui.add(egui::TextEdit::singleline(&mut self.sandbox_app_dir)
                    .hint_text("/path/to/a-clean/app-directory")
                    .desired_width(f32::INFINITY));
                ui.label("Optional writable output directory (only this chosen directory is writable on the host)");
                ui.add(egui::TextEdit::singleline(&mut self.sandbox_writable_dir)
                    .hint_text("/home/you/SecurityReports/sandbox-output")
                    .desired_width(f32::INFINITY));
                ui.label("Arguments: one argument per line; arguments are passed directly, never through a shell");
                ui.add(egui::TextEdit::multiline(&mut self.sandbox_args)
                    .desired_width(f32::INFINITY)
                    .desired_rows(3));
                egui::ComboBox::from_label("Network policy")
                    .selected_text(self.sandbox_network_mode.as_str())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.sandbox_network_mode, SandboxNetworkMode::Isolated, "Isolated (default)");
                        ui.selectable_value(&mut self.sandbox_network_mode, SandboxNetworkMode::Shared, "Shared (host networking)");
                        ui.selectable_value(&mut self.sandbox_network_mode, SandboxNetworkMode::Automatic, "Automatic (warns on capability fallback)");
                    });
                let can_launch = !self.sandbox_executable.trim().is_empty() && !self.sandbox_running;
                if ui.add_enabled(can_launch, egui::Button::new("Run CLI task in Software Shield →")).clicked() {
                    self.sandbox_message = None;
                    match locate_qsctl() {
                        Ok(qsctl) => {
                            let executable = self.sandbox_executable.trim().to_owned();
                            let app_dir = self.sandbox_app_dir.trim().to_owned();
                            let writable_dir = self.sandbox_writable_dir.trim().to_owned();
                            let network_mode = self.sandbox_network_mode;
                            let app_args = self.sandbox_args.lines().filter(|line| !line.is_empty()).map(OsString::from).collect::<Vec<_>>();
                            let tx = self.sandbox_tx.clone();
                            self.sandbox_running = true;
                            let ctx = ui.ctx().clone();
                            thread::spawn(move || {
                                let mut command = Command::new(&qsctl);
                                command.arg("sandbox-run").arg(&executable);
                                if !app_dir.is_empty() {
                                    command.arg("--app-dir").arg(&app_dir);
                                }
                                if !writable_dir.is_empty() {
                                    command.arg("--writable-dir").arg(&writable_dir);
                                }
                                command.arg("--network-mode").arg(network_mode.as_str());
                                if !app_args.is_empty() {
                                    command.arg("--").args(app_args);
                                }
                                let event = match command.output() {
                                    Ok(output) => {
                                        let mut message = String::new();
                                        if !output.stdout.is_empty() {
                                            message.push_str(&String::from_utf8_lossy(&output.stdout));
                                        }
                                        if !output.stderr.is_empty() {
                                            if !message.is_empty() { message.push('\n'); }
                                            message.push_str(&String::from_utf8_lossy(&output.stderr));
                                        }
                                        if let Some(code) = output.status.code() {
                                            message.push_str(&format!("\nProcess exit code: {code}"));
                                        }
                                        AuditEvent {
                                            success: output.status.success(),
                                            message: truncate_for_ui(message.trim(), 9000),
                                        }
                                    }
                                    Err(error) => AuditEvent {
                                        success: false,
                                        message: format!("Could not launch qsctl at {}: {error}", qsctl.display()),
                                    },
                                };
                                let _ = tx.send(event);
                                ctx.request_repaint();
                            });
                        }
                        Err(error) => self.sandbox_message = Some(AuditEvent { success: false, message: error }),
                    }
                }
                if self.sandbox_running {
                    ui.horizontal(|ui| { ui.spinner(); ui.label("Software Shield sandbox is running…"); });
                }
                if let Some(event) = &self.sandbox_message {
                    let color = if event.success { Color32::from_rgb(112, 218, 155) } else { Color32::from_rgb(255, 125, 115) };
                    ui.label(RichText::new(if event.success { "Sandbox task completed" } else { "Sandbox task failed or was blocked" }).strong().color(color));
                    if !event.message.is_empty() {
                        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| { ui.label(event.message.as_str()); });
                    }
                }
                ui.label(RichText::new("Limitations: this profile is not for GUI desktop apps; it has no syscall allowlist or CPU/memory/process quotas. It is a baseline isolation layer, not a guarantee against kernel exploits or denial of service.").small().color(Color32::from_rgb(230, 190, 105)));
            });

            ui.add_space(14.0);
            let layer_count = 1 + (self.layer_at_rest as usize) + (self.layer_application as usize);
            let can_prepare = layer_count >= 2 && !self.domain.trim().is_empty() && !self.upstream.trim().is_empty();
            if ui.add_enabled(can_prepare, egui::Button::new(RichText::new("Prepare my one-click setup  →").strong().size(17.0))).clicked() {
                self.result.error = None;
                self.result.output_dir = None;
                match validate_form(self) {
                    Ok(cfg) => match create_setup_bundle(self, &cfg) {
                        Ok(path) => self.result.output_dir = Some(path),
                        Err(error) => self.result.error = Some(error),
                    },
                    Err(error) => self.result.error = Some(error),
                }
            }
            if self.deployment == DeploymentKind::DockerCompose {
                ui.add_space(8.0);
                let certificate_inputs_ready = if self.use_acme {
                    !self.acme_email.trim().is_empty()
                        && !self.local_test
                        && self.acknowledge_public_listener
                        && (!self.acme_production || self.acknowledge_acme_production)
                } else {
                    !self.cert_path.trim().is_empty()
                        && !self.key_path.trim().is_empty()
                        && (self.local_test || self.acknowledge_public_listener)
                };
                let can_apply = layer_count >= 2
                    && !self.domain.trim().is_empty()
                    && !self.upstream.trim().is_empty()
                    && !self.compose_file.trim().is_empty()
                    && certificate_inputs_ready
                    && !self.deploy_running;
                if ui.add_enabled(can_apply, egui::Button::new(RichText::new("Apply TLS layer to Docker Compose  →").strong().size(16.0))).clicked() {
                    self.result.error = None;
                    self.deploy_message = None;
                    match validate_form(self) {
                        Ok(cfg) => match create_setup_bundle(self, &cfg) {
                            Ok(bundle_path) => {
                                self.result.output_dir = Some(bundle_path.clone());
                                let config_path = bundle_path.join("qs-config.toml");
                                match locate_qsctl() {
                                    Ok(qsctl) => {
                                        let compose_file = self.compose_file.trim().to_owned();
                                        let cert_path = self.cert_path.trim().to_owned();
                                        let key_path = self.key_path.trim().to_owned();
                                        let use_acme = self.use_acme;
                                        let acme_email = self.acme_email.trim().to_owned();
                                        let acme_production = self.acme_production;
                                        let local_test = self.local_test;
                                        let tx = self.deploy_tx.clone();
                                        self.deploy_running = true;
                                        let ctx = ui.ctx().clone();
                                        thread::spawn(move || {
                                            let mut command = Command::new(&qsctl);
                                            command
                                                .arg("deploy-compose")
                                                .arg(&config_path)
                                                .arg("--compose-file").arg(&compose_file);
                                            if use_acme {
                                                command.arg("--acme-email").arg(&acme_email);
                                                if acme_production {
                                                    command.arg("--production")
                                                        .arg("--acknowledge-production-issuance");
                                                }
                                                command.arg("--apply")
                                                    .arg("--acknowledge-public-listener");
                                            } else {
                                                command.arg("--cert").arg(&cert_path)
                                                    .arg("--key").arg(&key_path)
                                                    .arg("--apply");
                                                if local_test {
                                                    command.arg("--local-test");
                                                } else {
                                                    command.arg("--acknowledge-public-listener");
                                                }
                                            }
                                            let output = command.output();
                                            let event = match output {
                                                Ok(output) => {
                                                    let mut message = String::new();
                                                    if !output.stdout.is_empty() {
                                                        message.push_str(&String::from_utf8_lossy(&output.stdout));
                                                    }
                                                    if !output.stderr.is_empty() {
                                                        if !message.is_empty() { message.push('\n'); }
                                                        message.push_str(&String::from_utf8_lossy(&output.stderr));
                                                    }
                                                    DeployEvent {
                                                        success: output.status.success(),
                                                        message: format!("{}\n\nSelected storage/payload layers remain unapplied by the current adapter.", message.trim()),
                                                    }
                                                }
                                                Err(error) => DeployEvent { success: false, message: format!("Could not launch qsctl at {}: {error}", qsctl.display()) },
                                            };
                                            let _ = tx.send(event);
                                            ctx.request_repaint();
                                        });
                                    }
                                    Err(error) => self.result.error = Some(error),
                                }
                            }
                            Err(error) => self.result.error = Some(error),
                        },
                        Err(error) => self.result.error = Some(error),
                    }
                }
                if self.deploy_running {
                    ui.horizontal(|ui| { ui.spinner(); ui.label("Applying Docker Compose TLS adapter, then checking HTTPS…"); });
                }
                if let Some(event) = &self.deploy_message {
                    ui.add_space(8.0);
                    let color = if event.success { Color32::from_rgb(112, 218, 155) } else { Color32::from_rgb(255, 125, 115) };
                    ui.group(|ui| {
                        ui.label(RichText::new(if event.success { "TLS adapter result" } else { "Deployment failed" }).strong().color(color));
                        ui.label(event.message.as_str());
                    });
                }
            }

            if layer_count < 2 {
                ui.label(RichText::new("Select at least two protection layers. Layer 1 is always enabled.").color(Color32::from_rgb(240, 135, 110)));
            }

            if let Some(error) = &self.result.error {
                ui.add_space(8.0);
                ui.colored_label(Color32::from_rgb(255, 125, 115), format!("Setup not prepared: {error}"));
            }
            if let Some(path) = self.result.output_dir.clone() {
                ui.add_space(10.0);
                ui.group(|ui| {
                    ui.label(RichText::new("Setup bundle prepared").strong().color(Color32::from_rgb(112, 218, 155)));
                    ui.label(path.display().to_string());
                    ui.label("Files created: qs-config.toml and PROTECTION_PLAN.md");
                    if self.deploy_message.as_ref().is_some_and(|event| event.success) {
                        ui.label("HTTPS TLS layer was applied and passed its health check. Selected storage/payload layers are still not applied.");
                    } else {
                        ui.label("The setup bundle contains a validated route config and plan. The bundle itself does not activate unimplemented encryption layers.");
                    }
                    if ui.button("Open output folder").clicked() {
                        let result = open_output_folder(&path);
                        if let Err(error) = result {
                            self.result.error = Some(format!("could not open file manager: {error}"));
                        }
                    }
                });
            }
            ui.add_space(20.0);
            ui.separator();
            ui.label(RichText::new("Quantum Shield v1.0.0-rc.2 · Rust · Local-first · No telemetry in this wizard").small().color(Color32::from_rgb(150, 160, 180)));
        });
    }
}

fn open_output_folder(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");

    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");

    #[cfg(target_os = "windows")]
    let mut command = Command::new("explorer.exe");

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Err("folder opening is unsupported on this operating system".to_owned());

    command
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("could not open {}: {error}", path.display()))
}

fn truncate_for_ui(value: &str, max_chars: usize) -> String {
    let mut result = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        result.push_str(
            "\n… output truncated in the window; inspect the saved report for full results.",
        );
    }
    result
}

fn target_card(ui: &mut egui::Ui, selected: &mut TargetKind, target: TargetKind) {
    ui.group(|ui| {
        ui.set_min_width(260.0);
        let is_selected = *selected == target;
        let text = match target {
            TargetKind::Website => "Website",
            TargetKind::SoftwareApi => "Software / API",
        };
        let response = ui.selectable_label(is_selected, RichText::new(text).strong().size(16.0));
        if response.clicked() {
            *selected = target;
        }
        ui.label(target.description());
    });
}

fn validate_form(app: &DesktopApp) -> Result<config::Config, String> {
    let selected_layers = 1 + (app.layer_at_rest as usize) + (app.layer_application as usize);
    if selected_layers < 2 {
        return Err(
            "select at least two layers; transport TLS is always the first layer".to_owned(),
        );
    }
    let domain = app.domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let reserved = [
        "example.com",
        "example.org",
        "example.net",
        "invalid",
        "test",
        "localhost",
        "local",
    ];
    if reserved
        .iter()
        .any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
    {
        return Err(
            "enter a real hostname you control; reserved example/test/local names are not accepted"
                .to_owned(),
        );
    }
    let site_id = site_id_from_domain(&domain);
    let upstream = app.upstream.trim().to_owned();
    let cfg = config::Config {
        schema_version: config::SUPPORTED_SCHEMA_VERSION,
        sites: vec![config::SiteConfig {
            id: site_id,
            domain,
            upstream,
        }],
    };
    cfg.validate().map_err(|errors| errors.join("; "))?;
    if app.deployment == DeploymentKind::DockerCompose {
        let parsed = Url::parse(&cfg.sites[0].upstream)
            .map_err(|error| format!("invalid upstream URL: {error}"))?;
        match parsed.host() {
            Some(Host::Domain(host))
                if !host.eq_ignore_ascii_case("localhost") && !host.contains('.') => {}
            _ => return Err(
                "Docker Compose mode expects a single-label service name such as http://web:3000 on the same private network".to_owned(),
            ),
        }
    }
    Ok(cfg)
}

fn site_id_from_domain(domain: &str) -> String {
    let mut id: String = domain
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(63)
        .collect();
    while id.ends_with('-') {
        id.pop();
    }
    if id.is_empty() {
        "site".to_owned()
    } else {
        id
    }
}

fn data_root() -> Result<PathBuf, String> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        let path = PathBuf::from(xdg);
        if path.is_absolute() {
            return Ok(path.join("quantum-shield").join("plans"));
        }
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| "HOME is not set; cannot find a private output directory".to_owned())?;
    Ok(PathBuf::from(home).join(".local/share/quantum-shield/plans"))
}

fn create_setup_bundle(app: &DesktopApp, cfg: &config::Config) -> Result<PathBuf, String> {
    let domain = &cfg.sites[0].domain;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before UNIX epoch: {error}"))?
        .as_secs();
    let root = data_root()?;
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create output directory {}: {error}", root.display()))?;
    set_private_dir_permissions(&root)?;

    let slug = domain
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    let final_dir = root.join(format!("{slug}-{now}"));
    let temp_dir = root.join(format!(".{slug}-{now}.tmp"));
    fs::create_dir(&temp_dir).map_err(|error| {
        format!(
            "cannot create staging bundle {}: {error}",
            temp_dir.display()
        )
    })?;
    if let Err(error) = set_private_dir_permissions(&temp_dir)
        .and_then(|_| write_private_file(&temp_dir.join("qs-config.toml"), &render_config(cfg)))
        .and_then(|_| {
            write_private_file(
                &temp_dir.join("PROTECTION_PLAN.md"),
                &render_plan(app, cfg, now),
            )
        })
        .and_then(|_| {
            fs::rename(&temp_dir, &final_dir)
                .map_err(|error| format!("cannot finalize bundle: {error}"))
        })
    {
        let _ = fs::remove_dir_all(&temp_dir);
        return Err(error);
    }
    Ok(final_dir)
}

fn render_config(cfg: &config::Config) -> String {
    let site = &cfg.sites[0];
    format!(
        "# Generated by Quantum Shield v0.9.0. Review before use.\nschema_version = {}\n\n[[sites]]\nid = \"{}\"\ndomain = \"{}\"\nupstream = \"{}\"\n",
        cfg.schema_version, site.id, site.domain, site.upstream
    )
}

fn render_plan(app: &DesktopApp, cfg: &config::Config, timestamp: u64) -> String {
    let site = &cfg.sites[0];
    let mut output = format!(
        "# Quantum Shield protection setup plan\n\n- Generated (Unix time): {timestamp}\n- Target type: {}\n- Hostname: `{}`\n- Upstream: `{}`\n- Deployment: {}\n- Layers selected: {}\n\n",
        app.target.label(), site.domain, site.upstream, app.deployment.label(),
        1 + (app.layer_at_rest as usize) + (app.layer_application as usize)
    );
    output.push_str("## Selected layers\n\n1. **Transport encryption (required):** TLS 1.3 at the edge. Hybrid X25519MLKEM768 key exchange may be negotiated when both ends support it; verify the actual handshake.\n");
    let mut next_layer = 2;
    if app.layer_at_rest {
        output.push_str(&format!("{next_layer}. **Stored-data encryption (selected, not applied):** configure encryption for the applicable database, volume, backups or managed storage. This requires a tested storage/platform adapter and a key lifecycle plan.\n"));
        next_layer += 1;
    }
    if app.layer_application {
        output.push_str(&format!("{next_layer}. **Application/payload encryption (selected, not applied):** requires application-specific design, code changes and key management. A reverse proxy cannot safely provide this generically.\n"));
    }
    output.push_str("\n## Implementation status\n\nThe plan is descriptive, not a statement that selected layers are active. The Docker Compose adapter can apply the TLS edge with an existing certificate/key or ACME HTTP-01 automatic issuance/renewal (staging by default, production with separate acknowledgement). Public exposure requires explicit approval. Storage and application-payload encryption are not applied. The current proxy remains a limited supported adapter, not a general public production security gateway. Local test mode publishes only to 127.0.0.1 on a Docker-assigned port and permits an untrusted test certificate only for its loopback health check.\n\n## Next adapter requirements\n\n- Verify DNS ownership, A/AAAA resolution and required ports.\n- Create a before-state backup and a human-readable diff.\n- Use ACME staging first and keep certificate/account cache private.\n- Apply through a supported deployment adapter only after explicit approval.\n- Run external HTTPS health checks and verify the negotiated TLS parameters.\n- Roll back if any required health check fails.\n- Implement stored-data or application-level encryption only with a specific platform integration and documented key management.\n");
    output
}

fn write_private_file(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", path.display()))?;
    Ok(())
}

fn set_private_dir_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot secure directory {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn locate_qsctl() -> Result<PathBuf, String> {
    let current = std::env::current_exe()
        .map_err(|error| format!("cannot locate the desktop executable: {error}"))?;
    #[cfg(target_os = "windows")]
    let executable_name = "qsctl.exe";
    #[cfg(not(target_os = "windows"))]
    let executable_name = "qsctl";

    let sibling = current
        .parent()
        .ok_or_else(|| "desktop executable has no parent directory".to_owned())?
        .join(executable_name);
    if sibling.is_file() {
        return Ok(sibling);
    }

    let path_search = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(executable_name))
            .find(|candidate| candidate.is_file())
    });
    path_search.ok_or_else(|| format!("qsctl was not found beside {} or on PATH; build/install qsctl alongside qs-desktop first", current.display()))
}

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Quantum Shield — Protection Setup")
            .with_inner_size([980.0, 780.0])
            .with_min_inner_size([760.0, 620.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "Quantum Shield — Protection Setup",
        native_options,
        Box::new(|creation_context| {
            creation_context.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(DesktopApp::default()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app() -> DesktopApp {
        DesktopApp {
            domain: "app.quantumshield.dev".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn audit_modes_map_to_expected_cli_commands() {
        assert_eq!(AuditMode::Website.command(), "website-audit");
        assert_eq!(AuditMode::Application.command(), "app-audit");
        assert_eq!(AuditMode::Repository.command(), "repo-scan");
    }

    #[test]
    fn default_profile_selects_two_layers() {
        let app = DesktopApp::default();
        assert_eq!(
            1 + (app.layer_at_rest as usize) + (app.layer_application as usize),
            2
        );
        assert!(
            !app.use_acme,
            "ACME should require an explicit choice in the first run"
        );
        assert!(
            !app.acme_production,
            "production ACME must never be the default"
        );
    }

    #[test]
    fn at_least_two_layers_are_required() {
        let mut app = test_app();
        app.layer_at_rest = false;
        app.layer_application = false;
        assert!(validate_form(&app).is_err());
        app.layer_application = true;
        assert!(validate_form(&app).is_ok());
    }

    #[test]
    fn example_domain_is_rejected_for_setup() {
        let mut app = test_app();
        app.domain = "app.example.com".to_owned();
        assert!(validate_form(&app).is_err());
    }

    #[test]
    fn invalid_remote_upstream_is_rejected() {
        let mut app = test_app();
        app.upstream = "http://attacker.invalid:9000".to_owned();
        assert!(validate_form(&app).is_err());
    }

    #[test]
    fn docker_mode_requires_service_name_not_loopback() {
        let mut app = test_app();
        app.deployment = DeploymentKind::DockerCompose;
        assert!(validate_form(&app).is_err());
        app.upstream = "http://web:3000".to_owned();
        assert!(validate_form(&app).is_ok());
    }

    #[test]
    fn site_id_is_bounded_and_valid() {
        let id = site_id_from_domain(&"a".repeat(80));
        assert_eq!(id.len(), 63);
        assert!(id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'));
    }
}
