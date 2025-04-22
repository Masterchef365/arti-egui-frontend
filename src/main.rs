use log::{debug, error, info, warn, LevelFilter};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc,
    },
    thread::JoinHandle,
};
use tor_rtcompat::ToplevelBlockOn;

use anyhow::{Context, Result};
use arti::{
    dns::run_dns_resolver, reload_cfg, socks::run_socks_proxy, ArtiCombinedConfig, ArtiConfig,
};
use arti_client::{
    config::{default_config_files, CfgPathResolver},
    TorClient, TorClientConfig,
};
use eframe::egui::{self, Color32, DragValue, RichText, ScrollArea};
use log::{Level, Metadata, Record};
use tor_config::mistrust::BuilderExt;
use tor_config::{ConfigurationSource, ConfigurationSources, Listen};
use tor_rtcompat::tokio::TokioRustlsRuntime;

fn main() {
    let app = eframe::run_native(
        "Arti",
        Default::default(),
        Box::new(|cc| Ok(Box::new(ArtiApp::new(cc)?))),
    )
    .unwrap();
}

#[derive(Clone)]
struct FrontendLogRecord {
    level: Level,
    text: String,
}

struct LogCollector(Sender<FrontendLogRecord>, egui::Context);

impl log::Log for LogCollector {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        self.0
            .send(FrontendLogRecord {
                level: record.level(),
                text: format!("[{}] {}", record.level(), record.args().to_string()),
            })
            .unwrap();
        self.1.request_repaint();
    }

    fn flush(&self) {}
}

type PinnedFuture<T> = std::pin::Pin<Box<dyn futures::Future<Output = T>>>;

pub struct ArtiApp {
    pub save_data: SaveData,
    logs_rx: Receiver<FrontendLogRecord>,
    logs: Vec<FrontendLogRecord>,
    rt: TokioRustlsRuntime,
    instance: Option<JoinHandle<Result<()>>>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)] // if we add new fields, give them default values when deserializing old state
pub struct SaveData {
    socks_port: u16,
    dns_port: u16,
    dns_enabled: bool,
    config_files: Vec<PathBuf>,
    toml_overrides: HashMap<String, String>,
    log_level: LevelFilter,
}

impl ArtiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Result<Self> {
        let save_data: SaveData = cc
            .storage
            .and_then(|storage| eframe::get_value(storage, eframe::APP_KEY))
            .unwrap_or_default();
        let (tx, rx) = channel();

        log::set_logger(Box::leak(Box::new(LogCollector(tx, cc.egui_ctx.clone())))).unwrap();

        log::set_max_level(save_data.log_level);

        let rt = TokioRustlsRuntime::create()?;

        Ok(Self {
            rt,
            save_data,
            logs_rx: rx,
            logs: vec![],
            instance: None,
        })
    }
}

impl eframe::App for ArtiApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.save_data);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Read logs
        self.logs.extend(self.logs_rx.try_iter());

        // Only keep the last 25,000 log messages
        let n = self.logs.len();
        if n > 50_000 {
            self.logs = self.logs[n / 2..].to_vec();
        }

        egui::TopBottomPanel::bottom("logs")
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Logs");

                ui.horizontal(|ui| {
                    ui.label("Max log level: ");
                    for level in LevelFilter::iter() {
                        if level == LevelFilter::Trace {
                            continue;
                        }
                        if ui.selectable_value(&mut self.save_data.log_level, level, level.to_string()).clicked() {
                            log::set_max_level(self.save_data.log_level);
                        }
                    }
                });

                let n = self.logs.len();
                ScrollArea::vertical()
                    .auto_shrink(false)
                    .show_rows(ui, 18.0, n, |ui, rows| {
                        for row in rows {
                            let color = match self.logs[row].level {
                                Level::Warn => Color32::YELLOW,
                                Level::Error => Color32::RED,
                                Level::Info => Color32::GRAY,
                                Level::Trace => Color32::BLUE,
                                Level::Debug => Color32::GREEN,
                            };

                            ui.label(RichText::new(&self.logs[row].text).color(color));
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, true]).show(ui, |ui| {
            if let Some(instance) = &mut self.instance {
                if instance.is_finished() {
                    let Some(instance) = self.instance.take() else { unreachable!() };
                    match instance.join() {
                        Err(_) => { log::error!("Join failed"); return },
                        Ok(result) => {
                            if let Err(e) = result {
                                log::error!("Instance stopped, reason below:");
                                log::error!("{e:#}");
                            } else {
                                log::info!("Ended gracefully");
                            }
                        }
                    }
                } else {
                    ui.label("Running");
                    if ui.button("Stop").clicked() {
                        todo!();
                    }
                }
            } else {
                ui.spacing_mut().item_spacing.y = 10.0;
                ui.heading("Proxy Configuration");
                ui.checkbox(&mut self.save_data.dns_enabled, "DNS enabled");
                ui.horizontal(|ui| {
                    if !self.save_data.dns_enabled {
                        ui.disable();
                    }
                    ui.strong("DNS Port: ");
                    ui.add(DragValue::new(&mut self.save_data.dns_port));
                });
                ui.weak("Port to listen on for DNS request (overrides the port in the config if specified).");

                ui.horizontal(|ui| {
                    ui.strong("SOCKS Port: ");
                    ui.add(DragValue::new(&mut self.save_data.socks_port));
                });
                ui.weak("Port to listen on for SOCKS connections (overrides the port in the config if specified).");

                ui.group(|ui| {
                    ui.strong("Config files");
                    ui.weak("Add config files and directories");
                    ScrollArea::vertical()
                        .id_salt("config")
                        .show(ui, |ui| {
                            let mut del = None;
                            for (idx, cfg) in self.save_data.config_files.iter_mut().enumerate() {
                                let mut s = cfg.to_string_lossy().to_string();
                                ui.horizontal(|ui| {
                                    ui.text_edit_singleline(&mut s);
                                    if ui.button("Delete").clicked() {
                                        del = Some(idx);
                                    }
                                });
                                *cfg = s.into();
                            }
                            if let Some(idx) = del {
                                self.save_data.config_files.remove(idx);
                            }
                        });
                    ui.horizontal(|ui| {
                        if ui.button("Add empty").clicked() {
                            self.save_data.config_files.push("".into());
                        }
                        if ui.button("Add folder").clicked() {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                self.save_data.config_files.push(folder);
                            }
                        }
                        if ui.button("Add file").clicked() {
                            if let Some(file) = rfd::FileDialog::new().add_filter("toml", &["toml"]).pick_file() {
                                self.save_data.config_files.push(file);
                            }
                        }
                    });
                });

                if ui.button(RichText::new("START").strong().size(30.)).clicked() {
                    match run_from_savedata(self.rt.clone(), &self.save_data) {
                        Err(e) => error!("{e:#}"),
                        Ok(res) => self.instance = Some(res),
                    }
                }
            }

            });
        });
    }
}

impl Default for SaveData {
    fn default() -> Self {
        Self {
            dns_enabled: true,
            dns_port: 53,
            socks_port: 9150,
            config_files: default_config_files()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|cfg| {
                    if let ConfigurationSource::Dir(p) | ConfigurationSource::File(p) = cfg {
                        Some(p)
                    } else {
                        None
                    }
                })
            .collect(),
            toml_overrides: HashMap::new(),
            log_level: LevelFilter::Debug,
        }
    }
}

fn run_from_savedata(
    runtime: TokioRustlsRuntime,
    save: &SaveData,
) -> Result<JoinHandle<Result<()>>> {
    let mut cfg_sources = ConfigurationSources::new_empty();
    for path in &save.config_files {
        let src = ConfigurationSource::from_path(path);
        cfg_sources.push_source(src, tor_config::sources::MustRead::MustRead);
    }

    // A Mistrust object to use for loading our configuration.  Elsewhere, we
    // use the value _from_ the configuration.
    let cfg_mistrust = fs_mistrust::MistrustBuilder::default().build_for_arti()?;

    let cfg = cfg_sources.load()?;
    let (config, client_config) =
        tor_config::resolve::<ArtiCombinedConfig>(cfg).context("read configuration")?;

    let log_mistrust = client_config.fs_mistrust().clone();

    let socks_port = save.socks_port;
    let dns_port = 
            save.dns_enabled.then(|| save.dns_port);

    Ok(std::thread::spawn(move || {
        run(
            runtime,
            socks_port,
            dns_port,
            cfg_sources,
            config,
            client_config,
        )
    }))
}

fn run(
    runtime: TokioRustlsRuntime,
    socks_port: u16,
    dns_port: Option<u16>,
    cfg_sources: ConfigurationSources,
    config: ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    // Override configured SOCKS and DNS listen addresses from the command line.
    // This implies listening on localhost ports.
    let socks_listen = Listen::new_localhost(socks_port);

    let dns_listen = dns_port.map(|dns_port| Listen::new_localhost(dns_port));

    if !socks_listen.is_empty() {
        info!(
            "Starting Arti {} in SOCKS proxy mode on {} ...",
            env!("CARGO_PKG_VERSION"),
            socks_listen
        );
    }

    /*
    // TODO!!!
    let listen = 1337;
    metrics_exporter_prometheus::PrometheusBuilder::new()
    .with_http_listener(std::net::SocketAddr::new(
    "127.0.0.1".parse().unwrap(),
    listen,
    ))
    .install()
    .with_context(|| format!("set up Prometheus metrics exporter on {listen}"))?;
    info!("Arti Prometheus metrics export scraper endpoint http://{listen}");
    */

    use_max_file_limit();

    let rt_copy = runtime.clone();
    rt_copy.block_on(run_proxy(
            &runtime,
            socks_listen,
            dns_listen,
            cfg_sources,
            config,
            client_config,
    ))?;

    Ok(())
}

/// Set our current maximum-file limit to a large value, if we can.
///
/// Since we're going to be used as a proxy, we're likely to need a
/// _lot_ of simultaneous sockets.
///
/// # Limitations
///
/// This doesn't actually do anything on windows.
pub fn use_max_file_limit() {
    match rlimit::increase_nofile_limit(16384) {
        Ok(n) => debug!("Increased process file limit to {}", n),
        Err(e) => error!("Error while increasing file limit; {e}"),
    }
}

async fn run_proxy(
    runtime: &TokioRustlsRuntime,
    socks_listen: Listen,
    dns_listen: Option<Listen>,
    config_sources: ConfigurationSources,
    arti_config: ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    // Using OnDemand arranges that, while we are bootstrapping, incoming connections wait
    // for bootstrap to complete, rather than getting errors.
    use arti_client::BootstrapBehavior::OnDemand;
    use futures::FutureExt;

    let client_builder = TorClient::with_runtime(runtime.clone())
        .config(client_config)
        .bootstrap_behavior(OnDemand);
    let client = client_builder.create_unbootstrapped_async().await?;

    let mut reconfigurable_modules: Vec<Arc<dyn reload_cfg::ReconfigurableModule>> = vec![
        Arc::new(client.clone()),
        //Arc::new(reload_cfg::Application::new(arti_config.clone())),
    ];

    // We weak references here to prevent the thread spawned by watch_for_config_changes from
    // keeping these modules alive after this function exits.
    //
    // NOTE: reconfigurable_modules stores the only strong references to these modules,
    // so we must keep the variable alive until the end of the function
    let weak_modules = reconfigurable_modules.iter().map(Arc::downgrade).collect();
    reload_cfg::watch_for_config_changes(
        client.runtime(),
        config_sources,
        &arti_config,
        weak_modules,
    )?;

    let mut proxy: Vec<PinnedFuture<(Result<()>, &str)>> = Vec::new();

    {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        let socks_listen = socks_listen.clone();
        proxy.push(Box::pin(async move {
            let res = run_socks_proxy(runtime, client, socks_listen, None).await;
            (res, "SOCKS")
        }));
    }

    {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        if let Some(dns_listen) = dns_listen {
        proxy.push(Box::pin(async move {
            let res = run_dns_resolver(runtime, client, dns_listen).await;
            (res, "DNS")
        }));
        }
    }

    let proxy = futures::future::select_all(proxy).map(|(finished, _index, _others)| finished);
    futures::select!(
        //r = exit::wait_for_ctrl_c().fuse()
        //=> r.context("waiting for termination signal"),
        r = proxy.fuse()
        => r.0.context(format!("{} proxy failure", r.1)),
        r = async {
            client.bootstrap().await?;
            if !socks_listen.is_empty() {
                info!("Sufficiently bootstrapped; system SOCKS now functional.");
            } else {
                info!("Sufficiently bootstrapped.");
            }
            futures::future::pending::<Result<()>>().await
        }.fuse()
        => r.context("bootstrap"),
    )?;

    // The modules can be dropped now, because we are exiting.
    drop(reconfigurable_modules);

    Ok(())
}
