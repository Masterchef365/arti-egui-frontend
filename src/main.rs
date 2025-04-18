use std::sync::{mpsc::{channel, Receiver, Sender}, Arc};
use tor_rtcompat::ToplevelBlockOn;
use log::{warn, info, error};

use anyhow::Result;
use arti::{dns::run_dns_resolver, reload_cfg, socks::run_socks_proxy, ArtiConfig};
use arti_client::{config::CfgPathResolver, TorClient, TorClientConfig};
use eframe::egui::{self, Color32, DragValue, RichText, ScrollArea};
use log::{Level, Metadata, Record};
use tor_config::{ConfigurationSources, Listen};
use tor_rtcompat::tokio::TokioRustlsRuntime;

fn main() {
    eframe::run_native(
        "Arti",
        Default::default(),
        Box::new(|cc| Ok(Box::new(ArtiApp::new(cc)))),
    )
    .unwrap();
}

#[derive(Clone)]
struct FrontendLogRecord {
    level: Level,
    text: String,
}

struct LogCollector(Sender<FrontendLogRecord>);

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
    }

    fn flush(&self) {}
}

type PinnedFuture<T> = std::pin::Pin<Box<dyn futures::Future<Output = T>>>;

pub struct ArtiApp {
    pub save_data: SaveData,
    logs_rx: Receiver<FrontendLogRecord>,
    logs: Vec<FrontendLogRecord>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)] // if we add new fields, give them default values when deserializing old state
pub struct SaveData {
    socks_port: u16,
    dns_port: u16,
}

impl ArtiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let save_data = cc
            .storage
            .and_then(|storage| eframe::get_value(storage, eframe::APP_KEY))
            .unwrap_or_default();
        let (tx, rx) = channel();

        log::set_logger(Box::leak(Box::new(LogCollector(tx)))).unwrap();
        log::set_max_level(log::LevelFilter::Info);

        Self {
            save_data,
            logs_rx: rx,
            logs: vec![],
        }
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

        egui::TopBottomPanel::bottom("logs").show(ctx, |ui| {
            ui.heading("Logs");
            let n = self.logs.len();
            ScrollArea::vertical().show_rows(ui, 18.0, n, |ui, rows| {
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
            ui.spacing_mut().item_spacing.y = 10.0;
            ui.heading("Proxy Configuration");
            ui.horizontal(|ui| {
                ui.strong("DNS Port: ");
                ui.add(DragValue::new(&mut self.save_data.dns_port));
            });
            ui.weak("Port to listen on for DNS request (overrides the port in the config if specified).");

            ui.horizontal(|ui| {
                ui.strong("SOCKS Port: ");
                ui.add(DragValue::new(&mut self.save_data.dns_port));
            });
            ui.weak("Port to listen on for SOCKS connections (overrides the port in the config if specified).")

        });
    }
}

impl Default for SaveData {
    fn default() -> Self {
        Self {
            dns_port: 53,
            socks_port: 9150,
        }
    }
}

fn run(
    runtime: TokioRustlsRuntime,
    socks_port: u16,
    dns_port: u16,
    cfg_sources: ConfigurationSources,
    config: ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    // Override configured SOCKS and DNS listen addresses from the command line.
    // This implies listening on localhost ports.
    let socks_listen = Listen::new_localhost(socks_port);

    let dns_listen = Listen::new_localhost(dns_port);

    if !socks_listen.is_empty() {
        info!(
            "Starting Arti {} in SOCKS proxy mode on {} ...",
            env!("CARGO_PKG_VERSION"),
            socks_listen
        );
    }

    let listen = 1337;
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), listen))
        .install()
        .with_context(|| format!("set up Prometheus metrics exporter on {listen}"))?;
    info!("Arti Prometheus metrics export scraper endpoint http://{listen}");

    use_max_file_limit(&config);

    let rt_copy = runtime.clone();
    rt_copy.block_on(run_proxy(
        runtime,
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
pub fn use_max_file_limit(config: &ArtiConfig) {
    match rlimit::increase_nofile_limit(16384) {
        Ok(n) => debug!("Increased process file limit to {}", n),
        Err(e) => error!("Error while increasing file limit; {e}"),
    }
}


async fn run_proxy(
    runtime: TokioRustlsRuntime,
    socks_listen: Listen,
    dns_listen: Listen,
    config_sources: ConfigurationSources,
    arti_config: ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    // Using OnDemand arranges that, while we are bootstrapping, incoming connections wait
    // for bootstrap to complete, rather than getting errors.
    use arti_client::BootstrapBehavior::OnDemand;
    use futures::FutureExt;

    // TODO RPC: We may instead want to provide a way to get these items out of TorClient.
    #[allow(unused)]
    let fs_mistrust = client_config.fs_mistrust().clone();
    #[allow(unused)]
    let path_resolver: CfgPathResolver = AsRef::<CfgPathResolver>::as_ref(&client_config).clone();

    let client_builder = TorClient::with_runtime(runtime.clone())
        .config(client_config)
        .bootstrap_behavior(OnDemand);
    let client = client_builder.create_unbootstrapped_async().await?;

    #[allow(unused_mut)]
    let mut reconfigurable_modules: Vec<Arc<dyn reload_cfg::ReconfigurableModule>> = vec![
        Arc::new(client.clone()),
        Arc::new(reload_cfg::Application::new(arti_config.clone())),
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
    if !socks_listen.is_empty() {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        let socks_listen = socks_listen.clone();
        proxy.push(Box::pin(async move {
            let res = run_socks_proxy(runtime, client, socks_listen, rpc_data).await;
            (res, "SOCKS")
        }));
    }

    if !dns_listen.is_empty() {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        proxy.push(Box::pin(async move {
            let res = run_dns_resolver(runtime, client, dns_listen).await;
            (res, "DNS")
        }));
    }


    if proxy.is_empty() {
        if !launched_onion_svc {
            warn!("No proxy port set; specify -p PORT (for `socks_port`) or -d PORT (for `dns_port`). Alternatively, use the `socks_port` or `dns_port` configuration option.");
            return Ok(());
        } else {
            // Push a dummy future to appease future::select_all,
            // which expects a non-empty list
            proxy.push(Box::pin(futures::future::pending()));
        }
    }

    let proxy = futures::future::select_all(proxy).map(|(finished, _index, _others)| finished);
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse()
            => r.context("waiting for termination signal"),
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
