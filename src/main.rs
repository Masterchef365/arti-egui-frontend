use std::sync::mpsc::{channel, Receiver, Sender};

use anyhow::Result;
use arti::ArtiConfig;
use arti_client::TorClientConfig;
use eframe::egui::{self, Color32, DragValue, RichText, ScrollArea};
use log::{Level, Metadata, Record};
use tor_config::{ConfigurationSources, Listen};

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
