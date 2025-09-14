use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2, PasswordHasher,
};
use base64;

const ENCRYPTED_FILE: &str = "data.enc";
const SALT_FILE: &str = "salt.txt";

#[derive(Serialize, Deserialize, Clone)]
struct AppData {
    items: HashMap<String, String>,
}

impl Default for AppData {
    fn default() -> Self {
        let items = HashMap::new();
        Self { items }
    }
}

enum Screen {
    PasswordInput,
    Editor,
}

struct App {
    screen: Screen,
    password: String,
    show_password: bool,

    data: AppData,

    // UI & UX State
    error_message: String,
    status_message: Option<(String, egui::Color32, f64)>, // (msg, color, expire_at_seconds)
    search_query: String,
    delete_candidate: Option<String>,

    // Add form
    new_key: String,
    new_value: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            screen: Screen::PasswordInput,
            password: String::new(),
            show_password: false,
            data: AppData::default(),
            error_message: String::new(),
            status_message: None,
            search_query: String::new(),
            delete_candidate: None,
            new_key: String::new(),
            new_value: String::new(),
        }
    }
}

impl App {
    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt).map_err(|e| e.to_string())?;
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| e.to_string())?;
        let hash_binding = password_hash.hash.ok_or("No hash".to_string())?;
        let hash_bytes = hash_binding.as_bytes();
        if hash_bytes.len() < 32 {
            return Err("Hash too short".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        Ok(key)
    }

    fn encrypt_data(&self) -> Result<(), String> {
        let json_data = serde_json::to_string(&self.data).map_err(|e| e.to_string())?;
        let salt = if fs::metadata(SALT_FILE).is_ok() {
            fs::read(SALT_FILE).map_err(|e| e.to_string())?
        } else {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            fs::write(SALT_FILE, &salt).map_err(|e| e.to_string())?;
            salt.to_vec()
        };
        let key = Self::derive_key(&self.password, &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, json_data.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphertext);
        let encoded = base64::encode(&encrypted_data);
        fs::write(ENCRYPTED_FILE, encoded).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn decrypt_data(&mut self) -> Result<(), String> {
        if !fs::metadata(ENCRYPTED_FILE).is_ok() {
            self.data = AppData::default();
            self.encrypt_data()?;
            return Ok(());
        }
        let encoded_data = fs::read_to_string(ENCRYPTED_FILE).map_err(|e| e.to_string())?;
        let encrypted_data = base64::decode(encoded_data.trim()).map_err(|e| e.to_string())?;
        if encrypted_data.len() < 12 {
            return Err("Invalid encrypted data".into());
        }
        let salt = fs::read(SALT_FILE).map_err(|e| e.to_string())?;
        let key = Self::derive_key(&self.password, &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Falsches Passwort oder beschädigte Datei".to_string())?;
        let json_str = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
        self.data = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn try_login(&mut self) {
        match self.decrypt_data() {
            Ok(_) => {
                self.screen = Screen::Editor;
                self.error_message.clear();
                self.set_status(
                    "Erfolgreich entsperrt",
                    egui::Color32::from_rgb(0, 150, 0),
                    2.0,
                );
            }
            Err(e) => {
                self.error_message = e;
                self.password.clear();
            }
        }
    }

    fn set_status(&mut self, msg: &str, color: egui::Color32, seconds: f64) {
        // use a placeholder expire time; will be set in update when ctx is available
        let expire_at = egui::remap_clamp(seconds as f32, 0.0..=1.0, 0.0..=1.0) as f64; // temporary
        self.status_message = Some((msg.to_string(), color, expire_at));
    }

    fn show_status_toast(&mut self, ctx: &egui::Context) {
        if let Some((msg, color, expire_at)) = self.status_message.clone() {
            let now = ctx.input(|i| i.time);
            let real_expire_at = if expire_at < 1.0 {
                // patch first-time set to real time
                let t = now + 2.0;
                self.status_message = Some((msg.clone(), color, t));
                t
            } else {
                expire_at
            };

            if now < real_expire_at {
                egui::Window::new("")
                    .title_bar(false)
                    .resizable(false)
                    .collapsible(false)
                    .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -16.0))
                    .frame(
                        egui::Frame::popup(&ctx.style()).fill(egui::Color32::from_white_alpha(235)),
                    )
                    .show(ctx, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.add_space(4.0);
                            ui.colored_label(color, "●");
                            ui.label(msg);
                        });
                    });
            } else {
                self.status_message = None;
            }
        }
    }

    fn show_delete_confirm_dialog(&mut self, ctx: &egui::Context) {
        if let Some(key) = self.delete_candidate.clone() {
            egui::Window::new("Löschen bestätigen")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.label(format!("Eintrag „{}“ wirklich löschen?", key));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(egui::RichText::new("🗑️ Löschen").color(egui::Color32::RED))
                            .clicked()
                        {
                            self.data.items.remove(&key);
                            self.delete_candidate = None;
                            self.set_status(
                                "Eintrag gelöscht",
                                egui::Color32::from_rgb(200, 0, 0),
                                2.0,
                            );
                        }
                        if ui.button("Abbrechen").clicked() {
                            self.delete_candidate = None;
                        }
                    });
                });
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.screen {
            Screen::PasswordInput => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.heading("🔐 Encrypted JSON Editor");
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("Bitte Passwort eingeben, um zu entsperren").weak(),
                        );
                        ui.add_space(20.0);

                        egui::Frame::group(ui.style())
                            .rounding(egui::Rounding::same(8.0))
                            .inner_margin(egui::Margin::symmetric(16.0, 16.0))
                            .show(ui, |ui| {
                                ui.set_width(360.0);
                                ui.vertical(|ui| {
                                    let mut password_field =
                                        egui::TextEdit::singleline(&mut self.password)
                                            .password(!self.show_password)
                                            .hint_text("Passwort")
                                            .desired_width(f32::INFINITY);

                                    let response = ui.add(password_field);

                                    ui.horizontal(|ui| {
                                        ui.checkbox(&mut self.show_password, "Passwort anzeigen");
                                        ui.add_space(8.0);
                                        let login_enabled = !self.password.trim().is_empty();
                                        let mut button = egui::Button::new("➡️ Login")
                                            .min_size(egui::vec2(120.0, 28.0));
                                        if !login_enabled {
                                            button = button.sense(egui::Sense::hover());
                                            ui.add_enabled(false, button);
                                        } else if ui.add(button).clicked() {
                                            self.try_login();
                                        }

                                        if response.lost_focus()
                                            && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                        {
                                            if login_enabled {
                                                self.try_login();
                                            }
                                        }
                                    });

                                    if !self.error_message.is_empty() {
                                        ui.add_space(8.0);
                                        ui.colored_label(
                                            egui::Color32::RED,
                                            format!("❌ {}", self.error_message),
                                        );
                                    }
                                });
                            });

                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("Hinweis: Passwörter werden nicht gespeichert.")
                                .small()
                                .weak(),
                        );
                    });
                });
                // Toasts (z. B. nach erfolgreichem Login zeigen)
                self.show_status_toast(ctx);
            }
            Screen::Editor => {
                // Top Bar
                egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong("🔐 Encrypted JSON Editor");
                        ui.separator();
                        ui.add_space(8.0);

                        if ui.button("💾 Speichern").clicked() {
                            match self.encrypt_data() {
                                Ok(_) => self.set_status(
                                    "Gespeichert",
                                    egui::Color32::from_rgb(0, 150, 0),
                                    2.0,
                                ),
                                Err(e) => {
                                    self.set_status(
                                        "Fehler beim Speichern",
                                        egui::Color32::RED,
                                        2.5,
                                    );
                                    self.error_message = format!("❌ {}", e);
                                }
                            }
                        }

                        if ui.button("🚪 Speichern & Beenden").clicked() {
                            let _ = self.encrypt_data();
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_sized(
                                [220.0, 28.0],
                                egui::TextEdit::singleline(&mut self.search_query)
                                    .hint_text("🔎 Suchen…"),
                            );
                        });
                    });
                });

                // Main content
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Einträge").small().weak());
                    ui.add_space(6.0);

                    // Add form card
                    egui::Frame::group(ui.style())
                        .rounding(egui::Rounding::same(8.0))
                        .fill(egui::Color32::from_gray(245))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(210)))
                        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Neuen Eintrag hinzufügen:");
                                ui.add_space(8.0);
                                ui.label("Key:");
                                ui.add_sized(
                                    [160.0, 24.0],
                                    egui::TextEdit::singleline(&mut self.new_key)
                                        .hint_text("Schlüssel"),
                                );
                                ui.label("Value:");
                                ui.add_sized(
                                    [220.0, 24.0],
                                    egui::TextEdit::singleline(&mut self.new_value)
                                        .hint_text("Wert"),
                                );

                                let can_add = !self.new_key.trim().is_empty();
                                if ui
                                    .add_enabled(can_add, egui::Button::new("➕ Hinzufügen"))
                                    .clicked()
                                {
                                    self.data
                                        .items
                                        .insert(self.new_key.clone(), self.new_value.clone());
                                    self.new_key.clear();
                                    self.new_value.clear();
                                    self.set_status(
                                        "Eintrag hinzugefügt",
                                        egui::Color32::from_rgb(0, 120, 0),
                                        2.0,
                                    );
                                }
                            });
                        });

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(6.0);

                    // List of items (filtered)
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .show(ui, |ui| {
                            let mut keys: Vec<String> = self.data.items.keys().cloned().collect();
                            keys.sort();

                            let filter = self.search_query.to_lowercase();

                            for key in keys {
                                if !filter.is_empty() && !key.to_lowercase().contains(&filter) {
                                    continue;
                                }
                                let mut value = self.data.items[&key].clone();

                                egui::Frame::group(ui.style())
                                    .rounding(egui::Rounding::same(6.0))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(220)))
                                    .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.strong(&key);
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if ui
                                                        .button("🗑️")
                                                        .on_hover_text("Löschen")
                                                        .clicked()
                                                    {
                                                        self.delete_candidate = Some(key.clone());
                                                    }
                                                    if ui
                                                        .button("📋")
                                                        .on_hover_text("Wert kopieren")
                                                        .clicked()
                                                    {
                                                        ui.output_mut(|o| {
                                                            o.copied_text = value.clone()
                                                        });
                                                        self.set_status(
                                                            "In Zwischenablage kopiert",
                                                            egui::Color32::from_rgb(40, 120, 200),
                                                            1.5,
                                                        );
                                                    }
                                                },
                                            );
                                        });
                                        ui.add_space(4.0);
                                        let response = ui.add(
                                            egui::TextEdit::singleline(&mut value)
                                                .desired_width(f32::INFINITY),
                                        );

                                        if response.changed() {
                                            self.data.items.insert(key.clone(), value);
                                        }
                                    });

                                ui.add_space(6.0);
                            }

                            if self.data.items.is_empty() {
                                ui.vertical_centered(|ui| {
                                    ui.add_space(20.0);
                                    ui.label(
                                        egui::RichText::new("Keine Einträge vorhanden").weak(),
                                    );
                                    ui.label(
                                        egui::RichText::new("Füge oben einen neuen Eintrag hinzu.")
                                            .small()
                                            .weak(),
                                    );
                                    ui.add_space(10.0);
                                });
                            }
                        });

                    // Error line (if any)
                    if !self.error_message.is_empty() {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::RED, &self.error_message);
                    }
                });

                // Overlays
                self.show_status_toast(ctx);
                self.show_delete_confirm_dialog(ctx);
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 640.0])
            .with_min_inner_size([500.0, 420.0]),
        ..Default::default()
    };

    eframe::run_native(
        "🔐 Encrypted JSON Editor",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
}
