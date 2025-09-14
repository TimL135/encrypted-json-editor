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

struct ToastMessage {
    text: String,
    color: egui::Color32,
    start_time: f64,
    duration: f64,
    fade_progress: f32,
}

impl ToastMessage {
    fn new(text: String, color: egui::Color32, duration: f64, current_time: f64) -> Self {
        Self {
            text,
            color,
            start_time: current_time,
            duration,
            fade_progress: 0.0,
        }
    }

    fn update(&mut self, current_time: f64) -> bool {
        let elapsed = current_time - self.start_time;
        if elapsed >= self.duration {
            return false; // Toast expired
        }

        // Fade in first 0.2s, fade out last 0.5s
        if elapsed < 0.2 {
            self.fade_progress = (elapsed / 0.2) as f32;
        } else if elapsed > self.duration - 0.5 {
            let fade_out_progress = (self.duration - elapsed) / 0.5;
            self.fade_progress = fade_out_progress as f32;
        } else {
            self.fade_progress = 1.0;
        }

        true
    }
}

struct App {
    screen: Screen,
    password: String,
    show_password: bool,

    // Animation states
    login_shake_time: f64,
    login_button_hover: f32,
    screen_transition_progress: f32,

    data: AppData,

    // UI & UX State
    error_message: String,
    toast_messages: Vec<ToastMessage>,
    search_query: String,
    delete_candidate: Option<String>,

    // Add form
    new_key: String,
    new_value: String,
    add_form_expanded: bool,

    // Item animations
    item_hover_states: HashMap<String, f32>,
    item_delete_animations: HashMap<String, f32>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            screen: Screen::PasswordInput,
            password: String::new(),
            show_password: false,
            login_shake_time: 0.0,
            login_button_hover: 0.0,
            screen_transition_progress: 0.0,
            data: AppData::default(),
            error_message: String::new(),
            toast_messages: Vec::new(),
            search_query: String::new(),
            delete_candidate: None,
            new_key: String::new(),
            new_value: String::new(),
            add_form_expanded: false,
            item_hover_states: HashMap::new(),
            item_delete_animations: HashMap::new(),
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
            return Err("Beschädigte Datendatei".into());
        }
        let salt = fs::read(SALT_FILE).map_err(|e| e.to_string())?;
        let key = Self::derive_key(&self.password, &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Falsches Passwort".to_string())?;
        let json_str = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
        self.data = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn try_login(&mut self, current_time: f64) {
        match self.decrypt_data() {
            Ok(_) => {
                self.screen = Screen::Editor;
                self.error_message.clear();
                self.screen_transition_progress = 0.0;
                self.add_toast(
                    "Erfolgreich entsperrt",
                    egui::Color32::from_rgb(46, 160, 67),
                    2.0,
                    current_time,
                );
            }
            Err(e) => {
                self.error_message = e;
                self.password.clear();
                self.login_shake_time = current_time;
            }
        }
    }

    fn add_toast(&mut self, text: &str, color: egui::Color32, duration: f64, current_time: f64) {
        self.toast_messages.push(ToastMessage::new(
            text.to_string(),
            color,
            duration,
            current_time,
        ));
    }

    fn add_new_entry(&mut self, current_time: f64) {
        if !self.new_key.trim().is_empty() {
            self.data
                .items
                .insert(self.new_key.clone(), self.new_value.clone());
            self.new_key.clear();
            self.new_value.clear();
            self.add_toast(
                "Eintrag hinzugefügt",
                egui::Color32::from_rgb(46, 160, 67),
                2.0,
                current_time,
            );
        }
    }

    fn update_animations(&mut self, ctx: &egui::Context, dt: f32) {
        // Update login button hover animation
        self.login_button_hover = (self.login_button_hover + dt * 8.0).min(1.0);

        // Update screen transition
        if matches!(self.screen, Screen::Editor) {
            self.screen_transition_progress = (self.screen_transition_progress + dt * 4.0).min(1.0);
        }

        // Update item hover states
        for (_, hover_state) in self.item_hover_states.iter_mut() {
            *hover_state = (*hover_state - dt * 6.0).max(0.0);
        }

        // Update item delete animations
        self.item_delete_animations.retain(|_, progress| {
            *progress += dt * 8.0;
            *progress < 1.0
        });

        // Update toast messages
        let current_time = ctx.input(|i| i.time);
        self.toast_messages
            .retain_mut(|toast| toast.update(current_time));

        ctx.request_repaint();
    }

    fn show_toasts(&self, ctx: &egui::Context) {
        for (i, toast) in self.toast_messages.iter().enumerate() {
            let alpha = (toast.fade_progress * 255.0) as u8;
            let bg_color = egui::Color32::from_rgba_unmultiplied(40, 40, 40, alpha);
            let text_color = egui::Color32::from_rgba_unmultiplied(
                toast.color.r(),
                toast.color.g(),
                toast.color.b(),
                alpha,
            );

            egui::Window::new(format!("toast_{}", i))
                .title_bar(false)
                .resizable(false)
                .collapsible(false)
                .anchor(
                    egui::Align2::RIGHT_BOTTOM,
                    egui::vec2(-16.0, -16.0 - (i as f32 * 50.0)),
                )
                .frame(
                    egui::Frame::popup(&ctx.style())
                        .fill(bg_color)
                        .rounding(egui::Rounding::same(8.0))
                        .shadow(egui::epaint::Shadow {
                            offset: egui::vec2(0.0, 2.0),
                            blur: 8.0,
                            spread: 0.0,
                            color: egui::Color32::from_black_alpha(50),
                        }),
                )
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.add_space(4.0);
                        ui.colored_label(text_color, "●");
                        ui.colored_label(text_color, &toast.text);
                        ui.add_space(4.0);
                    });
                });
        }
    }

    fn show_delete_confirm_dialog(&mut self, ctx: &egui::Context) {
        if let Some(key) = self.delete_candidate.clone() {
            egui::Window::new("Löschen bestätigen")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .frame(
                    egui::Frame::window(&ctx.style())
                        .rounding(egui::Rounding::same(12.0))
                        .shadow(egui::epaint::Shadow {
                            offset: egui::vec2(0.0, 4.0),
                            blur: 16.0,
                            spread: 0.0,
                            color: egui::Color32::from_black_alpha(100),
                        }),
                )
                .show(ctx, |ui| {
                    ui.add_space(8.0);
                    ui.label(format!("Eintrag \"{}\" wirklich löschen?", key));
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new("Löschen")
                                    .fill(egui::Color32::from_rgb(220, 53, 69))
                                    .rounding(egui::Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.item_delete_animations.insert(key.clone(), 0.0);
                            self.data.items.remove(&key);
                            self.delete_candidate = None;
                            let current_time = ctx.input(|i| i.time);
                            self.add_toast(
                                "Eintrag gelöscht",
                                egui::Color32::from_rgb(220, 53, 69),
                                2.0,
                                current_time,
                            );
                        }
                        if ui
                            .add(
                                egui::Button::new("Abbrechen")
                                    .fill(egui::Color32::from_rgb(108, 117, 125))
                                    .rounding(egui::Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.delete_candidate = None;
                        }
                    });
                    ui.add_space(4.0);
                });
        }
    }

    fn show_login_screen(&mut self, ctx: &egui::Context) {
        let current_time = ctx.input(|i| i.time);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);

                // Animated title with glow effect
                let title_color = egui::Color32::from_rgb(52, 144, 220);
                ui.heading(
                    egui::RichText::new("🔐 Encrypted JSON Editor")
                        .size(28.0)
                        .color(title_color),
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Sichere Verwaltung deiner JSON-Daten")
                        .size(14.0)
                        .color(egui::Color32::from_gray(140)),
                );
                ui.add_space(30.0);

                // Login card with shake animation on error
                let shake_offset = if current_time - self.login_shake_time < 0.5 {
                    let shake_progress = (current_time - self.login_shake_time) * 20.0;
                    (shake_progress.sin()
                        * 3.0
                        * (1.0 - (current_time - self.login_shake_time) * 2.0).max(0.0))
                        as f32
                } else {
                    0.0
                };

                ui.allocate_ui_with_layout(
                    egui::vec2(400.0, 200.0),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        ui.add_space(shake_offset.max(0.0));

                        ui.vertical(|ui| {
                            egui::Frame::group(ui.style())
                                .rounding(egui::Rounding::same(16.0))
                                .fill(egui::Color32::DARK_GRAY)
                                .stroke(egui::Stroke::new(
                                    1.0,
                                    egui::Color32::from_rgb(222, 226, 230),
                                ))
                                .inner_margin(egui::Margin::symmetric(24.0, 20.0))
                                .shadow(egui::epaint::Shadow {
                                    offset: egui::vec2(0.0, 2.0),
                                    blur: 12.0,
                                    spread: 0.0,
                                    color: egui::Color32::from_black_alpha(30),
                                })
                                .show(ui, |ui| {
                                    ui.vertical(|ui| {
                                        ui.label("Passwort eingeben:");
                                        ui.add_space(8.0);

                                        let password_field =
                                            egui::TextEdit::singleline(&mut self.password)
                                                .password(!self.show_password)
                                                .hint_text("Dein sicheres Passwort")
                                                .desired_width(ui.available_width());

                                        let response = ui.add(password_field);

                                        ui.add_space(8.0);
                                        ui.horizontal(|ui| {
                                            ui.checkbox(
                                                &mut self.show_password,
                                                "Passwort anzeigen",
                                            );
                                        });

                                        ui.add_space(12.0);

                                        let login_enabled = !self.password.trim().is_empty();
                                        let button_color = if login_enabled {
                                            egui::Color32::from_rgb(40, 167, 69)
                                        } else {
                                            egui::Color32::from_rgb(108, 117, 125)
                                        };

                                        let button = egui::Button::new("🚀 Entsperren")
                                            .fill(button_color)
                                            .rounding(egui::Rounding::same(8.0))
                                            .min_size(egui::vec2(ui.available_width(), 36.0));

                                        if ui.add_enabled(login_enabled, button).clicked() {
                                            self.try_login(current_time);
                                        }

                                        if response.lost_focus()
                                            && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                            && login_enabled
                                        {
                                            self.try_login(current_time);
                                        }

                                        if !self.error_message.is_empty() {
                                            ui.add_space(12.0);
                                            ui.colored_label(
                                                egui::Color32::from_rgb(220, 53, 69),
                                                format!("❌ {}", self.error_message),
                                            );
                                        }
                                    });
                                });
                        });
                    },
                );

                ui.add_space(20.0);
                ui.label(
                    egui::RichText::new("Deine Daten werden lokal mit AES-256 verschlüsselt")
                        .size(12.0)
                        .color(egui::Color32::from_gray(120)),
                );
            });
        });
    }

    fn show_editor_screen(&mut self, ctx: &egui::Context) {
        let current_time = ctx.input(|i| i.time);

        // Animated slide-in effect
        let slide_progress = ease_in_out(self.screen_transition_progress);
        let slide_offset = (1.0 - slide_progress) * 50.0;

        // Top Bar with gradient background
        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(52, 58, 64))
                    .inner_margin(egui::Margin::symmetric(16.0, 12.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(
                        egui::RichText::new("🔐 Encrypted JSON Editor")
                            .size(16.0)
                            .color(egui::Color32::WHITE),
                    );
                    ui.separator();
                    ui.add_space(8.0);

                    // Save button with success animation
                    if ui
                        .add(
                            egui::Button::new("💾 Speichern")
                                .fill(egui::Color32::from_rgb(40, 167, 69))
                                .rounding(egui::Rounding::same(6.0)),
                        )
                        .clicked()
                    {
                        match self.encrypt_data() {
                            Ok(_) => self.add_toast(
                                "Erfolgreich gespeichert",
                                egui::Color32::from_rgb(40, 167, 69),
                                2.0,
                                current_time,
                            ),
                            Err(e) => {
                                self.add_toast(
                                    "Fehler beim Speichern",
                                    egui::Color32::from_rgb(220, 53, 69),
                                    3.0,
                                    current_time,
                                );
                                self.error_message = format!("❌ {}", e);
                            }
                        }
                    }

                    if ui
                        .add(
                            egui::Button::new("🚪 Speichern & Beenden")
                                .fill(egui::Color32::from_rgb(220, 53, 69))
                                .rounding(egui::Rounding::same(6.0)),
                        )
                        .clicked()
                    {
                        let _ = self.encrypt_data();
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_sized(
                            [250.0, 28.0],
                            egui::TextEdit::singleline(&mut self.search_query)
                                .hint_text("🔍 Einträge durchsuchen..."),
                        );
                    });
                });
            });

        // Main content with slide animation
        egui::CentralPanel::default().show(ctx, |ui| {
            let rect = ui.available_rect_before_wrap();
            let offset_rect = rect.translate(egui::vec2(0.0, slide_offset));

            ui.allocate_ui_at_rect(offset_rect, |ui| {
                ui.add_space(8.0);

                // Add new entry card
                egui::Frame::group(ui.style())
                    .rounding(egui::Rounding::same(12.0))
                    .fill(egui::Color32::DARK_GRAY)
                    .stroke(egui::Stroke::new(
                        1.5,
                        egui::Color32::from_rgb(52, 144, 220),
                    ))
                    .inner_margin(egui::Margin::symmetric(16.0, 12.0))
                    .shadow(egui::epaint::Shadow {
                        offset: egui::vec2(0.0, 2.0),
                        blur: 8.0,
                        spread: 0.0,
                        color: egui::Color32::from_black_alpha(20),
                    })
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.strong("➕ Neuen Eintrag hinzufügen");
                        });
                        ui.add_space(8.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.label("Schlüssel:");
                            let key_response = ui.add_sized(
                                [180.0, 28.0],
                                egui::TextEdit::singleline(&mut self.new_key)
                                    .hint_text("z.B. api_key"),
                            );

                            ui.add_space(8.0);
                            ui.label("Wert:");
                            let value_response = ui.add_sized(
                                [250.0, 28.0],
                                egui::TextEdit::singleline(&mut self.new_value)
                                    .hint_text("z.B. sk-1234567890abcdef"),
                            );

                            ui.add_space(8.0);
                            let can_add = !self.new_key.trim().is_empty();
                            if ui
                                .add_enabled(
                                    can_add,
                                    egui::Button::new("Hinzufügen")
                                        .fill(egui::Color32::from_rgb(40, 167, 69))
                                        .rounding(egui::Rounding::same(6.0))
                                        .min_size(egui::vec2(80.0, 28.0)),
                                )
                                .clicked()
                            {
                                self.add_new_entry(current_time);
                            }

                            // Enter key support
                            if (key_response.lost_focus() || value_response.lost_focus())
                                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                && can_add
                            {
                                self.add_new_entry(current_time);
                            }
                        });
                    });

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                // Items list with animations
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        if self.data.items.is_empty() {
                            ui.vertical_centered(|ui| {
                                ui.add_space(40.0);
                                ui.label(
                                    egui::RichText::new("📝 Noch keine Einträge vorhanden")
                                        .size(16.0)
                                        .color(egui::Color32::from_gray(120)),
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new("Füge oben deinen ersten Eintrag hinzu")
                                        .size(14.0)
                                        .color(egui::Color32::from_gray(100)),
                                );
                                ui.add_space(40.0);
                            });
                        } else {
                            let mut keys: Vec<String> = self.data.items.keys().cloned().collect();
                            keys.sort();

                            let filter = self.search_query.to_lowercase();

                            for key in keys {
                                if !filter.is_empty() && !key.to_lowercase().contains(&filter) {
                                    continue;
                                }

                                let mut value = self.data.items[&key].clone();
                                let hover_state =
                                    self.item_hover_states.entry(key.clone()).or_insert(0.0);

                                let hover_progress = *hover_state;
                                let bg_color = egui::Color32::DARK_GRAY;

                                egui::Frame::group(ui.style())
                                    .rounding(egui::Rounding::same(10.0))
                                    .fill(bg_color)
                                    .stroke(egui::Stroke::new(
                                        1.0 + hover_progress * 0.5,
                                        egui::Color32::from_rgb(
                                            (222 as f32 * (1.0 - hover_progress)
                                                + 52.0 * hover_progress)
                                                as u8,
                                            (226 as f32 * (1.0 - hover_progress)
                                                + 144.0 * hover_progress)
                                                as u8,
                                            (230 as f32 * (1.0 - hover_progress)
                                                + 220.0 * hover_progress)
                                                as u8,
                                        ),
                                    ))
                                    .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                                    .shadow(egui::epaint::Shadow {
                                        offset: egui::vec2(0.0, 1.0 + hover_progress * 2.0),
                                        blur: 4.0 + hover_progress * 4.0,
                                        spread: 0.0,
                                        color: egui::Color32::from_black_alpha(
                                            (20.0 + hover_progress * 20.0) as u8,
                                        ),
                                    })
                                    .show(ui, |ui| {
                                        ui.vertical(|ui| {
                                            ui.horizontal(|ui| {
                                                ui.strong(&key);
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        if ui
                                                            .add(
                                                                egui::Button::new("❌")
                                                                    .fill(egui::Color32::from_rgb(
                                                                        255, 240, 240,
                                                                    ))
                                                                    .stroke(egui::Stroke::new(
                                                                        1.0,
                                                                        egui::Color32::from_rgb(
                                                                            220, 53, 69,
                                                                        ),
                                                                    ))
                                                                    .rounding(
                                                                        egui::Rounding::same(6.0),
                                                                    ),
                                                            )
                                                            .on_hover_text("Eintrag löschen")
                                                            .clicked()
                                                        {
                                                            self.delete_candidate =
                                                                Some(key.clone());
                                                        }

                                                        ui.add_space(4.0);

                                                        if ui
                                                            .add(
                                                                egui::Button::new("📋")
                                                                    .fill(egui::Color32::from_rgb(
                                                                        240, 248, 255,
                                                                    ))
                                                                    .stroke(egui::Stroke::new(
                                                                        1.0,
                                                                        egui::Color32::from_rgb(
                                                                            52, 144, 220,
                                                                        ),
                                                                    ))
                                                                    .rounding(
                                                                        egui::Rounding::same(6.0),
                                                                    ),
                                                            )
                                                            .on_hover_text("Wert kopieren")
                                                            .clicked()
                                                        {
                                                            ui.output_mut(|o| {
                                                                o.copied_text =
                                                                    self.data.items[&key].clone()
                                                            });
                                                            self.add_toast(
                                                                "In Zwischenablage kopiert",
                                                                egui::Color32::from_rgb(
                                                                    52, 144, 220,
                                                                ),
                                                                1.5,
                                                                current_time,
                                                            );
                                                        }
                                                    },
                                                );
                                            });

                                            ui.add_space(4.0);
                                            let text_response = ui.add(
                                                egui::TextEdit::singleline(&mut value)
                                                    .desired_width(ui.available_width()),
                                            );

                                            if text_response.changed() {
                                                self.data.items.insert(key.clone(), value);
                                            }
                                        });
                                    });
                                ui.add_space(4.0);
                            }
                        }
                    });

                // Error display
                if !self.error_message.is_empty() {
                    ui.add_space(8.0);
                    ui.colored_label(egui::Color32::from_rgb(220, 53, 69), &self.error_message);
                }
            });
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let dt = ctx.input(|i| i.stable_dt);
        self.update_animations(ctx, dt);

        match self.screen {
            Screen::PasswordInput => {
                self.show_login_screen(ctx);
            }
            Screen::Editor => {
                self.show_editor_screen(ctx);
            }
        }

        // Show overlays
        self.show_toasts(ctx);
        self.show_delete_confirm_dialog(ctx);
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([600.0, 500.0])
            .with_icon(eframe::icon_data::from_png_bytes(&[]).unwrap_or_default()),
        ..Default::default()
    };

    eframe::run_native(
        "Encrypted JSON Editor",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
}

/// Einfaches Ease-In-Out (Smoothstep) Helferlein
fn ease_in_out(t: f32) -> f32 {
    // clamp zwischen 0 und 1
    let t = t.clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}
