use crate::font::FontSize;
use crate::style::settings_visuals;
use crate::theme::Theme;
use crate::widgets::CustomWidgets;
use anyhow::Result;
use egui::{
    containers::ScrollArea, widgets::Label, CentralPanel, RichText,
    SelectableLabel, Sense, Stroke,
};
use tpscube_core::{History, SyncRequest};

pub struct Settings {
    sync_key_visible: bool,
    set_key_visible: bool,
    new_sync_key: String,
    organize_result: Option<String>,
    import_result: Option<Result<String>>,
    export_result: Option<Result<()>>,
}

impl Settings {
    pub fn new() -> Self {
        Self {
            sync_key_visible: false,
            set_key_visible: false,
            new_sync_key: "".into(),
            organize_result: None,
            import_result: None,
            export_result: None,
        }
    }

    pub fn auto_sessions_enabled(history: &History) -> bool {
        history.setting_as_bool("auto_sessions").unwrap_or(true)
    }

    pub fn auto_session_time(history: &History) -> i64 {
        history.setting_as_i64("auto_session_time").unwrap_or(3600)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn import_solves_from_path(path: &str, history: &mut History) -> Result<String> {
        let contents = String::from_utf8(std::fs::read(path)?)?;
        history.import(contents)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn import_solves(&mut self, history: &mut History) {
        if let Some(path) = tinyfiledialogs::open_file_dialog(
            "Import Solves",
            ".",
            Some((&["*.json", "*.csv", "*.txt"], "Solve backups")),
        ) {
            self.import_result = Some(Self::import_solves_from_path(&path, history));
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn export_solves_to_path(path: &str, history: &mut History) -> Result<()> {
        let contents = history.export()?;
        Ok(std::fs::write(path, contents.as_bytes())?)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn export_solves(&mut self, history: &mut History) {
        if let Some(path) = tinyfiledialogs::save_file_dialog_with_filter(
            "Export Solves",
            "tpscube.json",
            &["*.json"],
            "Solve backups",
        ) {
            self.export_result = Some(Self::export_solves_to_path(&path, history));
        }
    }

    pub fn update(&mut self, ctx: &egui::Context, history: &mut History) {
        ctx.set_visuals(settings_visuals());
        CentralPanel::default().show(ctx, |ui| {
            ui.visuals_mut().widgets.inactive.bg_fill = Theme::BackgroundHighlight.into();
            ui.visuals_mut().widgets.hovered.bg_fill = Theme::Disabled.into();
            ui.visuals_mut().widgets.active.bg_fill = Theme::Disabled.into();
            ScrollArea::vertical().show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.section("Session Management");

                    if ui
                        .add(
                            Label::new(RichText::new(format!(
                                "{}  Automatic sessions",
                                if Self::auto_sessions_enabled(history) {
                                    "☑"
                                } else {
                                    "☐"
                                }
                            ))
                            .text_style(FontSize::Section.into()))
                            .sense(Sense::click()),
                        )
                        .clicked()
                    {
                        let new_auto_sessions_enabled = !Self::auto_sessions_enabled(history);
                        let _ =
                            history.set_bool_setting("auto_sessions", new_auto_sessions_enabled);
                    }
                    ui.add(
                        Label::new(
                            "Automatically create a new session after a period of time \
                                has passed.",
                        )
                        .wrap_mode(egui::TextWrapMode::Wrap),
                    );

                    if Self::auto_sessions_enabled(history) {
                        ui.add_space(8.0);

                        let auto_session_time = Self::auto_session_time(history);
                        let session_time_str = if auto_session_time >= 7200 {
                            format!("{} hours", auto_session_time / 3600)
                        } else if auto_session_time >= 3600 {
                            "1 hour".into()
                        } else {
                            format!("{} minutes", auto_session_time / 60)
                        };

                        let popup_id = ui.make_persistent_id("auto-session-time");
                        let response = ui.add(
                            Label::new(RichText::new(format!("⏰  Session Timeout: {} ⏷", session_time_str))
                                .text_style(FontSize::Section.into()))
                                .sense(Sense::click()),
                        );
                        if response.clicked() {
                            ui.memory_mut(|m| m.toggle_popup(popup_id));
                        }
                        egui::popup_below_widget(ui, popup_id, &response, egui::PopupCloseBehavior::CloseOnClickOutside, |ui| {
                            ui.set_min_width(180.0);
                            for time in &[1800, 3600, 3600 * 2, 3600 * 4, 3600 * 8, 3600 * 12] {
                                let item_time_str = if *time >= 7200 {
                                    format!("{} hours", *time / 3600)
                                } else if *time >= 3600 {
                                    "1 hour".into()
                                } else {
                                    format!("{} minutes", *time / 60)
                                };
                                if ui
                                    .add(
                                        SelectableLabel::new(
                                            auto_session_time == *time,
                                            RichText::new(item_time_str).text_style(FontSize::Normal.into()),
                                        ),
                                    )
                                    .clicked()
                                {
                                    let _ = history.set_i64_setting("auto_session_time", *time);
                                }
                            }
                        });

                        ui.add(
                            Label::new(
                                "If there have not been any solves in this amount of time, a new \
                                    session will be automatically created.",
                            )
                            .wrap_mode(egui::TextWrapMode::Wrap),
                        );

                        ui.add_space(8.0);

                        if ui
                            .add(
                                Label::new(RichText::new("🗄  Organize sessions")
                                    .text_style(FontSize::Section.into()))
                                    .sense(Sense::click()),
                            )
                            .clicked()
                        {
                            let new_session_count = history.auto_split_sessions(auto_session_time);
                            self.organize_result =
                                Some(format!("Created {} new session(s).", new_session_count));
                        }
                        if let Some(message) = &self.organize_result {
                            ui.add(
                                Label::new(RichText::new(format!("Organization complete.\n{}", message))
                                    .color(Theme::Green)),
                            );
                        }
                        ui.add(
                            Label::new(
                                "Automatically organize all existing sessions using the timeout \
                                    above. Sessions with gaps longer than the timeout will be \
                                    split into multiple sessions. Named sessions will not be \
                                    affected.",
                            )
                            .wrap_mode(egui::TextWrapMode::Wrap),
                        );
                    }

                    ui.add_space(16.0);
                    ui.section("Cloud Sync");

                    // Show sync key option
                    if ui
                        .add(
                            Label::new(RichText::new(format!(
                                "👁  {} sync key",
                                if self.sync_key_visible {
                                    "Hide"
                                } else {
                                    "Show"
                                }
                            ))
                            .text_style(FontSize::Section.into()))
                            .sense(Sense::click()),
                        )
                        .clicked()
                    {
                        self.sync_key_visible = !self.sync_key_visible
                    }
                    if self.sync_key_visible {
                        ui.add(
                            Label::new(RichText::new(history.sync_key())
                                .text_style(FontSize::Scramble.into())
                                .color(Theme::Yellow)),
                        );
                        if ui
                            .add(
                                Label::new(RichText::new("🗐  Copy")
                                    .text_style(FontSize::Section.into()))
                                    .sense(Sense::click()),
                            )
                            .clicked()
                        {
                            ui.ctx().copy_text(history.sync_key().into());
                        }
                    }
                    ui.add(
                        Label::new(format!(
                            "{} your active sync key. This key acts like a password to sync your \
                                solve information across devices. Never share your sync key with \
                                anyone.",
                            if self.sync_key_visible {
                                "This is"
                            } else {
                                "Show"
                            }
                        ))
                        .wrap_mode(egui::TextWrapMode::Wrap),
                    );

                    ui.add_space(8.0);

                    // Set sync key option
                    if ui
                        .add(
                            Label::new(RichText::new("🗝  Set sync key")
                                .text_style(FontSize::Section.into()))
                                .sense(Sense::click()),
                        )
                        .clicked()
                    {
                        self.set_key_visible = !self.set_key_visible;
                    }
                    ui.add(
                        Label::new(
                            "If you already have other devices with solve information, you can \
                                set your sync key here to sync with them. You can view \
                                your sync key on any device that is already being synced.",
                        )
                        .wrap_mode(egui::TextWrapMode::Wrap),
                    );

                    if self.set_key_visible {
                        // If set sync key is active, show edit box
                        ui.add_space(8.0);
                        ui.add(Label::new(RichText::new("New sync key: ").color(Theme::Yellow)));
                        ui.style_mut().visuals.widgets.inactive.bg_stroke = Stroke {
                            width: 1.0,
                            color: Theme::Disabled.into(),
                        };
                        ui.style_mut().visuals.widgets.hovered.bg_stroke = Stroke {
                            width: 1.0,
                            color: Theme::Disabled.into(),
                        };
                        ui.style_mut().visuals.widgets.active.bg_stroke = Stroke {
                            width: 1.0,
                            color: Theme::Content.into(),
                        };
                        ui.text_edit_singleline(&mut self.new_sync_key);

                        // Validate the sync key being entered
                        if let Some(key) = SyncRequest::validate_sync_key(&self.new_sync_key) {
                            if key == history.sync_key() {
                                ui.add(Label::new(RichText::new("Key set").color(Theme::Green)));
                            } else {
                                // Sync key is valid and different, allow the user to set it
                                if ui
                                    .add(
                                        Label::new(RichText::new("✔  Save")
                                            .text_style(FontSize::Section.into()))
                                            .sense(Sense::click()),
                                    )
                                    .clicked()
                                {
                                    let _ = history.set_sync_key(&key);
                                }
                            }
                        } else {
                            // Sync key is not valid, show error
                            ui.add(Label::new(RichText::new("(Not valid)").color(Theme::Red)));
                        }
                    }

                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        ui.add_space(16.0);
                        ui.section("Import / Export");

                        // Import solves option
                        if ui
                            .add(
                                Label::new(RichText::new("🗁  Import solves")
                                    .text_style(FontSize::Section.into()))
                                    .sense(Sense::click()),
                            )
                            .clicked()
                        {
                            self.import_solves(history);
                        }
                        if let Some(result) = &self.import_result {
                            match result {
                                Ok(message) => {
                                    ui.add(
                                        Label::new(RichText::new(format!("Import complete.\n{}", message))
                                            .color(Theme::Green)),
                                    );
                                }
                                Err(error) => {
                                    ui.add(
                                        Label::new(RichText::new(format!("Error: {}", error))
                                            .color(Theme::Red))
                                            .wrap_mode(egui::TextWrapMode::Wrap),
                                    );
                                }
                            }
                        }
                        ui.add(
                            Label::new(
                                "Import solves from a backup. Supports backups from \
                               TPS Cube, csTimer, and Cubeast.",
                            )
                            .wrap_mode(egui::TextWrapMode::Wrap),
                        );

                        ui.add_space(8.0);

                        // Export solves option
                        if ui
                            .add(
                                Label::new(RichText::new("🗐  Export solves")
                                    .text_style(FontSize::Section.into()))
                                    .sense(Sense::click()),
                            )
                            .clicked()
                        {
                            self.export_solves(history);
                        }
                        if let Some(result) = &self.export_result {
                            match result {
                                Ok(()) => {
                                    ui.add(Label::new(RichText::new("Export complete.").color(Theme::Green)));
                                }
                                Err(error) => {
                                    ui.add(
                                        Label::new(RichText::new(format!("Error: {}", error))
                                            .color(Theme::Red))
                                            .wrap_mode(egui::TextWrapMode::Wrap),
                                    );
                                }
                            }
                        }
                        ui.label("Export all solve information to a file for backup.")
                    }
                });
            });
        });
    }
}
