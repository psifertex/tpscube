use crate::algorithms::AlgorithmsWidget;
use crate::details::average::AverageDetailsWindow;
use crate::details::solve::SolveDetailsWindow;
use crate::font::{font_definitions, text_styles, ScreenSize};
use crate::framerate::Framerate;
use crate::future::spawn_future;
use crate::gl::GlContext;
use crate::graph::GraphWidget;
use crate::history::HistoryWidget;
use crate::mode::SolveTypeSelectWindow;
use crate::settings::Settings;
use crate::style::{base_visuals, content_visuals, header_visuals};
use crate::theme::Theme;
use crate::timer::TimerWidget;
use crate::widgets::CustomWidgets;
use anyhow::Result;
use egui::{
    widgets::Label, CentralPanel, Color32, Event, Key, Layout, Rect, RichText, Rgba, Sense,
    Stroke, TopBottomPanel, Vec2,
};
use image::GenericImageView;
use std::sync::{Arc, Mutex};
use tpscube_core::{History, HistoryLoadProgress, Solve, SolveType, SyncStatus};

#[cfg(target_arch = "wasm32")]
use crate::is_safari;
#[cfg(target_arch = "wasm32")]
use instant::Instant;
#[cfg(target_arch = "wasm32")]
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use crate::bluetooth::BluetoothState;

#[derive(Copy, Clone, PartialEq, Eq)]
enum Mode {
    Timer,
    History,
    Graphs,
    Algorithms,
    Settings,
}

pub struct Application {
    mode: Mode,
    timer_widget: TimerWidget,
    history_widget: HistoryWidget,
    graph_widget: GraphWidget,
    algorithms_widget: AlgorithmsWidget,
    settings_widget: Settings,
    history: Option<History>,
    history_load_progress: Arc<Mutex<HistoryLoadProgress>>,
    loading_history: Arc<Mutex<Option<Result<Option<History>>>>>,
    repaint_context: Arc<Mutex<Option<egui::Context>>>,
    framerate: Option<Framerate>,
    timer_cube_rect: Option<Rect>,
    bluetooth_cube_rect: Option<Rect>,
    solve_details: Option<SolveDetailsWindow>,
    solve_details_cube_rect: Option<Rect>,
    average_details: Option<AverageDetailsWindow>,
    solve_type_select: Option<SolveTypeSelectWindow>,
    first_frame: bool,
    screen_size: ScreenSize,
    solve_type: SolveType,

    #[cfg(not(target_arch = "wasm32"))]
    bluetooth: BluetoothState,

    bluetooth_icon: Icon,
    bluetooth_dialog_open: bool,

    #[cfg(target_arch = "wasm32")]
    start_time: Instant,
}

pub struct ErrorApplication {
    message: String,
}

struct Image {
    width: usize,
    height: usize,
    pixels: Vec<Color32>,
    texture: Option<egui::TextureHandle>,
}

enum IconState {
    Inactive,
    Hovered,
    Active,
}

struct Icon {
    inactive: Image,
    hover: Image,
    active: Image,
    state: IconState,
}

pub enum SolveDetails {
    IndividualSolve(Solve),
    AverageOfSolves(Vec<Solve>),
}

pub trait App {
    fn warm_up_enabled(&self) -> bool {
        false
    }

    fn auto_save_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }

    fn max_size_points(&self) -> Vec2 {
        Vec2::new(2560.0, 1600.0)
    }

    fn clear_color(&self) -> Rgba {
        Color32::from_rgba_premultiplied(12, 12, 12, 180).into()
    }

    fn setup(&mut self, _ctx: &egui::Context) {}
    fn on_exit(&mut self) {}
    fn name(&self) -> &str;
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame);
    fn update_gl(&mut self, _ctx: &egui::Context, _gl: &mut GlContext<'_>) {}
    fn screensaver_enabled(&self) -> bool {
        true
    }
}

impl Application {
    pub fn new() -> Result<Self> {
        let history_load_progress = Arc::new(Mutex::new(HistoryLoadProgress::default()));
        let history_load_progress_copy = history_load_progress.clone();
        let loading_history = Arc::new(Mutex::new(None));
        let loading_history_copy = loading_history.clone();
        let repaint_context: Arc<Mutex<Option<egui::Context>>> = Arc::new(Mutex::new(None));
        let repaint_context_copy = repaint_context.clone();
        spawn_future(async move {
            *loading_history_copy.lock().unwrap() = Some(
                History::open_with_progress(history_load_progress_copy)
                    .await
                    .map(|history| Some(history)),
            );

            // Wake up UI thread now that history is loaded. If we beat the UI initialization, the
            // first frame will immediately recognize that it was complete.
            let repaint_context = repaint_context_copy.lock().unwrap();
            if let Some(ctx) = repaint_context.as_ref() {
                ctx.request_repaint();
            }
        });

        let bluetooth_inactive =
            Image::new(include_bytes!("../images/bluetooth_deselect.png")).unwrap();
        let bluetooth_hover = Image::new(include_bytes!("../images/bluetooth_hover.png")).unwrap();
        let bluetooth_active =
            Image::new(include_bytes!("../images/bluetooth_active.png")).unwrap();
        let bluetooth_icon = Icon {
            inactive: bluetooth_inactive,
            hover: bluetooth_hover,
            active: bluetooth_active,
            state: IconState::Inactive,
        };

        Ok(Application {
            mode: Mode::Timer,
            timer_widget: TimerWidget::new(),
            history_widget: HistoryWidget::new(),
            graph_widget: GraphWidget::new(),
            algorithms_widget: AlgorithmsWidget::new(),
            settings_widget: Settings::new(),
            history: None,
            history_load_progress,
            loading_history,
            repaint_context,
            framerate: None,
            timer_cube_rect: None,
            bluetooth_cube_rect: None,
            solve_details: None,
            solve_details_cube_rect: None,
            average_details: None,
            solve_type_select: None,
            first_frame: true,
            screen_size: ScreenSize::Normal,
            solve_type: SolveType::Standard3x3x3,

            #[cfg(not(target_arch = "wasm32"))]
            bluetooth: BluetoothState::new(),

            bluetooth_icon,
            bluetooth_dialog_open: false,

            #[cfg(target_arch = "wasm32")]
            start_time: Instant::now(),
        })
    }

    fn populate_repaint_context(&self, ctx: &egui::Context) {
        let mut repaint_context = self.repaint_context.lock().unwrap();
        if repaint_context.is_none() {
            *repaint_context = Some(ctx.clone());
        }
    }
}

impl App for Application {
    fn setup(&mut self, ctx: &egui::Context) {
        ctx.set_fonts(font_definitions());
        ctx.style_mut(|s| s.text_styles = text_styles(self.screen_size));
        ctx.set_visuals(base_visuals());
    }

    fn name(&self) -> &str {
        "TPS Cube"
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let aspect = ctx.available_rect().width() / ctx.available_rect().height();
        let landscape = aspect > 1.0;
        let effective_height = if landscape {
            ctx.available_rect().height()
        } else {
            ctx.available_rect().height() * 0.75
        };
        let new_screen_size = if effective_height < 540.0 {
            ScreenSize::Small
        } else if effective_height < 800.0 {
            ScreenSize::Normal
        } else if effective_height < 1100.0 {
            ScreenSize::Large
        } else {
            ScreenSize::VeryLarge
        };

        if self.screen_size != new_screen_size {
            self.screen_size = new_screen_size;
            ctx.set_fonts(font_definitions());
            ctx.style_mut(|s| s.text_styles = text_styles(self.screen_size));
        }

        if self.history.is_some() {
            ctx.set_visuals(header_visuals());
            TopBottomPanel::top("header").show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.add_space(5.0);

                    ui.horizontal(|ui| {
                        ui.add_space(5.0);
                        ui.style_mut().spacing.item_spacing.x = 20.0;

                        if ui
                            .header_label("⏱", "Timer", landscape, self.mode == Mode::Timer)
                            .clicked()
                        {
                            self.mode = Mode::Timer;
                        }

                        if ui
                            .header_label("📖", "History", landscape, self.mode == Mode::History)
                            .clicked()
                        {
                            self.mode = Mode::History;
                        }

                        if ui
                            .header_label("📉", "Graphs", landscape, self.mode == Mode::Graphs)
                            .clicked()
                        {
                            self.mode = Mode::Graphs;
                        }

                        if ui
                            .header_label(
                                "♞",
                                "Algorithms",
                                landscape,
                                self.mode == Mode::Algorithms,
                            )
                            .clicked()
                        {
                            self.mode = Mode::Algorithms;
                        }

                        if ui
                            .header_label("⚙", "Settings", landscape, self.mode == Mode::Settings)
                            .clicked()
                        {
                            self.mode = Mode::Settings;
                        }

                        // Check status of sync and create tooltip text for sync button
                        let sync_status = self.history.as_mut().unwrap().check_sync_status();
                        let local_count = self.history.as_ref().unwrap().local_action_count();
                        let local_status = match local_count {
                            0 => "No new solves to sync.".into(),
                            count => format!("{} actions to sync.", count),
                        };
                        let sync_status = match sync_status {
                            SyncStatus::NotSynced => local_status,
                            SyncStatus::SyncPending => {
                                if local_count != 0 {
                                    format!("{}\nSync in progress...", local_status)
                                } else {
                                    "Sync in progress...".into()
                                }
                            }
                            SyncStatus::SyncFailed(message) => {
                                format!("{}\nSync failed: {}", local_status, message)
                            }
                            SyncStatus::SyncComplete => {
                                if local_count != 0 {
                                    local_status
                                } else {
                                    "Sync complete".into()
                                }
                            }
                        };

                        // Show icons on the right of the header
                        ui.style_mut().spacing.item_spacing.x = 12.0;
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            // Show sync button
                            if self.history.as_ref().unwrap().sync_in_progress() {
                                ui.style_mut().visuals.widgets.inactive.fg_stroke = Stroke {
                                    width: 1.0,
                                    color: Theme::Blue.into(),
                                };
                                ui.style_mut().visuals.widgets.hovered.fg_stroke = Stroke {
                                    width: 1.0,
                                    color: Theme::Blue.into(),
                                };
                                ui.style_mut().visuals.widgets.active.fg_stroke = Stroke {
                                    width: 1.0,
                                    color: Theme::Blue.into(),
                                };
                            }
                            if ui
                                .add(
                                    Label::new(if local_count == 0 {
                                        "🔃".into()
                                    } else {
                                        format!("🔃 {}", local_count)
                                    })
                                    .sense(Sense::click()),
                                )
                                .on_hover_text(sync_status)
                                .clicked()
                            {
                                self.history.as_mut().unwrap().start_sync();
                            }

                            // Show bluetooth button
                            #[cfg(not(target_arch = "wasm32"))]
                            if let Some(tex) = self.bluetooth_icon.texture(ctx) {
                                let response = ui.add(
                                    egui::Image::new(egui::load::SizedTexture::new(
                                        tex.id(),
                                        Vec2::new(20.0, 20.0),
                                    ))
                                    .sense(Sense::click()),
                                );
                                if response.hovered() {
                                    self.bluetooth_icon.state = IconState::Hovered;
                                } else if self.bluetooth.active() {
                                    self.bluetooth_icon.state = IconState::Active;
                                } else {
                                    self.bluetooth_icon.state = IconState::Inactive;
                                }
                                if response.clicked() {
                                    if self.bluetooth.active() {
                                        self.bluetooth.disconnect();
                                    } else {
                                        self.bluetooth_dialog_open = true;
                                        self.bluetooth.start_connect_flow(ctx);
                                    }
                                }
                                response.on_hover_ui(|ui| {
                                    ui.add(Label::new(
                                        RichText::new(self.bluetooth.status())
                                            .color(self.bluetooth.status_color()),
                                    ));
                                });
                            }

                            // Check for storage errors
                            if let Some(error) = self.history.as_ref().unwrap().check_for_error() {
                                ui.add(
                                    Label::new(RichText::new("⚠").color(Theme::Red))
                                        .sense(Sense::hover()),
                                )
                                .on_hover_text(error);
                            }

                            #[cfg(target_arch = "wasm32")]
                            let allow_change_solve_type = true;
                            #[cfg(not(target_arch = "wasm32"))]
                            let allow_change_solve_type = !self.bluetooth.active();

                            // Show solve type
                            ui.style_mut().visuals.widgets = base_visuals().widgets;
                            if ui
                                .add(Label::new(self.solve_type.to_string()).sense(Sense::click()))
                                .clicked()
                                && allow_change_solve_type
                            {
                                self.solve_type_select =
                                    Some(SolveTypeSelectWindow::new(self.solve_type));
                            }
                        });
                    });

                    ui.add_space(5.0);
                });
            });

            let framerate = if let Some(framerate) = &mut self.framerate {
                framerate
            } else {
                self.framerate = Some(Framerate::new(ctx.clone()));
                self.framerate.as_mut().unwrap()
            };

            self.timer_cube_rect = None;
            self.bluetooth_cube_rect = None;
            self.solve_details_cube_rect = None;

            if self.history.as_ref().unwrap().sync_in_progress() {
                framerate.request(Some(10));
            }

            let mut details = None;
            match self.mode {
                Mode::Timer => {
                    #[cfg(target_arch = "wasm32")]
                    let (bluetooth_state, bluetooth_events, bluetooth_name) =
                        (None, Vec::new(), None);
                    #[cfg(not(target_arch = "wasm32"))]
                    let (bluetooth_state, bluetooth_events, bluetooth_name) =
                        if !self.bluetooth_dialog_open && self.bluetooth.ready() {
                            if self.bluetooth.timer_only() {
                                let events = self.bluetooth.new_events();
                                let name = self
                                    .bluetooth
                                    .name()
                                    .unwrap_or("Bluetooth Smart Timer".to_string());
                                (None, events, Some(name))
                            } else {
                                let events = self.bluetooth.new_events();
                                let state = self.bluetooth.cube_state();
                                let name = self
                                    .bluetooth
                                    .name()
                                    .unwrap_or("Bluetooth Cube".to_string());
                                (Some(state), events, Some(name))
                            }
                        } else {
                            (None, Vec::new(), None)
                        };

                    self.timer_widget.update(
                        ctx,
                        self.history.as_mut().unwrap(),
                        bluetooth_state,
                        bluetooth_events,
                        bluetooth_name,
                        framerate,
                        &mut self.timer_cube_rect,
                        &mut details,
                        self.solve_details.is_none(),
                        &mut self.solve_type,
                    )
                }
                Mode::History => self.history_widget.update(
                    ctx,
                    self.history.as_mut().unwrap(),
                    &mut details,
                    self.solve_type,
                ),
                Mode::Graphs => self.graph_widget.update(
                    ctx,
                    self.history.as_mut().unwrap(),
                    self.solve_type,
                ),
                Mode::Algorithms => {
                    self.algorithms_widget
                        .update(ctx, self.history.as_mut().unwrap())
                }
                Mode::Settings => {
                    self.settings_widget
                        .update(ctx, self.history.as_mut().unwrap())
                }
            }

            match details {
                Some(SolveDetails::IndividualSolve(solve)) => {
                    self.solve_details = Some(SolveDetailsWindow::new(solve));
                }
                Some(SolveDetails::AverageOfSolves(solves)) => {
                    self.average_details = Some(AverageDetailsWindow::new(solves));
                }
                None => (),
            }

            let mut escape_down = false;
            let events = ctx.input(|i| i.events.clone());
            for event in &events {
                match event {
                    Event::Key { key, pressed, .. } => {
                        if *pressed {
                            match key {
                                Key::Escape => escape_down = true,
                                _ => (),
                            }
                        }
                    }
                    _ => (),
                }
            }

            if let Some(solve_details) = &mut self.solve_details {
                let mut open = true;
                solve_details.update(
                    ctx,
                    framerate,
                    &mut self.solve_details_cube_rect,
                    &mut open,
                );
                if !open || escape_down {
                    self.solve_details = None;
                }
            } else if let Some(average_details) = &mut self.average_details {
                let mut open = true;
                let mut details = None;
                average_details.update(ctx, &mut open, &mut details);
                if !open || escape_down {
                    self.average_details = None;
                }

                match details {
                    Some(SolveDetails::IndividualSolve(solve)) => {
                        self.solve_details = Some(SolveDetailsWindow::new(solve));
                    }
                    _ => (),
                }
            } else if let Some(solve_type_select) = &self.solve_type_select {
                let mut open = true;
                let mut selection = None;
                solve_type_select.update(ctx, &mut open, &mut selection);
                if !open || escape_down || selection.is_some() {
                    self.solve_type_select = None;
                }

                match selection {
                    Some(solve_type) => {
                        self.solve_type = solve_type;
                        let _ = self
                            .history
                            .as_mut()
                            .unwrap()
                            .set_string_setting("solve_type", &solve_type.to_string());
                    }
                    _ => (),
                }
            }

            #[cfg(not(target_arch = "wasm32"))]
            if self.bluetooth_dialog_open {
                let mut open = true;
                self.bluetooth.update(
                    ctx,
                    framerate,
                    &mut self.bluetooth_cube_rect,
                    &mut open,
                );
                if !open || escape_down {
                    self.bluetooth_dialog_open = false;
                    self.bluetooth.close();
                }

                if self.bluetooth.finished() {
                    self.bluetooth_dialog_open = false;
                }
            }

            framerate.commit();

            if self.first_frame {
                // On some devices the 3D elements don't render properly on the first frame. Render
                // a second frame immediately.
                ctx.request_repaint();
                self.first_frame = false;
            }
        } else {
            let mut error = None;

            // Give history loading future access to the repaint context. If the history load is
            // already completed, it is OK that it did not have the context yet because
            // we are going to immediately complete the load.
            self.populate_repaint_context(ctx);

            // Check for history load completion
            let mut loading_history = self.loading_history.lock().unwrap();
            if let Some(result) = loading_history.as_mut() {
                if let Ok(history) = result.as_mut() {
                    // When history load completes, move `History` object into the
                    // application context. This will start the main UI on the next
                    // frame, which will be scheduled immediately.
                    std::mem::swap(&mut self.history, history);
                    *loading_history = None;

                    // Load initial solve type from settings
                    self.solve_type = SolveType::from_str(
                        &self
                            .history
                            .as_ref()
                            .unwrap()
                            .setting_as_string("solve_type")
                            .unwrap_or("3x3x3".into()),
                    )
                    .unwrap_or(SolveType::Standard3x3x3);

                    ctx.request_repaint();
                } else if let Err(load_error) = result {
                    error = Some(load_error.to_string());
                }
            }

            CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    if let Some(error) = error {
                        ui.add(Label::new(
                            RichText::new(format!("Error: {}", error)).color(Theme::Red),
                        ));
                    } else {
                        let progress = *self.history_load_progress.lock().unwrap();

                        match progress {
                            HistoryLoadProgress::InitializeDatabase => {
                                #[cfg(target_arch = "wasm32")]
                                {
                                    let now = Instant::now();
                                    if now - self.start_time > Duration::from_secs(2) {
                                        if is_safari() == Some(true) {
                                            // Some versions of Safari have a bug that causes
                                            // IndexedDB to hang on the initial visit. If we
                                            // are on the initialization phase for 2 seconds,
                                            // just reload the page to fix it.
                                            let _ = web_sys::window().unwrap().location().reload();
                                        }
                                    }
                                }

                                ui.add(Label::new(
                                    RichText::new("Initializing database...")
                                        .color(Theme::Disabled),
                                ));
                            }
                            HistoryLoadProgress::ReadSyncedActions => {
                                ui.add(Label::new(
                                    RichText::new(format!(
                                        "Reading synced solves... ({:.0}%)",
                                        progress.approximate_percent_done()
                                    ))
                                    .color(Theme::Disabled),
                                ));
                            }
                            HistoryLoadProgress::ReadLocalActions => {
                                ui.add(Label::new(
                                    RichText::new(format!(
                                        "Reading local solves... ({:.0}%)",
                                        progress.approximate_percent_done()
                                    ))
                                    .color(Theme::Disabled),
                                ));
                            }
                            HistoryLoadProgress::ResolveDeltas(_, _) => {
                                ui.add(Label::new(
                                    RichText::new(format!(
                                        "Resolving deltas... ({:.0}%)",
                                        progress.approximate_percent_done()
                                    ))
                                    .color(Theme::Disabled),
                                ));
                            }
                        }
                    }
                })
            });

            // Run loading indicator at 10 FPS to update the progress percentage
            let framerate = if let Some(framerate) = &mut self.framerate {
                framerate
            } else {
                self.framerate = Some(Framerate::new(ctx.clone()));
                self.framerate.as_mut().unwrap()
            };
            framerate.request(Some(10));
            framerate.commit();
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn update_gl(&mut self, ctx: &egui::Context, gl: &mut GlContext<'_>) {
        if self.bluetooth_dialog_open {
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(rect) = &self.bluetooth_cube_rect {
                self.bluetooth.paint_cube(ctx, gl, rect).unwrap();
            }
        } else if self.solve_details.is_some() {
            if let Some(rect) = &self.solve_details_cube_rect {
                if let Some(solve_details) = &mut self.solve_details {
                    solve_details.paint_cube(ctx, gl, rect).unwrap();
                }
            }
        } else if self.average_details.is_none() && self.solve_type_select.is_none() {
            if let Some(rect) = &self.timer_cube_rect {
                self.timer_widget.paint_cube(ctx, gl, rect).unwrap();
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn update_gl(&mut self, ctx: &egui::Context, gl: &mut GlContext<'_>) {
        if self.bluetooth_dialog_open {
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(rect) = &self.bluetooth_cube_rect {
                self.bluetooth.paint_cube(ctx, gl, rect).unwrap();
            }
        } else if self.solve_details.is_some() {
            if let Some(rect) = &self.solve_details_cube_rect {
                if let Some(solve_details) = &mut self.solve_details {
                    solve_details.paint_cube(ctx, gl, rect).unwrap();
                }
            }
        } else if self.average_details.is_none() && self.solve_type_select.is_none() {
            if let Some(rect) = &self.timer_cube_rect {
                self.timer_widget.paint_cube(ctx, gl, rect).unwrap();
            }
        }
    }

    fn screensaver_enabled(&self) -> bool {
        #[cfg(target_arch = "wasm32")]
        let bluetooth_enabled = false;
        #[cfg(not(target_arch = "wasm32"))]
        let bluetooth_enabled = self.bluetooth.active();

        self.mode != Mode::Timer || (!self.timer_widget.is_solving() && !bluetooth_enabled)
    }
}

impl ErrorApplication {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl App for ErrorApplication {
    fn setup(&mut self, ctx: &egui::Context) {
        ctx.set_fonts(font_definitions());
        ctx.style_mut(|s| s.text_styles = text_styles(ScreenSize::Normal));
        ctx.set_visuals(base_visuals());
    }

    fn name(&self) -> &str {
        "TPS Cube"
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(content_visuals());
        CentralPanel::default().show(ctx, |ui| {
            ui.centered_and_justified(|ui| {
                ui.add(Label::new(
                    RichText::new(format!("Error: {}", self.message)).color(Theme::Red),
                ));
            })
        });
    }
}

impl Image {
    fn new(png: &[u8]) -> Result<Self> {
        let image = image::load_from_memory(png)?;
        let image_rgb = image.to_rgba8();
        let width = image.width() as usize;
        let height = image.height() as usize;
        let pixels = image_rgb
            .into_vec()
            .chunks(4)
            .map(|rgba| Color32::from_rgba_unmultiplied(rgba[0], rgba[1], rgba[2], rgba[3]))
            .collect();
        Ok(Self {
            width,
            height,
            pixels,
            texture: None,
        })
    }

    fn texture(&mut self, ctx: &egui::Context) -> Option<&egui::TextureHandle> {
        if self.texture.is_none() {
            let image = egui::ColorImage {
                size: [self.width, self.height],
                pixels: self.pixels.clone(),
            };
            self.texture = Some(ctx.load_texture("icon", image, egui::TextureOptions::default()));
        }
        self.texture.as_ref()
    }
}

impl Icon {
    fn texture(&mut self, ctx: &egui::Context) -> Option<&egui::TextureHandle> {
        match self.state {
            IconState::Inactive => self.inactive.texture(ctx),
            IconState::Hovered => self.hover.texture(ctx),
            IconState::Active => self.active.texture(ctx),
        }
    }
}
