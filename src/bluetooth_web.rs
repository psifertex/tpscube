use crate::cube::CubeRenderer;
use crate::font::FontSize;
use crate::framerate::Framerate;
use crate::gl::GlContext;
use crate::style::dialog_visuals;
use crate::theme::Theme;
use crate::timer::BluetoothEvent;
use anyhow::{anyhow, Result};
use egui::{
    Color32, Direction, Label, Layout, Rect, RichText, Sense, Stroke, Ui, Vec2, Window,
};
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use tpscube_core::{
    BluetoothCube, BluetoothCubeEvent, BluetoothCubeState, Cube3x3x3, History, InitialCubeState,
};

#[derive(Copy, Clone, PartialEq, Eq)]
enum BluetoothMode {
    PromptConnect,
    WaitForConnection,
    CheckState,
    ResetState,
    Finished,
    Error,
}

pub struct BluetoothState {
    mode: BluetoothMode,
    cube: Option<BluetoothCube>,
    error: Option<String>,
    renderer: CubeRenderer,
    move_queue: Arc<Mutex<Vec<BluetoothCubeEvent>>>,
    cube_state: Cube3x3x3,
    timer_only: bool,
}

impl BluetoothState {
    pub fn new() -> Self {
        Self {
            mode: BluetoothMode::PromptConnect,
            cube: None,
            error: None,
            renderer: CubeRenderer::new(Box::new(Cube3x3x3::new())),
            move_queue: Arc::new(Mutex::new(Vec::new())),
            cube_state: Cube3x3x3::new(),
            timer_only: false,
        }
    }

    pub fn active(&self) -> bool {
        if let Some(cube) = &self.cube {
            if let Ok(state) = cube.state() {
                state == BluetoothCubeState::Connected
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn timer_only(&self) -> bool {
        self.timer_only
    }

    pub fn status(&self) -> String {
        if let Some(cube) = &self.cube {
            match cube.state() {
                Ok(BluetoothCubeState::Connected) => {
                    let mut string = if let Ok(Some(name)) = cube.name() {
                        format!("Connected to {}", name)
                    } else {
                        "Connected to Bluetooth cube".into()
                    };
                    if let Ok(Some(battery)) = cube.battery_percentage() {
                        string += &format!("\n Battery: {}%", battery);
                        if let Ok(Some(charging)) = cube.battery_charging() {
                            if charging {
                                string += " (charging)";
                            }
                        }
                    }
                    string
                }
                Ok(BluetoothCubeState::Connecting) => "Connecting...".into(),
                Ok(BluetoothCubeState::Discovering) => "Disconnected".into(),
                Ok(BluetoothCubeState::Desynced) => "Cube state desynced".into(),
                Ok(BluetoothCubeState::Error) => "Internal error".into(),
                Err(error) => format!("Connection error: {}", error),
            }
        } else {
            "Disconnected".into()
        }
    }

    pub fn status_color(&self) -> Color32 {
        if let Some(cube) = &self.cube {
            match cube.state() {
                Ok(BluetoothCubeState::Connected) => Theme::Content.into(),
                Ok(BluetoothCubeState::Desynced) => Theme::Red.into(),
                Err(_) => Theme::Red.into(),
                _ => Theme::Disabled.into(),
            }
        } else {
            Theme::Disabled.into()
        }
    }

    pub fn finished(&self) -> bool {
        self.mode == BluetoothMode::Finished
    }

    pub fn ready(&self) -> bool {
        self.finished() && self.active()
    }

    pub fn cube_state(&self) -> Cube3x3x3 {
        self.cube_state.clone()
    }

    pub fn name(&self) -> Option<String> {
        if let Some(cube) = &self.cube {
            if let Ok(name) = cube.name() {
                name
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn new_events(&mut self) -> Vec<BluetoothEvent> {
        let mut move_queue = self.move_queue.lock().unwrap();
        let mut result = Vec::new();
        for event in move_queue.deref() {
            match event {
                BluetoothCubeEvent::Move(moves, state) => {
                    for mv in moves {
                        result.push(BluetoothEvent::Move(mv.clone()));
                    }
                    self.cube_state = state.clone();
                }
                BluetoothCubeEvent::HandsOnTimer => result.push(BluetoothEvent::HandsOnTimer),
                BluetoothCubeEvent::TimerStartCancel => {
                    result.push(BluetoothEvent::TimerStartCancel)
                }
                BluetoothCubeEvent::TimerReady => result.push(BluetoothEvent::TimerReady),
                BluetoothCubeEvent::TimerStarted => result.push(BluetoothEvent::TimerStarted),
                BluetoothCubeEvent::TimerFinished(time) => {
                    result.push(BluetoothEvent::TimerFinished(*time))
                }
            }
        }
        move_queue.clear();
        result
    }

    pub fn disconnect(&mut self) {
        if let Some(cube) = &self.cube {
            cube.disconnect();
        }
    }

    pub fn start_connect_flow(&mut self, ctx: &egui::Context, _history: &History) {
        self.disconnect();
        self.mode = BluetoothMode::PromptConnect;
        self.error = None;
        if self.cube.is_none() {
            let cube = BluetoothCube::new();

            let repaint_ctx = ctx.clone();
            let move_queue = self.move_queue.clone();
            cube.register_move_listener(move |event| {
                move_queue.lock().unwrap().push(event);
                repaint_ctx.request_repaint();
            });

            self.cube = Some(cube);
        }
    }

    pub fn close(&mut self) {
        if self.mode != BluetoothMode::Finished {
            self.disconnect();
        }
    }

    fn prompt_connect(&mut self, ui: &mut Ui) {
        ui.vertical(|ui| {
            ui.add(Label::new(
                "Click the button below to search for a Bluetooth cube. \
                 Your browser will show a device picker.",
            ));

            ui.add_space(16.0);

            ui.with_layout(Layout::top_down(egui::Align::Center), |ui| {
                ui.visuals_mut().widgets.inactive.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Content.into(),
                };
                ui.visuals_mut().widgets.hovered.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Green.into(),
                };
                ui.visuals_mut().widgets.active.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Green.into(),
                };

                if ui
                    .add(
                        Label::new(
                            RichText::new("Connect to Cube")
                                .text_style(FontSize::Section.into()),
                        )
                        .sense(Sense::click()),
                    )
                    .clicked()
                {
                    if let Some(cube) = &self.cube {
                        cube.request_device();
                        self.mode = BluetoothMode::WaitForConnection;
                    }
                }
            });

            ui.add_space(16.0);

            ui.add(Label::new(
                RichText::new(
                    "Supported cubes: GAN (v2+), GoCube, Rubik's Connected, \
                     Giiker, MoYu AI (MHC), MoYu AiCube",
                )
                .color(Theme::Disabled),
            ));
        });
    }

    fn waiting_for_connection(&mut self, ui: &mut Ui) -> Result<()> {
        ui.with_layout(Layout::centered_and_justified(Direction::TopDown), |ui| {
            ui.with_layout(
                Layout::centered_and_justified(Direction::LeftToRight),
                |ui| {
                    ui.add(
                        Label::new(
                            RichText::new("Connecting to cube...")
                                .text_style(FontSize::Section.into())
                                .color(Theme::Disabled),
                        ),
                    );
                },
            );
        });

        let cube = self.cube.as_ref().unwrap();
        match cube.state()? {
            BluetoothCubeState::Connected => {
                let state = cube.cube_state()?;
                let timer_only = cube.timer_only()?;
                self.cube_state = state.clone();
                self.timer_only = timer_only;
                self.renderer.set_cube_state(Box::new(state));
                if timer_only {
                    self.mode = BluetoothMode::Finished;
                } else {
                    self.mode = BluetoothMode::CheckState;
                }
            }
            BluetoothCubeState::Desynced => {
                self.mode = BluetoothMode::Error;
                self.error = Some("Cube state desynced".into());
            }
            BluetoothCubeState::Error => {
                self.mode = BluetoothMode::Error;
                self.error = Some("Internal error".into());
            }
            BluetoothCubeState::Discovering => {
                // User cancelled the picker, go back to prompt
                self.mode = BluetoothMode::PromptConnect;
            }
            _ => (),
        }

        Ok(())
    }

    fn check_state(
        &mut self,
        ctx: &egui::Context,
        ui: &mut Ui,
        framerate: &mut Framerate,
        cube_rect: &mut Option<Rect>,
    ) -> Result<()> {
        ui.vertical(|ui| {
            ui.label("Does this state match your cube?");

            ui.horizontal(|ui| {
                ui.visuals_mut().widgets.inactive.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Disabled.into(),
                };
                ui.visuals_mut().widgets.hovered.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Green.into(),
                };
                ui.visuals_mut().widgets.active.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Green.into(),
                };
                if ui
                    .add(
                        Label::new(
                            RichText::new("Yes").text_style(FontSize::Section.into()),
                        )
                        .sense(Sense::click()),
                    )
                    .clicked()
                {
                    self.mode = BluetoothMode::Finished;
                }

                ui.add_space(20.0);

                ui.visuals_mut().widgets.hovered.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Red.into(),
                };
                ui.visuals_mut().widgets.active.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Red.into(),
                };
                if ui
                    .add(
                        Label::new(
                            RichText::new("No").text_style(FontSize::Section.into()),
                        )
                        .sense(Sense::click()),
                    )
                    .clicked()
                {
                    self.mode = BluetoothMode::ResetState;
                    self.renderer.set_cube_state(Box::new(Cube3x3x3::new()));
                }
            });

            let (rect, response) =
                ui.allocate_exact_size(Vec2::new(250.0, 250.0), Sense::click_and_drag());
            *cube_rect = Some(rect.clone());
            framerate.request_max();

            if ui.rect_contains_pointer(rect) {
                let scroll_delta = ctx.input(|i| i.raw_scroll_delta);
                self.renderer
                    .adjust_angle(scroll_delta.x / 3.0, scroll_delta.y / 3.0);
            }
            if response.dragged() {
                let delta = ui.input(|i| i.pointer.delta());
                self.renderer
                    .adjust_angle(delta.x / 3.0, delta.y / 3.0);
            }
        });

        for event in self.move_queue.lock().unwrap().deref_mut().drain(..) {
            match event {
                BluetoothCubeEvent::Move(moves, state) => {
                    for mv in moves {
                        self.renderer.do_move(mv.move_());
                    }
                    self.cube_state = state.clone();
                    self.renderer.verify_state(Box::new(state));
                }
                _ => (),
            }
        }

        let cube = self.cube.as_ref().unwrap();
        if !cube.synced()? {
            return Err(anyhow!("Cube state desynced"));
        }

        Ok(())
    }

    fn reset_state(
        &mut self,
        ctx: &egui::Context,
        ui: &mut Ui,
        framerate: &mut Framerate,
        cube_rect: &mut Option<Rect>,
    ) -> Result<()> {
        ui.vertical(|ui| {
            ui.label("Solve your cube to reset its state.");

            ui.horizontal(|ui| {
                ui.visuals_mut().widgets.inactive.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Disabled.into(),
                };
                ui.visuals_mut().widgets.hovered.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Green.into(),
                };
                ui.visuals_mut().widgets.active.fg_stroke = Stroke {
                    width: 1.0,
                    color: Theme::Green.into(),
                };
                if ui
                    .add(
                        Label::new(
                            RichText::new("I'm ready").text_style(FontSize::Section.into()),
                        )
                        .sense(Sense::click()),
                    )
                    .clicked()
                {
                    let cube = self.cube.as_ref().unwrap();
                    if let Err(error) = cube.reset_cube_state() {
                        self.mode = BluetoothMode::Error;
                        self.error = Some(error.to_string());
                    } else {
                        self.mode = BluetoothMode::Finished;
                        self.cube_state = Cube3x3x3::new();
                    }
                }
            });

            let (rect, response) =
                ui.allocate_exact_size(Vec2::new(250.0, 250.0), Sense::click_and_drag());
            *cube_rect = Some(rect.clone());
            framerate.request_max();

            if ui.rect_contains_pointer(rect) {
                let scroll_delta = ctx.input(|i| i.raw_scroll_delta);
                self.renderer
                    .adjust_angle(scroll_delta.x / 3.0, scroll_delta.y / 3.0);
            }
            if response.dragged() {
                let delta = ui.input(|i| i.pointer.delta());
                self.renderer
                    .adjust_angle(delta.x / 3.0, delta.y / 3.0);
            }
        });

        let cube = self.cube.as_ref().unwrap();
        if !cube.synced()? {
            return Err(anyhow!("Cube state desynced"));
        }

        Ok(())
    }

    fn show_error(&self, ui: &mut Ui) {
        if let Some(error) = &self.error {
            ui.add(Label::new(RichText::new(error).color(Theme::Red)));
        }
    }

    pub fn update(
        &mut self,
        ctx: &egui::Context,
        framerate: &mut Framerate,
        cube_rect: &mut Option<Rect>,
        open: &mut bool,
    ) {
        ctx.set_visuals(dialog_visuals());
        Window::new("Connect")
            .fixed_size(Vec2::new(250.0, 300.0))
            .collapsible(false)
            .open(open)
            .show(ctx, |ui| {
                ui.set_min_size(Vec2::new(250.0, 300.0));
                ui.set_max_size(Vec2::new(250.0, 300.0));
                match self.mode {
                    BluetoothMode::PromptConnect => self.prompt_connect(ui),
                    BluetoothMode::WaitForConnection => match self.waiting_for_connection(ui) {
                        Ok(_) => (),
                        Err(error) => {
                            self.mode = BluetoothMode::Error;
                            self.error = Some(error.to_string());
                        }
                    },
                    BluetoothMode::CheckState => {
                        match self.check_state(ctx, ui, framerate, cube_rect) {
                            Ok(_) => (),
                            Err(error) => {
                                self.mode = BluetoothMode::Error;
                                self.error = Some(error.to_string());
                            }
                        }
                    }
                    BluetoothMode::ResetState => {
                        match self.reset_state(ctx, ui, framerate, cube_rect) {
                            Ok(_) => (),
                            Err(error) => {
                                self.mode = BluetoothMode::Error;
                                self.error = Some(error.to_string());
                            }
                        }
                    }
                    BluetoothMode::Error => self.show_error(ui),
                    _ => (),
                }
            });

        framerate.request(Some(10));
    }

    pub fn paint_cube(
        &mut self,
        ctx: &egui::Context,
        gl: &mut GlContext<'_>,
        rect: &Rect,
    ) -> Result<()> {
        self.renderer.draw(ctx, gl, rect)
    }
}
