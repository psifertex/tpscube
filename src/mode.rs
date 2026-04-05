use crate::theme::Theme;
use crate::widgets::CustomWidgets;
use egui::{Color32, Label, RichText, Sense, Ui, Window};
use tpscube_core::SolveType;

pub struct SolveTypeSelectWindow {
    solve_type: SolveType,
}

impl SolveTypeSelectWindow {
    pub fn new(solve_type: SolveType) -> Self {
        Self { solve_type }
    }

    fn option(
        &self,
        ui: &mut Ui,
        selected: &mut Option<SolveType>,
        solve_type: SolveType,
        name: &str,
    ) {
        let label = if self.solve_type == solve_type {
            Label::new(RichText::new(name).color(Into::<Color32>::into(Theme::Green))).sense(Sense::click())
        } else {
            Label::new(name).sense(Sense::click())
        };
        if ui.add(label).clicked() {
            *selected = Some(solve_type);
        }
    }

    pub fn update(&self, ctxt: &egui::Context, open: &mut bool, selected: &mut Option<SolveType>) {
        Window::new("Select Puzzle")
            .collapsible(false)
            .resizable(false)
            .scroll([false, true])
            .open(open)
            .show(ctxt, |ui| {
                ui.vertical(|ui| {
                    ui.section("Standard Cubes");
                    self.option(ui, selected, SolveType::Standard2x2x2, "2x2x2");
                    self.option(ui, selected, SolveType::Standard3x3x3, "3x3x3");
                    self.option(ui, selected, SolveType::OneHanded3x3x3, "3x3x3 One Handed");

                    ui.section("Blindfolded");
                    self.option(ui, selected, SolveType::Blind3x3x3, "3x3x3 Blindfolded");
                });
            });
    }
}
