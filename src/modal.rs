use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::ui::theme;

#[derive(Clone, Copy, PartialEq)]
pub enum ModalKind {
    Error,
    Success,
    Progress,
    Confirm,
}

#[derive(Clone, PartialEq)]
pub enum ModalAction {
    Dismiss,
    RetryConnect,
    StartUpdate(String),
    CancelUpdate,
    RestartApp,
    DeleteProfile(usize),
    RetryLogin,
}

#[derive(Clone, Copy)]
pub enum ButtonStyle {
    Primary,
    Danger,
    Ghost,
}

pub struct ModalButton {
    pub label: String,
    pub style: ButtonStyle,
    pub action: ModalAction,
}

impl ModalButton {
    pub fn new(label: &str, style: ButtonStyle, action: ModalAction) -> Self {
        Self { label: label.into(), style, action }
    }
}

#[derive(Clone, Default)]
pub struct Progress {
    pub done: Arc<AtomicU64>,
    pub total: Arc<AtomicU64>,
}

pub struct Modal {
    pub kind: ModalKind,
    pub title: String,
    pub body: String,
    pub progress: Option<Progress>,
    pub buttons: Vec<ModalButton>,
    pub closable: bool,
}

impl Modal {
    pub fn error(title: &str, body: &str, buttons: Vec<ModalButton>) -> Self {
        Self { kind: ModalKind::Error, title: title.into(), body: body.into(), progress: None, buttons, closable: true }
    }

    pub fn success(title: &str, body: &str, buttons: Vec<ModalButton>) -> Self {
        Self { kind: ModalKind::Success, title: title.into(), body: body.into(), progress: None, buttons, closable: true }
    }

    pub fn progress(title: &str, body: &str, progress: Progress, buttons: Vec<ModalButton>) -> Self {
        Self { kind: ModalKind::Progress, title: title.into(), body: body.into(), progress: Some(progress), buttons, closable: false }
    }

    pub fn confirm(title: &str, body: &str, buttons: Vec<ModalButton>) -> Self {
        Self { kind: ModalKind::Confirm, title: title.into(), body: body.into(), progress: None, buttons, closable: true }
    }

    pub fn draw(&self, ctx: &egui::Context) -> Option<ModalAction> {
        let t = theme();
        let mut action: Option<ModalAction> = None;

        let frame = egui::Frame::default()
            .fill(t.surface)
            .stroke(egui::Stroke::new(1.0_f32, t.border))
            .corner_radius(egui::CornerRadius::same(14))
            .inner_margin(18.0);

        let response = egui::Modal::new(egui::Id::new("ng_modal"))
            .frame(frame)
            .backdrop_color(egui::Color32::from_black_alpha(150))
            .show(ctx, |ui| {
                ui.set_width(280.0);

                let (dot, title_color) = match self.kind {
                    ModalKind::Error => ("●", t.danger),
                    ModalKind::Success => ("●", t.success),
                    ModalKind::Progress => ("●", t.accent),
                    ModalKind::Confirm => ("●", t.warning),
                };
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(dot).size(10.0).color(title_color));
                    ui.label(egui::RichText::new(&self.title).size(14.0).strong().color(t.text));
                });
                ui.add_space(6.0);
                ui.label(egui::RichText::new(&self.body).size(12.0).color(t.text_secondary));

                if let Some(ref p) = self.progress {
                    let done = p.done.load(Ordering::Relaxed);
                    let total = p.total.load(Ordering::Relaxed);
                    let frac = if total > 0 { (done as f32 / total as f32).clamp(0.0, 1.0) } else { 0.0 };
                    ui.add_space(10.0);
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .desired_height(8.0)
                            .fill(t.accent)
                            .corner_radius(egui::CornerRadius::same(4)),
                    );
                    ui.add_space(4.0);
                    let text = if total > 0 {
                        format!("{} / {}  ({:.0}%)", fmt_mb(done), fmt_mb(total), frac * 100.0)
                    } else if done > 0 {
                        format!("{} downloaded", fmt_mb(done))
                    } else {
                        "Starting download...".into()
                    };
                    ui.label(egui::RichText::new(text).size(11.0).color(t.text_muted));
                    ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
                }

                if !self.buttons.is_empty() {
                    ui.add_space(14.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        for b in self.buttons.iter().rev() {
                            if ui.add(self.button_widget(b, t)).clicked() {
                                action = Some(b.action.clone());
                            }
                        }
                    });
                }
            });

        if action.is_none() && self.closable && response.should_close() {
            action = Some(ModalAction::Dismiss);
        }
        action
    }

    fn button_widget(&self, b: &ModalButton, t: &crate::ui::Theme) -> egui::Button<'static> {
        let size = egui::vec2(0.0, 30.0);
        match b.style {
            ButtonStyle::Primary => egui::Button::new(
                egui::RichText::new(&b.label).size(12.0).strong().color(t.text),
            )
            .fill(t.accent)
            .min_size(size),
            ButtonStyle::Danger => egui::Button::new(
                egui::RichText::new(&b.label).size(12.0).strong().color(t.text),
            )
            .fill(t.danger)
            .min_size(size),
            ButtonStyle::Ghost => egui::Button::new(
                egui::RichText::new(&b.label).size(12.0).color(t.text_secondary),
            )
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0_f32, t.border))
            .min_size(size),
        }
    }
}

fn fmt_mb(b: u64) -> String {
    format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
}
