use egui::{FontDefinitions, FontFamily, FontId, RichText, TextStyle};
use std::collections::BTreeMap;

#[derive(Copy, Clone, PartialEq, Eq)]
// We use the text styles not as they are actually intended, as we need
// some abnormal font sizes and we can only have font sizes associated with
// the text styles. This enumeration acts as an easy way to semantically
// express the font size we want but automatically convert to the text
// style required to get the correct size.
pub enum FontSize {
    Small,
    Normal,
    Section,
    Scramble,
    BestTime,
    Timer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScreenSize {
    Small,
    Normal,
    Large,
    VeryLarge,
}

impl Into<TextStyle> for FontSize {
    fn into(self) -> TextStyle {
        match self {
            FontSize::Small => TextStyle::Small,
            FontSize::Normal => TextStyle::Body,
            FontSize::Section => TextStyle::Heading,
            FontSize::Scramble => TextStyle::Button,
            FontSize::BestTime => TextStyle::Button,
            FontSize::Timer => TextStyle::Monospace,
        }
    }
}

/// Helper to create RichText with a specific font size
pub fn sized_text(text: impl Into<String>, size: FontSize) -> RichText {
    RichText::new(text).text_style(size.into())
}

pub fn font_definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();

    // OpenSans has height_unscaled/units_per_em = 1.3618. egui 0.31+ applies
    // this as a scaling multiplier (see egui#2068), making fonts ~36% larger
    // than they were in egui 0.13. Compensate with FontTweak to preserve the
    // original visual sizes.
    let opensans_tweak = egui::FontTweak {
        scale: 1.0 / 1.3618,
        ..Default::default()
    };
    fonts.font_data.insert(
        "OpenSans".into(),
        egui::FontData::from_static(include_bytes!("../fonts/OpenSans-Regular.ttf"))
            .tweak(opensans_tweak)
            .into(),
    );
    fonts.font_data.insert(
        "OpenSans Light".into(),
        egui::FontData::from_static(include_bytes!("../fonts/OpenSans-Light.ttf"))
            .tweak(opensans_tweak)
            .into(),
    );
    fonts.font_data.insert(
        "emoji-icon-font".into(),
        egui::FontData::from_static(include_bytes!("../fonts/emoji-icon-font.ttf")).into(),
    );
    fonts.families.insert(
        FontFamily::Proportional,
        vec!["OpenSans".into(), "emoji-icon-font".into()],
    );
    fonts.families.insert(
        FontFamily::Monospace,
        vec!["OpenSans Light".into(), "emoji-icon-font".into()],
    );

    fonts
}

pub fn text_styles(screen_size: ScreenSize) -> BTreeMap<TextStyle, FontId> {
    let mut styles = BTreeMap::new();

    if crate::is_mobile() == Some(true) {
        styles.insert(TextStyle::Small, FontId::new(16.0, FontFamily::Proportional));
        styles.insert(TextStyle::Body, FontId::new(24.0, FontFamily::Proportional));
        styles.insert(TextStyle::Heading, FontId::new(30.0, FontFamily::Proportional));
    } else {
        styles.insert(TextStyle::Small, FontId::new(16.0, FontFamily::Proportional));
        styles.insert(TextStyle::Body, FontId::new(20.0, FontFamily::Proportional));
        styles.insert(TextStyle::Heading, FontId::new(24.0, FontFamily::Proportional));
    }

    styles.insert(
        TextStyle::Button,
        FontId::new(
            match screen_size {
                ScreenSize::Small => 32.0,
                ScreenSize::Normal => 40.0,
                ScreenSize::Large => 48.0,
                ScreenSize::VeryLarge => 64.0,
            },
            FontFamily::Monospace,
        ),
    );
    styles.insert(
        TextStyle::Monospace,
        FontId::new(
            match screen_size {
                ScreenSize::Small => 80.0,
                ScreenSize::Normal => 128.0,
                ScreenSize::Large => 144.0,
                ScreenSize::VeryLarge => 192.0,
            },
            FontFamily::Monospace,
        ),
    );

    styles
}
