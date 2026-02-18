use colored::{ColoredString, Colorize};

#[must_use]
pub fn progress_bar(value: f64, width: usize) -> String {
    let ratio = (value / 100.0).clamp(0.0, 1.0);
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let filled = (ratio * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);

    let bar_filled = "█".repeat(filled);
    let bar_empty = "░".repeat(empty);

    let colored_bar = if value >= 90.0 {
        bar_filled.red().bold()
    } else if value >= 70.0 {
        bar_filled.yellow()
    } else {
        bar_filled.green()
    };

    format!("{colored_bar}{bar_empty}")
}

#[must_use]
pub fn colorize_percent(value: f64) -> ColoredString {
    let text = format!("{value:.1}%");
    if value >= 90.0 {
        text.red().bold()
    } else if value >= 70.0 {
        text.yellow()
    } else {
        text.green()
    }
}

pub fn print_section_header(title: &str) {
    println!("{}", title.bold().cyan());
    let display_width = title.chars().count();
    println!("{}", "─".repeat(display_width).cyan());
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::control;

    fn disable_colors() {
        control::set_override(false);
    }

    #[test]
    fn progress_bar_zero_percent() {
        disable_colors();
        let bar = progress_bar(0.0, 10);
        assert!(bar.contains("░░░░░░░░░░"));
    }

    #[test]
    fn progress_bar_full_percent() {
        disable_colors();
        let bar = progress_bar(100.0, 10);
        assert!(bar.contains("██████████"));
    }

    #[test]
    fn progress_bar_half_percent() {
        disable_colors();
        let bar = progress_bar(50.0, 10);
        assert!(bar.contains("█████"));
        assert!(bar.contains("░░░░░"));
    }

    #[test]
    fn progress_bar_clamps_above_100() {
        disable_colors();
        let bar = progress_bar(150.0, 10);
        assert!(bar.contains("██████████"));
    }

    #[test]
    fn progress_bar_clamps_negative() {
        disable_colors();
        let bar = progress_bar(-10.0, 10);
        assert!(bar.contains("░░░░░░░░░░"));
    }

    #[test]
    fn colorize_percent_formats_correctly() {
        disable_colors();
        let result = colorize_percent(42.3);
        assert_eq!(result.to_string(), "42.3%");
    }

    #[test]
    fn colorize_percent_high_value() {
        disable_colors();
        let result = colorize_percent(95.0);
        assert_eq!(result.to_string(), "95.0%");
    }

    #[test]
    fn progress_bar_yellow_range() {
        disable_colors();
        let bar = progress_bar(75.0, 10);
        assert!(bar.contains("████████"));
    }

    #[test]
    fn colorize_percent_yellow_range() {
        disable_colors();
        let result = colorize_percent(80.0);
        assert_eq!(result.to_string(), "80.0%");
    }

    #[test]
    fn print_section_header_does_not_panic() {
        disable_colors();
        print_section_header("Test Header");
        print_section_header("💾 Mémoire RAM");
    }
}
