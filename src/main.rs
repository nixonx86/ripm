mod utils;

#[cfg(feature = "gui")]
mod gui;
//#[cfg(feature = "gui")]
//pub use crate::gui;



#[cfg(feature = "cli")]
mod cli;



fn main() {
    #[cfg(feature = "cli")]
    cli::cli();
    #[cfg(feature = "gui")]
    gui::gui();
}
