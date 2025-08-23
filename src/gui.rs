use iced::{widget::{button, column, row, pick_list, text, text_input}, window::Icon, Settings};
use iced::run;

use std::path::Path;

use crate::utils::*;

pub fn gui() -> iced::Result{
    iced::run("GRIP", App::update, App::view) 
}

#[derive(Debug, Clone)]
enum Message {
    ButtonPressed,
    PasswordSubmited(String),
    EntrySelected(PasswordData),
    Unset,
}

#[derive(Default)]
struct App {
    master: String,
    list: Vec<PasswordData>,
    tmp: String,
    selected: Option<PasswordData>
}

impl App {
    fn update(&mut self, message: Message) {
        if self.master.len() == 0 {
            match message {
                    Message::PasswordSubmited(s) => self.tmp = s,
                    Message::ButtonPressed => self.master = self.tmp.clone(),
                    _ => (),
                }
            let (length, _, passwords) = check_config();
            for i in passwords {
                let mut j = 0;
                if self.master.len() != 0 {
                    self.list.push(create_passwd_struct(&Path::new(&i.1), i.0, length, self.master.as_bytes().to_vec(), Type::NEW, Mode::READ));
                    self.list[j].get_done();
                    j += 1;
                }
            }
        } else {
            match message {
                Message::EntrySelected(s) => {self.selected = Some(s.clone()); self.selected.clone().unwrap().get_done(); println!("{:?}", self.selected.clone().unwrap().password);},
                _ => (),
            }
        }
    }

    fn view(&self) -> iced::Element<Message> {
        if self.master.len() == 0 {
            column![
                text_input("Master password", &self.tmp).secure(true).on_input(Message::PasswordSubmited),
                button("Confirm").on_press(Message::ButtonPressed) 
            ].into()
        }
        else {
            let mut list = Vec::new();
            for i in self.list.clone() {
                list.push(i.name);
            }
            let pass = match self.selected.clone() {
                Some(mut s) => match s.password {
                    Some(c) => c,
                    None => {s.get_done(); "Unable to get password".to_string()}
                },
                None => "Unable to get password".to_string()
            };
            column![
                pick_list(self.list.clone(), self.selected.clone(), Message::EntrySelected).placeholder("Select a entry"),
                row![text("Password: "), text(match &self.selected {
                    None => " ".to_string(),
                    Some(_) => pass,
                })],

            ].into()
        }
    }

}
