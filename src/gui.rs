use iced::{widget::{button, column, pick_list, row, text, text_input, Toggler, image}};
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
    Update(bool),
    Unset,
}

#[derive(Default)]
struct App {
    master: String,
    list: Vec<PasswordData>,
    tmp: String,
    selected: Option<PasswordData>,
    old_e: bool 
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
                Message::EntrySelected(s) => {self.selected = Some(s.clone()); self.selected.as_mut().unwrap().get_done(); if self.old_e == true {self.selected.as_mut().unwrap().type_e = Type::NEW;} else {self.selected.as_mut().unwrap().type_e = Type::OLD;}},
                Message::Update(b) => {self.old_e = b; if self.old_e == true {self.selected.as_mut().unwrap().type_e = Type::NEW;} else {self.selected.as_mut().unwrap().type_e = Type::OLD;} self.selected.as_mut().unwrap().password = None; self.selected.as_mut().unwrap().get_done(); println!("{:?}",self.selected.clone().unwrap());}
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
                Toggler::new(self.old_e).label("Newer encryption algorithm").on_toggle(|b| Message::Update(b)),
                image(self.selected.clone().unwrap().path)
            ].into()
        }
    }

}
