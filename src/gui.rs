use iced::{widget::{button, column, pick_list, row, text, text_input, Toggler}, Alignment::Center};
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use std::{path::Path, usize};

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
    ToCopy(Option<String>),
    LengthChange(String),
    Unset,
}


#[derive(Default)]
struct App {
    master: String,
    list: Vec<PasswordData>,
    tmp_lp: String,
    selected: usize,
    old_e: bool,
    length: usize
}

impl App {
    fn update(&mut self, message: Message) {
        if self.list.len() == 0 {
            self.old_e=true;
            self.list.push(create_passwd_struct(&Path::new(""), String::from("Select entry"), 0, Vec::new(), Type::NEW, Mode::READ));
            self.list[0].password = Some(String::from("Select entry")); 
            self.length = 8;
        }
        if self.master.len() == 0 {
            match message {
                    Message::PasswordSubmited(s) => self.tmp_lp = s,
                    Message::ButtonPressed => {self.master = self.tmp_lp.clone();
                        let (l, _, passwords) = check_config();
                        self.length = l;
                        for i in passwords {
                            let mut j = 1;
                            if self.master.len() != 0 {
                                self.list.push(create_passwd_struct(&Path::new(&i.1), i.0, self.length, self.master.as_bytes().to_vec(), if self.old_e==true {Type::NEW} else {Type::OLD}, Mode::READ));
                                self.list[j].get_done();
                                j += 1;
                            }
                        }
                        self.tmp_lp = "".to_string();
                    },
            _ => ()
            }
        } else {
            match message {
                Message::EntrySelected(s) => {self.selected = self.list.iter().position(|k| *k == s).unwrap(); self.list[self.selected].get_done(); if self.old_e == true {self.list[self.selected].type_e = Type::NEW;} else {self.list[self.selected].type_e = Type::OLD;} self.list[self.selected].length = self.length},
                Message::Update(b) => {if self.selected != 0 {self.old_e = b; if self.old_e == true {self.list[self.selected].type_e = Type::NEW;} else {self.list[self.selected].type_e = Type::OLD;} self.list[self.selected].password = None; self.list[self.selected].get_done(); println!("{:?}",self.selected.clone());} else {self.old_e=!self.old_e}},
                Message::ToCopy(c) => {let mut ctx = ClipboardContext::new().unwrap(); if self.selected != 0 {ctx.set_contents(c.unwrap().to_owned()).unwrap()}},
                Message::LengthChange(l) => {for i in l.as_bytes() {if (*i as char).is_numeric() {self.tmp_lp = l.clone();}} self.length = self.tmp_lp.trim().parse().unwrap(); self.list[self.selected].length= self.length; self.list[self.selected].get_done();}
                _ => (),
            }
        }
    }

    fn view(&self) -> iced::Element<Message> {
        if self.master.len() == 0 {
            column![
                text_input("Master password", &self.tmp_lp).secure(true).on_input(Message::PasswordSubmited),
                button("Confirm").on_press(Message::ButtonPressed) 
            ].align_x(Center).into()
        }
        else {
            let mut list = Vec::new();
            for i in self.list.clone() {
                list.push(i.name);
            }
            let pass =  match &self.list[self.selected].password {
                Some(c) => c,
                None => "Unable to get password"
            };
            column![
                pick_list(self.list.clone(), Some(self.list[self.selected].clone()), Message::EntrySelected).placeholder("Select a entry"),
                row![text("Password: "), button(pass).on_press(Message::ToCopy(self.list[self.selected].password.clone()))],
                Toggler::new(self.old_e).label("Newer encryption algorithm").on_toggle(|b| Message::Update(b)),
                row![text("Length: "), text_input("length", &self.tmp_lp).on_input(Message::LengthChange).width(50)]
            ].into()
        }
    }

}
