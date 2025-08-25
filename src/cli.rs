use crate::utils::*;
use std::path::Path;
use std::io::{self, prelude::*};
use rpassword::read_password;
use std::env;

#[cfg(feature = "gui")]
use crate::gui::*;

pub fn cli() {
    let (mut length, passwd_hash, shortcuts) = check_config();
    let mut args: Vec<String> = env::args().collect();
    let mut paths: Vec<String> = Vec::new();
    let mut hash: Vec<u8> = vec![];
    let mut operation: Mode = Mode::UNSET;
    let mut type_e = Type::NEW;
    args.remove(0);
    if args.len() < 2{
        #[cfg(feature = "gui")]
        {   gui();
            return;}
        println!("not enough argument");
        help(); 
        return;
    }
    loop {
        if args.len() == 0{
            break;
        }
        match args[0].as_str() {
            "-l" => {length = get_length(args[1].clone()); for _ in 0..2 {args.remove(0);}},
            "--length" => {length = get_length(args[1].clone()); for _ in 0..2 {args.remove(0);}},
            "-H" => {hash = args[1].clone().into(); for _ in 0..2 {args.remove(0);}},
            "--hash" => {hash = args[1].clone().into(); for _ in 0..2 {args.remove(0);}},
            "-p" => paths.append(&mut get_params(&mut args)),
            "--path" => paths.append(&mut get_params(&mut args.clone())),
            "-s" => paths.append(&mut get_saved_path(shortcuts.clone(), get_params(&mut args))),
            "--saved" => paths.append(&mut get_saved_path(shortcuts.clone(), get_params(&mut args))),
            "-r" => {operation = Mode::READ; args.remove(0);},
            "--read" => {operation = Mode::READ; args.remove(0);},
            "-w" => {operation = Mode::WRITE; args.remove(0);},
            "--write" => {operation = Mode::WRITE; args.remove(0);},
            "-h" => help(),
            "--help" => help(),
            "-o" => {type_e = Type::OLD; args.remove(0);},
            "--old" => {type_e = Type::OLD; args.remove(0);}
            "-n" => {type_e = Type::NEW; args.remove(0);}
            "--new" => {type_e = Type::NEW; args.remove(0);}
            #[cfg(feature = "gui")]
            "--gui" => gui().expect("No window system"),
            #[cfg(feature = "gui")]
            "-g" => gui().expect("NO window system"),
            _ => {println!("{} is unknown argument", args[0]); help(); return;},
        }
    }
    if hash.len() == 0{
         hash = password_check(passwd_hash, hash.clone());
    }
    let mut passwd_vec = Vec::new();
    for i in &paths {
        passwd_vec.push(create_passwd_struct(&Path::new(&i), String::new(), length, hash.clone(), type_e.clone(), operation.clone()));
    }
    
    for mut i in passwd_vec {
        i.get_done();
    }
}

pub fn desired(s: &mut Option<String>) {
    print!("please enter your desired password to save: ");
    io::stdout().flush().unwrap();
    *s = Some(read_password().unwrap());
}
