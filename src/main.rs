use core::panic;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::path::Path;
use std::{env, u8, usize};

fn remove_whitespace(s: &str) -> String{
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn open_file(path: &Path) -> Vec<u8>{
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => panic!("Could not open {:?}, error: {}", path, e),
    };
    let mut content: Vec<u8> = Vec::new();
    match file.read_to_end(&mut content) {
        Err(e) => panic!("Could not read {:?}, error {}", path, e),
        _ => (),
    };
    content
}

fn bytes_check(content: Vec<u8>,mut i: usize) -> u8{
    loop {
        let tmp = content[i];
        if tmp < 32 || tmp > 126{
            i += 1;
        } else {
            return tmp;
        }
    }
}

fn get_chars(content: Vec<u8>, length: usize, hash: Vec<u8>) -> Vec<u8>{
    let mut tmp: usize = {
        let mut ret: u64 = hash[0] as u64;
        for i in 1..hash.len() {
            ret += hash[i] as u64;
        }
        ret.try_into().unwrap()    };
    let mut ret_array: Vec<u8> = Vec::new();
    let mut j: usize = 1;
    for i in 0..length {
        j += 1;
        if j <= hash.len() {
            j = 0;
        }
        let tmp_i: usize = hash[j].into();
        if i%2 == 0 {
            if tmp + tmp_i < content.len() {
                tmp = tmp + tmp_i;
            } else {
                tmp = (tmp + tmp_i) % content.len();
            }
        } else {
            if tmp * tmp_i < content.len() {
                tmp = tmp * tmp_i;
            } else {
                tmp = (tmp * tmp_i) % content.len();
            }
        }
        ret_array.push(bytes_check(content.clone(), tmp)); 
    }
    if ret_array[0] == 0 {
        ret_array[0] = bytes_check(content, tmp);
    }
    ret_array
}

fn get_password(path: String, length: usize, hash: Vec<u8>) -> String{
    let content = open_file(Path::new(&path));
    let byte_array = get_chars(content, length, hash);
    let s = String::from_utf8_lossy(&byte_array);
    s.to_string()
}

fn get_length(arg: String) -> usize{
    let length_result: std::result::Result<usize, std::num::ParseIntError> = arg.trim().parse();
    match length_result {
        Ok(len) => return len,
        _ => panic!("not valid length"),
    };
}

fn get_saved_path(shortcuts: HashMap<String, String>, keys: Vec<String>) -> Vec<String>{
    let mut paths: Vec<String> = vec![];
    if shortcuts.len() > 0 {
        for k in keys {
            match shortcuts.get(&k) {
                Some(v) => paths.push(remove_whitespace(v)),
                None => println!("{} has invalid path", k),
            }
        }
    }
    paths
}

fn remove_args(mut args: Vec<String>) -> Vec<String> {
    for _ in 0..2 {
        args.remove(0);
    }
    args
}

fn create_config() ->  bool{
    match fs::create_dir(home::home_dir().unwrap().join(".config/ripm")) {
        Err(e) => {println!("{} failed to create config directory", e); return false},
        Ok(_) => (),
    }
    let conf_file = home::home_dir().unwrap().join(".config/ripm/ripm.conf");
    let mut f = match File::create_new(conf_file) {
        Err(e) => {println!("{} failed to create config directory", e); return false},
        Ok(f) => f,
    };
    match f.write_all("default_length: 8\ndefault_password: password.hash\n".as_bytes()) {
        Err(e) => {println!("{} failed to write into config file", e); return false;},
        _ => (),
    }
    true
}

fn check_config() -> (usize, Option<String>, HashMap<String, String>){
    let conf_file = home::home_dir().unwrap().join(".config/ripm/ripm.conf");
    let mut files = true;
    if conf_file.exists() == false {
        files = create_config();
    }
    let mut length: usize = 8;
    let mut hash = None;
    let mut shortcuts: HashMap<String, String> = HashMap::new();
    if files {
        let mut password = String::new();
        let conf_file = home::home_dir().unwrap().join(".config/ripm/ripm.conf");
        let content = open_file(&conf_file);
        let binding = content;
        let tmp = String::from_utf8_lossy(&binding);
        let lines: Vec<&str> = tmp.split("\n").collect();
        for i in 0..lines.len() {
            if lines[i].len() == 0 {
                break;
            }
            let parts: Vec<&str> = lines[i].split(":").collect();
            if parts.len() % 2 == 1 {
                println!("invalid config file");
                continue;
            }
            match parts[0].trim(){
                "default_length" => length = get_length(parts[1].to_string()),
                "default_password" => {let passwd_hash = parts[1].trim().to_string(); password = String::from_utf8_lossy(&open_file(&Path::new(&passwd_hash))).to_string();},
                _ => {shortcuts.insert(parts[0].to_string(), parts[1].to_string());},

            }
        }
        if password.len() > 0 {
            let mut pass_vec: Vec<u8> = password.as_bytes().to_vec();
            pass_vec.remove(pass_vec.len()-1);
            hash = Some(String::from_utf8_lossy(&pass_vec).to_string());
        }
    }
    (length, hash, shortcuts)

}

fn get_options(args: Vec<String>) -> Vec<String> {
    let mut options: Vec<String> = vec![];
    for i in 1..args.len(){
        if args[i].as_bytes()[0] == '-' as u8{
            break;
        }
        options.push(args[i].clone());
    }
    return options;
}

fn sanitize_string(s: String) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    if v[v.len()-1] == 10 {
        v.remove(v.len()-1);
    }
    v
}

fn main() {
    let (mut length, passwd_hash, shortcuts) = check_config();
    let mut args: Vec<String> = env::args().collect();
    let mut paths: Vec<String> = Vec::new();
    let mut hash: Vec<u8> = vec![];
    args.remove(0);
    if args.len() < 2{
        panic!("not enough argument")
    }
    loop {
        if args.len() == 0{
            break;
        }
        match args[0].as_str() {
            "-l" => length = get_length(args[1].clone()),
            "--length" => length = get_length(args[1].clone()),
            "-H" => hash = sanitize_string(args[1].clone()),
            "--hash" => hash = sanitize_string(args[1].clone()),
            "-p" => paths.append(&mut get_options(args.clone())),
            "--path" => paths.append(&mut get_options(args.clone())),
            "-s" => paths.append(&mut get_saved_path(shortcuts.clone(), get_options(args.clone()))),
            "--saved" => paths.append(&mut get_saved_path(shortcuts.clone(), get_options(args.clone()))),
            _ => panic!("{} is unknown argument", args[0]),
        }
        args = remove_args(args);
    }
    if hash.len() == 0 {
        let mut passwd: String = String::new();
        println!("please enter your password: ");
        io::stdin().read_line(&mut passwd).expect("Failed to get password");
        hash = sanitize_string(passwd);
    }
    if passwd_hash != None {
        if sha256::digest(&hash).to_string() != passwd_hash.unwrap(){
            println!("Your password may be wrong")
        } 
    }
    else {
        println!("Hash of the password: {:?}",sha256::digest(&hash));
    }
    for i in 0..paths.len(){
        let password = get_password(paths[i].clone(), length, hash.clone());
        println!("{}: {}", paths[i], password); 
    }
}
