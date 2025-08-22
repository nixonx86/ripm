use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::path::Path;
use std::{env, u8, usize};

use rpassword::read_password;

#[derive(Clone)]
enum Mode {
    READ,
    WRITE,
    UNSET,
}

enum WriteRet {
    SUCSSES,
    FAIL,
    ERROR,
    UNKNOWN,
}

#[derive(Clone)]
enum Type {
    OLD,
    NEW
}

struct PasswordData {
    path: Box<Path>,
    length: usize,
    master_password: Vec<u8>,
    type_e: Type,
    mode: Mode,
    password: Option<String>,
    content: Vec<u8>,
    desired: Option<String>
}

impl PasswordData {
    fn get_saved_password(&mut self) -> Option<String>{
        match open_file(&*self.path) {
            None => {println!("Could not read {}", (*self.path).display()); return None},
            Some(c) => self.content = c,
        }
        self.get_chars();
        self.password.clone()
    }
    fn get_chars(&mut self) -> Vec<u8>{
        let mut tmp: usize = {
            let mut ret: u64 = self.master_password[0] as u64;
            for i in 1..self.master_password.len() {
                ret += self.master_password[i] as u64;
            }
            ret.try_into().unwrap()};
        match self.type_e {
            Type::NEW => tmp = tmp + self.length,
            _ => (),
        }
        let mut ret_array: Vec<u8> = Vec::new();
        let mut j: usize = 1;
        if self.master_password.len() == 1 {j = 0;} 
        for i in 0..self.length {
            j += 1;
            if j <= self.master_password.len() {
                j = 0;
            }
        let tmp_i: usize = self.master_password[j].into();
        if i%2 == 0 {
            if tmp + tmp_i < self.content.len() {
                tmp = tmp + tmp_i;
            } else {
                tmp = (tmp + tmp_i) % self.content.len();
            }
        } else {
            if tmp * tmp_i < self.content.len() {
                tmp = tmp * tmp_i;
            } else {
                tmp = (tmp * tmp_i) % self.content.len();
            }
        }
        ret_array.push(self.bytes_check(tmp)); 
        }
        if ret_array[0] == 0 {
            ret_array[0] = self.bytes_check(tmp);
        }
        self.password = Some(String::from_utf8_lossy(&ret_array).to_string());
        return ret_array;
    }
    fn bytes_check(&self ,mut i: usize) -> u8{
        loop {
            let tmp = self.content[i];
            if tmp < 32 || tmp > 126{
                i += 1;
            } else {
                return tmp;
            }
        }
    }
    fn get_done(&mut self) {
        match self.mode {
            Mode::READ => {
                self.get_saved_password(); 
                match &self.password {
                    Some(c) => println!("{}: {}", (*self.path).display(), c),
                    None => println!("Could not read {}", (*self.path).display()),
                }
            },
            Mode::WRITE => {
                if self.desired == None{
                    print!("please enter your desired password to save: ");
                    io::stdout().flush().unwrap();
                    self.desired = Some(read_password().unwrap());
                }
                match self.write_password() {
                    WriteRet::SUCSSES => println!("{} was sucssesfuly writen", (*self.path).display()),
                    WriteRet::FAIL => println!("{} was not sucssesfull", (*self.path).display()),
                    WriteRet::ERROR => println!("Was not able to write to {}", (*self.path).display()),
                    WriteRet::UNKNOWN => println!("{} can not be sure if is correctly saved", (*self.path).display()),
                }
            },
            _ => {println!("not valid mode"); help()},
        }
    }
    fn write_password(&mut self) -> WriteRet{
        self.length = self.desired.clone().unwrap().len();
        match open_file(&(*self.path)) {
            None => {println!("Could not read {}", (*self.path).display()); return WriteRet::ERROR;},
            Some(c) => self.content = c,
        }
        self.write_chars();
        if self.desired.clone().unwrap().as_bytes() == self.get_chars() {
            let mut file = match File::options().write(true).open(&(*self.path)) {
                Ok(f) => f,
                Err(e) => {println!("Could not open {:?}, error: {}", (*self.path).display(), e); return WriteRet::ERROR},
            };
            match file.write_all(&self.content) {
                Err(e) => {println!("Could not write to {:?}, error {}", (*self.path).display(), e); return WriteRet::ERROR;},
                _ => (),
            }
            match file.sync_data() {
                Err(e) => {println!("Could not write to {:?}, error {}", (*self.path).display(), e); return WriteRet::ERROR;},
                _ => (),
            }
            match self.get_saved_password() {
                Some(c) => {
                    if self.desired == Some(c){
                        return WriteRet::SUCSSES;
                    } else {
                        return WriteRet::FAIL;
                    }
                },
                None => {println!("Could not verify {:?}", (*self.path).display()); return WriteRet::UNKNOWN;}
            }
        } else {
            WriteRet::FAIL
        }
    }
    fn write_chars(&mut self) {
        let mut tmp: usize = {
            let mut ret: u64 = self.master_password[0] as u64;
            for i in 1..self.master_password.len() {
                ret += self.master_password[i] as u64;
            }
            ret.try_into().unwrap()    };
        match self.type_e {
            Type::NEW => tmp = tmp + self.length,
            _ => (),
        }
        let mut j: usize = 1;
        for i in 0..self.length {
            j += 1;
            if j <= self.master_password.len() {
                j = 0;
            }
            let tmp_i: usize = self.master_password[j].into();
            if i%2 == 0 {
                if tmp + tmp_i < self.content.len() {
                    tmp = tmp + tmp_i;
                } else {
                    tmp = (tmp + tmp_i) % self.content.len();
                }
            } else {
                if tmp * tmp_i < self.content.len() {
                    tmp = tmp * tmp_i;
                } else {
                    tmp = (tmp * tmp_i) % self.content.len();
                }
            }
            self.write_byte(tmp, self.desired.clone().unwrap().as_bytes().to_vec()[i]); 
        }
    }
    fn write_byte(&mut self,mut i: usize, byte: u8) {
        loop {
            let tmp = self.content[i];
            if tmp < 32 || tmp > 126{
                i += 1;
            } else {
                self.content[i] = byte;
                return;
            }
    }
}
}

fn create_passwd_struct(path: &Path, length: usize, master_password: Vec<u8>, type_e: Type, mode: Mode) -> PasswordData{
   PasswordData {
        path: path.into(),
        length,
        master_password,
        type_e,
        mode,
        password: None,
        content: Vec::new(),
        desired: None
   } 
}

fn help() {
    println!("   
ripm <arguments> \n
\t --length (-l) <length> \t specify the length of the password (defaults to 8) \n
\t --hash (-H) <hash> \t specify the password under which is the final password encrypted (if not set, the program will ask you for one, which is better and safer method) \n
\t --path (-p) <paths> \t specify where the file is stored, you need to set path and/or saved \n
\t --saved (-s) <saved name> \t if in config file is set saved path you can use its name as you saved it, you need to set saved and/or path \n
\t --read -r \t this will set to read password from the image \n
\t --write -w \t this will set to write password into the image \n
\t --old -o \t uses the old method to store password (only use if you use this up to 0.3.3 version), the new one is safer \n
\t --new -n \t uses the new method to store password \n
\t --help -h \t help
");
}

fn remove_whitespace(s: &str) -> String{
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn open_file(path: &Path) -> Option<Vec<u8>>{
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => { println!("Could not open {:?}, error: {}", path, e); return None; },
    };
    let mut content: Vec<u8> = Vec::new();
    match file.read_to_end(&mut content) {
        Err(e) => { println!("Could not read {:?}, error {}", path, e); return None; },
        _ => (),
    };
    drop(file);
    Some(content)
}

fn get_length(arg: String) -> usize{
    let length_result: std::result::Result<usize, std::num::ParseIntError> = arg.trim().parse();
    match length_result {
        Ok(len) => return len,
        _ => {println!("not valid length"); help(); return usize::min_value();},
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
    match f.write_all("default_length: 8".as_bytes()) {
        Err(e) => {println!("{} failed to write into config file", e); return false},
        _ => (),
    }
    true
}

fn check_config() -> (usize, Vec<String>, HashMap<String, String>){
    let conf_file = home::home_dir().unwrap().join(".config/ripm/ripm.conf");
    let mut files = true;
    if conf_file.exists() == false {
        files = create_config();
    }
    let mut length: usize = 8;
    let mut password: Vec<String> = Vec::new();
    let mut shortcuts: HashMap<String, String> = HashMap::new();
    if files {
        let conf_file = home::home_dir().unwrap().join(".config/ripm/ripm.conf");
        let content = open_file(&conf_file);
        match content {
            None => println!("Error reading content file"),
            Some(c) => { 
                let binding = c;
                let tmp = String::from_utf8_lossy(&binding);
                let lines: Vec<&str> = tmp.split("\n").collect();
                for i in 0..lines.len() {
                    if lines[i].len() == 0 {
                        continue;
                    }
                    let parts: Vec<&str> = lines[i].split(":").collect();
                    if parts.len() % 2 == 1 {
                        println!("invalid config file");
                        break;
                    }
                    match parts[0].trim(){
                        "default_length" => length = get_length(parts[1].to_string()),
                        "password" => {
                            let tmp_p = parts[1].trim().to_string();
                            if Path::new(&tmp_p).exists(){
                                    match open_file(&Path::new(&tmp_p)){
                                        Some(c) => {
                                            for i in String::from_utf8_lossy(&c).split("\n") {
                                                if i.len() != 0 {
                                                    let mut tmp1: Vec<u8> = i.as_bytes().to_vec();
                                                    if i.as_bytes()[i.len()-1] == 10 {
                                                        tmp1.remove(tmp1.len()-1);
                                                        if tmp1.len() != 64 {
                                                            println!("invalid sha256 hash {}", tmp_p);
                                                        }
                                                        
                                                    }
                                                    if i.as_bytes()[0] == 32 {
                                                        tmp1.remove(0);
                                                        if tmp1.len() != 64 {
                                                            println!("invalid sha256 hash {}", tmp_p);
                                                        }
                                                    }
                                                    password.push(String::from_utf8_lossy(&tmp1).to_string());
                                                }
                                            }
                                        },
                                        _ => (),
                                    }
                                    continue;
                            } 
                            if tmp_p.as_bytes()[tmp_p.len()-1] == 10 {
                                let mut tmp1: Vec<u8> = tmp_p.as_bytes().to_vec();
                                tmp1.remove(tmp1.len()-1);
                                if tmp1.len() != 64 {
                                    println!("invalid sha256 hash {}", tmp_p);
                                }
                                password.push(String::from_utf8_lossy(&tmp1).to_string());
                                continue;
                            }
                            if tmp_p.len() != 64 {
                                println!("invalid sha256 hash {}", tmp_p);
                                continue;
                            }
                            password.push(tmp_p);
                        },
                        _ => { 
                            if parts[1].to_string().as_bytes()[0] == '/' as u8 { // absoulte path
                                shortcuts.insert(parts[0].to_string(), parts[1].to_string());
                                continue;
                            }
                            // dynamic
                            let path = home::home_dir().unwrap().join(".config/ripm").join(parts[1]).to_str().unwrap().to_string();
                            shortcuts.insert(parts[0].to_string(), path);
                        }
                    }
                }
            }
        }
    }
    (length, password, shortcuts)

}

fn get_params(args: &mut Vec<String>) -> Vec<String> {
    let mut options: Vec<String> = vec![];
    for _ in 1..args.len(){
        if args[1].as_bytes()[0] == '-' as u8{
            break;
        }
        options.push(args[1].clone());
        args.remove(1);
    }
    args.remove(0);
    return options;
}

fn password_check(hash: Vec<String>, mut password: Vec<u8>) -> Vec<u8>{
    if password.len() == 0 {
        print!("please enter your password: ");
        io::stdout().flush().unwrap();
        password = read_password().unwrap().into();
    }
    for i in hash{
        if sha256::digest(&password).to_string() == i{
            return password;
        }
    }
    'out: loop {
        print!("Hash of your password was not found, do you wish to autowrite it? (y/n) ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("error: unable to read user input");
        match input.trim().to_lowercase().as_str() {
            "y" => {
                let hashed = sha256::digest(&password).to_string();
                let mut path = home::home_dir().unwrap().join(".config/ripm/ripm.conf");
                let mut conf_file = match File::options().write(true).read(true).open(&path) {
                    Ok(f) => f,
                    Err(e) => { println!("Could not open {}, error: {} \n hash of password: {}", path.display(), e, hashed); return password; },
                };
                let mut content = vec![];
                match conf_file.read_to_end(&mut content) {
                    Err(e) => println!("Could not read {}, error {} \n hash of password {}", path.display(), e, hashed),
                    Ok(_) => {
                        let tmp = String::from_utf8_lossy(&content);
                        let lines: Vec<&str> = tmp.split("\n").collect();
                        for i in 0..lines.len() {
                            if lines[i].len() == 0 {
                                continue;
                            }
                            let parts: Vec<&str> = lines[i].split(":").collect();
                            if parts.len() % 2 == 1 {
                                println!("invalid config file");
                                break;
                            }
                            match parts[0].trim(){
                                "password" => if parts[1].contains(".hash") && Path::new(&parts[1].trim().to_string()).exists(){
                                        path = home::home_dir().unwrap().join(".config/ripm").join(parts[1].trim());
                                        let mut file = match File::options().write(true).read(true).open(&path) {
                                            Ok(f) => f,
                                            Err(e) => { println!("Could not open {}, error: {} \n hash of password: {}", path.display(), e, hashed); break;},
                                        };
                                        let mut hash_content = vec![];
                                        match file.read_to_end(&mut hash_content) {
                                            Err(e) => {println!("Could not read {}, error {} \n hash of password {}", path.display(), e, hashed); break;},
                                            _ => ()
                                        }
                                        let mut to_write = String::new();
                                        if hash_content.len() == 0 || hash_content[hash_content.len()-1] == 32 {
                                            to_write = hashed.clone();
                                        } else {
                                            to_write = ("\n").to_owned() + &hashed
                                        }                            
                                        match file.write_all(to_write.as_bytes()) {
                                            Err(e) => println!("Could not write to {}, error: {} \n hash of password: {}", path.display(), e, hashed),
                                            _ => break 'out,
                                        }
                                },
                                _ => (),
                            }
                        }
                        let mut to_write = String::new();
                        if content.len() == 0 || content[content.len()-1] == 32 {
                            to_write = "password: ".to_owned() + &hashed;
                        } else {
                            to_write = ("\n password: ").to_owned() + &hashed
                        }
                        match conf_file.write_all(to_write.as_bytes()) {
                            Err(e) =>  println!("Could not write to {}, error: {} \n hash of password: {}", path.display(), e, hashed),
                            _ => break 'out,

                        }
                    }
                }
                break 'out;
            },
            "n" => break 'out,
            _ => (),
        }

    }
    password
}

fn main() {
    if env::var_os("RUST_BACKTRACE").is_none() {
        env::set_var("RUST_BACKTRACE", "1");
    }
    let (mut length, passwd_hash, shortcuts) = check_config();
    let mut args: Vec<String> = env::args().collect();
    let mut paths: Vec<String> = Vec::new();
    let mut hash: Vec<u8> = vec![];
    let mut operation: Mode = Mode::UNSET;
    let mut type_e = Type::NEW;
    args.remove(0);
    if args.len() < 2{
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
            _ => {println!("{} is unknown argument", args[0]); help(); return;},
        }
    }
    if hash.len() == 0{
         hash = password_check(passwd_hash, hash.clone());
    }
    let mut passwd_vec = Vec::new();
    for i in &paths {
        passwd_vec.push(create_passwd_struct(&Path::new(&i), length, hash.clone(), type_e.clone(), operation.clone()));
    }
    
    for mut i in passwd_vec {
    /*match operation {
        Mode::READ => {
            for i in 0..paths.len() {
                match get_saved_password(paths[i].clone(), length, hash.clone(), type_e.clone()) {
                    Some(c) => println!("{}: {}", paths[i], c),
                    None => println!("Could not read {}", paths[i]),
                }
                
            }
        },
        Mode::WRITE => {
            print!("please enter your desired password to save: ");
            io::stdout().flush().unwrap();
            let desired = read_password().unwrap();
            for i in 0..paths.len() {
                match write_password(paths[i].clone(), hash.clone(), desired.clone(), type_e.clone()) {
                    WriteRet::SUCSSES => println!("{} was sucssesfuly writen", paths[i]),
                    WriteRet::FAIL => println!("{} was not sucssesfull", paths[i]),
                    WriteRet::ERROR => println!("Was not able to write to {}", paths[i]),
                    WriteRet::UNKNOWN => println!("{} can not be sure if is correctly saved", paths[i]),
                }
            }
        },
        _ => {println!("please enter valid mode"); help()},
    }*/
        i.get_done();
    }
}
