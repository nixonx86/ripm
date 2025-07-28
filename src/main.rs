use core::panic;
use std::fs::File;
use std::io::prelude::*;
use std::{env, u8, usize};

fn open_file(path: String) -> std::io::Result<Vec<u8>>{
    let mut file = File::open(path)?;
    let mut content: Vec<u8> = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
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
    return ret_array;
}

fn get_password(path: String, length: usize, hash: Vec<u8>) -> String{
   let content = open_file(path).unwrap();
   let byte_array = get_chars(content, length, hash);
   let s = String::from_utf8_lossy(&byte_array);
   return s.to_string();
}

fn get_length(arg: String) -> usize{
    let length_result: std::result::Result<usize, std::num::ParseIntError> = arg.trim().parse();
    match length_result {
        Ok(len) => return len,
        _ => panic!("not valid length"),
    };
}

fn remove_args(mut args: Vec<String>) -> Vec<String> {
    for _ in 0..2 {
        args.remove(0);
    }
    args
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let mut length: usize = 8;
    let mut hash: Vec<u8> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    args.remove(0);
    if args.len() < 4{
        panic!("not enough argument")
    }
    loop {
        if args.len() < 2 {
            panic!("not enough arguments");
        }
        match args[0].as_str() {
            "-l" => length = get_length(args[1].clone()),
            "--length" => length = get_length(args[1].clone()),
            "-H" => hash = args[1].clone().as_bytes().to_vec(),
            "--hash" => hash = args[1].clone().as_bytes().to_vec(),
            "-p" => {paths = args.clone(); paths.remove(0);},
            "--path" => {paths = args.clone(); paths.remove(0);},
            _ => panic!("{} is unknown argument", args[0]),
        }
        if hash.len() > 0 && paths.len() > 0{
            break;
        }
        args = remove_args(args);
    }
    for i in 0..paths.len(){
        let passwd = get_password(paths[i].clone(), length, hash.clone());
        println!("{}: {}", paths[i], passwd); 
    }
}
