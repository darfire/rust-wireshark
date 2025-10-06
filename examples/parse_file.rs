extern crate rust_wireshark;

use clap::Parser;
use rust_wireshark::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args{
  #[arg(short, long)]
  file: String,
}

fn main() {
  let args = Args::parse();
  
  wtap_init();
  
  if !epan_init() {
    panic!("Could not initialize EPAN!");
  }
  
  let mut wtap = Wtap::new(args.file).unwrap();
  
  let mut session = Session::new();
  
  loop {
    let mut rec = wtap.read();
    
    match rec {
      Ok(mut rec) => {
        println!("Got record!");
    
        let prec = session.dissect(&mut rec);
        
        println!("Dissected {:?}", prec);
      },
      Err(e) => {
              println!("Got error: {:?}", e);
              break;
            }
    }
  }
}