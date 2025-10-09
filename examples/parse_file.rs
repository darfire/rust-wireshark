extern crate rust_wireshark;

use clap::Parser;
use rust_wireshark::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
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

        let root_node = prec.get_root_node().unwrap();

        println!(
          "ip.src: {:?}",
          root_node.find_hierarchical("ip.src".to_string())
        );

        let frames = prec.get_frames().unwrap();

        println!("Got {} frames", frames.len());

        for (idx, frame) in frames.iter().enumerate() {
          println!("Frame #{}: {}", idx, frame);

          frame.iter_depth_first().for_each(|node| {
            println!(
              "{}{}: {}",
              " ".repeat(node.get_depth() as usize),
              node,
              node.get_fvalue().map_or("NO VALUE".to_string(), |fv| {
                format!(
                  "{}({}) / {}",
                  fv.to_string(),
                  fv.length()
                    .map_or("NO_LENGTH".to_string(), |l| l.to_string()),
                  fv.get_ftype_name(),
                )
              })
            );
          });
        }
      }
      Err(e) => {
        println!("Got error: {:?}", e);
        break;
      }
    }
  }
}
