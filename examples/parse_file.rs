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

  let session = Session::new();
  
  let dfilter = DFilter::new("udp.port == 53".to_string()).unwrap();

  loop {
    let rec = wtap.read();

    match rec {
      Ok(mut rec) => {
        println!("Got record!");
        
        let mut prec = session.new_prec(&mut rec);
        
        prec.prime_with_dfilter(&dfilter);

        prec.dissect();
        
        let root_node = prec.get_root_node().unwrap();

        if dfilter.apply_rec(&prec) {
          println!("Record MATCHES {}", dfilter);
        } else {
          println!("Record does NOT MATCH {}", dfilter);
        }

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
