use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;

mod kprobe{
	include!(concat!(env!("OUT_DIR"), "/kprobe.skel.rs"));
}

use kprobe::*;

fn main() -> Result<()> {

	let mut skel_builder = KprobeSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
	let mut skel = open_skel.load()?;
	skel.attach()?;


	// Block until SIGINT
	loop {
    	    sleep(Duration::new(1, 0));
	}
}