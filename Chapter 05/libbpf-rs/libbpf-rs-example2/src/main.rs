use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian}; // Import byteorder crate
use libbpf_rs::{Map, MapFlags};


mod kprobe{
    include!(concat!(env!("OUT_DIR"), "/kprobe.skel.rs"));
}

use kprobe::*;

fn main() -> Result<()> {
    let mut skel_builder = KprobeSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;


    sleep(Duration::new(30, 0));


    // Process BPF map entries after exiting the loop
    // Access the map (using the map name from your BPF program)
    let maps = skel.maps(); // Store the maps object
    let map = maps.openat_count(); // Now we have a reference to the specific map
    let mut key_iter = map.keys();
    while let Some(key) = key_iter.next() {
        // Ensure the key is 4 bytes (a u32), and convert it to u32
        // Lookup the value (count) for this pid
        let pid: u32 = LittleEndian::read_u32(&key);
        // let pid: u32 = key.as_slice().try_into().expect("Key is not 4 bytes");
        match map.lookup(&key, MapFlags::empty()) {
            Ok(Some(value)) => {
                let count: u64 = LittleEndian::read_u64(&value);
                println!("PID: {}, Count: {}", pid, count);
            }
            Ok(None) => {
                println!("PID not found: {}", pid);
            }
            Err(e) => {
                eprintln!("Error looking up PID {}: {}", pid, e);
            }
        }
    }
    Ok(())
}