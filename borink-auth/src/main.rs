use std::{sync::{atomic::AtomicU64, mpsc::{Receiver, SyncSender}, Arc}, time::Instant};

struct Database {}

fn loop_increment(receiver: Receiver<SyncSender<u64>>, max: u64) {
    let mut val = 0;
    loop {
        if val >= max {
            break;
        }
        let s = receiver.recv().unwrap();
        s.send(val).unwrap();
        val += 1;
        //println!("sent: {val}")
    }
}

// fn main() {
//     use std::sync::mpsc::sync_channel;
//     use std::thread;

//     let (sender, receiver) = sync_channel(32);

//     // this returns immediately
//     //sender.send(1).unwrap();

//     let iters = 100;
//     let threads = 1;

//     thread::spawn(move || {
//         loop_increment(receiver, iters*threads)
//     });

//     thread::scope(|s| {
//         let mut time = 0;
//         let mut handles = Vec::new();
//         for _ in 0..threads {
//             let sender = sender.clone();
//             let h = s.spawn(move || {
//                 let mut t_time = 0;
//                 let (c_sender, c_receiver) = sync_channel(1);
    
//                 for _ in 0..iters {
//                     let d = Instant::now();
//                     sender.send(c_sender.clone()).unwrap();
//                     let rec = c_receiver.recv().unwrap();
//                     t_time += d.elapsed().as_nanos();
//                     //println!("received: {rec}");
//                 }

//                 t_time
//             });
//             handles.push(h);
//         }
//         for h in handles {
//             time += h.join().unwrap();
//         }

//         let per_op = (time as f64)/(((iters*threads) * 1_000) as f64);
//         println!("time per send/recv: {per_op} us.")
//     });
// }

fn main() {
    use std::sync::mpsc::sync_channel;
    use std::thread;

    let val = Arc::new(AtomicU64::new(0));

    //let (sender, receiver) = sync_channel(32);

    // this returns immediately
    //sender.send(1).unwrap();

    let iters = 100;
    let threads = 32;

    // thread::spawn(move || {
    //     loop_increment(receiver, iters*threads)
    // });

    thread::scope(|s| {
        let mut time = 0;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let val = val.clone();
            let h = s.spawn(move || {
                let mut t_time = 0;
    
                for _ in 0..iters {
                    let d = Instant::now();
                    let rec = val.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    t_time += d.elapsed().as_nanos();
                    //println!("received: {rec}");
                }

                t_time
            });
            handles.push(h);
        }
        for h in handles {
            time += h.join().unwrap();
        }

        let per_op = (time as f64)/(((iters*threads) * 1_000) as f64);
        println!("time per send/recv: {per_op} us.")
    });
}

// Experiment result: for fetching, < 0.1 us (~0.05) for using an atomic variable, while 8-20 us for when using message passing