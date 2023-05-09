use std::error::Error;
use std::fs::File;
use std::fs::{self, DirEntry};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{sleep, spawn};
use std::time::Duration;
use threadpool::ThreadPool;

enum Message {
    Entry(String),
    Shutdown,
}

fn read_into_chan(path: DirEntry, tx: Sender<Message>) {
    println!("Name: {}", path.path().display());
    // File hosts must exist in current path before this produces output
    if let Ok(lines) = read_lines(path.path()) {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            if let Ok(l) = line {
                tx.send(Message::Entry(l)).unwrap();
            }
            sleep(Duration::from_millis(10));
        }
    }
}

fn writer<W: Write>(mut out: W, rx: Receiver<Message>) {
    for msg in rx {
        match msg {
            Message::Entry(r) => {
                match out.write(r.as_bytes()) {
                    Ok(_) => continue,
                    Err(e) => println!("failed to write {r}: {e}"),
                };
            }
            Message::Shutdown => return,
        }
    }
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[test]
fn test_threading() -> Result<(), Box<dyn Error>> {
    // Count the number of files and launch that many threads.
    let mut paths = fs::read_dir("test_text/").unwrap();
    let pool = ThreadPool::new(paths.count());

    let (tx, rx) = channel();

    // refresh the path list and launch jobs
    paths = fs::read_dir("test_text/").unwrap();
    for path in paths {
        match path {
            Ok(p) => {
                let tx = tx.clone();
                pool.execute(move || read_into_chan(p, tx));
            }
            Err(e) => panic!("failed getting dir: {e:}"),
        }
    }

    let writer_thread = spawn(move || writer(io::stdout(), rx));

    pool.join(); // all threads must complete or the process will hang

    tx.send(Message::Shutdown)?;
    writer_thread.join().unwrap();

    // if using a writer that requires close, do so here.

    Ok(())
}
