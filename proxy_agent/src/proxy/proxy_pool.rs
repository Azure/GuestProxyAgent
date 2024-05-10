// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

use crate::common::logger;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct ProxyPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

impl ProxyPool {
    pub fn new(size: usize) -> Self {
        assert!(size > 0);

        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)))
        }

        ProxyPool {
            workers: workers,
            sender: Some(sender),
        }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        _ = self.sender.as_ref().unwrap().send(job);
    }
}

impl Drop for ProxyPool {
    fn drop(&mut self) {
        drop(self.sender.take());

        for worker in &mut self.workers {
            logger::write(format!("Shutting down worker {}", worker.id));
            if let Some(thread) = worker.thread.take() {
                _ = thread.join();
            }
        }
    }
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> Self {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv();

            match message {
                Ok(job) => {
                    job();
                }
                Err(e) => {
                    logger::write_warning(format!(
                        "Worker {id} disconnected with error {e}; shutting down."
                    ));
                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}
