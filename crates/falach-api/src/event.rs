use std::sync::mpsc;

pub trait EventSink<T: Send>: Send + 'static {
    fn send(&self, event: T);
}

pub struct MpscEventSink<T> {
    tx: mpsc::Sender<T>,
}

impl<T: Send> MpscEventSink<T> {
    pub fn new(tx: mpsc::Sender<T>) -> Self {
        Self { tx }
    }
}

impl<T: Send + 'static> EventSink<T> for MpscEventSink<T> {
    fn send(&self, event: T) {
        let _ = self.tx.send(event);
    }
}
