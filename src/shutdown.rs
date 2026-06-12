use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

/// Cooperative shutdown triggered by Ctrl+C.
#[derive(Clone)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self { tx, rx }
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }

    pub fn is_triggered(&self) -> bool {
        *self.rx.borrow()
    }

    fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// Listen for Ctrl+C and trigger shutdown on first press.
    pub fn spawn_ctrlc_handler(&self) {
        let shutdown = self.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Ctrl+C received — stopping...");
                shutdown.trigger();
            }
        });
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait until shutdown has been triggered.
pub async fn wait(mut rx: watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    let _ = rx.changed().await;
}

/// Read from `reader`, returning early when shutdown is triggered.
pub async fn read_cancellable<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<usize> {
    if *shutdown.borrow() {
        return Err(cancelled_io_error());
    }

    tokio::select! {
        biased;
        _ = wait(shutdown.clone()) => Err(cancelled_io_error()),
        result = reader.read(buf) => result,
    }
}

/// Write to `writer`, returning early when shutdown is triggered.
pub async fn write_cancellable<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    buf: &[u8],
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    if *shutdown.borrow() {
        return Err(cancelled_io_error());
    }

    tokio::select! {
        biased;
        _ = wait(shutdown.clone()) => Err(cancelled_io_error()),
        result = writer.write_all(buf) => result,
    }
}

fn cancelled_io_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Interrupted, "operation cancelled")
}

pub fn is_cancelled(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::Interrupted)
        || err.to_string().contains("cancelled")
}
