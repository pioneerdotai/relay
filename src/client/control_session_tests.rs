//! Deterministic control-session tests using the production parser and select loop.
use super::*;
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

#[derive(Debug)]
struct ObservedStream {
    stream: DuplexStream,
    bytes_read: usize,
    waiting: mpsc::UnboundedSender<usize>,
}

impl io::AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        self.bytes_read += buf.filled().len() - before;
        if result.is_pending() {
            // Confirms that read_exact consumed bytes and polled for the remainder.
            let _ = self.waiting.send(self.bytes_read);
        }
        result
    }
}

impl io::AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn stream() -> (ObservedStream, DuplexStream, mpsc::UnboundedReceiver<usize>) {
    let (stream, peer) = io::duplex(64);
    let (waiting, rx) = mpsc::unbounded_channel();
    (
        ObservedStream {
            stream,
            bytes_read: 0,
            waiting,
        },
        peer,
        rx,
    )
}

async fn waiting_after(rx: &mut mpsc::UnboundedReceiver<usize>, bytes: usize) {
    loop {
        let consumed = rx
            .recv()
            .await
            .expect("reader ended before reaching barrier");
        assert!(consumed <= bytes, "reader passed the requested barrier");
        if consumed == bytes {
            return;
        }
    }
}

#[tokio::test]
async fn partial_command_survives_data_task_completion() {
    let (mut reader, mut peer, mut waiting) = stream();
    let (finish, finished) = oneshot::channel();
    let mut data_tasks = JoinSet::new();
    data_tasks.spawn(async move {
        let _ = finished.await;
    });
    let task = tokio::spawn(async move {
        let heartbeat = time::sleep(Duration::ZERO);
        tokio::pin!(heartbeat);
        let first = next_control_command(
            &mut reader,
            &mut data_tasks,
            heartbeat.as_mut(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        let second = next_control_command(
            &mut reader,
            &mut data_tasks,
            heartbeat.as_mut(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert!(data_tasks.is_empty(), "data completion was not reaped");
        (first, second)
    });
    waiting_after(&mut waiting, 0).await;
    let first = bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap();
    let second = bincode::serialize(&ControlChannelCmd::CreateDataChannel).unwrap();
    peer.write_all(&first[..2]).await.unwrap();
    waiting_after(&mut waiting, 2).await;
    while waiting.try_recv().is_ok() {}
    finish.send(()).unwrap();
    // With no new bytes, a second pending poll happens only after reaping the task.
    waiting_after(&mut waiting, 2).await;
    peer.write_all(&first[2..]).await.unwrap();
    peer.write_all(&second).await.unwrap();
    let (first, second) = time::timeout(Duration::from_secs(2), task)
        .await
        .expect("partial command lost or session stalled")
        .unwrap();
    assert!(matches!(first, ControlChannelCmd::HeartBeat));
    assert!(matches!(second, ControlChannelCmd::CreateDataChannel));
}

#[tokio::test(start_paused = true)]
async fn data_completion_does_not_extend_heartbeat_deadline() {
    let (mut reader, _peer, mut waiting) = stream();
    let (finish, finished) = oneshot::channel();
    let mut data_tasks = JoinSet::new();
    data_tasks.spawn(async move {
        let _ = finished.await;
    });
    let task = tokio::spawn(async move {
        let start = Instant::now();
        let interval = Duration::from_secs(40);
        let heartbeat = time::sleep(interval);
        tokio::pin!(heartbeat);
        let result =
            next_control_command(&mut reader, &mut data_tasks, heartbeat.as_mut(), interval).await;
        (result, start.elapsed())
    });
    waiting_after(&mut waiting, 0).await;
    time::advance(Duration::from_secs(35)).await;
    while waiting.try_recv().is_ok() {}
    finish.send(()).unwrap();
    waiting_after(&mut waiting, 0).await;
    assert!(!task.is_finished());
    time::advance(Duration::from_secs(4)).await;
    assert!(!task.is_finished());
    time::advance(Duration::from_secs(1)).await;
    let (result, elapsed) = task.await.unwrap();
    assert_eq!(result.unwrap_err().to_string(), "Heartbeat timed out");
    assert_eq!(elapsed, Duration::from_secs(40));
}

#[tokio::test(start_paused = true)]
async fn every_valid_control_command_refreshes_the_deadline() {
    for command in [
        ControlChannelCmd::HeartBeat,
        ControlChannelCmd::CreateDataChannel,
    ] {
        let (mut reader, mut peer, mut waiting) = stream();
        let (received, receipt) = oneshot::channel();
        let task = tokio::spawn(async move {
            let start = Instant::now();
            let interval = Duration::from_secs(40);
            let heartbeat = time::sleep(interval);
            tokio::pin!(heartbeat);
            let mut data_tasks = JoinSet::new();
            let command =
                next_control_command(&mut reader, &mut data_tasks, heartbeat.as_mut(), interval)
                    .await
                    .unwrap();
            received.send(command).unwrap();
            let result =
                next_control_command(&mut reader, &mut data_tasks, heartbeat.as_mut(), interval)
                    .await;
            (result, start.elapsed())
        });
        waiting_after(&mut waiting, 0).await;
        time::advance(Duration::from_secs(35)).await;
        peer.write_all(&bincode::serialize(&command).unwrap())
            .await
            .unwrap();
        let parsed = receipt.await.unwrap();
        assert_eq!(
            bincode::serialize(&parsed).unwrap(),
            bincode::serialize(&command).unwrap()
        );
        waiting_after(&mut waiting, 4).await;
        time::advance(Duration::from_secs(5)).await;
        assert!(!task.is_finished(), "old session deadline was not reset");
        time::advance(Duration::from_secs(34)).await;
        assert!(!task.is_finished());
        time::advance(Duration::from_secs(1)).await;
        let (result, elapsed) = task.await.unwrap();
        assert_eq!(result.unwrap_err().to_string(), "Heartbeat timed out");
        assert_eq!(elapsed, Duration::from_secs(75));
    }
}

#[tokio::test(start_paused = true)]
async fn zero_heartbeat_timeout_remains_disabled_after_data_completion() {
    let (mut reader, mut peer, mut waiting) = stream();
    let (finish, finished) = oneshot::channel();
    let mut data_tasks = JoinSet::new();
    data_tasks.spawn(async move {
        let _ = finished.await;
    });
    let task = tokio::spawn(async move {
        let heartbeat = time::sleep(Duration::ZERO);
        tokio::pin!(heartbeat);
        next_control_command(
            &mut reader,
            &mut data_tasks,
            heartbeat.as_mut(),
            Duration::ZERO,
        )
        .await
        .unwrap()
    });
    waiting_after(&mut waiting, 0).await;
    time::advance(Duration::from_secs(4000)).await;
    while waiting.try_recv().is_ok() {}
    finish.send(()).unwrap();
    waiting_after(&mut waiting, 0).await;
    assert!(!task.is_finished());
    peer.write_all(&bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap())
        .await
        .unwrap();
    assert!(matches!(task.await.unwrap(), ControlChannelCmd::HeartBeat));
}
