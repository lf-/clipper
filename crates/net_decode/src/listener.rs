use crate::chomp::IPTarget;

/// Type which receives some kind of messages from a layer up the stack.
///
/// The `target` is the same in both directions so a flow can be tracked.
pub trait Listener<MessageType> {
    fn on_data(&mut self, target: IPTarget, to_client: bool, data: MessageType);
}

#[derive(Debug, Default)]
pub struct NoOpListener {}

impl Listener<Vec<u8>> for NoOpListener {
    fn on_data(&mut self, _target: IPTarget, _to_client: bool, _data: Vec<u8>) {
        // do nothing! :D
    }
}

#[derive(Debug, Default)]
pub struct HexDumpListener {}

impl Listener<Vec<u8>> for HexDumpListener {
    fn on_data(&mut self, target: IPTarget, to_client: bool, data: Vec<u8>) {
        tracing::info!(
            "tcp {target:?} to_client={to_client}:\n{}",
            hexdump::HexDumper::new(&data)
        );
    }
}
