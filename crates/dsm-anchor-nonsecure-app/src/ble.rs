// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Bluetooth Low Energy host link: the anchor's GATT service on the radio's controller. A
//! wallet writes a request frame to the `request` characteristic in chunks of up to ATT_MTU − 3
//! bytes and takes the answer frame back as notifications of the `answer` characteristic, the
//! same LE32-length-prefixed frames as over USB. One connection at a time; a connection's frame
//! waits its turn at the gateway behind a frame on USB, and the other way round.
//!
//! On the air: the service's UUID and the name, and a static random address drawn from the Secure
//! side's entropy at boot. Nothing of the anchor's identity is advertised (A27).

use embassy_futures::join::join;
use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::pipe::Pipe;
use embassy_time::Timer;
use heapless::Vec;
use static_cell::StaticCell;
use trouble_host::prelude::*;

use crate::frames::{FrameServer, HostGone, Link};
use crate::radio::{at, stage};

const CONNECTIONS_MAX: usize = 1;
/// The signalling channel and the attribute channel.
const L2CAP_CHANNELS_MAX: usize = 2;
/// The largest chunk either characteristic carries: ATT_MTU 512 less the 3-byte ATT header.
pub const CHUNK: usize = 509;
/// Request bytes taken from the air and not yet read into a frame.
const INBOUND: usize = 2048;

/// The DSM anchor service and its two characteristics.
pub const SERVICE_UUID: [u8; 16] = [
    0xd5, 0xa1, 0x00, 0x00, 0x7d, 0x51, 0x4d, 0x00, 0xa0, 0x4c, 0x00, 0x00, 0x00, 0x00, 0xd5, 0xa1,
];

#[gatt_server]
struct Server {
    anchor: AnchorService,
}

#[gatt_service(uuid = "d5a10000-7d51-4d00-a04c-00000000d5a1")]
struct AnchorService {
    /// A request frame, in chunks, in the order sent.
    #[characteristic(uuid = "d5a10001-7d51-4d00-a04c-00000000d5a1", write, write_without_response, value = Vec::new())]
    request: Vec<u8, CHUNK>,
    /// The answer frame, in chunks, in the order sent.
    #[characteristic(uuid = "d5a10002-7d51-4d00-a04c-00000000d5a1", notify, value = Vec::new())]
    answer: Vec<u8, CHUNK>,
}

/// Serve the anchor over the radio, forever: advertise, take one connection, serve its frames until
/// it drops, advertise again. `address` is the static random address this boot answers to.
pub async fn run(bt: cyw43::bluetooth::BtDriver<'static>, address: [u8; 6]) {
    let controller: ExternalController<_, 10> = ExternalController::new(bt);
    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack =
        trouble_host::new(controller, &mut resources).set_random_address(Address::random(address));
    let Host {
        mut peripheral,
        runner,
        ..
    } = stack.build();
    let Ok(server) = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "DSM Anchor",
        appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
    })) else {
        // The attribute table did not build: a size mistake in this image, not a condition of the
        // board. Without the service there is nothing to serve on the air.
        at(stage::HOST_NOT_BUILT);
        return;
    };
    at(stage::HOST_BUILT);
    static FRAMES: StaticCell<FrameServer> = StaticCell::new();
    let frames = FRAMES.init(FrameServer::new());

    join(host_task(runner), async {
        loop {
            at(stage::ADVERTISING);
            match advertise(&mut peripheral, &server).await {
                Ok(conn) => {
                    at(stage::CONNECTED);
                    serve_connection(&server, &conn, frames).await
                }
                // The controller refused to advertise or accept: let it settle and offer again.
                Err(_controller) => {
                    at(stage::ADVERTISE_REFUSED);
                    Timer::after_millis(500).await
                }
            }
        }
    })
    .await;
}

/// The host's own work: the controller's events, the connections, the attribute protocol.
async fn host_task<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
    loop {
        match runner.run().await {
            Ok(()) => {}
            // The host stack reported a fault; it is restarted with the same controller.
            Err(_fault) => Timer::after_millis(100).await,
        }
    }
}

async fn advertise<'v, 's, C: Controller>(
    peripheral: &mut Peripheral<'v, C, DefaultPacketPool>,
    server: &'s Server<'v>,
) -> Result<GattConnection<'v, 's, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut adv = [0u8; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids128(&[SERVICE_UUID]),
            AdStructure::ShortenedLocalName(b"DSM Anchor"),
        ],
        &mut adv[..],
    )?;
    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv[..len],
                scan_data: &[],
            },
        )
        .await?;
    let conn = advertiser.accept().await?.with_attribute_server(server)?;
    Ok(conn)
}

/// One connection: its GATT writes feed the inbound pipe; the frame server reads frames from the
/// pipe and answers with notifications. Both end when the connection does.
async fn serve_connection(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    frames: &mut FrameServer,
) {
    let inbound: Pipe<CriticalSectionRawMutex, INBOUND> = Pipe::new();
    let request_handle = server.anchor.request.handle;
    let events = async {
        loop {
            match conn.next().await {
                GattConnectionEvent::Disconnected { .. } => break,
                GattConnectionEvent::Gatt { event } => {
                    if let GattEvent::Write(write) = &event {
                        if write.handle() == request_handle {
                            inbound.write_all(write.data()).await;
                        }
                    }
                    match event.accept() {
                        Ok(reply) => reply.send().await,
                        // The connection cannot be answered: it is as good as gone.
                        Err(_unanswerable) => break,
                    }
                }
                _ => {}
            }
        }
    };
    let mut link = BleLink {
        inbound: &inbound,
        conn,
        answer: &server.anchor.answer,
        chunk: usize::from(conn.raw().att_mtu().saturating_sub(3)).clamp(1, CHUNK),
    };
    select(events, frames.serve(&mut link)).await;
}

struct BleLink<'a, 'v, 's> {
    inbound: &'a Pipe<CriticalSectionRawMutex, INBOUND>,
    conn: &'a GattConnection<'v, 's, DefaultPacketPool>,
    answer: &'a Characteristic<Vec<u8, CHUNK>>,
    /// The most an answer notification carries on this connection.
    chunk: usize,
}

impl Link for BleLink<'_, '_, '_> {
    async fn read(&mut self, into: &mut [u8]) -> Result<usize, HostGone> {
        // The pipe answers with at least one byte; the connection's end cancels this read.
        Ok(self.inbound.read(into).await)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), HostGone> {
        for part in bytes.chunks(self.chunk) {
            let Ok(value) = Vec::<u8, CHUNK>::from_slice(part) else {
                return Err(HostGone);
            };
            if let Err(_gone) = self.answer.notify(self.conn, &value).await {
                return Err(HostGone);
            }
        }
        Ok(())
    }
}
