use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use hyper::{Body, Request, Response, Server};
use hyper::server::accept::from_stream;
use hyper::server::conn::Http;
use hyper::service::{make_service_fn, service_fn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use turmoil::{Builder, lookup, net};

const PORT: u16 = 9999;

#[test]
fn network_partition_after_init() -> turmoil::Result {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "trace");
    }

    tracing_subscriber::fmt::init();

    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let listener = net::TcpListener::bind(get_listen_addr()).await.unwrap();

        loop {
            let (tcp_stream, _) = listener.accept().await?;

            tokio::task::spawn(async move {
                let handler = service_fn(move |_: Request<Body>| {
                    tracing::info!("Got message!");
                    async move {
                        Ok::<_, Infallible>(Response::new(Body::from("Hello World!")))
                    }
                });

                if let Err(http_err) = Http::new()
                        .serve_connection(tcp_stream, handler)
                        .await
                {
                    eprintln!("Error while serving HTTP connection: {}", http_err);
                }
            });
        }
    });

    sim.client("client", async {
        let io = net::TcpStream::connect(addr("server")).await.unwrap();

        let (mut sender, connection) = hyper::client::conn::Builder::new()
            .handshake::<_, Body>(io)
            .await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in connection: {}", e);
            }
        });

        let req = Request::new(Body::empty());

        tracing::info!("Sending!");
        sender.send_request(req).await.unwrap();
        tracing::info!("Complete!");

        Ok(())
    });

    sim.run()
}

#[test]
fn test_theory() -> turmoil::Result {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "trace");
    }

    tracing_subscriber::fmt::init();

    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let listener = net::TcpListener::bind(get_listen_addr()).await.unwrap();

        let (mut stream, addr) = listener.accept().await.unwrap();
        tracing::info!("Got stream: {}", addr);

        let mut data = Vec::new();
        let n = stream.read_to_end(&mut data).await.unwrap();

        tracing::info!("Message: {}", String::from_utf8_lossy(&data[..n]));

        stream.write_all(&data[..n]).await.unwrap();

        Ok(())
    });

    sim.client("client", async {
        let io = net::TcpStream::connect(addr("server")).await.unwrap();
        let (mut rx, mut tx) = io.into_split();

        tx.write_all(b"GET / HTTP/1.1").await.unwrap();
        drop(tx);

        let mut data = Vec::new();
        let n = rx.read_to_end(&mut data).await.unwrap();

        tracing::info!("Response: {}", String::from_utf8_lossy(&data[..n]));

        Ok(())
    });

    sim.run()
}


fn get_listen_addr() -> SocketAddr {
    (IpAddr::from(Ipv4Addr::UNSPECIFIED), PORT).into()
}

fn addr(name: &str) -> SocketAddr {
    (lookup(name), PORT).into()
}


#[tokio::test]
async fn network_partition_after_init_ok() -> anyhow::Result<()> {
    println!("{}", String::from_utf8_lossy(&[0x47, 0x45, 0x54, 0x20, 0x2F, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0xD, 0xA, 0xD, 0xA]));

    let addr = "127.0.0.1:9990".parse::<SocketAddr>()?;
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        let accept = from_stream(async_stream::stream! {
            yield listener.accept().await.map(|(s, _)| s);
        });

        Server::builder(accept)
            .serve(make_service_fn(move |_| {
                println!("Reading connection");
                async move {
                    Ok::<_, Infallible>(service_fn(move |_: Request<Body>| {
                        println!("Got message!");
                        async move {
                            Ok::<_, Infallible>(Response::new(Body::from("Hello World!")))
                        }
                    }))
                }
            }))
            .await
            .unwrap();

        Ok::<_, anyhow::Error>(())
    });

    let io = tokio::net::TcpStream::connect(addr).await.unwrap();

    let (mut sender, connection) = hyper::client::conn::Builder::new()
        .handshake(io)
        .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Error in connection: {}", e);
        }
    });

    let req = Request::new(Body::empty());

    println!("Sending!");
    sender.send_request(req).await.unwrap();
    println!("Complete!");

    Ok(())
}