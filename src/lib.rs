use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use hyper::{Body, Request, Response, Server};
use hyper::server::accept::from_stream;
use hyper::service::{make_service_fn, service_fn};
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

        let accept = from_stream(async_stream::stream! {
            yield listener.accept().await.map(|(s, _)| s);
        });

        Server::builder(accept)
            .serve(make_service_fn(move |_| {
                tracing::info!("Reading connection");
                async move {
                    Ok::<_, Infallible>(service_fn(move |_: Request<Body>| {
                        tracing::info!("Got message!");
                        async move {
                            Ok::<_, Infallible>(Response::new(Body::from("Hello World!")))
                        }
                    }))
                }
            }))
            .await
            .unwrap();

        Ok(())
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