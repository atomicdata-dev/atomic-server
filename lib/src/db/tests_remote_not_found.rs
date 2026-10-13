use super::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod remote_not_found_tests {
    use super::*;
    use crate::Storelike;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves `status` to every request and counts them.
    fn serve(status: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
            }
        });
        (url, hits)
    }

    #[tokio::test]
    async fn a_404_property_is_fetched_once() {
        let db = Db::init_temp("remote_not_found_404").await.unwrap();
        let (server, hits) = serve("404 Not Found");
        let property = format!("{server}/properties/demo/speaker");

        for _ in 0..3 {
            assert!(db.get_property(&property).await.is_err());
        }

        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_404_is_fetched_again() {
        let db = Db::init_temp("remote_not_found_expiry").await.unwrap();
        let (server, hits) = serve("404 Not Found");
        let property = format!("{server}/properties/demo/speaker");

        assert!(db.get_property(&property).await.is_err());
        assert!(db.get_property(&property).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // Backdate the entry: it expires now.
        db.remote_not_found
            .lock()
            .unwrap()
            .insert(property.clone(), web_time::Instant::now());

        assert!(db.get_property(&property).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_server_error_is_retried() {
        let db = Db::init_temp("remote_not_found_500").await.unwrap();
        let (server, hits) = serve("500 Internal Server Error");
        let property = format!("{server}/properties/demo/speaker");

        for _ in 0..2 {
            assert!(db.get_property(&property).await.is_err());
        }

        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}
