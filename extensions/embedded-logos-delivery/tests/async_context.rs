use embedded_logos_delivery::{DeliveryError, EmbeddedLogosDelivery, P2pConfig};

#[tokio::test]
async fn start_inside_a_runtime_is_an_error_not_an_abort() {
    let err = EmbeddedLogosDelivery::start(P2pConfig::default())
        .expect_err("start must refuse to run on a runtime thread");
    assert!(matches!(err, DeliveryError::Startup(_)));
}
