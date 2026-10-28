// Linkable entry points over liblogosdelivery's typed helpers.
//
// The library's call surface is the `logosdelivery_ctx_*` helpers in its
// generated header: `static inline` functions that CBOR-encode each request,
// make the raw call and decode the reply. Being inline, they have no symbols
// Rust can link against, so each one used here is re-exported under an
// `lcshim_` name. Every reply callback fires exactly once with the terminal
// result; the helpers swallow the non-terminal progress ticks.

#include "liblogosdelivery.h"

int lcshim_create(const char *config_json, LogosDeliveryCreateFn on_created, void *user_data) {
    return logosdelivery_ctx_create(config_json, on_created, user_data);
}

int lcshim_destroy(LogosDeliveryCtx *ctx) {
    return logosdelivery_ctx_destroy(ctx);
}

int lcshim_start_node(const LogosDeliveryCtx *ctx, LogosDeliveryStartNodeReplyFn on_reply, void *user_data) {
    return logosdelivery_ctx_start_node(ctx, on_reply, user_data);
}

int lcshim_stop_node(const LogosDeliveryCtx *ctx, LogosDeliveryStopNodeReplyFn on_reply, void *user_data) {
    return logosdelivery_ctx_stop_node(ctx, on_reply, user_data);
}

int lcshim_subscribe(const LogosDeliveryCtx *ctx, const char *content_topic,
                     LogosDeliverySubscribeReplyFn on_reply, void *user_data) {
    return logosdelivery_ctx_subscribe(ctx, content_topic, on_reply, user_data);
}

int lcshim_unsubscribe(const LogosDeliveryCtx *ctx, const char *content_topic,
                       LogosDeliveryUnsubscribeReplyFn on_reply, void *user_data) {
    return logosdelivery_ctx_unsubscribe(ctx, content_topic, on_reply, user_data);
}

int lcshim_send(const LogosDeliveryCtx *ctx, const char *message_json,
                LogosDeliverySendReplyFn on_reply, void *user_data) {
    return logosdelivery_ctx_send(ctx, message_json, on_reply, user_data);
}

// The event registry is not part of the typed surface: it takes the raw
// handle, which only the C side can read out of the context.
uint64_t lcshim_add_event_listener(const LogosDeliveryCtx *ctx, const char *event_name,
                                   FFICallBack callback, void *user_data) {
    return logosdelivery_add_event_listener(ctx->ptr, event_name, callback, user_data);
}
