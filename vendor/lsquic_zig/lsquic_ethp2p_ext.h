/* lsquic_ethp2p_ext.h -- zig-ethp2p extensions to the lsquic public API.
 *
 * These declarations cover capabilities that are internal to lsquic but
 * needed for non-HTTP unidirectional QUIC stream support (BCAST/SESS/CHUNK
 * protocols used by github.com/ethp2p/ethp2p).
 */
#ifndef LSQUIC_ETHP2P_EXT_H
#define LSQUIC_ETHP2P_EXT_H

#include "lsquic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Open a new outbound unidirectional stream on `conn`.
 *
 * Analogous to lsquic_conn_make_stream() but uses the QUIC unidirectional
 * stream namespace (client-initiated IDs 2, 6, 10 … or server-initiated
 * IDs 3, 7, 11 …, depending on which side this connection represents).
 *
 * The on_new_stream callback fires synchronously before this function
 * returns; the resulting stream context is write-only (the read side always
 * yields EOF to the opener).
 *
 * Returns 0 on success, -1 on allocation failure.
 * Must only be called after the QUIC handshake is complete.
 */
int lsquic_conn_make_uni_stream(lsquic_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* LSQUIC_ETHP2P_EXT_H */
