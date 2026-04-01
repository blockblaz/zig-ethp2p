#!/bin/sh
# patch_uni.sh <input_c> <output_c>
#
# Patches lsquic_full_conn_ietf.c to:
#   1. Remove 'static' from create_uni_stream_out so it can be called externally.
#   2. Append a public lsquic_conn_make_uni_stream() wrapper at the end of the file.
#
# awk replaces the 'static int' line that immediately precedes create_uni_stream_out,
# leaving all other 'static int' functions unchanged.
awk '
/^static int$/ { pending = 1; buf = $0; next }
pending && /^create_uni_stream_out/ { print "int"; pending = 0 }
pending { print buf; pending = 0 }
{ print }
' "$1" > "$2"

cat >> "$2" <<'EOF'

/* zig-ethp2p extension: public wrapper for non-HTTP unidirectional stream creation.
 * Exposes create_uni_stream_out (now non-static above) so callers outside this
 * translation unit can open outbound UNI streams without HTTP/3. */
int
lsquic_conn_make_uni_stream (lsquic_conn_t *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return create_uni_stream_out(conn, 0,
                                 conn->ifc_enpub->enp_stream_if,
                                 conn->ifc_enpub->enp_stream_if_ctx);
}
EOF
