/* Force-included into the harness TUs: the upstream harnesses expect real glib, but melonDS
 * bundles libslirp with a minimal glib shim that lacks these few typedefs/macros. */
#include <glib.h>
#include <assert.h>
#include <stdint.h>
typedef uint16_t guint16;
typedef uint32_t guint32;
typedef int32_t gint32;
#define g_assert_cmpint(a, op, b) assert((a) op (b))
