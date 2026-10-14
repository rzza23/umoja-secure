package com.umoja.secure.transport

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Minimal HTTP/1.1 proxy that forwards requests through a local SOCKS5
 * proxy (Tor).
 *
 * Why this exists:
 *   OkHttp + Java's Socket implementation resolves hostnames locally even
 *   when a SOCKS proxy is configured. That breaks .onion addresses because
 *   they are not in DNS. This bridge solves that by taking HTTP requests
 *   from OkHttp (via Proxy.Type.HTTP), extracting the target host from the
 *   request line, and dialing SOCKS5 with the domain name in ATYP=0x03
 *   form. The SOCKS proxy (Tor) then handles the .onion resolution.
 *
 * Protocol:
 *   - Listens on 127.0.0.1:<ephemeral>.
 *   - Accepts OkHttp requests in absolute-URI form:
 *       GET http://<host>:<port>/path HTTP/1.1
 *     and rewrites them to origin-form before forwarding:
 *       GET /path HTTP/1.1
 *   - Handles CONNECT for HTTPS passthrough (not currently used by Umoja
 *     but implemented for completeness).
 *
 * Lifecycle: start() is idempotent; stop() closes the listener and lets
 * in-flight connections drain.
 */
object Socks5Bridge {
    private const val TAG = "UmojaSocksBridge"
    private const val SOCKS_HOST = "127.0.0.1"
    private const val SOCKS_PORT = 9050
    private const val SOCKS_VERSION: Byte = 0x05
    private const val SOCKS_CMD_CONNECT: Byte = 0x01
    private const val SOCKS_ATYP_DOMAIN: Byte = 0x03
    private const val SOCKS_ATYP_IPV4: Byte = 0x01
    private const val SOCKS_METHOD_NO_AUTH: Byte = 0x00

    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var port: Int = -1
    private val activeConnections = AtomicInteger(0)

    @Synchronized
    fun start(): Int {
        serverSocket?.let { return port }
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        serverSocket = ss
        port = ss.localPort
        Log.i(TAG, "bridge listening on 127.0.0.1:$port -> SOCKS $SOCKS_HOST:$SOCKS_PORT")
        thread(name = "socks-bridge-accept", isDaemon = true) {
            acceptLoop(ss)
        }
        return port
    }

    @Synchronized
    fun stop() {
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        port = -1
    }

    fun activeCount(): Int = activeConnections.get()

    private fun acceptLoop(ss: ServerSocket) {
        while (!ss.isClosed) {
            val client = try {
                ss.accept()
            } catch (_: Exception) {
                break
            }
            thread(name = "socks-bridge-conn", isDaemon = true) {
                activeConnections.incrementAndGet()
                try {
                    handleClient(client)
                } catch (e: Exception) {
                    Log.d(TAG, "connection closed: ${e.message}")
                } finally {
                    try { client.close() } catch (_: Exception) {}
                    activeConnections.decrementAndGet()
                }
            }
        }
    }

    private fun handleClient(client: Socket) {
        client.tcpNoDelay = true
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()

        // 1. Read the request line.
        val firstLine = readLine(clientIn) ?: return
        val parts = firstLine.split(" ")
        if (parts.size < 2) return
        val method = parts[0]
        val target = parts[1]
        val version = if (parts.size >= 3) parts[2] else "HTTP/1.1"

        val host: String
        val targetPort: Int
        val rewrittenFirstLine: String

        if (method == "CONNECT") {
            val (h, p) = parseHostPort(target, defaultPort = 443)
            host = h
            targetPort = p
            rewrittenFirstLine = firstLine
        } else if (target.startsWith("/")) {
            // Origin-form: we need the Host header. For Phase 1 we don't
            // support this (OkHttp sends absolute-URI when HTTP proxy is
            // configured). Log and bail.
            Log.w(TAG, "origin-form request not supported: $firstLine")
            writeSimpleResponse(clientOut, 400, "origin-form not supported")
            return
        } else {
            val url = target.removePrefix("http://").removePrefix("https://")
            val slash = url.indexOf('/')
            val authority = if (slash == -1) url else url.substring(0, slash)
            val path = if (slash == -1) "/" else url.substring(slash)
            val (h, p) = parseHostPort(authority, defaultPort = 80)
            host = h
            targetPort = p
            rewrittenFirstLine = "$method $path $version"
        }

        // 2. SOCKS5 to local Tor.
        val socks = Socket(SOCKS_HOST, SOCKS_PORT)
        socks.tcpNoDelay = true
        val socksIn = socks.getInputStream()
        val socksOut = socks.getOutputStream()

        try {
            // Greeting.
            socksOut.write(byteArrayOf(SOCKS_VERSION, 1, SOCKS_METHOD_NO_AUTH))
            socksOut.flush()
            val greet = ByteArray(2)
            readFully(socksIn, greet)
            if (greet[0] != SOCKS_VERSION || greet[1] != SOCKS_METHOD_NO_AUTH) {
                throw RuntimeException("SOCKS5 greeting rejected: ${greet.joinToString()}")
            }

            // CONNECT with domain name (ATYP=0x03).
            val hostBytes = host.toByteArray(Charsets.US_ASCII)
            require(hostBytes.isNotEmpty() && hostBytes.size <= 255) { "host length" }
            val req = ByteArray(4 + 1 + hostBytes.size + 2)
            req[0] = SOCKS_VERSION
            req[1] = SOCKS_CMD_CONNECT
            req[2] = 0
            req[3] = SOCKS_ATYP_DOMAIN
            req[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
            req[5 + hostBytes.size] = ((targetPort shr 8) and 0xFF).toByte()
            req[6 + hostBytes.size] = (targetPort and 0xFF).toByte()
            socksOut.write(req)
            socksOut.flush()

            // Reply: version, rep, rsv, atyp, addr, port.
            val head = ByteArray(4)
            readFully(socksIn, head)
            if (head[0] != SOCKS_VERSION || head[1] != 0x00.toByte()) {
                throw RuntimeException("SOCKS5 CONNECT failed: rep=${head[1]}")
            }
            when (head[3]) {
                SOCKS_ATYP_IPV4 -> readFully(socksIn, ByteArray(4 + 2))
                SOCKS_ATYP_DOMAIN -> {
                    val len = ByteArray(1); readFully(socksIn, len)
                    readFully(socksIn, ByteArray(len[0].toInt() + 2))
                }
                else -> throw RuntimeException("unknown ATYP ${head[3]}")
            }

            // 3. Forward the (possibly rewritten) request line + remaining bytes.
            socksOut.write((rewrittenFirstLine + "\r\n").toByteArray(Charsets.ISO_8859_1))
            socksOut.flush()

            // 4. Bidirectional relay.
            val t1 = thread(name = "socks-relay-c2s", isDaemon = true) {
                try { pipe(clientIn, socksOut) } catch (_: Exception) {}
                try { socks.shutdownOutput() } catch (_: Exception) {}
            }
            val t2 = thread(name = "socks-relay-s2c", isDaemon = true) {
                try { pipe(socksIn, clientOut) } catch (_: Exception) {}
                try { client.shutdownOutput() } catch (_: Exception) {}
            }
            t1.join()
            t2.join()
        } finally {
            try { socks.close() } catch (_: Exception) {}
        }
    }

    private fun pipe(from: InputStream, to: OutputStream) {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = from.read(buf)
            if (n <= 0) break
            to.write(buf, 0, n)
            to.flush()
        }
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) {
                if (sb.isNotEmpty() && sb.last() == '\r') sb.deleteAt(sb.length - 1)
                return sb.toString()
            }
            sb.append(b.toChar())
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n <= 0) throw RuntimeException("eof")
            off += n
        }
    }

    private fun parseHostPort(s: String, defaultPort: Int): Pair<String, Int> {
        val colon = s.lastIndexOf(':')
        return if (colon == -1 || colon == s.length - 1) {
            s to defaultPort
        } else {
            val host = s.substring(0, colon)
            val port = s.substring(colon + 1).toIntOrNull() ?: defaultPort
            host to port
        }
    }

    private fun writeSimpleResponse(out: OutputStream, code: Int, msg: String) {
        val body = msg.toByteArray(Charsets.UTF_8)
        val resp = "HTTP/1.1 $code $msg\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n"
        try {
            out.write(resp.toByteArray(Charsets.ISO_8859_1))
            out.write(body)
            out.flush()
        } catch (_: Exception) {}
    }
}
