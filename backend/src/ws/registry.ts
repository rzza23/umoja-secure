import type { WebSocket } from 'ws';

export interface Connection {
  ws: WebSocket;
  device_id: string;
  session_id: string;
  ws_id: string;
  last_revalidated_at: number;
  is_alive: boolean;
}

class ConnectionRegistry {
  private byDevice = new Map<string, Set<Connection>>();
  private all = new Set<Connection>();

  register(conn: Connection): void {
    this.all.add(conn);
    let set = this.byDevice.get(conn.device_id);
    if (!set) {
      set = new Set();
      this.byDevice.set(conn.device_id, set);
    }
    set.add(conn);
  }

  unregister(conn: Connection): void {
    this.all.delete(conn);
    const set = this.byDevice.get(conn.device_id);
    if (set) {
      set.delete(conn);
      if (set.size === 0) this.byDevice.delete(conn.device_id);
    }
  }

  findByDevice(device_id: string): Connection[] {
    const set = this.byDevice.get(device_id);
    return set ? Array.from(set) : [];
  }

  isConnected(device_id: string): boolean {
    return this.findByDevice(device_id).length > 0;
  }

  sendToDevice(device_id: string, frame: object): boolean {
    const conns = this.findByDevice(device_id);
    let sent = false;
    for (const conn of conns) {
      try {
        if (conn.ws.readyState === 1) {
          conn.ws.send(JSON.stringify(frame));
          sent = true;
        }
      } catch {
        // ignore send failures; conn will be cleaned up on close
      }
    }
    return sent;
  }

  closeByDevice(device_id: string, code: number, reason: string): number {
    const conns = this.findByDevice(device_id);
    for (const conn of conns) {
      try {
        conn.ws.close(code, reason);
      } catch {
        // ignore
      }
    }
    return conns.length;
  }

  size(): number {
    return this.all.size;
  }

  clear(): void {
    for (const conn of this.all) {
      try {
        conn.ws.close(1001, 'server shutdown');
      } catch {
        // ignore
      }
    }
    this.byDevice.clear();
    this.all.clear();
  }
}

export const registry = new ConnectionRegistry();
