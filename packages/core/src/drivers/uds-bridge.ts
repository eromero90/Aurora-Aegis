import net from 'node:net';
import {
  type DiagnosticReporter,
  formatErrorMessage,
  getErrnoCode,
  isExpectedErrno,
} from '../utils/error-codes.js';

const EXPECTED_SOCKET_ERRNOS = new Set([
  'ERR_SOCKET_CLOSED',
  'ERR_STREAM_DESTROYED',
  'EPIPE',
  'ENOTCONN',
  'ECONNRESET',
]);

export class UdsLoopbackBridge {
  private server: net.Server | undefined;
  private readonly activeSockets = new Set<net.Socket>();

  constructor(private readonly onDiagnostic?: DiagnosticReporter) {}

  async start(udsSocketPath: string, listenPort = 0): Promise<number> {
    if (this.server) {
      throw new Error('UdsLoopbackBridge is already running.');
    }

    const server = net.createServer((tcpSocket) => {
      const udsSocket = net.createConnection({ path: udsSocketPath });
      this.activeSockets.add(tcpSocket);
      this.activeSockets.add(udsSocket);

      const cleanupBoth = () => {
        this.activeSockets.delete(tcpSocket);
        this.activeSockets.delete(udsSocket);
        if (!tcpSocket.destroyed) tcpSocket.destroy();
        if (!udsSocket.destroyed) udsSocket.destroy();
      };

      tcpSocket.on('error', cleanupBoth);
      udsSocket.on('error', cleanupBoth);
      tcpSocket.on('close', cleanupBoth);
      udsSocket.on('close', cleanupBoth);

      tcpSocket.pipe(udsSocket);
      udsSocket.pipe(tcpSocket);
    });

    this.server = server;

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(listenPort, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });

    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('Failed to obtain TCP port for UdsLoopbackBridge.');
    }

    return address.port;
  }

  async stop(): Promise<void> {
    for (const socket of this.activeSockets) {
      try {
        socket.destroy();
      } catch (err) {
        if (!isExpectedErrno(err, EXPECTED_SOCKET_ERRNOS)) {
          this.onDiagnostic?.({
            source: 'UdsLoopbackBridge.stop',
            code: getErrnoCode(err),
            message: formatErrorMessage(err),
          });
        }
      }
    }
    this.activeSockets.clear();

    if (!this.server) {
      return;
    }

    const serverToClose = this.server;
    this.server = undefined;
    await new Promise<void>((resolve) => {
      serverToClose.close(() => resolve());
    });
  }
}
