/**
 * Application-level flow control for file chunks (2026-10-21 audit, F02).
 *
 * The data channel's own buffer only shows how fast the network takes bytes. A receiver that writes to a slow disk queues
 * every chunk it has not written yet in page memory, up to a whole 2 GB file. With the receive window the receiver reports,
 * every PROGRESS_STEP_BYTES it has written, how many chunks it has handled; the sender stays at most RECEIVE_WINDOW_BYTES
 * ahead of the last report. Both hellos must carry `receiveWindow`; otherwise neither side changes behaviour.
 */
import { FILE_CHUNK_SIZE } from "./constants";

export const RECEIVE_WINDOW_BYTES = 16 * 1024 * 1024;
export const PROGRESS_STEP_BYTES = 2 * 1024 * 1024;
export const RECEIVE_WINDOW_CHUNKS = RECEIVE_WINDOW_BYTES / FILE_CHUNK_SIZE;
export const PROGRESS_STEP_CHUNKS = PROGRESS_STEP_BYTES / FILE_CHUNK_SIZE;
/** No progress for this long while the sender waits: the receiving device stopped handling the file. */
export const RECEIVE_STALL_MS = 120_000;
export const RECEIVE_STALL_MESSAGE = "The receiving browser stopped saving this file; try sending it again";

/** Whether the receiver reports after handling chunks up to `next` (exclusive). The last chunk needs no report: the
 * completion receipt follows it. */
export function progressDue(next: number, reported: number, total: number, step = PROGRESS_STEP_CHUNKS): boolean {
  return next < total && next - reported >= step;
}

/** The sender's side: how far the receiver says it has got, and a wait for room. */
export class SendWindow {
  #acked: number;
  #wake: (() => void) | undefined;

  constructor(start: number, readonly total: number, readonly limit = RECEIVE_WINDOW_CHUNKS) {
    this.#acked = start;
  }

  get acked(): number { return this.#acked; }

  /** Take a report. Old, repeated or impossible values are ignored, so a replayed report cannot move the window. */
  acknowledge(next: number): boolean {
    if (!Number.isSafeInteger(next) || next <= this.#acked || next > this.total) return false;
    this.#acked = next;
    const wake = this.#wake;
    this.#wake = undefined;
    wake?.();
    return true;
  }

  /** Resolves once chunk `index` may be sent. Rejects when `signal` aborts or no report arrives for `stallMs`. */
  async before(index: number, signal: AbortSignal, stallMs = RECEIVE_STALL_MS): Promise<void> {
    while (index - this.#acked >= this.limit) {
      signal.throwIfAborted();
      await new Promise<void>((resolve, reject) => {
        const done = (error?: unknown) => {
          clearTimeout(timer);
          signal.removeEventListener("abort", onAbort);
          if (this.#wake === wake) this.#wake = undefined;
          if (error) reject(error); else resolve();
        };
        const onAbort = () => done(signal.reason ?? new Error("File transfer cancelled"));
        const wake = () => done();
        const timer = setTimeout(() => done(new Error(RECEIVE_STALL_MESSAGE)), stallMs);
        signal.addEventListener("abort", onAbort, { once: true });
        this.#wake = wake;
      });
    }
  }
}
