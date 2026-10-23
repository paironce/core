/**
 * Collects the decrypted chunks of one received file and hands them to the browser's Blob storage in runs of a few MiB,
 * so the page holds only the current run instead of the whole file until it completes. Measured on 2026-10-18
 * in a browser: holding every chunk and building one Blob at the end peaked at about 2.4 times the
 * file size in the receiving page. Blob storage belongs to the browser, which can move large blobs to disk.
 *
 * Chunks are taken in order. One that arrives early waits until the gap before it is filled; the caller has already rejected
 * replays, out-of-range indexes and wrong sizes, and has reserved the file's size against the receive budget.
 */
export const ASSEMBLY_RUN_BYTES = 4 * 1024 * 1024;

export class ChunkAssembler {
  readonly #total: number;
  readonly #runLimit: number;
  #next = 0;
  #early = new Map<number, Uint8Array<ArrayBuffer>>();
  #run: Uint8Array<ArrayBuffer>[] = [];
  #runBytes = 0;
  #parts: Blob[] = [];

  constructor(totalChunks: number, runLimit = ASSEMBLY_RUN_BYTES) {
    if (!Number.isSafeInteger(totalChunks) || totalChunks < 1) throw new RangeError("A file needs at least one chunk");
    this.#total = totalChunks;
    this.#runLimit = runLimit;
  }

  add(index: number, chunk: Uint8Array<ArrayBuffer>): void {
    if (!Number.isSafeInteger(index) || index < this.#next || index >= this.#total || this.#early.has(index)) {
      throw new Error("File chunk index is out of order");
    }
    this.#early.set(index, chunk);
    for (let next = this.#early.get(this.#next); next; next = this.#early.get(this.#next)) {
      this.#early.delete(this.#next);
      this.#next += 1;
      this.#run.push(next);
      this.#runBytes += next.byteLength;
      if (this.#runBytes >= this.#runLimit) this.#flush();
    }
  }

  get complete(): boolean { return this.#next === this.#total; }

  /** Bytes still held by the page (the current run and any early chunks), for tests and diagnostics. */
  get heldBytes(): number {
    let early = 0;
    for (const chunk of this.#early.values()) early += chunk.byteLength;
    return this.#runBytes + early;
  }

  /** The whole file as one Blob. Joining Blob parts does not copy their bytes into the page. */
  finish(type: string): Blob {
    if (!this.complete) throw new Error("File completion arrived before all chunks");
    this.#flush();
    const blob = new Blob(this.#parts, { type });
    this.#parts = [];
    return blob;
  }

  /** Drop everything, for a cancelled or failed transfer. */
  clear(): void {
    this.#early.clear();
    this.#run = [];
    this.#runBytes = 0;
    this.#parts = [];
  }

  #flush(): void {
    if (this.#run.length === 0) return;
    this.#parts.push(new Blob(this.#run));
    this.#run = [];
    this.#runBytes = 0;
  }
}
