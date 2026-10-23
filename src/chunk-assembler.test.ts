import { describe, expect, it } from "vitest";
import { ChunkAssembler } from "./chunk-assembler";

const chunk = (size: number, fill: number) => new Uint8Array(size).fill(fill) as Uint8Array<ArrayBuffer>;
const bytesOf = async (blob: Blob) => new Uint8Array(await blob.arrayBuffer());

describe("chunk assembler", () => {
  it("rebuilds the file byte for byte and keeps only the current run in the page", async () => {
    const assembler = new ChunkAssembler(5, 2 * 1024);
    const chunks = [0, 1, 2, 3, 4].map(i => chunk(1024, i + 1));
    assembler.add(0, chunks[0]!);
    expect(assembler.heldBytes).toBe(1024);
    assembler.add(1, chunks[1]!);
    expect(assembler.heldBytes).toBe(0); // 2 KiB reached: handed to Blob storage
    for (const i of [2, 3, 4]) assembler.add(i, chunks[i]!);
    expect(assembler.complete).toBe(true);
    const blob = assembler.finish("application/octet-stream");
    expect(blob.type).toBe("application/octet-stream");
    expect(blob.size).toBe(5 * 1024);
    const bytes = await bytesOf(blob);
    for (let i = 0; i < 5; i++) expect(bytes[i * 1024]).toBe(i + 1);
  });

  it("holds an early chunk until the gap before it is filled", async () => {
    const assembler = new ChunkAssembler(3, 1);
    assembler.add(2, chunk(4, 3));
    expect(assembler.heldBytes).toBe(4);
    expect(assembler.complete).toBe(false);
    expect(() => assembler.finish("")).toThrow("File completion arrived before all chunks");
    assembler.add(0, chunk(4, 1));
    assembler.add(1, chunk(4, 2));
    expect(assembler.heldBytes).toBe(0);
    expect([...await bytesOf(assembler.finish(""))]).toEqual([1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3]);
  });

  it("refuses a repeated, already taken or out-of-range index", () => {
    const assembler = new ChunkAssembler(3);
    assembler.add(0, chunk(4, 1));
    expect(() => assembler.add(0, chunk(4, 1))).toThrow("out of order");
    assembler.add(2, chunk(4, 3));
    expect(() => assembler.add(2, chunk(4, 3))).toThrow("out of order");
    expect(() => assembler.add(3, chunk(4, 4))).toThrow("out of order");
    expect(() => assembler.add(-1, chunk(4, 4))).toThrow("out of order");
    expect(() => new ChunkAssembler(0)).toThrow(RangeError);
  });

  it("drops everything when cleared", () => {
    const assembler = new ChunkAssembler(4, 1024 * 1024);
    assembler.add(0, chunk(512, 1));
    assembler.add(2, chunk(512, 3));
    assembler.clear();
    expect(assembler.heldBytes).toBe(0);
  });
});
