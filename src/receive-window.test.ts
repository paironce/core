import { afterEach, describe, expect, it, vi } from "vitest";
import { progressDue, RECEIVE_STALL_MESSAGE, RECEIVE_WINDOW_CHUNKS, SendWindow } from "./receive-window";

describe("receive window (2026-10-21 audit, F02)", () => {
  afterEach(() => { vi.useRealTimers(); });

  it("keeps the sender at most the window ahead of what the receiver handled", async () => {
    const window = new SendWindow(0, 2000, 4);
    const signal = new AbortController().signal;
    for (let index = 0; index < 4; index += 1) await window.before(index, signal);
    let sent = false;
    const waiting = window.before(4, signal).then(() => { sent = true; });
    await Promise.resolve();
    expect(sent).toBe(false);
    window.acknowledge(1);
    await waiting;
    expect(sent).toBe(true);
    expect(RECEIVE_WINDOW_CHUNKS * 32 * 1024).toBe(16 * 1024 * 1024);
  });

  it("ignores old, repeated and impossible reports, so a replay cannot open the window", () => {
    const window = new SendWindow(10, 100, 4);
    expect(window.acknowledge(10)).toBe(false);
    expect(window.acknowledge(9)).toBe(false);
    expect(window.acknowledge(101)).toBe(false);
    expect(window.acknowledge(1.5)).toBe(false);
    expect(window.acknowledge(20)).toBe(true);
    expect(window.acknowledge(20)).toBe(false);
    expect(window.acked).toBe(20);
  });

  it("starts from where a continued transfer resumes", async () => {
    const window = new SendWindow(500, 2000, 4);
    await window.before(503, new AbortController().signal);
    expect(window.acked).toBe(500);
  });

  it("gives up with a clear message when the receiver stops reporting, and stops at once on cancel", async () => {
    vi.useFakeTimers();
    const window = new SendWindow(0, 100, 2);
    const stalled = window.before(2, new AbortController().signal, 1000);
    const check = expect(stalled).rejects.toThrow(RECEIVE_STALL_MESSAGE);
    await vi.advanceTimersByTimeAsync(1000);
    await check;
    const abort = new AbortController();
    const cancelled = window.before(2, abort.signal, 1000);
    abort.abort(new Error("stopped"));
    await expect(cancelled).rejects.toThrow("stopped");
  });

  it("asks the receiver to report every step, but not after the last chunk", () => {
    expect(progressDue(63, 0, 1000, 64)).toBe(false);
    expect(progressDue(64, 0, 1000, 64)).toBe(true);
    expect(progressDue(127, 64, 1000, 64)).toBe(false);
    expect(progressDue(1000, 900, 1000, 64)).toBe(false);
  });
});
