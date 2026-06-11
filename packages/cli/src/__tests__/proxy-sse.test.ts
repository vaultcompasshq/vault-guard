import { parseAnthropicSseUsage } from '../commands/proxy-sse';

const REALISTIC_STREAM =
  'event: message_start\n' +
  'data: {"type":"message_start","message":{"id":"msg_1","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":1200,"output_tokens":1}}}\n\n' +
  'event: content_block_start\n' +
  'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n' +
  'event: content_block_delta\n' +
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}\n\n' +
  'event: message_delta\n' +
  'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":120}}\n\n' +
  'event: message_delta\n' +
  'data: {"type":"message_delta","delta":{},"usage":{"output_tokens":350}}\n\n' +
  'event: message_stop\n' +
  'data: {"type":"message_stop"}\n\n';

describe('parseAnthropicSseUsage', () => {
  it('extracts input tokens from message_start and final output tokens from last message_delta', () => {
    const result = parseAnthropicSseUsage(REALISTIC_STREAM, null);
    expect(result.inputTokens).toBe(1200);
    expect(result.outputTokens).toBe(350);
    expect(result.model).toBe('claude-3-5-sonnet-20241022');
  });

  it('uses fallbackModel when message_start has no model field', () => {
    const stream =
      'data: {"type":"message_start","message":{"usage":{"input_tokens":500,"output_tokens":1}}}\n\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":80}}\n\n';
    const result = parseAnthropicSseUsage(stream, 'claude-3-opus');
    expect(result.model).toBe('claude-3-opus');
    expect(result.inputTokens).toBe(500);
    expect(result.outputTokens).toBe(80);
  });

  it('returns zeros and null model on empty stream', () => {
    const result = parseAnthropicSseUsage('', null);
    expect(result.inputTokens).toBe(0);
    expect(result.outputTokens).toBe(0);
    expect(result.model).toBeNull();
  });

  it('ignores garbage data lines and keeps parsing', () => {
    const stream =
      'data: not-json-at-all\n' +
      'data: {"type":"message_start","message":{"model":"claude-3","usage":{"input_tokens":100,"output_tokens":1}}}\n' +
      'data: {broken\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":42}}\n';
    const result = parseAnthropicSseUsage(stream, null);
    expect(result.inputTokens).toBe(100);
    expect(result.outputTokens).toBe(42);
  });

  it('ignores [DONE] sentinel lines', () => {
    const stream =
      'data: {"type":"message_start","message":{"model":"claude-3","usage":{"input_tokens":10,"output_tokens":1}}}\n' +
      'data: [DONE]\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":5}}\n';
    const result = parseAnthropicSseUsage(stream, null);
    expect(result.inputTokens).toBe(10);
    expect(result.outputTokens).toBe(5);
  });

  it('uses initial output_tokens from message_start when no message_delta arrives', () => {
    const stream =
      'data: {"type":"message_start","message":{"model":"claude-3","usage":{"input_tokens":200,"output_tokens":5}}}\n';
    const result = parseAnthropicSseUsage(stream, null);
    expect(result.inputTokens).toBe(200);
    expect(result.outputTokens).toBe(5);
  });

  it('handles stream with no usage fields gracefully', () => {
    const stream =
      'data: {"type":"message_start","message":{"model":"claude-3"}}\n' +
      'data: {"type":"message_stop"}\n';
    const result = parseAnthropicSseUsage(stream, 'fallback');
    expect(result.inputTokens).toBe(0);
    expect(result.outputTokens).toBe(0);
    expect(result.model).toBe('claude-3');
  });

  it('last message_delta output_tokens wins (cumulative)', () => {
    const stream =
      'data: {"type":"message_start","message":{"model":"m","usage":{"input_tokens":50,"output_tokens":1}}}\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":10}}\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":25}}\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":99}}\n';
    const result = parseAnthropicSseUsage(stream, null);
    expect(result.outputTokens).toBe(99);
  });
});
