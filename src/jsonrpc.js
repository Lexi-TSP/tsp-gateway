/**
 * Newline-delimited JSON-RPC 2.0 framing (MCP stdio transport).
 * Tolerant reader: buffers partial lines, skips unparseable ones (a proxy
 * must not crash on a peer's garbage — it drops the line and keeps framing).
 */
export const createLineReader = (onMessage) => {
  let buffer = '';
  return (chunk) => {
    buffer += chunk.toString('utf8');
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      try {
        onMessage(JSON.parse(line));
      } catch {
        // dropped: not JSON; framing preserved
      }
    }
  };
};

export const writeMessage = (stream, message) => {
  stream.write(JSON.stringify(message) + '\n');
};
