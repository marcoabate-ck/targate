const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const color = (code: number, text: string) =>
  useColor ? `\u001b[${code}m${text}\u001b[0m` : text;

export const bold = (text: string) => color(1, text);
export const dim = (text: string) => color(2, text);
export const red = (text: string) => color(31, text);
export const green = (text: string) => color(32, text);
export const yellow = (text: string) => color(33, text);
export const cyan = (text: string) => color(36, text);

/**
 * Neutralize attacker-controlled text before it is rendered to the terminal.
 * Package metadata and tarball paths are hostile input: raw ANSI escapes,
 * carriage returns, or newlines let a malicious package forge reassuring
 * checklist lines, scroll away the real verdict, or hide findings. Strip ANSI
 * CSI/OSC sequences, the lone ESC, C0/C1 controls and DEL, and flatten any
 * newline to a space so every value stays on its intended single line. (The
 * tool's OWN colors are applied via the helpers above, AFTER this runs, so they
 * are unaffected.)
 */
export function clean(text: unknown): string {
  return (
    String(text)
      // ANSI CSI sequences: ESC [ … final byte.
      // eslint-disable-next-line no-control-regex
      .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
      // ANSI OSC sequences: ESC ] … terminated by BEL or ST (ESC \).
      // eslint-disable-next-line no-control-regex
      .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, "")
      // Any remaining control char (lone ESC, CR/LF, other C0, DEL, C1) -> space,
      // so hostile text can never break onto its own line or emit an escape.
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ")
  );
}
