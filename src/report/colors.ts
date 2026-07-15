const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const color = (code: number, text: string) =>
  useColor ? `\u001b[${code}m${text}\u001b[0m` : text;

export const bold = (text: string) => color(1, text);
export const dim = (text: string) => color(2, text);
export const red = (text: string) => color(31, text);
export const green = (text: string) => color(32, text);
export const yellow = (text: string) => color(33, text);
export const cyan = (text: string) => color(36, text);

