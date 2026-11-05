// Deliberately poor code used by SAYTU's quality scanner tests.
import { readFileSync } from "fs";

export function render(template: string, data: any) {
  const unused = 42;
  return readFileSync(template, "utf8").replace("{{name}}", data[template]);
}
