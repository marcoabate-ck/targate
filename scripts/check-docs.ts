import path from "node:path";
import { checkDocumentation } from "../src/docs-consistency.js";

const errors = await checkDocumentation(path.resolve(process.cwd()));
if (errors.length > 0) {
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log("Documentation is consistent with the command registry.");
}

