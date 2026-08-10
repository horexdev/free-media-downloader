import { readFile } from "node:fs/promises";

const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
const title = event.pull_request?.title ?? "";
const body = event.pull_request?.body ?? "";
const conventional = /^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\((app|core|ui|engine|download|update|i18n|security|build|release|deps|docs)\))?!?: [a-z][^\r\n.]{0,70}$/;
if (!conventional.test(title)) fail("pull request title must follow the project commit convention");
if (title.length > 72) fail("pull request title is longer than 72 characters");
const headings = ["Summary", "Why", "Testing", "Risks", "Checklist"];
const normalizedBody = `\n${body.replace(/\r\n?/g, "\n")}\n`;
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const sectionPattern = (heading) => new RegExp(`(?:^|\\n)\\s*#*\\s*${escapeRegex(heading)}\\b`, "i");
const missingSection = headings.find((heading) => !sectionPattern(heading).test(normalizedBody));
if (missingSection) {
  fail("pull request body must contain Summary, Why, Testing, Risks, and Checklist sections");
}
const forbiddenSource = process.env.FORBIDDEN_METADATA_REGEX;
if (!forbiddenSource) fail("FORBIDDEN_METADATA_REGEX repository variable is required");
let forbidden;
try { forbidden = new RegExp(forbiddenSource, "iu"); } catch { fail("FORBIDDEN_METADATA_REGEX is invalid"); }
if (forbidden.test(`${title}\n${body}`)) fail("pull request metadata contains a forbidden marker");

function fail(message) { console.error(message); process.exit(1); }
