import { fromMarkdown } from "mdast-util-from-markdown";

import type { Finding } from "./model.js";

export const REQUIRED_AUTHMD_SECTIONS = [
  "Discover",
  "Pick a method",
  "Register",
  "Claim ceremony",
  "Exchange the assertion",
  "Use the access_token",
  "Errors",
  "Revocation",
] as const;

export type RequiredAuthMdSection = (typeof REQUIRED_AUTHMD_SECTIONS)[number];

export type AuthMdHeading = {
  text: string;
  normalized: string;
  level: number;
  line: number;
};

export type AuthMdSection = AuthMdHeading & {
  canonicalName?: RequiredAuthMdSection;
  content: string;
};

export type LinkReference = {
  url: string;
  line: number;
  label?: string;
};

export type MetadataReference = LinkReference & {
  kind: "protected-resource" | "authorization-server";
};

export type AuthMdDocument = {
  sourceUrl: string;
  text: string;
  headings: AuthMdHeading[];
  sections: AuthMdSection[];
  links: LinkReference[];
  metadataReferences: MetadataReference[];
  issuerReferences: LinkReference[];
  registrationModes: string[];
};

const sectionAliases: Record<string, RequiredAuthMdSection> = {
  discover: "Discover",
  "pick a method": "Pick a method",
  register: "Register",
  "claim ceremony": "Claim ceremony",
  "exchange the assertion": "Exchange the assertion",
  "use the access token": "Use the access_token",
  errors: "Errors",
  revocation: "Revocation",
};

export function parseAuthMd(sourceUrl: string, text: string): AuthMdDocument {
  const markdown = text.replace(/\r\n/g, "\n");
  const lines = markdown.split("\n");
  const proseLines = maskCodeBlocks(markdown, lines);
  const headings: AuthMdHeading[] = [];
  const topLevelSections: Array<AuthMdHeading & { startLine: number }> = [];

  for (const [index, line] of proseLines.entries()) {
    const match = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (match === null) {
      continue;
    }

    const level = match[1]?.length ?? 1;
    const rawText = match[2] ?? "";
    const heading = {
      text: rawText,
      normalized: normalizeHeading(rawText),
      level,
      line: index + 1,
    };
    headings.push(heading);

    if (level === 2) {
      topLevelSections.push({ ...heading, startLine: index + 1 });
    }
  }

  const sections = topLevelSections.map((section, index) => {
    const next = topLevelSections[index + 1];
    const endLine = next === undefined ? lines.length : next.startLine - 1;
    const content = lines.slice(section.startLine, endLine).join("\n").trim();
    const canonicalName = sectionAliases[section.normalized];

    return {
      text: section.text,
      normalized: section.normalized,
      level: section.level,
      line: section.line,
      content,
      ...(canonicalName === undefined ? {} : { canonicalName }),
    };
  });

  const links = extractLinks(proseLines);
  const metadataReferences = links
    .map((link) =>
      metadataKind(link) === undefined ? undefined : { ...link, kind: metadataKind(link) },
    )
    .filter((reference): reference is MetadataReference => reference !== undefined);

  return {
    sourceUrl,
    text,
    headings,
    sections,
    links,
    metadataReferences,
    issuerReferences: extractIssuerReferences(proseLines),
    registrationModes: extractRegistrationModes(proseLines),
  };
}

export function validateAuthMdDocument(document: AuthMdDocument): Finding[] {
  const findings: Finding[] = [];

  for (const requiredSection of REQUIRED_AUTHMD_SECTIONS) {
    const sections = document.sections.filter(
      (section) => section.canonicalName === requiredSection,
    );
    if (sections.length === 0) {
      findings.push(
        authMdFinding(
          "AUTHMD_REQUIRED_SECTION",
          "error",
          `Missing required section: ${requiredSection}.`,
          document,
          undefined,
          `Add a level-two heading named ${requiredSection}.`,
        ),
      );
      continue;
    }

    if (sections.length > 1) {
      for (const duplicate of sections.slice(1)) {
        findings.push(
          authMdFinding(
            "AUTHMD_DUPLICATE_SECTION",
            "error",
            `Duplicate section: ${requiredSection}.`,
            document,
            duplicate,
            `Keep one ${requiredSection} section.`,
          ),
        );
      }
    }

    for (const section of sections) {
      if (section.content.length === 0) {
        findings.push(
          authMdFinding(
            "AUTHMD_EMPTY_SECTION",
            "error",
            `Required section is empty: ${requiredSection}.`,
            document,
            section,
            "Add the registration guidance an agent needs for this step.",
          ),
        );
      }
    }
  }

  for (const section of document.sections) {
    if (section.canonicalName !== undefined) {
      continue;
    }

    findings.push(
      authMdFinding(
        "AUTHMD_UNKNOWN_SECTION",
        "warning",
        `Unknown auth.md section: ${section.text}.`,
        document,
        section,
        "Use one of the documented auth.md section names or nest this content under a known section.",
      ),
    );
  }

  for (const reference of document.metadataReferences) {
    if (isAbsoluteHttpsUrlWithoutFragment(reference.url)) {
      continue;
    }

    findings.push({
      ruleId: "AUTHMD_METADATA_URL",
      severity: "error",
      message: `Metadata URL must be an absolute HTTPS URL without a fragment: ${reference.url}.`,
      location: {
        document: document.sourceUrl,
        line: reference.line,
      },
      help: `Use an absolute https:// URL for ${reference.kind} metadata.`,
      specReference: "auth.md discovery guidance",
    });
  }

  return findings;
}

function normalizeHeading(value: string): string {
  return value
    .trim()
    .replace(/^step\s+\d+[a-z]?\s*[—–:-]\s*/i, "")
    .replace(/^\d+[a-z]?[.)]\s*/, "")
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .toLowerCase();
}

function extractLinks(lines: readonly string[]): LinkReference[] {
  const references: LinkReference[] = [];
  const seen = new Set<string>();

  for (const [index, line] of lines.entries()) {
    const markdownLink = /\[([^\]]+)]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
    for (const match of line.matchAll(markdownLink)) {
      addLink(references, seen, match[2] ?? "", index + 1, match[1]);
    }

    const rawUrl = /https?:\/\/[^\s)<>\]]+/g;
    for (const match of line.matchAll(rawUrl)) {
      addLink(references, seen, match[0], index + 1);
    }
  }

  return references;
}

function addLink(
  references: LinkReference[],
  seen: Set<string>,
  url: string,
  line: number,
  label?: string,
): void {
  const key = `${line}\u0000${url}`;
  if (url.length === 0 || seen.has(key)) {
    return;
  }
  seen.add(key);
  references.push({ url, line, ...(label === undefined ? {} : { label }) });
}

function metadataKind(link: LinkReference): MetadataReference["kind"] | undefined {
  const label = link.label?.toLowerCase() ?? "";
  const url = link.url.toLowerCase();

  if (
    label.includes("protected resource metadata") ||
    url.includes("/.well-known/oauth-protected-resource")
  ) {
    return "protected-resource";
  }

  if (
    label.includes("authorization server metadata") ||
    label.includes("openid configuration") ||
    url.includes("/.well-known/oauth-authorization-server") ||
    url.includes("/.well-known/openid-configuration")
  ) {
    return "authorization-server";
  }

  return undefined;
}

function extractIssuerReferences(lines: readonly string[]): LinkReference[] {
  const references: LinkReference[] = [];

  for (const [index, line] of lines.entries()) {
    const match = /\bissuer\b[^\n]*?(https?:\/\/[^\s)<>\]]+)/i.exec(line);
    if (match?.[1] !== undefined) {
      references.push({ url: match[1], line: index + 1, label: "issuer" });
    }
  }

  return references;
}

function extractRegistrationModes(lines: readonly string[]): string[] {
  const modes = ["identity_assertion", "service_auth", "anonymous"];
  const lowerCaseText = lines.join("\n").toLowerCase();
  return modes.filter((mode) => lowerCaseText.includes(mode));
}

function maskCodeBlocks(markdown: string, lines: readonly string[]): string[] {
  const codeLines = new Set<number>();
  markCodeLines(fromMarkdown(markdown), codeLines);
  return lines.map((line, index) => (codeLines.has(index + 1) ? "" : line));
}

type MarkdownNode = {
  type: string;
  position?: {
    start: { line: number };
    end: { line: number };
  };
  children?: unknown;
};

function markCodeLines(node: MarkdownNode, codeLines: Set<number>): void {
  if (node.type === "code" && node.position !== undefined) {
    for (let line = node.position.start.line; line <= node.position.end.line; line += 1) {
      codeLines.add(line);
    }
  }

  if (!Array.isArray(node.children)) {
    return;
  }
  for (const child of node.children) {
    if (isMarkdownNode(child)) {
      markCodeLines(child, codeLines);
    }
  }
}

function isMarkdownNode(value: unknown): value is MarkdownNode {
  return (
    typeof value === "object" && value !== null && "type" in value && typeof value.type === "string"
  );
}

function isAbsoluteHttpsUrlWithoutFragment(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin !== "null" && url.hash.length === 0;
  } catch {
    return false;
  }
}

function authMdFinding(
  ruleId: string,
  severity: Finding["severity"],
  message: string,
  document: AuthMdDocument,
  section: AuthMdSection | undefined,
  help: string,
): Finding {
  return {
    ruleId,
    severity,
    message,
    location: {
      document: document.sourceUrl,
      ...(section === undefined ? {} : { section: section.text, line: section.line }),
    },
    help,
    specReference: "auth.md document format",
  };
}
