// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import { createStarlightTypeDocPlugin } from "starlight-typedoc";

// GitHub Pages project site. The Pages URL path IS the repo name, so we derive
// org/repo from GITHUB_REPOSITORY in CI — renaming the repo then moves the site
// automatically, no edit here. Locally, fall back to the current repo so
// `pnpm build` matches CI.
const [ENV_ORG, ENV_REPO] = (process.env.GITHUB_REPOSITORY ?? "").split("/");
const ORG = ENV_ORG || "marcoabate-ck";
const REPO = ENV_REPO || "targate";

// Generate the API reference from the package's public entry point. TypeDoc
// runs at build time (via typedoc-plugin-markdown) and writes Markdown into
// src/content/docs/api; the sidebar group tracks whatever the entry exports.
const [typeDocPlugin, typeDocSidebarGroup] = createStarlightTypeDocPlugin();

// Astro only auto-resolves relative Markdown links inside `src/pages`, not
// inside Starlight content collections — so internal doc links are written
// root-relative (`/getting-started/`) and this rehype pass prepends the Pages
// `base`. Keeping links root-relative avoids trailing-slash depth math, and
// deriving the prefix from REPO keeps a repo rename working without edits.
function rehypeBaseLinks() {
  const prefix = REPO ? `/${REPO}` : "";
  /** @param {any} node */
  const walk = (node) => {
    if (
      prefix &&
      node.tagName === "a" &&
      node.properties &&
      typeof node.properties.href === "string"
    ) {
      const href = node.properties.href;
      if (
        href.startsWith("/") &&
        !href.startsWith("//") &&
        !href.startsWith(`${prefix}/`)
      ) {
        node.properties.href = `${prefix}${href}`;
      }
    }
    if (Array.isArray(node.children)) node.children.forEach(walk);
  };
  /** @param {any} tree */
  return function rehypeBaseLinksTransform(tree) {
    walk(tree);
  };
}

export default defineConfig({
  site: `https://${ORG}.github.io`,
  base: `/${REPO}/`,
  trailingSlash: "always",

  // `markdown.rehypePlugins` is the plugin hook Starlight 0.41 still merges into.
  // Astro 7 marks it deprecated in favor of a custom `processor: unified(...)`,
  // but swapping the processor would bypass Starlight's own injected pipeline —
  // so we stay on this supported (warning-only) path until Starlight migrates.
  markdown: { rehypePlugins: [rehypeBaseLinks] },

  integrations: [
    starlight({
      title: "targate",
      description:
        "Install-time supply-chain security for npm — open source, AI-optional, in your terminal.",
      logo: { src: "./src/assets/logo.svg", alt: "targate" },
      favicon: "/favicon.svg",
      customCss: ["./src/styles/custom.css"],
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: `https://github.com/${ORG}/${REPO}`,
        },
      ],
      editLink: {
        baseUrl: `https://github.com/${ORG}/${REPO}/edit/main/website/`,
      },
      plugins: [
        typeDocPlugin({
          entryPoints: ["../src/index.ts"],
          tsconfig: "../tsconfig.json",
          output: "api",
          typeDoc: {
            parametersFormat: "table",
            propertiesFormat: "table",
            enumMembersFormat: "table",
            indexFormat: "table",
            expandObjects: true,
            useCodeBlocks: true,
          },
        }),
      ],
      sidebar: [
        { label: "What is targate?", link: "/" },
        { label: "Getting started", link: "/getting-started/" },
        { label: "How it works", link: "/how-it-works/" },
        {
          label: "Concepts",
          collapsed: false,
          items: [
            "concepts/decisions-and-trust",
            "concepts/approvals-and-policy",
            "concepts/transitive-and-install",
            "concepts/ai-and-privacy",
            "concepts/react-native",
          ],
        },
        { label: "CLI commands", link: "/cli/" },
        { label: "Scenarios", link: "/scenarios/" },
        { label: "FAQ", link: "/faq/" },
        typeDocSidebarGroup,
      ],
    }),
  ],
});
