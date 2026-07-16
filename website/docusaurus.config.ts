import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import { themes as prismThemes } from "prism-react-renderer";

// GitHub Pages project site. The product is "targate"; the repository is
// currently "before-you-execute". The Pages URL path IS the repo name, so we
// derive org/repo from GITHUB_REPOSITORY in CI — renaming the repo (e.g. to
// "targate") then moves the site to /targate/ automatically, no edit here.
// Locally, fall back to the current repo so `npm run build` matches CI.
const [ENV_ORG, ENV_REPO] = (process.env.GITHUB_REPOSITORY ?? "").split("/");
const ORG = ENV_ORG || "marcoabate-ck";
const REPO = ENV_REPO || "before-you-execute";

const config: Config = {
  title: "targate",
  tagline: "Gate every dependency before it runs.",
  favicon: "img/favicon.svg",

  url: `https://${ORG}.github.io`,
  baseUrl: `/${REPO}/`,

  organizationName: ORG,
  projectName: REPO,
  trailingSlash: false,

  // Broken links are a docs bug — fail the build so CI catches them.
  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",

  // Render every .md as CommonMark, not MDX. The TypeDoc-generated API pages
  // contain tokens MDX misparses as JSX/expressions — generic types like
  // `Record<string, string>` and doc-comment fragments like `policy.{ts,js}`.
  // The guide pages use only admonitions, raw HTML, and mermaid, all of which
  // work under CommonMark, so nothing here needs MDX.
  markdown: {
    mermaid: true,
    format: "md",
    hooks: { onBrokenMarkdownLinks: "throw" },
  },
  themes: ["@docusaurus/theme-mermaid"],

  i18n: { defaultLocale: "en", locales: ["en"] },

  presets: [
    [
      "classic",
      {
        docs: {
          routeBasePath: "/", // docs are the whole site
          sidebarPath: "./sidebars.ts",
          editUrl: `https://github.com/${ORG}/${REPO}/tree/main/website/`,
        },
        blog: false,
        theme: { customCss: "./src/css/custom.css" },
      } satisfies Preset.Options,
    ],
  ],

  // Generate the API reference from the package's public entry point.
  // TypeDoc runs at build time and writes Markdown into docs/api.
  plugins: [
    [
      "docusaurus-plugin-typedoc",
      {
        entryPoints: ["../src/index.ts"],
        tsconfig: "../tsconfig.json",
        out: "docs/api",
        readme: "none",
        sidebar: { autoConfiguration: true, pretty: true },
        parametersFormat: "table",
        propertiesFormat: "table",
        enumMembersFormat: "table",
        expandObjects: true,
        indexFormat: "table",
      },
    ],
  ],

  themeConfig: {
    colorMode: { respectPrefersColorScheme: true },
    navbar: {
      title: "targate",
      logo: { alt: "targate", src: "img/logo.svg" },
      items: [
        { type: "docSidebar", sidebarId: "guide", position: "left", label: "Guide" },
        { type: "docSidebar", sidebarId: "api", position: "left", label: "API" },
        {
          href: `https://github.com/${ORG}/${REPO}`,
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            { label: "Getting started", to: "/getting-started" },
            { label: "How it works", to: "/how-it-works" },
            { label: "Scenarios", to: "/scenarios" },
          ],
        },
        {
          title: "More",
          items: [
            { label: "GitHub", href: `https://github.com/${ORG}/${REPO}` },
            { label: "Issues", href: `https://github.com/${ORG}/${REPO}/issues` },
          ],
        },
      ],
      copyright: "targate — AI-gated pre-install security. MIT licensed.",
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash", "json", "yaml", "diff"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
