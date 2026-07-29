// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import { createStarlightTypeDocPlugin } from "starlight-typedoc";

// One Astro site served at the apex domain (Cloudflare Pages): the marketing
// landing owns `/` (src/pages/index.astro) and the Starlight docs live under
// `/docs/` (their content is nested in src/content/docs/docs/**). base is `/`,
// so internal links are plain absolute paths — no base-path rewriting needed.
const SITE = "https://targate.dev";
const REPO = "https://github.com/marcoabate-ck/targate";

// Generate the API reference from the package's public entry point. TypeDoc
// runs at build time (via typedoc-plugin-markdown) and writes Markdown into
// src/content/docs/docs/api, so it is served under /docs/api.
const [typeDocPlugin, typeDocSidebarGroup] = createStarlightTypeDocPlugin();

export default defineConfig({
  site: SITE,
  trailingSlash: "always",

  integrations: [
    starlight({
      title: "targate",
      description:
        "Install-time supply-chain security for npm — open source, AI-optional, in your terminal.",
      logo: { src: "./src/assets/logo.svg", alt: "targate" },
      favicon: "/favicon.svg",
      customCss: ["./src/styles/custom.css"],
      social: [{ icon: "github", label: "GitHub", href: REPO }],
      editLink: {
        baseUrl: `${REPO}/edit/main/website/`,
      },
      plugins: [
        typeDocPlugin({
          entryPoints: ["../src/index.ts"],
          tsconfig: "../tsconfig.json",
          output: "docs/api",
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
        { label: "What is targate?", link: "/docs/" },
        { label: "Getting started", link: "/docs/getting-started/" },
        { label: "How it works", link: "/docs/how-it-works/" },
        {
          label: "Concepts",
          collapsed: false,
          items: [
            "docs/concepts/decisions-and-trust",
            "docs/concepts/approvals-and-policy",
            "docs/concepts/transitive-and-install",
            "docs/concepts/ai-and-privacy",
            "docs/concepts/react-native",
          ],
        },
        { label: "CLI commands", link: "/docs/cli/" },
        { label: "Scenarios", link: "/docs/scenarios/" },
        { label: "FAQ", link: "/docs/faq/" },
        typeDocSidebarGroup,
      ],
    }),
  ],
});
