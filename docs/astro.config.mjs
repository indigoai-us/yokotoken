import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  integrations: [
    starlight({
      title: "HQ Vault",
      description:
        "Agent-native encrypted credential vault — keep secrets out of AI conversation context",
      social: {
        github: "https://github.com/indigoai-us/hq-vault",
      },
      customCss: ["./src/styles/custom.css"],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            { slug: "getting-started/introduction" },
            { slug: "getting-started/installation" },
            { slug: "getting-started/concepts" },
          ],
        },
        {
          label: "CLI Reference",
          items: [
            { slug: "cli/vault-management" },
            { slug: "cli/secrets" },
            { slug: "cli/tokens" },
            { slug: "cli/audit" },
          ],
        },
        {
          label: "HTTP API",
          items: [
            { slug: "api/secrets" },
            { slug: "api/tokens" },
            { slug: "api/server" },
          ],
        },
        {
          label: "SDK",
          items: [{ slug: "sdk/usage" }],
        },
        {
          label: "Guides",
          items: [
            { slug: "guides/agent-workflows" },
            { slug: "guides/daemon-mode" },
          ],
        },
        {
          label: "Security",
          items: [
            { slug: "security/encryption" },
            { slug: "security/network" },
          ],
        },
      ],
    }),
  ],
});
