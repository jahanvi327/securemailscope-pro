import { createFileRoute } from "@tanstack/react-router";
import App from "../App";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SecureMailScope | Email Security Posture Assessment" },
      { name: "description", content: "Analyze email traffic, TLS configuration, certificates, and security findings." },
      { property: "og:title", content: "SecureMailScope | Email Security Posture Assessment" },
      { property: "og:description", content: "Analyze email traffic, TLS configuration, certificates, and security findings." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: App,
});
