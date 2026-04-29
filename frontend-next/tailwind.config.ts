import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        academy: {
          50: "#f6f8ff",
          100: "#e9efff",
          500: "#3b5bcc",
          700: "#233f9f",
          900: "#162762",
        },
      },
      boxShadow: {
        card: "0 6px 24px rgba(11, 36, 109, 0.08)",
      },
    },
  },
  plugins: [],
};

export default config;
