/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'shigoku-primary': '#6366f1',
        'shigoku-dark': '#1e293b',
      }
    },
  },
  plugins: [],
}
